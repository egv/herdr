//! Which Herdr executable long-lived configuration should run: a hub
//! `authorized_keys` forced command or a slave service unit outlives the
//! running binary, so a versioned package path is replaced by a stable
//! launcher when one exists.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

/// Path fragments of package-manager directories that change on upgrade.
const VERSIONED_PATH_MARKERS: &[&str] = &[
    "/nix/store/",
    "/Cellar/",
    "/mise/installs/",
    "/.cargo/registry/",
];

pub(crate) fn path_looks_versioned(path: &Path) -> bool {
    let text = path.to_string_lossy();
    VERSIONED_PATH_MARKERS
        .iter()
        .any(|marker| text.contains(marker))
}

/// Which Herdr executable long-lived configuration should run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HerdrPathChoice {
    path: PathBuf,
    /// Set when `path` is a stable launcher used instead of a versioned executable.
    replaced: Option<PathBuf>,
    /// Set when `path` is versioned and no stable launcher was found.
    warning: Option<String>,
}

/// Stable `herdr` launchers to try, in order, when the running executable
/// lives in a versioned package directory. Paths are not canonicalized:
/// a stable symlink into a versioned store is exactly what is wanted.
fn stable_launcher_candidates(home: Option<&Path>, path_env: Option<&OsStr>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut push = |candidate: PathBuf| {
        if candidate.is_absolute()
            && !path_looks_versioned(&candidate)
            && !candidates.contains(&candidate)
        {
            candidates.push(candidate);
        }
    };
    if let Some(home) = home {
        push(home.join(".local/bin/herdr"));
    }
    push(PathBuf::from("/opt/homebrew/bin/herdr"));
    push(PathBuf::from("/usr/local/bin/herdr"));
    if let Some(home) = home {
        push(home.join(".nix-profile/bin/herdr"));
    }
    if let Some(path_env) = path_env {
        for directory in std::env::split_paths(path_env) {
            push(directory.join("herdr"));
        }
    }
    candidates
}

/// Uses `executable` unless it looks versioned; then the first existing
/// stable launcher, or `executable` with a warning when there is none.
fn choose_herdr_path(
    executable: &Path,
    home: Option<&Path>,
    path_env: Option<&OsStr>,
    exists: impl Fn(&Path) -> bool,
) -> HerdrPathChoice {
    if !path_looks_versioned(executable) {
        return HerdrPathChoice {
            path: executable.to_path_buf(),
            replaced: None,
            warning: None,
        };
    }
    let candidates = stable_launcher_candidates(home, path_env);
    if let Some(stable) = candidates.iter().find(|candidate| exists(candidate)) {
        return HerdrPathChoice {
            path: stable.clone(),
            replaced: Some(executable.to_path_buf()),
            warning: None,
        };
    }
    HerdrPathChoice {
        path: executable.to_path_buf(),
        replaced: None,
        warning: Some(format!(
            "{} is inside a versioned install directory that may disappear after an upgrade, and no stable `herdr` launcher was found in ~/.local/bin, /opt/homebrew/bin, /usr/local/bin, ~/.nix-profile/bin, or PATH; pass --herdr-path with a path that survives upgrades",
            executable.display()
        )),
    }
}

/// `explicit` when given (it must be absolute; a warning notes when it is
/// not a file on this machine), else the running executable unless it lives
/// in a versioned package directory and a stable launcher exists. The second
/// value is a `note: ...` or `warning: ...` line to show on stderr.
pub(crate) fn stable_herdr_path(explicit: Option<&Path>) -> io::Result<(PathBuf, Option<String>)> {
    if let Some(path) = explicit {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the Herdr path must be absolute: {}", path.display()),
            ));
        }
        let warning = (!path.is_file())
            .then(|| format!("warning: {} is not a file on this machine", path.display()));
        return Ok((path.to_path_buf(), warning));
    }
    let executable = crate::platform::launch_executable()?;
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from);
    let path_env = std::env::var_os("PATH");
    let choice = choose_herdr_path(
        &executable,
        home.as_deref(),
        path_env.as_deref(),
        Path::is_file,
    );
    let message = match (&choice.replaced, choice.warning) {
        (Some(replaced), _) => Some(format!(
            "note: using the stable launcher {} instead of the versioned executable {}",
            choice.path.display(),
            replaced.display()
        )),
        (None, Some(warning)) => Some(format!("warning: {warning}")),
        (None, None) => None,
    };
    Ok((choice.path, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_install_paths_are_detected() {
        for versioned in [
            "/nix/store/abc123-herdr-0.9.0/bin/herdr",
            "/opt/homebrew/Cellar/herdr/0.9.0/bin/herdr",
            "/home/u/.local/share/mise/installs/herdr/0.9.0/herdr",
            "/home/u/.cargo/registry/src/herdr/herdr",
        ] {
            assert!(path_looks_versioned(Path::new(versioned)), "{versioned}");
        }
        for stable in [
            "/home/u/.local/bin/herdr",
            "/opt/homebrew/bin/herdr",
            "/usr/local/bin/herdr",
            "/home/u/.nix-profile/bin/herdr",
            "/home/u/.cargo/bin/herdr",
        ] {
            assert!(!path_looks_versioned(Path::new(stable)), "{stable}");
        }
    }

    #[test]
    fn stable_launcher_is_preferred_only_for_versioned_executables() {
        let home = Path::new("/home/u");
        let path_env =
            std::env::join_paths(["/nix/store/x/bin", "relative", "/custom/bin"]).unwrap();
        assert_eq!(
            stable_launcher_candidates(Some(home), Some(&path_env)),
            [
                PathBuf::from("/home/u/.local/bin/herdr"),
                PathBuf::from("/opt/homebrew/bin/herdr"),
                PathBuf::from("/usr/local/bin/herdr"),
                PathBuf::from("/home/u/.nix-profile/bin/herdr"),
                PathBuf::from("/custom/bin/herdr"),
            ]
        );

        let plain = Path::new("/usr/bin/herdr");
        let choice = choose_herdr_path(plain, Some(home), Some(&path_env), |_| true);
        assert_eq!(choice.path, plain);
        assert_eq!(choice.replaced, None);
        assert_eq!(choice.warning, None);

        let versioned = Path::new("/nix/store/abc-herdr/bin/herdr");
        let choice = choose_herdr_path(versioned, Some(home), Some(&path_env), |candidate| {
            candidate == Path::new("/home/u/.nix-profile/bin/herdr")
                || candidate == Path::new("/custom/bin/herdr")
        });
        assert_eq!(choice.path, Path::new("/home/u/.nix-profile/bin/herdr"));
        assert_eq!(choice.replaced.as_deref(), Some(versioned));
        assert_eq!(choice.warning, None);

        let choice = choose_herdr_path(versioned, None, None, |_| false);
        assert_eq!(choice.path, versioned);
        assert_eq!(choice.replaced, None);
        assert!(choice.warning.unwrap().contains("--herdr-path"));
    }

    #[test]
    fn explicit_herdr_paths_must_be_absolute_and_warn_when_missing() {
        assert_eq!(
            stable_herdr_path(Some(Path::new("bin/herdr")))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let missing = std::env::temp_dir().join("herdr-no-such-launcher/herdr");
        let (path, warning) = stable_herdr_path(Some(&missing)).unwrap();
        assert_eq!(path, missing);
        assert!(warning.unwrap().starts_with("warning: "));
        let (_, warning) = stable_herdr_path(Some(Path::new("/bin/sh"))).unwrap();
        assert_eq!(warning, None);
        assert!(stable_herdr_path(None).unwrap().0.is_absolute());
    }
}
