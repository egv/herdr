//! Editing the hub's `authorized_keys` file for dial-in machines: adding,
//! replacing, and revoking exactly the lines Herdr rendered (ending in
//! `herdr-link:<id>`), atomically and without touching any other line.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use super::authorized_keys::LINK_KEY_COMMENT_PREFIX;
use crate::client::endpoint::ProfileId;

/// `$HOME/.ssh/authorized_keys`.
pub(crate) fn default_path() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".ssh").join("authorized_keys"))
        .ok_or_else(|| "HOME is not set; pass --authorized-keys <path>".into())
}

/// Adds `line`, the rendered line for `id` carrying the key `key_base64`.
/// Refuses when the key is already authorized on another line, and when a
/// line for `id` exists unless `replace`, which swaps that line in place.
/// Creates a missing parent directory (0700) and file (0600). Returns whether
/// a line was replaced.
pub(crate) fn authorize(
    path: &Path,
    id: &ProfileId,
    key_base64: &str,
    line: &str,
    replace: bool,
) -> Result<bool, String> {
    let content = read_checked(path, true)?.unwrap_or_default();
    let terminator: &[u8] = if content.windows(2).any(|pair| pair == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    };
    let mut output = Vec::with_capacity(content.len() + line.len() + 2);
    let mut replaced = false;
    for (index, raw) in content.split_inclusive(|&byte| byte == b'\n').enumerate() {
        let body = line_body(raw);
        if is_link_line(body, id) {
            if !replace {
                return Err(format!(
                    "{}:{}: a line for this machine already exists; pass --replace to replace it",
                    path.display(),
                    index + 1
                ));
            }
            if !replaced {
                output.extend_from_slice(line.as_bytes());
                output.extend_from_slice(&raw[body.len()..]);
                replaced = true;
            }
            continue;
        }
        if has_key(body, key_base64) {
            return Err(format!(
                "{}:{}: this key is already authorized on that line; remove it first",
                path.display(),
                index + 1
            ));
        }
        output.extend_from_slice(raw);
    }
    if !replaced {
        if !output.is_empty() && !output.ends_with(b"\n") {
            output.extend_from_slice(terminator);
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(terminator);
    }
    write_atomically(path, &output)?;
    Ok(replaced)
}

/// Removes every line Herdr rendered for `id`; returns how many it removed.
pub(crate) fn revoke(path: &Path, id: &ProfileId) -> Result<usize, String> {
    let Some(content) = read_checked(path, false)? else {
        return Ok(0);
    };
    let mut output = Vec::with_capacity(content.len());
    let mut removed = 0;
    for raw in content.split_inclusive(|&byte| byte == b'\n') {
        if is_link_line(line_body(raw), id) {
            removed += 1;
        } else {
            output.extend_from_slice(raw);
        }
    }
    if removed > 0 {
        write_atomically(path, &output)?;
    }
    Ok(removed)
}

/// A line without its `\n` or `\r\n` terminator.
fn line_body(raw: &[u8]) -> &[u8] {
    let body = raw.strip_suffix(b"\n").unwrap_or(raw);
    body.strip_suffix(b"\r").unwrap_or(body)
}

/// Whether Herdr rendered `body` for `id`.
fn is_link_line(body: &[u8], id: &ProfileId) -> bool {
    body.starts_with(b"restrict,command=\"")
        && body.ends_with(format!(" {LINK_KEY_COMMENT_PREFIX}{id}").as_bytes())
}

/// Whether an active (uncommented) line carries the key data `key_base64`.
fn has_key(body: &[u8], key_base64: &str) -> bool {
    !body.trim_ascii_start().starts_with(b"#")
        && body
            .split(u8::is_ascii_whitespace)
            .any(|field| field == key_base64.as_bytes())
}

/// The file's content (`None` when it does not exist). Refuses a symlinked
/// file or parent directory and a file owned by someone else. With `create`,
/// a missing parent directory is created private.
fn read_checked(path: &Path, create: bool) -> Result<Option<Vec<u8>>, String> {
    let refuse = |what: &str| format!("refusing to edit {}: {what}", path.display());
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| refuse("it has no parent directory"))?;
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(refuse("its directory is a symlink"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
            crate::platform::ensure_private_directory(parent)
                .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", parent.display())),
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(refuse("it is a symlink")),
        Ok(metadata) if !metadata.is_file() => return Err(refuse("it is not a regular file")),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    }
    if !crate::platform::file_is_owned_by_current_user(path)
        .map_err(|error| format!("{}: {error}", path.display()))?
    {
        return Err(refuse("it is owned by another user"));
    }
    std::fs::read(path)
        .map(Some)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))
}

/// Replaces `path` with `content` through a temporary file in the same
/// directory, keeping the existing file's permissions (0600 for a new file).
fn write_atomically(path: &Path, content: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let temp = parent.join(format!(".{name}.herdr-{}.tmp", std::process::id()));
    let permissions = std::fs::symlink_metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let written = (|| {
        let mut file = crate::platform::create_private_state_file(&temp)?;
        file.write_all(content)?;
        if let Some(permissions) = permissions {
            file.set_permissions(permissions)?;
        }
        file.sync_all()?;
        drop(file);
        crate::platform::replace_file(&temp, path)
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("failed to write {}: {error}", path.display()));
    }
    if let Err(error) = crate::platform::sync_parent_directory(parent) {
        tracing::debug!(%error, "could not sync the authorized_keys directory");
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAICiyVkMtB424oOJkudA7Gr13nYvfcpJFBxq2EoLwM5LW";

    fn id() -> ProfileId {
        ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    fn other_id() -> ProfileId {
        ProfileId::parse("fedcba9876543210fedcba9876543210").unwrap()
    }

    fn line(id: &ProfileId, key: &str) -> String {
        format!("restrict,command=\"'/bin/herdr' link-accept --link {id}\" ssh-ed25519 {key} herdr-link:{id}")
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "herdr-authorized-keys-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn a_missing_directory_and_file_are_created_private() {
        let home = scratch("create");
        let path = home.join(".ssh").join("authorized_keys");
        assert!(!authorize(&path, &id(), KEY, &line(&id(), KEY), false).unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", line(&id(), KEY))
        );
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(revoke(&home.join("nothing").join("keys"), &id()), Ok(0));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn other_lines_stay_byte_for_byte_and_the_terminator_is_kept() {
        let home = scratch("preserve");
        let path = home.join("authorized_keys");
        let other = line(&other_id(), "AAAAother");
        for (before, terminator) in [
            (
                format!("# keys\r\nssh-rsa AAAAx a@b\r\n{other}\r\n"),
                "\r\n",
            ),
            (format!("ssh-rsa AAAAx a@b\n\n{other}"), "\n"),
            (String::new(), "\n"),
        ] {
            std::fs::write(&path, &before).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            authorize(&path, &id(), KEY, &line(&id(), KEY), false).unwrap();
            let mut expected = before.clone();
            if !expected.is_empty() && !expected.ends_with('\n') {
                expected.push_str(terminator);
            }
            expected.push_str(&format!("{}{terminator}", line(&id(), KEY)));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
            assert_eq!(mode(&path), 0o644, "the mode is preserved");

            assert_eq!(revoke(&path, &id()), Ok(1));
            let mut restored = before.clone();
            if !restored.is_empty() && !restored.ends_with('\n') {
                restored.push_str(terminator);
            }
            assert_eq!(std::fs::read_to_string(&path).unwrap(), restored);
            assert_eq!(revoke(&path, &id()), Ok(0));
        }
        let leftovers = std::fs::read_dir(&home)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            })
            .count();
        assert_eq!(leftovers, 0);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn duplicates_are_refused_and_replace_swaps_only_the_link_line() {
        let home = scratch("replace");
        let path = home.join("authorized_keys");
        let first = format!(
            "ssh-ed25519 AAAAold x\r\n{}\r\nssh-rsa AAAAy\n",
            line(&id(), "AAAAold")
        );
        std::fs::write(&path, &first).unwrap();

        let error = authorize(&path, &id(), KEY, &line(&id(), KEY), false).unwrap_err();
        assert!(
            error.contains(":2:") && error.contains("--replace"),
            "{error}"
        );
        assert!(authorize(&path, &id(), KEY, &line(&id(), KEY), true).unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!(
                "ssh-ed25519 AAAAold x\r\n{}\r\nssh-rsa AAAAy\n",
                line(&id(), KEY)
            )
        );
        // Replacing with the same key is allowed; the key elsewhere is not.
        assert!(authorize(&path, &id(), KEY, &line(&id(), KEY), true).unwrap());
        let error = authorize(&path, &id(), "AAAAold", &line(&id(), "AAAAold"), true).unwrap_err();
        assert!(error.contains(":1:"), "{error}");
        let error = authorize(&path, &other_id(), KEY, &line(&other_id(), KEY), false).unwrap_err();
        assert!(
            error.contains(":2:") && error.contains("already authorized"),
            "{error}"
        );
        // A commented-out key does not count.
        std::fs::write(&path, format!("# ssh-ed25519 {KEY}\n")).unwrap();
        authorize(&path, &id(), KEY, &line(&id(), KEY), false).unwrap();
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn revoke_removes_only_lines_rendered_for_that_machine() {
        let home = scratch("revoke");
        let path = home.join("authorized_keys");
        let keep = [
            line(&other_id(), KEY),
            format!("ssh-ed25519 {KEY} herdr-link:{}", id()),
            format!("{} trailing", line(&id(), KEY)),
        ];
        let content = format!(
            "{}\n{}\n{}\n{}\n{}",
            keep[0],
            line(&id(), KEY),
            keep[1],
            keep[2],
            line(&id(), "AAAAsecond")
        );
        std::fs::write(&path, content).unwrap();
        assert_eq!(revoke(&path, &id()), Ok(2));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n{}\n{}\n", keep[0], keep[1], keep[2])
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn symlinks_and_directories_are_refused() {
        let home = scratch("symlink");
        let real_dir = home.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::fs::write(real_dir.join("authorized_keys"), "").unwrap();
        symlink(&real_dir, home.join(".ssh")).unwrap();
        symlink(
            real_dir.join("authorized_keys"),
            real_dir.join("linked_keys"),
        )
        .unwrap();
        for path in [
            home.join(".ssh").join("authorized_keys"),
            real_dir.join("linked_keys"),
        ] {
            let error = authorize(&path, &id(), KEY, &line(&id(), KEY), false).unwrap_err();
            assert!(error.contains("symlink"), "{error}");
            assert!(revoke(&path, &id()).unwrap_err().contains("symlink"));
        }
        assert!(authorize(&real_dir, &id(), KEY, &line(&id(), KEY), false)
            .unwrap_err()
            .contains("not a regular file"));
        assert_eq!(
            std::fs::read_to_string(real_dir.join("authorized_keys")).unwrap(),
            ""
        );
        std::fs::remove_dir_all(home).unwrap();
    }
}
