use std::path::{Path, PathBuf};

pub(crate) fn classify_child_exit(status: &portable_pty::ExitStatus) -> super::ChildExitReason {
    if status.signal().is_some() {
        super::ChildExitReason::Interrupted
    } else {
        super::ChildExitReason::Exited
    }
}

pub(crate) fn read_fd(fd: std::os::fd::RawFd, data: &mut [u8]) -> std::io::Result<usize> {
    let result = unsafe { libc::read(fd, data.as_mut_ptr().cast(), data.len()) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

pub(crate) fn poll_fd_readable(fd: std::os::fd::RawFd, timeout_ms: i32) -> std::io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result > 0)
    }
}

pub(crate) fn shutdown_client_stream(stream: &crate::ipc::LocalStream) -> std::io::Result<()> {
    let crate::ipc::LocalStream::UdSocket(stream) = stream;
    stream.inner().shutdown(std::net::Shutdown::Both)
}

pub(crate) struct ClientStreamReader<'a>(pub(crate) &'a mut crate::ipc::LocalStream);

impl std::io::Read for ClientStreamReader<'_> {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd as _;

        loop {
            match self.0.read(data) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let crate::ipc::LocalStream::UdSocket(stream) = &*self.0;
                    let mut descriptor = libc::pollfd {
                        fd: stream.inner().as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // Sleep until input or shutdown, without polling quiet observers.
                    if unsafe { libc::poll(&mut descriptor, 1, -1) } < 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() != std::io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
                result => return result,
            }
        }
    }
}

pub(crate) fn write_client_stream(
    stream: &crate::ipc::LocalStream,
    mut data: &[u8],
) -> std::io::Result<()> {
    use std::io::{self, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::time::Instant;

    let crate::ipc::LocalStream::UdSocket(socket) = stream;
    let mut socket = socket.inner();
    let Some(timeout) = socket.write_timeout()? else {
        return socket.write_all(data);
    };
    let timed_out = || {
        // Dropping the writer clone alone would leave the reader blocked.
        let _ = shutdown_client_stream(stream);
        io::Error::new(
            io::ErrorKind::TimedOut,
            "terminal observer stopped receiving output",
        )
    };
    let mut progress = Instant::now();
    while !data.is_empty() {
        match socket.write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => {
                data = &data[written..];
                progress = Instant::now();
                continue;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        let remaining = timeout
            .checked_sub(progress.elapsed())
            .ok_or_else(timed_out)?;
        let mut descriptor = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let wait_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut descriptor, 1, wait_ms) };
        if ready == 0 {
            return Err(timed_out());
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    Ok(())
}

pub(crate) fn wait_client_stream_readable(stream: &crate::ipc::LocalStream) -> std::io::Result<()> {
    use std::os::fd::{AsFd as _, AsRawFd as _};
    let crate::ipc::LocalStream::UdSocket(stream) = stream;
    let mut descriptor = libc::pollfd {
        fd: stream.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // Bound cancellation latency without polling idle connections hundreds of times per second.
    let result = unsafe { libc::poll(&mut descriptor, 1, 100) };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

pub(crate) fn forward_remote_bridge_stdio(
    stream: crate::ipc::LocalStream,
    idle_timeout: bool,
) -> std::io::Result<()> {
    forward_remote_bridge_stdio_with_timeout(
        stream,
        idle_timeout.then_some(super::remote_bridge::IDLE_TIMEOUT),
    )
}

pub(super) fn forward_remote_bridge_stdio_with_timeout(
    stream: crate::ipc::LocalStream,
    idle_timeout: Option<std::time::Duration>,
) -> std::io::Result<()> {
    use super::remote_bridge::{Activity, TrackedIo};
    use interprocess::TryClone as _;

    let activity = idle_timeout.map(Activity::start).transpose()?;
    let mut stdout = TrackedIo::new(std::io::stdout().lock(), activity.clone());
    let mut socket_to_stdout = TrackedIo::new(stream.try_clone()?, activity.clone());
    let mut stdin_to_socket = stream;
    let _upload = std::thread::spawn(move || {
        let mut stdin = TrackedIo::new(std::io::stdin(), activity.clone());
        let _ = copy_flush(
            &mut stdin,
            &mut TrackedIo::new(&mut stdin_to_socket, activity),
        );
        let crate::ipc::LocalStream::UdSocket(stream) = stdin_to_socket;
        let _ = stream.inner().shutdown(std::net::Shutdown::Write);
    });
    copy_flush(&mut socket_to_stdout, &mut stdout)
}

fn copy_flush<R: std::io::Read, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        writer.write_all(&buffer[..read])?;
        writer.flush()?;
    }
}

pub(crate) struct RemoteBridgeWake {
    reader: std::os::unix::net::UnixStream,
    writer: std::os::unix::net::UnixStream,
}

impl RemoteBridgeWake {
    pub(crate) fn new() -> std::io::Result<Self> {
        let (reader, writer) = std::os::unix::net::UnixStream::pair()?;
        Ok(Self { reader, writer })
    }

    pub(crate) fn cancel(&self) -> std::io::Result<()> {
        // EOF stays readable, including when cancellation precedes the wait.
        self.writer.shutdown(std::net::Shutdown::Write)
    }

    pub(crate) fn wait(&self, stream: &crate::ipc::LocalStream) -> std::io::Result<()> {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let crate::ipc::LocalStream::UdSocket(stream) = stream;
        let mut descriptors = [
            libc::pollfd {
                fd: stream.as_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            // SAFETY: both descriptors remain borrowed and the array has two entries.
            if unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) } >= 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

pub(super) fn read_terminal_grid_size() -> std::io::Result<(u16, u16)> {
    crossterm::terminal::window_size().map(|size| (size.columns, size.rows))
}

fn set_sigpipe_disposition(handler: libc::sighandler_t) {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        // Rust starts with SIGPIPE ignored. If this best-effort transition
        // fails, stdout retains the existing Rust behavior.
        libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut());
    }
}

pub(crate) fn begin_cli_output() {
    set_sigpipe_disposition(libc::SIG_DFL);
}

pub(crate) fn end_cli_output() {
    set_sigpipe_disposition(libc::SIG_IGN);
}

pub(crate) fn remote_ssh_config_paths() -> super::RemoteSshConfigPaths {
    super::RemoteSshConfigPaths {
        user_config: std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".ssh").join("config")),
        system_config: Some(PathBuf::from("/etc/ssh/ssh_config")),
        multiplexing: true,
    }
}

pub(crate) fn create_remote_ssh_config_dir(control_socket_name: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    let mut bases = vec![std::env::temp_dir()];
    let short_tmp = PathBuf::from("/tmp");
    if bases.first() != Some(&short_tmp) {
        bases.push(short_tmp);
    }

    let mut last_error = None;
    let mut path_fits = false;
    for base in bases {
        for attempt in 0..100 {
            let dir = base.join(format!("herdr-ssh-{}-{attempt}", std::process::id()));
            if !fits_unix_socket_path(&dir.join(control_socket_name)) {
                continue;
            }
            path_fits = true;
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(dir),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    last_error = Some(err);
                    break;
                }
            }
        }
    }

    if let Some(err) = last_error {
        return Err(err);
    }
    let message = if path_fits {
        "failed to create private herdr ssh config directory"
    } else {
        "SSH control socket path exceeds the Unix socket length limit"
    };
    Err(std::io::Error::new(
        if path_fits {
            std::io::ErrorKind::AlreadyExists
        } else {
            std::io::ErrorKind::InvalidInput
        },
        message,
    ))
}

pub(crate) fn create_remote_ssh_config_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

pub(crate) fn create_remote_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new().mode(0o700).create(path)
}

pub(crate) fn remote_private_temp_base() -> PathBuf {
    std::env::temp_dir()
}

pub(crate) fn remote_bridge_endpoint_path(readable_name: &str, short_name: &str) -> PathBuf {
    let tmp = std::env::temp_dir();
    let readable = tmp.join(readable_name);
    if fits_unix_socket_path(&readable) {
        return readable;
    }
    let short = tmp.join(short_name);
    if fits_unix_socket_path(&short) {
        return short;
    }
    PathBuf::from("/tmp").join(short_name)
}

pub(crate) fn remote_reattach_program(program: &str) -> String {
    shell_quote(if program.is_empty() { "herdr" } else { program })
}

pub(crate) fn remote_reattach_argument(value: &str) -> String {
    shell_quote(value)
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '@' | '%' | '_' | '+' | '=' | ':' | ',' | '.' | '/' | '-'
                )
        })
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn fits_unix_socket_path(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().len() <= 103
}

/// The machine's node name, as shown by tmux's `#h`.
pub(crate) fn hostname() -> Option<String> {
    let mut buffer = [0_u8; 256];
    let result =
        unsafe { libc::gethostname(buffer.as_mut_ptr().cast::<libc::c_char>(), buffer.len()) };
    if result != 0 {
        return None;
    }
    let end = buffer
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(buffer.len());
    let name = String::from_utf8_lossy(&buffer[..end]).into_owned();
    (!name.is_empty()).then_some(name)
}

pub(crate) fn local_datetime() -> Option<time::PrimitiveDateTime> {
    let mut timestamp: libc::time_t = 0;
    if unsafe { libc::time(&mut timestamp) } == -1 {
        return None;
    }
    let mut local: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&timestamp, &mut local) }.is_null() {
        return None;
    }
    datetime_from_tm(&local)
}

pub(crate) fn status_commands_supported() -> bool {
    true
}

pub(crate) fn configure_status_command(process: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    process.process_group(0);
}

pub(crate) struct StatusCommandGuard {
    process_group_id: Option<i32>,
}

impl StatusCommandGuard {
    pub(crate) fn new(child: &tokio::process::Child) -> std::io::Result<Self> {
        let process_id = child
            .id()
            .ok_or_else(|| std::io::Error::other("status command has no process id"))?;
        let process_group_id = i32::try_from(process_id)
            .map_err(|_| std::io::Error::other("status command process id exceeds i32"))?;
        Ok(Self {
            process_group_id: Some(process_group_id),
        })
    }
}

impl StatusCommandGuard {
    pub(crate) fn terminate(&mut self) {
        if let Some(process_group_id) = self.process_group_id.take() {
            // The command was spawned as this process group's leader. Killing the
            // group also cleans up background descendants on completion/cancellation.
            unsafe {
                libc::kill(-process_group_id, libc::SIGKILL);
            }
        }
    }
}

impl Drop for StatusCommandGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn datetime_from_tm(value: &libc::tm) -> Option<time::PrimitiveDateTime> {
    let month = time::Month::try_from(u8::try_from(value.tm_mon + 1).ok()?).ok()?;
    let date = time::Date::from_calendar_date(
        value.tm_year + 1900,
        month,
        u8::try_from(value.tm_mday).ok()?,
    )
    .ok()?;
    let time = time::Time::from_hms(
        u8::try_from(value.tm_hour).ok()?,
        u8::try_from(value.tm_min).ok()?,
        u8::try_from(value.tm_sec).ok()?,
    )
    .ok()?;
    Some(time::PrimitiveDateTime::new(date, time))
}

pub(crate) fn set_default_plugin_pane_pwd(env: &mut Vec<(String, String)>, cwd: &std::path::Path) {
    if !env.iter().any(|(key, _)| key == "PWD") {
        env.push(("PWD".to_string(), cwd.display().to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_pane_pwd_defaults_to_cwd_without_overriding_explicit_env() {
        let cwd = Path::new("/plugin-cwd");
        let mut derived = vec![("OTHER".to_string(), "value".to_string())];
        set_default_plugin_pane_pwd(&mut derived, cwd);
        assert!(derived.contains(&("PWD".to_string(), "/plugin-cwd".to_string())));

        let mut explicit = vec![("PWD".to_string(), "/caller-pwd".to_string())];
        set_default_plugin_pane_pwd(&mut explicit, cwd);
        assert_eq!(explicit, [("PWD".to_string(), "/caller-pwd".to_string())]);
    }

    #[test]
    fn remote_ssh_config_dir_rejects_overlong_control_socket_name() {
        let err = create_remote_ssh_config_dir(&"x".repeat(200)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}

/// Shared OpenSSH sockets outlive individual helpers. Never adopt a directory
/// belonging to another uid, a symlink, or a directory accessible by others.
pub(crate) fn shared_ssh_control_path(namespace: &Path, target: &str) -> std::io::Result<PathBuf> {
    use sha2::{Digest, Sha256};
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt},
    };

    // Validate the resolved system temp directory, but retain the short /tmp
    // spelling for sockets. On macOS /tmp resolves to /private/tmp; those extra
    // bytes would consume the space OpenSSH needs for its staging suffix.
    let base = Path::new("/tmp");
    let resolved_base = std::fs::canonicalize(base)?;
    let metadata = std::fs::symlink_metadata(&resolved_base)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o1000 == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe SSH control directory parent",
        ));
    }
    let dir = base.join(format!("hssh-{}", unsafe { libc::geteuid() }));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    validate_shared_ssh_dir(&dir)?;
    let namespace = if namespace.is_absolute() {
        namespace.to_owned()
    } else {
        std::env::current_dir()?.join(namespace)
    };
    let mut hash = Sha256::new();
    hash.update(namespace.as_os_str().as_bytes());
    hash.update([0]);
    hash.update(target.as_bytes());
    // %C additionally scopes the socket to OpenSSH's resolved destination,
    // port and jump host, rather than merely the spelling of an alias.
    // Keep 96 bits of namespace/target hash plus OpenSSH's 160-bit %C.
    let hash = format!("{:x}", hash.finalize());
    let path = dir.join(format!("{}-%C", &hash[..24]));
    // OpenSSH first binds ControlPath + '.' + 16 random characters, then
    // renames it. Reserve those 17 bytes, not just the final socket's length.
    let expanded = path.to_string_lossy().replace("%C", &"0".repeat(40));
    let staging = PathBuf::from(format!("{expanded}.{}", "0".repeat(16)));
    if !fits_unix_socket_path(&staging) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SSH control socket staging path exceeds the Unix socket length limit",
        ));
    }
    Ok(path)
}

fn validate_shared_ssh_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(dir)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SSH control directory must be owned by the current user, mode 0700, and not a symlink",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod shared_ssh_tests {
    use super::*;

    #[test]
    fn shared_ssh_control_path_is_stable_scoped_and_bounded() {
        let path = shared_ssh_control_path(Path::new("/config/one"), "user@host").unwrap();
        assert_eq!(
            path,
            shared_ssh_control_path(Path::new("/config/one"), "user@host").unwrap()
        );
        assert_ne!(
            path,
            shared_ssh_control_path(Path::new("/config/two"), "user@host").unwrap()
        );
        assert_ne!(
            path,
            shared_ssh_control_path(Path::new("/config/one"), "other@host").unwrap()
        );
        let expanded = path.to_string_lossy().replace("%C", &"f".repeat(40));
        assert!(fits_unix_socket_path(&PathBuf::from(&expanded)));
        // OpenSSH binds this temporary socket before renaming it to ControlPath.
        assert!(fits_unix_socket_path(&PathBuf::from(format!(
            "{expanded}.QuuYe7ZFE2HYeAE4"
        ))));
        validate_shared_ssh_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn shared_ssh_staging_path_fits_with_maximum_uid_width() {
        let path = shared_ssh_control_path(Path::new("/config/one"), "user@host").unwrap();
        let directory = path.parent().unwrap();
        let name = directory.file_name().unwrap().to_string_lossy();
        let prefix = name.trim_end_matches(|ch: char| ch.is_ascii_digit());
        let maximum_uid_directory = directory
            .parent()
            .unwrap()
            .join(format!("{prefix}{}", u32::MAX));
        let expanded = maximum_uid_directory
            .join(path.file_name().unwrap())
            .to_string_lossy()
            .replace("%C", &"f".repeat(40));
        assert!(fits_unix_socket_path(&PathBuf::from(format!(
            "{expanded}.QuuYe7ZFE2HYeAE4"
        ))));
    }

    #[test]
    fn shared_ssh_directory_rejects_symlinks_and_public_modes() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = create_remote_ssh_config_dir("ctl").unwrap();
        let link = dir.join("link");
        symlink(&dir, &link).unwrap();
        assert_eq!(
            validate_shared_ssh_dir(&link).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            validate_shared_ssh_dir(&dir).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

// Dial-in link helpers: private state directories, ownership checks and
// advisory locks shared by the hub acceptor, the slave dialer and the TUI.

pub(crate) fn current_uid() -> Option<u32> {
    Some(unsafe { libc::geteuid() })
}

pub(crate) fn local_socket_path_fits(path: &Path) -> bool {
    fits_unix_socket_path(path)
}

fn private_path_error(path: &Path, reason: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("{}: {reason}", path.display()),
    )
}

fn check_private_directory_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    require_private_mode: bool,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if metadata.file_type().is_symlink() {
        return Err(private_path_error(path, "private directory is a symlink"));
    }
    if !metadata.is_dir() {
        return Err(private_path_error(
            path,
            "private directory path is not a directory",
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(private_path_error(
            path,
            "private directory is not owned by the current user",
        ));
    }
    if require_private_mode && metadata.mode() & 0o077 != 0 {
        return Err(private_path_error(
            path,
            "private directory is accessible by other users (expected mode 0700)",
        ));
    }
    Ok(())
}

/// Creates `path` (and its parents) as a directory private to the effective
/// user. The leaf must not be a symlink and must be owned by the effective
/// user; an owned leaf with a wider mode is repaired to 0700.
pub(crate) fn ensure_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    check_private_directory_metadata(path, &std::fs::symlink_metadata(path)?, false)?;
    // Re-check and repair through a descriptor so a swapped-in symlink is never followed.
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                private_path_error(path, "private directory is a symlink")
            } else {
                error
            }
        })?;
    let metadata = directory.metadata()?;
    check_private_directory_metadata(path, &metadata, false)?;
    if metadata.mode() & 0o7777 != 0o700 {
        directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Checks that `path` is a directory owned by the effective user, not a
/// symlink, and inaccessible to group and others. Never creates or repairs.
/// A missing directory reports `NotFound`; every privacy failure reports
/// `PermissionDenied`.
pub(crate) fn verify_private_directory(path: &Path) -> std::io::Result<()> {
    check_private_directory_metadata(path, &std::fs::symlink_metadata(path)?, true)
}

/// Whether `path` itself (never a symlink target) is owned by the effective
/// user. Symlinks report `false`; a missing path reports `NotFound`.
pub(crate) fn file_is_owned_by_current_user(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    Ok(!metadata.file_type().is_symlink() && metadata.uid() == unsafe { libc::geteuid() })
}

/// Whether `path` is a regular file (not a symlink) owned by the effective
/// user and not writable by group or others. A missing path reports `NotFound`.
pub(crate) fn file_is_private_to_current_user(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    Ok(metadata.file_type().is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o022 == 0)
}

/// Opens (creating 0600 if needed) `path` and takes a non-blocking exclusive
/// `flock`. `Ok(None)` means another open file description holds the lock.
pub(crate) fn try_lock_exclusive(path: &Path) -> std::io::Result<Option<super::ExclusiveFileLock>> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                private_path_error(path, "lock file is a symlink")
            } else {
                error
            }
        })?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(private_path_error(
            path,
            "lock file must be a regular file owned by the current user",
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(super::ExclusiveFileLock { file }));
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => return Ok(None),
            _ => return Err(error),
        }
    }
}

impl Drop for super::ExclusiveFileLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;

        // Closing the descriptor also releases the lock; unlock explicitly so
        // the release does not depend on descriptor lifetime elsewhere.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Shuts down one or both directions of a connected local stream; shutting
/// down `Write` lets the peer read end-of-file while it can still send.
pub(crate) fn shutdown_local_stream(
    stream: &crate::ipc::LocalStream,
    how: std::net::Shutdown,
) -> std::io::Result<()> {
    let crate::ipc::LocalStream::UdSocket(stream) = stream;
    stream.inner().shutdown(how)
}

/// Takes ownership of standard output as an unbuffered file. Dropping it
/// closes stdout so the reader sees end-of-file; nothing may write through
/// `std::io::stdout()` afterwards.
pub(crate) fn take_stdout_unbuffered() -> std::io::Result<std::fs::File> {
    use std::os::fd::FromRawFd as _;

    if unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFD) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: descriptor 1 is open (checked above) and the caller takes over
    // its lifetime for the rest of the process.
    Ok(unsafe { std::fs::File::from_raw_fd(libc::STDOUT_FILENO) })
}

/// Runs a service-manager command (`systemctl`, `launchctl`) with null
/// stdin. Dial service code takes it as a parameter so tests can fake it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn run_service_command(
    mut command: std::process::Command,
) -> std::io::Result<std::process::Output> {
    command.stdin(std::process::Stdio::null()).output()
}

/// Runs `command` through `run`: its stdout on success, else an error that
/// names the command and quotes its stderr.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn checked_service_command(
    run: &mut dyn FnMut(std::process::Command) -> std::io::Result<std::process::Output>,
    command: std::process::Command,
) -> std::io::Result<String> {
    let shown = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let output = run(command).map_err(|error| {
        std::io::Error::new(error.kind(), format!("failed to run `{shown}`: {error}"))
    })?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "`{shown}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Device, inode, size, and modification time (seconds, nanoseconds) of
/// `path`, following symlinks: a new value means the file was replaced or
/// rewritten.
pub(crate) fn file_identity(path: &Path) -> std::io::Result<[u64; 5]> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path)?;
    Ok([
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime() as u64,
        metadata.mtime_nsec() as u64,
    ])
}

/// Replaces this process with `path args...`, applying `env` (`Some` sets a
/// variable, `None` removes it). Returns only on failure. Descriptors opened
/// by Rust are close-on-exec, so locks held through them are released.
pub(crate) fn reexec_process(
    path: &Path,
    args: &[String],
    env: &[(String, Option<String>)],
) -> std::io::Error {
    use std::os::unix::process::CommandExt as _;

    let mut command = std::process::Command::new(path);
    command.args(args);
    for (name, value) in env {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    command.exec()
}

#[cfg(test)]
mod private_state_tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn scratch(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "herdr-private-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn ensure_private_directory_creates_nested_0700_leaf_and_is_idempotent() {
        let root = scratch("create");
        let leaf = root.join("a").join("b").join("leaf");
        ensure_private_directory(&leaf).unwrap();
        assert_eq!(mode(&leaf), 0o700);
        ensure_private_directory(&leaf).unwrap();
        assert_eq!(mode(&leaf), 0o700);
        verify_private_directory(&leaf).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ensure_private_directory_repairs_wide_mode_but_verify_refuses_it() {
        let root = scratch("repair");
        let leaf = root.join("leaf");
        std::fs::create_dir(&leaf).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            verify_private_directory(&leaf).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        ensure_private_directory(&leaf).unwrap();
        assert_eq!(mode(&leaf), 0o700);
        verify_private_directory(&leaf).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_directory_helpers_refuse_symlinks_and_files() {
        let root = scratch("refuse");
        let target = root.join("target");
        ensure_private_directory(&target).unwrap();
        let link = root.join("link");
        symlink(&target, &link).unwrap();
        assert_eq!(
            ensure_private_directory(&link).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            verify_private_directory(&link).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let file = root.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            ensure_private_directory(&file).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            verify_private_directory(&root.join("missing"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ownership_checks_ignore_symlink_targets() {
        let root = scratch("owner");
        let file = root.join("file");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(file_is_owned_by_current_user(&file).unwrap());
        assert!(file_is_private_to_current_user(&file).unwrap());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(!file_is_private_to_current_user(&file).unwrap());
        let link = root.join("link");
        symlink(&file, &link).unwrap();
        assert!(!file_is_owned_by_current_user(&link).unwrap());
        assert!(!file_is_private_to_current_user(&link).unwrap());
        assert_eq!(
            file_is_owned_by_current_user(&root.join("missing"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(current_uid(), Some(unsafe { libc::geteuid() }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exclusive_lock_excludes_second_open_until_dropped() {
        let root = scratch("lock");
        let path = root.join("link.lock");
        let first = try_lock_exclusive(&path).unwrap().expect("first lock");
        assert_eq!(mode(&path), 0o600);
        assert!(try_lock_exclusive(&path).unwrap().is_none());
        first.record_pid().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            std::process::id().to_string()
        );
        drop(first);
        let second = try_lock_exclusive(&path)
            .unwrap()
            .expect("lock after release");
        // Contenders must not truncate the holder's pid record.
        assert!(try_lock_exclusive(&path).unwrap().is_none());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            std::process::id().to_string()
        );
        drop(second);
        let link = root.join("lock-link");
        symlink(&path, &link).unwrap();
        assert_eq!(
            try_lock_exclusive(&link).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
