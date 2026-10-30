//! The final process handoff, after application authorization has succeeded.
use crate::model::AllowedExecutable;
use crate::policy::{GrantError, Result};
use std::convert::Infallible;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub(crate) fn command(allowed: &AllowedExecutable, arguments: &[String]) -> Command {
    let mut process = Command::new(&allowed.path);
    // Canonicalization may resolve coreutils applets to a shared multicall
    // executable. Preserve the granted applet name even for path invocations.
    process
        .arg0(&allowed.name)
        .args(arguments)
        .env_clear()
        .envs([
            ("HOME", "/root"),
            ("USER", "root"),
            ("LOGNAME", "root"),
            ("PATH", "/run/current-system/sw/bin:/run/wrappers/bin"),
            ("LANG", "C.UTF-8"),
        ]);
    // SAFETY: the hook contains only syscalls and OS-error construction. It
    // preserves the existing terminal, process group, standard I/O, and cwd.
    unsafe {
        process.pre_exec(|| {
            libc::umask(0o077);
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    process
}

/// The lock is intentionally retained until CLOEXEC releases it atomically.
pub(crate) fn replace(
    allowed: &AllowedExecutable,
    arguments: &[String],
    directory: Option<File>,
    root_lock: Option<File>,
) -> Result<Infallible> {
    let _root_lock = root_lock;
    // SAFETY: a null array is valid for zero supplementary groups.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(GrantError("Unable to establish root execution credentials"));
    }
    let mut process = command(allowed, arguments);
    if let Some(directory) = directory {
        // SAFETY: the closure owns the already-authorized directory descriptor.
        // fchdir uses that descriptor directly, never re-resolving a mutable path.
        // CLOEXEC closes it on successful execution, after this hook completes.
        unsafe {
            process.pre_exec(move || {
                if libc::fchdir(directory.as_raw_fd()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let _error = process.uid(0).gid(0).exec();
    Err(GrantError("Unable to execute the allowed program"))
}
