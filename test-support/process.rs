//! Bounded subprocess capture and real Unix login identities for VM fixtures.

use crate::Result;
use nix::unistd::{User, getgrouplist};
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct Account {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) groups: Vec<u32>,
    pub(crate) home: PathBuf,
}

impl Account {
    pub(crate) fn named(name: &str) -> Result<Self> {
        let user =
            User::from_name(name)?.ok_or_else(|| io::Error::other("VM account is missing"))?;
        let groups = getgrouplist(&CString::new(name)?, user.gid)?
            .into_iter()
            .map(|group| group.as_raw())
            .collect();
        Ok(Self {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            groups,
            home: user.dir,
        })
    }
}

pub(crate) fn capture(mut command: Command, input: &[u8]) -> Result<Output> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing stderr pipe"))?;
    let stdout = thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).map(|_| output)
    });
    let stderr = thread::spawn(move || {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output).map(|_| output)
    });
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(error) = stdin.write_all(input) {
            if error.kind() != io::ErrorKind::BrokenPipe {
                child.kill()?;
                child.wait()?;
                return Err(error.into());
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(io::Error::other("acceptance subprocess timed out").into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout
        .join()
        .map_err(|_| io::Error::other("stdout reader panicked"))??;
    let stderr = stderr
        .join()
        .map_err(|_| io::Error::other("stderr reader panicked"))??;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

pub(crate) fn configure(command: &mut Command, account: Option<&Account>) {
    let identity = account.map(|account| (account.uid, account.gid, account.groups.clone()));
    // SAFETY: only async-signal-safe syscalls execute after fork.
    unsafe {
        command.pre_exec(move || {
            if let Some((uid, gid, groups)) = &identity {
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(*gid) != 0
                    || libc::setuid(*uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}
