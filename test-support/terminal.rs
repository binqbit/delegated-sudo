//! Real controlling-terminal coverage of the default hidden-token input path.

use crate::Result;
use crate::harness::{CLI, Harness, SecretGrant, check};
use crate::process::configure;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PROMPT: &[u8] = b"Delegation token: ";

struct RunningChild {
    child: Child,
    reaped: bool,
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: the unreaped session leader's PID cannot be reused. A
            // negative PID signals this test's isolated process group only.
            unsafe {
                libc::kill(-(self.child.id() as libc::pid_t), libc::SIGHUP);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn terminal_pair(harness: &Harness) -> Result<(File, File)> {
    let (mut master, mut slave) = (-1, -1);
    let dimensions = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: writable descriptor outputs and dimensions remain valid. Null
    // name/termios arguments request the standard PTY setup without a path copy.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &dimensions,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: a successful openpty returns two fresh descriptors we now own.
    let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        // SAFETY: both descriptors remain owned and open in this function.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    // The terminal belongs to the same real login identity used by the child.
    // SAFETY: slave is open; fchown takes numeric IDs and no pointers.
    if unsafe { libc::fchown(slave.as_raw_fd(), harness.agent.uid, harness.agent.gid) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut settings = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: settings provides writable storage for the terminal attributes.
    if unsafe { libc::tcgetattr(slave.as_raw_fd(), settings.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful tcgetattr initialized settings.
    let mut settings = unsafe { settings.assume_init() };
    settings.c_lflag |= libc::ECHO | libc::ICANON | libc::ISIG;
    // Start with echo explicitly enabled: hiding input must be done by the
    // actual CLI/sudo terminal path, not supplied accidentally by the fixture.
    // SAFETY: settings is initialized and slave remains open.
    if unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &settings) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: master is an open descriptor; these fcntl operations use no pointers.
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok((master, slave))
}

fn drain(master: &mut File, transcript: &mut Vec<u8>, secret: &str) -> Result<()> {
    let mut buffer = [0u8; 2048];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                transcript.extend_from_slice(&buffer[..count]);
                check(
                    transcript.len() <= 16 * 1024,
                    "interactive token output exceeded its bound",
                )?;
                check(
                    !transcript
                        .windows(secret.len())
                        .any(|window| window == secret.as_bytes()),
                    "interactive token was echoed to the terminal",
                )?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(libc::EIO) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn echo_disabled(master: &File) -> Result<bool> {
    let mut settings = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: settings provides writable storage and master is an open PTY.
    if unsafe { libc::tcgetattr(master.as_raw_fd(), settings.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful tcgetattr initialized settings.
    Ok(unsafe { settings.assume_init() }.c_lflag & libc::ECHO == 0)
}

pub(crate) fn interactive_token(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    check(
        harness.agent.uid != 0,
        "terminal fixture must invoke a non-root account",
    )?;
    check(!grant.token.is_empty(), "terminal fixture requires a token")?;
    let (mut master, slave) = terminal_pair(harness)?;
    let mut command = Command::new(CLI);
    command
        .args(["exec", "id", "-u"])
        .env_clear()
        .env("PATH", "/run/current-system/sw/bin:/run/wrappers/bin")
        .env("HOME", &harness.agent.home)
        .env("TERM", "dumb")
        .current_dir(&harness.agent.home)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    // SAFETY: the hook uses only async-signal-safe syscalls after fork. Rust has
    // already installed the PTY slave as fd0 before invoking pre_exec callbacks.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    configure(&mut command, Some(&harness.agent));
    let mut running = RunningChild {
        child: command.spawn()?,
        reaped: false,
    };
    // Close all parent copies of the slave held inside Command's Stdio fields.
    drop(command);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut transcript = Vec::new();
    let mut supplied = false;
    loop {
        drain(&mut master, &mut transcript, &grant.token)?;
        if !supplied
            && transcript
                .windows(PROMPT.len())
                .any(|window| window == PROMPT)
            && echo_disabled(&master)?
        {
            master.write_all(grant.token.as_bytes())?;
            master.write_all(b"\n")?;
            supplied = true;
        }
        if let Some(status) = running.child.try_wait()? {
            running.reaped = true;
            drain(&mut master, &mut transcript, &grant.token)?;
            check(
                supplied,
                "default token prompt did not accept hidden terminal input",
            )?;
            check(status.success(), "interactive token execution failed")?;
            let transcript = String::from_utf8_lossy(&transcript);
            check(
                transcript
                    .split_once("Delegation token: ")
                    .is_some_and(|(_, after_prompt)| after_prompt.trim() == "0"),
                "interactive terminal output contained echoed input or an unexpected command result",
            )?;
            return Ok(());
        }
        check(Instant::now() < deadline, "interactive token PTY timed out")?;
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one valid descriptor record, and its short
        // timeout keeps both process-exit checks and the absolute deadline live.
        if unsafe { libc::poll(&mut poll, 1, 20) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }
}
