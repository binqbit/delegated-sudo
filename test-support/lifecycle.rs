//! Prove grants unlock at exec and revocation only prevents new launches.

use crate::Result;
use crate::grants::revocation;
use crate::harness::{Harness, PROBE, check};
use std::fs;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

struct ProbeGuard(Option<i32>);

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            // SAFETY: this is the PID published by the test's own root probe.
            // The guard is armed only while that probe is expected to be alive.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

pub(crate) fn revoke_running_command(harness: &Harness) -> Result<()> {
    let marker = Path::new("/run/delegated-sudo-probe.pid");
    match fs::remove_file(marker) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let grant = harness.create("id,delegated-sudo-check", "60m")?;
    let child_harness = harness.clone();
    let token = grant.token.clone();
    let child = thread::spawn(move || {
        child_harness
            .cli(&["exec", PROBE, "--probe", "--wait"], false, Some(&token))
            .map_err(|error| error.to_string())
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Ok(contents) = fs::read_to_string(marker) {
            if let Ok(pid) = contents.parse::<i32>() {
                break pid;
            }
        }
        check(
            Instant::now() < deadline && !child.is_finished(),
            "long-running delegated probe did not start",
        )?;
        thread::sleep(Duration::from_millis(10));
    };
    let mut guard = ProbeGuard(Some(pid));
    // A leaked database/lock descriptor would prevent this from completing
    // while the granted process is running. Revocation must allow its existing
    // execution to finish while rejecting every subsequent launch.
    revocation(harness, &grant)?;
    check(
        Path::new(&format!("/proc/{pid}")).exists(),
        "revocation unexpectedly killed an existing command",
    )?;
    // SAFETY: this PID belongs to the live probe checked directly above.
    check(
        unsafe { libc::kill(pid, libc::SIGTERM) } == 0,
        "could not signal the delegated probe",
    )?;
    let output = child
        .join()
        .map_err(|_| io::Error::other("delegated probe worker panicked"))?
        .map_err(io::Error::other)?;
    guard.0 = None;
    check(
        output.status.code() == Some(143) || output.status.signal() == Some(libc::SIGTERM),
        "sudo did not preserve the command signal result",
    )
}
