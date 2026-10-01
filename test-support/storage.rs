//! Inspect the private state actually created inside this configured NixOS VM.

use crate::Result;
use crate::harness::{DATABASE, Harness, SecretGrant, check, denied};
use crate::process::{capture, configure};
use rusqlite::Connection;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::process::Command;

pub(crate) struct StoredGrant {
    pub(crate) token_hash: String,
    pub(crate) expires_at: f64,
}

pub(crate) fn row(grant: &SecretGrant) -> Result<StoredGrant> {
    let database = Connection::open(DATABASE)?;
    let (token_hash, expires_at): (String, f64) = database.query_row(
        "SELECT token_hash, expires_at FROM grants WHERE id = ?",
        [&grant.id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(StoredGrant {
        token_hash,
        expires_at,
    })
}

pub(crate) fn private_state(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    for (path, mode) in [("/var/lib/delegated-sudo", 0o700), (DATABASE, 0o600)] {
        let metadata = fs::symlink_metadata(path)?;
        check(
            metadata.uid() == 0 && metadata.mode() & 0o777 == mode,
            "grant storage has unsafe owner or permissions",
        )?;
    }
    for entry in fs::read_dir("/var/lib/delegated-sudo")? {
        let path = entry?.path();
        if path.is_file() {
            let bytes = fs::read(path)?;
            check(
                !bytes
                    .windows(grant.token.len())
                    .any(|window| window == grant.token.as_bytes()),
                "plaintext token persisted in grant storage",
            )?;
        }
    }
    let mut command = Command::new("/run/current-system/sw/bin/cat");
    command.arg(DATABASE);
    configure(&mut command, Some(&harness.agent));
    denied(capture(command, b"")?)
}
