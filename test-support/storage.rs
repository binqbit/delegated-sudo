//! Inspect the private state actually created inside this configured NixOS VM.

use crate::Result;
use crate::harness::{DATABASE, Harness, SecretGrant, check, denied, succeeded};
use crate::process::{capture, configure};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct StoredGrant {
    pub(crate) token_hash: String,
    pub(crate) created_at: f64,
    pub(crate) allowed_executables: String,
    pub(crate) expires_at: f64,
    pub(crate) directory: Option<String>,
}

pub(crate) fn row(grant: &SecretGrant) -> Result<StoredGrant> {
    let database = Connection::open(DATABASE)?;
    let (token_hash, expires_at, created_at, allowed_executables, directory): (String, f64, f64, String, Option<String>) = database.query_row(
        "SELECT token_hash, expires_at, created_at, allowed_executables, directory FROM grants WHERE name = ?",
        [&grant.name],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    Ok(StoredGrant {
        token_hash,
        expires_at,
        created_at,
        allowed_executables,
        directory,
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

/// This runs first, inside the disposable VM, before the application has opened
/// its store. create_new prevents overwriting any unexpected existing database.
pub(crate) fn legacy_upgrade(harness: &Harness) -> Result<()> {
    let directory = fs::symlink_metadata("/var/lib/delegated-sudo")?;
    check(
        directory.is_dir() && directory.uid() == 0 && directory.mode() & 0o777 == 0o700,
        "legacy fixture requires the VM's private root-owned state directory",
    )?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(DATABASE)?;
    let legacy_token = format!("dst_{}", "a".repeat(64));
    let legacy_hash = format!("{:x}", Sha256::digest(legacy_token.as_bytes()));
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
    let allowed = serde_json::json!([{
        "name": "id",
        "path": fs::canonicalize("/run/current-system/sw/bin/id")?,
        "argument_policy": {"mode": "any"}
    }]);
    {
        let database = Connection::open(DATABASE)?;
        database.execute_batch(
            "CREATE TABLE grants (
            id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
            allowed_executables TEXT NOT NULL, created_at REAL NOT NULL,
            expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
            CHECK (revoked IN (0, 1)))",
        )?;
        database.execute(
            "INSERT INTO grants VALUES (?, ?, ?, ?, ?, 0)",
            params![
                "dg_000000000000000000000000",
                legacy_hash,
                allowed.to_string(),
                timestamp,
                timestamp + 3600.0
            ],
        )?;
    }
    let listing = succeeded(harness.cli(&["grant", "list"], true, None)?)?;
    check(
        listing.trim() == "No delegation grants.",
        "upgrade did not retire the old unnamed grant",
    )?;
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&legacy_token))?)?;
    {
        let database = Connection::open(DATABASE)?;
        let version: i64 = database.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let remaining: i64 =
            database.query_row("SELECT count(*) FROM grants", [], |row| row.get(0))?;
        check(
            version == 2 && remaining == 0,
            "upgrade did not commit the empty named schema",
        )?;
    }
    let current = harness.create_named("post-upgrade", "id", "60m")?;
    for _ in 0..2 {
        let output = succeeded(harness.cli(&["grant", "show", &current.name], true, None)?)?;
        check(
            output.contains(&current.name),
            "opening upgraded storage lost a new grant",
        )?;
        check(
            succeeded(harness.cli(&["exec", "id", "-u"], false, Some(&current.token))?)?.trim()
                == "0",
            "grant created after legacy upgrade did not survive reopening",
        )?;
    }
    Ok(())
}

/// Simulate an upgrade from the previous named-grant schema, preserving real
/// tokens created by the CLI. The isolated VM already owns this test database.
pub(crate) fn named_upgrade(harness: &Harness) -> Result<()> {
    let current = harness.create_named("named-before-directory-upgrade", "id", "60m")?;
    let original = row(&current)?;
    check(
        original.directory.is_none(),
        "a grant without --dir unexpectedly had a directory restriction",
    )?;
    {
        let database = Connection::open(DATABASE)?;
        database.execute_batch(
            "BEGIN IMMEDIATE;
            ALTER TABLE grants RENAME TO previous_grants;
            CREATE TABLE grants (
                name TEXT PRIMARY KEY NOT NULL, token_hash TEXT UNIQUE NOT NULL,
                allowed_executables TEXT NOT NULL, created_at REAL NOT NULL,
                expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
                CHECK (revoked IN (0, 1)));
            INSERT INTO grants
                SELECT name, token_hash, allowed_executables, created_at, expires_at, revoked
                FROM previous_grants;
            DROP TABLE previous_grants;
            PRAGMA user_version=1;
            COMMIT;",
        )?;
    }
    for _ in 0..2 {
        succeeded(harness.cli(&["grant", "show", &current.name], true, None)?)?;
        let preserved = row(&current)?;
        check(
            preserved.token_hash == original.token_hash
                && preserved.created_at == original.created_at
                && preserved.expires_at == original.expires_at
                && preserved.allowed_executables == original.allowed_executables
                && preserved.directory.is_none(),
            "directory schema upgrade changed an existing named grant or token",
        )?;
        let mut elsewhere = harness.clone();
        elsewhere.agent.home = "/tmp".into();
        check(
            succeeded(elsewhere.cli(&["exec", "id", "-u"], false, Some(&current.token))?)?.trim()
                == "0",
            "existing named token lost unrestricted working-directory access after upgrade",
        )?;
    }
    let database = Connection::open(DATABASE)?;
    let version: i64 = database.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    check(
        version == 2,
        "named grant migration did not persist schema version 2",
    )
}
