//! Private SQLite persistence and an interprocess lock held across each operation.

use crate::policy::{GrantError, Result, StoredGrant};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
    allowed_executables TEXT NOT NULL, created_at REAL NOT NULL,
    expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
    CHECK (revoked IN (0, 1)))";
const SELECT: &str = "SELECT id, allowed_executables, created_at, expires_at, revoked FROM grants";
fn unavailable(_: impl std::fmt::Display) -> GrantError {
    GrantError("Grant storage unavailable")
}

fn private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(unavailable)?;
    let metadata = file.metadata().map_err(unavailable)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.nlink() != 1 {
        return Err(GrantError("Grant state must be a root-owned regular file"));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(unavailable)?;
    Ok(file)
}

pub(crate) fn lock_exclusive(file: &File) -> io::Result<()> {
    loop {
        // SAFETY: file owns the descriptor; flock only changes its kernel lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn decode(row: &Row<'_>) -> rusqlite::Result<StoredGrant> {
    let serialized: String = row.get(1)?;
    let allowed_executables = serde_json::from_str(&serialized).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(StoredGrant {
        id: row.get(0)?,
        allowed_executables,
        created_at: row.get(2)?,
        expires_at: row.get(3)?,
        revoked: row.get(4)?,
    })
}

pub(crate) struct Store {
    // Fields drop in declaration order: close SQLite before releasing the lock.
    connection: Connection,
    root_lock: Option<File>,
}

impl Store {
    pub fn open(directory: &Path) -> Result<Self> {
        match DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
        {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(unavailable(error)),
        }
        let metadata = fs::symlink_metadata(directory).map_err(unavailable)?;
        if !metadata.is_dir() || metadata.uid() != 0 {
            return Err(GrantError("Grant directory must be a root-owned directory"));
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(unavailable)?;
        let root_lock = private_file(&directory.join("grants.lock"))?;
        lock_exclusive(&root_lock).map_err(unavailable)?;
        let path = directory.join("grants.sqlite3");
        let _file = private_file(&path)?;
        let connection = Connection::open(path).map_err(unavailable)?;
        connection
            .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
            .map_err(unavailable)?;
        connection.execute_batch(SCHEMA).map_err(unavailable)?;
        Ok(Self {
            connection,
            root_lock: Some(root_lock),
        })
    }

    pub fn insert(&self, grant: &StoredGrant, token_hash: &str) -> Result<()> {
        let allowed = serde_json::to_string(&grant.allowed_executables).map_err(unavailable)?;
        self.connection.execute(
            "INSERT INTO grants (id, token_hash, allowed_executables, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, ?, ?)",
            params![grant.id, token_hash, allowed, grant.created_at, grant.expires_at, grant.revoked],
        ).map_err(unavailable)?;
        Ok(())
    }

    pub fn find(&self, id: &str) -> Result<StoredGrant> {
        self.connection
            .query_row(&format!("{SELECT} WHERE id = ?"), [id], decode)
            .optional()
            .map_err(unavailable)?
            .ok_or(GrantError("Grant not found"))
    }

    pub fn find_hash(&self, hash: &str) -> Result<Option<StoredGrant>> {
        self.connection
            .query_row(&format!("{SELECT} WHERE token_hash = ?"), [hash], decode)
            .optional()
            .map_err(unavailable)
    }

    pub fn page(&self, cursor: Option<&str>) -> Result<Vec<StoredGrant>> {
        if let Some(cursor) = cursor {
            let previous = self.find(cursor)?;
            let mut query = self.connection.prepare(&format!(
                "{SELECT} WHERE (created_at, id) < (?, ?) ORDER BY created_at DESC, id DESC LIMIT 101"
            )).map_err(unavailable)?;
            query
                .query_map(params![previous.created_at, previous.id], decode)
                .map_err(unavailable)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(unavailable)
        } else {
            let mut query = self
                .connection
                .prepare(&format!(
                    "{SELECT} ORDER BY created_at DESC, id DESC LIMIT 101"
                ))
                .map_err(unavailable)?;
            query
                .query_map([], decode)
                .map_err(unavailable)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(unavailable)
        }
    }

    pub fn revoke(&self, id: &str) -> Result<()> {
        self.connection
            .execute("UPDATE grants SET revoked = 1 WHERE id = ?", [id])
            .map_err(unavailable)?;
        Ok(())
    }

    pub fn set_expiration(&self, id: &str, expires_at: f64) -> Result<()> {
        self.connection
            .execute(
                "UPDATE grants SET expires_at = ? WHERE id = ?",
                params![expires_at, id],
            )
            .map_err(unavailable)?;
        Ok(())
    }

    /// SQLite closes first; the caller retains the CLOEXEC lock through exec.
    pub fn into_exec_lock(self) -> Option<File> {
        let Self {
            connection,
            root_lock,
        } = self;
        drop(connection);
        root_lock
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        Self {
            connection,
            root_lock: None,
        }
    }

    #[cfg(test)]
    pub fn saved_hash(&self, id: &str) -> String {
        self.connection
            .query_row("SELECT token_hash FROM grants WHERE id = ?", [id], |row| {
                row.get(0)
            })
            .unwrap()
    }
}
