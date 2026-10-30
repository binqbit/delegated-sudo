//! Private SQLite persistence and an interprocess lock held across each operation.

use crate::directories::StoredDirectory;
use crate::policy::{GrantError, Result, StoredGrant};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS grants (
    name TEXT PRIMARY KEY NOT NULL, token_hash TEXT UNIQUE NOT NULL,
    allowed_executables TEXT NOT NULL, created_at REAL NOT NULL,
    expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
    CHECK (revoked IN (0, 1)), directory TEXT)";
const SELECT: &str =
    "SELECT name, allowed_executables, created_at, expires_at, revoked, directory FROM grants";
fn unavailable(_: impl std::fmt::Display) -> GrantError {
    GrantError("Grant storage unavailable")
}

/// The name-based format intentionally retires legacy unnamed grants. This is
/// atomic and runs under the same exclusive lock as every grant operation.
/// The directory-scope upgrade preserves all existing named grants and tokens.
fn initialize(connection: &Connection) -> Result<()> {
    let transaction = connection.unchecked_transaction().map_err(unavailable)?;
    let version: i64 = transaction
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(unavailable)?;
    let columns = {
        let mut query = transaction
            .prepare("SELECT name FROM pragma_table_info('grants') ORDER BY cid")
            .map_err(unavailable)?;
        query
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(unavailable)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(unavailable)?
    };
    let legacy = [
        "id",
        "token_hash",
        "allowed_executables",
        "created_at",
        "expires_at",
        "revoked",
    ];
    let named = [
        "name",
        "token_hash",
        "allowed_executables",
        "created_at",
        "expires_at",
        "revoked",
    ];
    match version {
        0 if columns.is_empty() => (),
        0 if columns == legacy => {
            transaction
                .execute_batch("DROP TABLE grants")
                .map_err(unavailable)?;
        }
        1 if columns == named => {
            transaction
                .execute_batch("ALTER TABLE grants ADD COLUMN directory TEXT")
                .map_err(unavailable)?;
        }
        2 if columns == [&named[..], &["directory"]].concat() => {
            return transaction.commit().map_err(unavailable);
        }
        _ => return Err(GrantError("Unsupported grant storage format")),
    }
    transaction.execute_batch(SCHEMA).map_err(unavailable)?;
    transaction
        .execute_batch("PRAGMA user_version=2")
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)
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
    let directory = row
        .get::<_, Option<String>>(5)?
        .map(|serialized| serde_json::from_str::<StoredDirectory>(&serialized))
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    Ok(StoredGrant {
        name: row.get(0)?,
        allowed_executables,
        directory,
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
        initialize(&connection)?;
        Ok(Self {
            connection,
            root_lock: Some(root_lock),
        })
    }

    pub fn insert(&self, grant: &StoredGrant, token_hash: &str) -> Result<()> {
        let allowed = serde_json::to_string(&grant.allowed_executables).map_err(unavailable)?;
        let directory = grant
            .directory
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(unavailable)?;
        self.connection.execute(
            "INSERT INTO grants (name, token_hash, allowed_executables, created_at, expires_at, revoked, directory) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![grant.name, token_hash, allowed, grant.created_at, grant.expires_at, grant.revoked, directory],
        ).map_err(|error| {
            if error.sqlite_error().is_some_and(|error| error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY) {
                GrantError("A grant with this name already exists; extend it or choose another name")
            } else {
                unavailable(error)
            }
        })?;
        Ok(())
    }

    pub fn find(&self, name: &str) -> Result<StoredGrant> {
        self.connection
            .query_row(&format!("{SELECT} WHERE name = ?"), [name], decode)
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
                "{SELECT} WHERE (created_at, name) < (?, ?) ORDER BY created_at DESC, name DESC LIMIT 101"
            )).map_err(unavailable)?;
            query
                .query_map(params![previous.created_at, previous.name], decode)
                .map_err(unavailable)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(unavailable)
        } else {
            let mut query = self
                .connection
                .prepare(&format!(
                    "{SELECT} ORDER BY created_at DESC, name DESC LIMIT 101"
                ))
                .map_err(unavailable)?;
            query
                .query_map([], decode)
                .map_err(unavailable)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(unavailable)
        }
    }

    pub fn revoke(&self, name: &str) -> Result<()> {
        self.connection
            .execute("UPDATE grants SET revoked = 1 WHERE name = ?", [name])
            .map_err(unavailable)?;
        Ok(())
    }

    pub fn renew(&self, name: &str, expires_at: f64, token_hash: &str) -> Result<()> {
        self.connection
            .execute(
                "UPDATE grants SET expires_at = ?, token_hash = ? WHERE name = ?",
                params![expires_at, token_hash, name],
            )
            .map_err(unavailable)?;
        Ok(())
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let deleted = self
            .connection
            .execute("DELETE FROM grants WHERE name = ?", [name])
            .map_err(unavailable)?;
        if deleted == 0 {
            return Err(GrantError("Grant not found"));
        }
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
        initialize(&connection).unwrap();
        Self {
            connection,
            root_lock: None,
        }
    }

    #[cfg(test)]
    pub fn saved_hash(&self, name: &str) -> String {
        self.connection
            .query_row(
                "SELECT token_hash FROM grants WHERE name = ?",
                [name],
                |row| row.get(0),
            )
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMED_SCHEMA: &str = "CREATE TABLE grants (
        name TEXT PRIMARY KEY NOT NULL, token_hash TEXT UNIQUE NOT NULL,
        allowed_executables TEXT NOT NULL, created_at REAL NOT NULL,
        expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
        CHECK (revoked IN (0, 1)))";

    #[test]
    fn upgrade_retires_unnamed_grants_once_and_preserves_named_grants() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                &NAMED_SCHEMA.replace("name TEXT PRIMARY KEY NOT NULL", "id TEXT PRIMARY KEY"),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO grants VALUES ('dg_legacy', 'old-hash', '[]', 1, 100, 0)",
                [],
            )
            .unwrap();
        initialize(&connection).unwrap();
        let store = Store {
            connection,
            root_lock: None,
        };
        assert!(store.page(None).unwrap().is_empty());
        assert!(store.find_hash("old-hash").unwrap().is_none());
        let grant = StoredGrant {
            name: "named".into(),
            allowed_executables: vec![],
            directory: None,
            created_at: 1.0,
            expires_at: 100.0,
            revoked: false,
        };
        store.insert(&grant, "new-hash").unwrap();
        initialize(&store.connection).unwrap();
        assert_eq!(store.find_hash("new-hash").unwrap().unwrap().name, "named");
    }

    #[test]
    fn unsupported_schema_is_not_deleted() {
        for sql in [
            "CREATE TABLE grants (id TEXT, unexpected TEXT); INSERT INTO grants VALUES ('keep', 'me')",
            "CREATE TABLE grants (id TEXT, unexpected TEXT); INSERT INTO grants VALUES ('keep', 'me'); PRAGMA user_version=2",
        ] {
            let connection = Connection::open_in_memory().unwrap();
            connection.execute_batch(sql).unwrap();
            assert!(initialize(&connection).is_err());
            let value: String = connection
                .query_row("SELECT id FROM grants", [], |row| row.get(0))
                .unwrap();
            assert_eq!(value, "keep");
        }
    }

    #[test]
    fn failed_token_rotation_does_not_partially_change_expiration() {
        let store = Store::in_memory();
        let grant = StoredGrant {
            name: "named".into(),
            allowed_executables: vec![],
            directory: None,
            created_at: 1.0,
            expires_at: 100.0,
            revoked: false,
        };
        store.insert(&grant, "old-hash").unwrap();
        store.connection.execute_batch("CREATE TRIGGER fail_renew BEFORE UPDATE ON grants BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END;").unwrap();
        assert!(store.renew("named", 200.0, "new-hash").is_err());
        assert_eq!(store.find("named").unwrap().expires_at, 100.0);
        assert!(store.find_hash("old-hash").unwrap().is_some());
        assert!(store.find_hash("new-hash").unwrap().is_none());
    }

    #[test]
    fn directory_upgrade_preserves_named_grants_and_tokens() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(NAMED_SCHEMA).unwrap();
        connection.execute_batch("PRAGMA user_version=1").unwrap();
        connection
            .execute(
                "INSERT INTO grants VALUES ('kept', 'kept-hash', '[]', 10, 100, 1)",
                [],
            )
            .unwrap();
        initialize(&connection).unwrap();
        let store = Store {
            connection,
            root_lock: None,
        };
        let saved = store.find_hash("kept-hash").unwrap().unwrap();
        assert_eq!(saved.name, "kept");
        assert_eq!(saved.created_at, 10.0);
        assert_eq!(saved.expires_at, 100.0);
        assert!(saved.revoked);
        assert!(saved.directory.is_none());
        initialize(&store.connection).unwrap();
        assert!(store.find_hash("kept-hash").unwrap().is_some());
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn invalid_stored_directory_cannot_become_an_unrestricted_grant() {
        let store = Store::in_memory();
        let grant = StoredGrant {
            name: "restricted".into(),
            allowed_executables: vec![],
            directory: None,
            created_at: 1.0,
            expires_at: 100.0,
            revoked: false,
        };
        store.insert(&grant, "hash").unwrap();
        for value in [
            "null",
            "{}",
            "not-json",
            r#"{"scope":{"path":"/project","recursive":"yes"},"device":1,"inode":2}"#,
            r#"{"scope":{"path":"/project","recursive":true},"device":1,"inode":2,"unknown":true}"#,
        ] {
            store
                .connection
                .execute("UPDATE grants SET directory = ?", [value])
                .unwrap();
            assert!(store.find_hash("hash").is_err());
            assert!(store.find("restricted").is_err());
            assert!(store.page(None).is_err());
        }
    }
}
