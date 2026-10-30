//! Coordinate root authorization, grant policy, persistence, and execution.

use crate::credentials::{self, SecretToken};
use crate::executables;
use crate::execution;
use crate::input_policy;
use crate::model::{AdminResponse, AllowedExecutable, ArgumentPolicy, Request};
use crate::policy::{self, GrantError, Result, StoredGrant};
use crate::storage::Store;
use std::convert::Infallible;
use std::error::Error;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const STATE_DIRECTORY: &str = "/var/lib/delegated-sudo";

fn require_root() -> Result<()> {
    // SAFETY: credential queries take no pointers. This single-threaded CLI
    // sets its file creation mask before opening grant storage.
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return Err(GrantError(
            "Grant operations require ordinary root/sudo privileges",
        ));
    }
    unsafe {
        libc::umask(0o077);
    }
    Ok(())
}

fn now() -> Result<f64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs_f64())
        .map_err(|_| GrantError("System clock is invalid"))
}

pub(crate) fn create_grant(
    store: &Store,
    name: String,
    allowed: Vec<AllowedExecutable>,
    seconds: u64,
    timestamp: f64,
) -> Result<AdminResponse> {
    policy::validate_name(&name)?;
    for executable in &allowed {
        let arguments = match &executable.argument_policy {
            ArgumentPolicy::Any => &[][..],
            ArgumentPolicy::Exact(arguments) | ArgumentPolicy::Prefix(arguments) => arguments,
        };
        input_policy::invocation(&executable.name, arguments)?;
        input_policy::executable(&executable.path)?;
    }
    let token = SecretToken::generate()?;
    let record = StoredGrant {
        name,
        allowed_executables: allowed,
        created_at: timestamp,
        expires_at: timestamp + seconds as f64,
        revoked: false,
    };
    let grant = record.public(timestamp);
    if serde_json::to_vec(&grant)
        .map_err(|_| GrantError("Invalid grant"))?
        .len()
        > 60 * 1024
    {
        return Err(GrantError("Executable list is too large for one grant"));
    }
    store.insert(&record, &token.hash())?;
    Ok(AdminResponse::Created { grant, token })
}

pub(crate) fn list_grants(
    store: &Store,
    cursor: Option<&str>,
    timestamp: f64,
) -> Result<AdminResponse> {
    if let Some(cursor) = cursor {
        policy::validate_name(cursor)?;
    }
    let records = store.page(cursor)?;
    let grants: Vec<_> = records
        .iter()
        .take(100)
        .map(|record| record.public(timestamp))
        .collect();
    let next_cursor = if grants.len() < records.len() {
        grants.last().map(|grant| grant.name.clone())
    } else {
        None
    };
    Ok(AdminResponse::List {
        grants,
        next_cursor,
    })
}

pub(crate) fn dispatch(store: &Store, request: Request, timestamp: f64) -> Result<AdminResponse> {
    match request {
        Request::Create {
            name,
            commands,
            ttl,
        } => {
            policy::validate_name(&name)?;
            let seconds = policy::parse_ttl(&ttl)?;
            create_grant(
                store,
                name,
                executables::resolve_commands(&commands)?,
                seconds,
                timestamp,
            )
        }
        Request::CreateCommand {
            name,
            command,
            arguments,
            ttl,
        } => {
            policy::validate_name(&name)?;
            let seconds = policy::parse_ttl(&ttl)?;
            input_policy::invocation(&command, &arguments)?;
            let mut allowed = executables::resolve_commands(&[command])?;
            allowed[0].argument_policy = policy::argument_policy(arguments);
            create_grant(store, name, allowed, seconds, timestamp)
        }
        Request::List { cursor } => list_grants(store, cursor.as_deref(), timestamp),
        Request::Show { name } => {
            policy::validate_name(&name)?;
            Ok(AdminResponse::Grant(store.find(&name)?.public(timestamp)))
        }
        Request::Revoke { name } => {
            policy::validate_name(&name)?;
            let mut record = store.find(&name)?;
            store.revoke(&name)?;
            record.revoked = true;
            Ok(AdminResponse::Grant(record.public(timestamp)))
        }
        Request::Extend { name, ttl } => {
            policy::validate_name(&name)?;
            let seconds = policy::parse_ttl(&ttl)?;
            let mut record = store.find(&name)?;
            record.expires_at = policy::extended_expiration(&record, seconds, timestamp)?;
            let token = SecretToken::generate()?;
            store.renew(&name, record.expires_at, &token.hash())?;
            Ok(AdminResponse::Extended {
                grant: record.public(timestamp),
                token,
            })
        }
        Request::Delete { name } => {
            policy::validate_name(&name)?;
            store.delete(&name)?;
            Ok(AdminResponse::Deleted { name })
        }
    }
}

pub fn administer(request: Request) -> std::result::Result<AdminResponse, Box<dyn Error>> {
    require_root()?;
    let store = Store::open(Path::new(STATE_DIRECTORY))?;
    Ok(dispatch(&store, request, now()?)?)
}

pub fn execute(
    token: &str,
    command: &str,
    arguments: &[String],
) -> std::result::Result<Infallible, Box<dyn Error>> {
    require_root()?;
    input_policy::invocation(command, arguments)?;
    let store = Store::open(Path::new(STATE_DIRECTORY))?;
    let record = store
        .find_hash(&credentials::lookup_hash(token)?)?
        .ok_or(GrantError("Invalid or inactive delegation token"))?;
    let allowed = policy::authorize(&record, command, arguments, now()?)?;
    executables::validate_executable(Path::new(&allowed.path))?;
    // The root lock spans the complete lookup/authorize/validate/exec sequence.
    Ok(execution::replace(
        &allowed,
        arguments,
        store.into_exec_lock(),
    )?)
}
