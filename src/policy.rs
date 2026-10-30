//! Domain rules independent of storage, privilege elevation, and process I/O.

use crate::model::{AllowedExecutable, ArgumentPolicy, Grant};
use std::{error::Error, fmt};

pub(crate) const MAX_TTL: u64 = 30 * 24 * 60 * 60;

#[derive(Debug)]
pub struct GrantError(pub(crate) &'static str);
impl fmt::Display for GrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl Error for GrantError {}
pub(crate) type Result<T> = std::result::Result<T, GrantError>;

pub(crate) struct StoredGrant {
    pub name: String,
    pub allowed_executables: Vec<AllowedExecutable>,
    pub created_at: f64,
    pub expires_at: f64,
    pub revoked: bool,
}

impl StoredGrant {
    pub fn public(&self, timestamp: f64) -> Grant {
        Grant {
            name: self.name.clone(),
            allowed_executables: self.allowed_executables.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            revoked: self.revoked,
            active: !self.revoked && timestamp < self.expires_at,
        }
    }
}

pub(crate) fn parse_ttl(value: &str) -> Result<u64> {
    let bad = || GrantError("TTL must be a positive number followed by s, m, h, or d");
    if value.len() < 2 || value.len() > 16 || !value.is_ascii() {
        return Err(bad());
    }
    let (number, unit) = value.split_at(value.len() - 1);
    if number.starts_with('0') || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(bad());
    }
    let factor = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(bad()),
    };
    let seconds = number
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(factor))
        .ok_or_else(bad)?;
    if seconds == 0 {
        return Err(bad());
    }
    if seconds > MAX_TTL {
        return Err(GrantError("TTL must not exceed 30 days"));
    }
    Ok(seconds)
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('-')
        || name.trim() != name
        || name.chars().count() > 80
        || name.chars().any(|c| c.is_control() || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}'))
    {
        return Err(GrantError("Grant name must contain 1 to 80 characters, without a leading dash, surrounding whitespace, control characters, or invisible formatting"));
    }
    Ok(())
}

pub(crate) fn authorize(
    record: &StoredGrant,
    command: &str,
    arguments: &[String],
    timestamp: f64,
) -> Result<AllowedExecutable> {
    if record.revoked || timestamp >= record.expires_at {
        return Err(GrantError("Invalid or inactive delegation token"));
    }
    record
        .allowed_executables
        .iter()
        .find(|item| {
            (command == item.name || command == item.path)
                && match &item.argument_policy {
                    ArgumentPolicy::Any => true,
                    ArgumentPolicy::Exact(expected) => expected == arguments,
                    ArgumentPolicy::Prefix(prefix) => arguments.starts_with(prefix),
                }
        })
        .cloned()
        .ok_or(GrantError(
            "Executable or arguments are not allowed by this grant",
        ))
}

/// Only a final, standalone creation marker enables prefix matching.
pub(crate) fn argument_policy(mut arguments: Vec<String>) -> ArgumentPolicy {
    if arguments.last().is_some_and(|argument| argument == "*") {
        arguments.pop();
        ArgumentPolicy::Prefix(arguments)
    } else {
        ArgumentPolicy::Exact(arguments)
    }
}

pub(crate) fn extended_expiration(
    record: &StoredGrant,
    seconds: u64,
    timestamp: f64,
) -> Result<f64> {
    if record.revoked {
        return Err(GrantError(
            "A revoked grant cannot be extended; delete it and create a new grant",
        ));
    }
    Ok(timestamp + seconds as f64)
}
