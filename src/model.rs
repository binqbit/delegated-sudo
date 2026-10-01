//! Shared grant data and typed administrative operations; no transport layer.

use serde::{Deserialize, Serialize};

/// Bearer credential with no automatic debugging, formatting, serialization,
/// or cloning. Creation output is the only UI path that exposes its contents.
pub struct SecretToken(pub(crate) String);

impl SecretToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedExecutable {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub argument_policy: ArgumentPolicy,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "arguments",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ArgumentPolicy {
    #[default]
    Any,
    Exact(Vec<String>),
    Prefix(Vec<String>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub allowed_executables: Vec<AllowedExecutable>,
    pub created_at: f64,
    pub expires_at: f64,
    pub revoked: bool,
    pub active: bool,
}

#[derive(Debug)]
pub enum Request {
    Create {
        commands: Vec<String>,
        ttl: String,
    },
    CreateCommand {
        command: String,
        arguments: Vec<String>,
        ttl: String,
    },
    List {
        cursor: Option<String>,
    },
    Show {
        id: String,
    },
    Revoke {
        id: String,
    },
    Extend {
        id: String,
        ttl: String,
    },
}

pub enum AdminResponse {
    Created {
        grant: Grant,
        token: SecretToken,
    },
    Grant(Grant),
    List {
        grants: Vec<Grant>,
        next_cursor: Option<String>,
    },
}
