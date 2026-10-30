//! Shared grant data and typed administrative operations; no transport layer.

use serde::{Deserialize, Serialize};

/// Bearer credential with no automatic debugging, formatting, serialization,
/// or cloning. Creation and renewal output explicitly expose its contents.
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryScope {
    pub path: String,
    pub recursive: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub name: String,
    pub allowed_executables: Vec<AllowedExecutable>,
    pub directory: Option<DirectoryScope>,
    pub created_at: f64,
    pub expires_at: f64,
    pub revoked: bool,
    pub active: bool,
}

#[derive(Debug)]
pub enum Request {
    Create {
        name: String,
        commands: Vec<String>,
        ttl: String,
        directory: Option<String>,
    },
    CreateCommand {
        name: String,
        command: String,
        arguments: Vec<String>,
        ttl: String,
        directory: Option<String>,
    },
    List {
        cursor: Option<String>,
    },
    Show {
        name: String,
    },
    Revoke {
        name: String,
    },
    Extend {
        name: String,
        ttl: String,
    },
    Delete {
        name: String,
    },
}

pub enum AdminResponse {
    Created {
        grant: Grant,
        token: SecretToken,
    },
    Extended {
        grant: Grant,
        token: SecretToken,
    },
    Deleted {
        name: String,
    },
    Grant(Grant),
    List {
        grants: Vec<Grant>,
        next_cursor: Option<String>,
    },
}
