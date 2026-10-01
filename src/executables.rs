//! Resolve fixed system-profile names and validate pinned Nix-store targets.
use crate::input_policy;
use crate::model::{AllowedExecutable, ArgumentPolicy};
use crate::policy::{GrantError, Result};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const SYSTEM_PATH: &str = "/run/current-system/sw/bin";
const DENIED_NAMES: &[&str] = &["delegated-sudo", ".delegated-sudo-wrapped"];

fn valid_command_name(name: &str) -> bool {
    name.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

fn store_output(path: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix("/nix/store").ok()?;
    let output = relative.components().next()?;
    if !matches!(output, std::path::Component::Normal(_)) {
        return None;
    }
    Some(Path::new("/nix/store").join(output.as_os_str()))
}

pub(crate) fn validate_executable(path: &Path) -> Result<()> {
    if store_output(path).is_none() || fs::canonicalize(path).ok().as_deref() != Some(path) {
        return Err(GrantError(
            "Executable must resolve to a canonical Nix store path",
        ));
    }
    let own_output = std::env::current_exe()
        .ok()
        .and_then(|path| store_output(&path));
    if path
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| DENIED_NAMES.contains(&name))
        || own_output
            .as_ref()
            .is_some_and(|output| store_output(path).as_ref() == Some(output))
    {
        return Err(GrantError(
            "The delegation tool cannot delegate its own executable",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| GrantError("Allowed executable is no longer available"))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(GrantError(
            "Executable must be a root-owned, non-writable Nix store executable",
        ));
    }
    Ok(())
}

pub(crate) fn resolve_commands(values: &[String]) -> Result<Vec<AllowedExecutable>> {
    if values.is_empty() || values.len() > 64 {
        return Err(GrantError("Specify between one and 64 executables"));
    }
    let mut commands: Vec<AllowedExecutable> = Vec::with_capacity(values.len());
    for value in values {
        input_policy::executable(value)?;
        let input = Path::new(value);
        let (name, target) = if value.contains('/') {
            if !input.starts_with("/nix/store") && !input.starts_with(SYSTEM_PATH) {
                return Err(GrantError(
                    "Absolute executables must be in the Nix store or system profile",
                ));
            }
            let name = input
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or(GrantError("Invalid executable name"))?;
            (name, input.to_path_buf())
        } else {
            (value.as_str(), Path::new(SYSTEM_PATH).join(value))
        };
        if !valid_command_name(name) || DENIED_NAMES.contains(&name) {
            return Err(GrantError("Invalid or reserved executable name"));
        }
        if commands.iter().any(|item| item.name == name) {
            return Err(GrantError("Executable names must be unique within a grant"));
        }
        let canonical = fs::canonicalize(target).map_err(|_| {
            GrantError("An executable was not found in the system profile or Nix store")
        })?;
        validate_executable(&canonical)?;
        let path = canonical
            .to_str()
            .ok_or(GrantError("Executable path must be valid UTF-8"))?;
        commands.push(AllowedExecutable {
            name: name.to_owned(),
            path: path.to_owned(),
            argument_policy: ArgumentPolicy::Any,
        });
    }
    Ok(commands)
}
