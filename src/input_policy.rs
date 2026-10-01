//! A conservative literal-argument grammar, shared by creation and execution.
//! This is not shell parsing: arguments are always passed directly to exec.

use crate::policy::{GrantError, Result};

fn literal(value: &str) -> Result<()> {
    if value.chars().any(|character| {
        character.is_control() || matches!(character, ';' | '|' | '&' | '<' | '>' | '`')
    }) || value.contains("$(")
        || value.contains("${")
    {
        return Err(GrantError(
            "Shell operators, substitutions, and control characters are not permitted",
        ));
    }
    Ok(())
}

pub(crate) fn executable(command: &str) -> Result<()> {
    if command.is_empty() || command.len() > 4096 {
        return Err(GrantError("Invalid executable"));
    }
    literal(command)
}

pub(crate) fn invocation(command: &str, arguments: &[String]) -> Result<()> {
    executable(command)?;
    if arguments.len() > 4096 {
        return Err(GrantError("Invalid command arguments"));
    }
    for argument in arguments {
        literal(argument)?;
    }
    Ok(())
}
