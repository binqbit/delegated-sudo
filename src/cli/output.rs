//! Human-readable grant output, with explicit credential display at creation.

use crate::model::{ArgumentPolicy, Grant};
use std::io::{self, Write};

fn quote_argument(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./:@%+=,-".contains(&byte))
    {
        value.into()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn timestamp(value: f64) -> String {
    if !value.is_finite() || value < 0.0 || value >= i64::MAX as f64 {
        return "invalid timestamp".into();
    }
    let seconds = value as libc::time_t;
    let mut result = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: seconds is initialized; result points to writable tm storage.
    if unsafe { libc::gmtime_r(&seconds, result.as_mut_ptr()) }.is_null() {
        return "invalid timestamp".into();
    }
    // SAFETY: a successful gmtime_r initialized result.
    let result = unsafe { result.assume_init() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        result.tm_year + 1900,
        result.tm_mon + 1,
        result.tm_mday,
        result.tm_hour,
        result.tm_min,
        result.tm_sec,
    )
}

pub(super) fn grant(writer: &mut impl Write, grant: &Grant, token: Option<&str>) -> io::Result<()> {
    writeln!(writer, "Grant ID: {}", grant.id)?;
    if let Some(token) = token {
        writeln!(writer, "Token: {token}")?;
    }
    writeln!(
        writer,
        "Commands: {}",
        grant
            .allowed_executables
            .iter()
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(writer, "Created: {}", timestamp(grant.created_at))?;
    writeln!(writer, "Expires: {}", timestamp(grant.expires_at))?;
    writeln!(
        writer,
        "Status: {}",
        if grant.revoked {
            "revoked"
        } else if grant.active {
            "active"
        } else {
            "expired"
        }
    )?;
    for executable in &grant.allowed_executables {
        writeln!(writer, "  {}: {}", executable.name, executable.path)?;
        match &executable.argument_policy {
            ArgumentPolicy::Any => writeln!(
                writer,
                "    Scope: ANY arguments and subcommands (shell syntax rejected)"
            )?,
            ArgumentPolicy::Exact(arguments) | ArgumentPolicy::Prefix(arguments) => {
                let invocation = std::iter::once(executable.name.as_str())
                    .chain(arguments.iter().map(String::as_str))
                    .map(quote_argument)
                    .collect::<Vec<_>>()
                    .join(" ");
                match &executable.argument_policy {
                    ArgumentPolicy::Exact(_) => writeln!(writer, "    Scope: EXACT {invocation}")?,
                    ArgumentPolicy::Prefix(_) => writeln!(
                        writer,
                        "    Scope: PREFIX {invocation} '*' (additional arguments allowed)"
                    )?,
                    ArgumentPolicy::Any => unreachable!(),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displayed_scope_distinguishes_exact_prefix_and_unrestricted_grants() {
        for (argument_policy, expected) in [
            (ArgumentPolicy::Any, "Scope: ANY arguments and subcommands"),
            (
                ArgumentPolicy::Exact(vec![
                    "compose".into(),
                    "a b.yml".into(),
                    "".into(),
                    "don't".into(),
                ]),
                "Scope: EXACT docker compose 'a b.yml' '' 'don'\\''t'\n",
            ),
            (
                ArgumentPolicy::Prefix(vec!["compose".into(), "up".into()]),
                "Scope: PREFIX docker compose up '*' (additional arguments allowed)\n",
            ),
        ] {
            let record = Grant {
                id: "dg_example".into(),
                allowed_executables: vec![crate::model::AllowedExecutable {
                    name: "docker".into(),
                    path: "/nix/store/example/bin/docker".into(),
                    argument_policy,
                }],
                created_at: 0.0,
                expires_at: 60.0,
                revoked: false,
                active: true,
            };
            let mut output = Vec::new();
            grant(&mut output, &record, None).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains(expected));
            assert!(!output.contains("Token:"));
        }
    }
}
