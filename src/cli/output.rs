//! Human-readable grants; credentials appear only on creation and renewal.

use crate::model::{AllowedExecutable, ArgumentPolicy, Grant};
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

pub(super) fn issued_grant(writer: &mut impl Write, grant: &Grant, token: &str) -> io::Result<()> {
    writeln!(writer, "delegated-sudo grant {}:", grant.name)?;
    writeln!(writer, "- command: {}", scopes(grant))?;
    writeln!(writer, "- dir: {}", directory(grant))?;
    writeln!(writer, "- token: {token}")?;
    writeln!(writer, "- expires: {}", timestamp(grant.expires_at))
}

pub(super) fn grant(writer: &mut impl Write, grant: &Grant) -> io::Result<()> {
    writeln!(writer, "Name: {}", grant.name)?;
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
    writeln!(writer, "Directory: {}", directory(grant))?;
    writeln!(writer, "Created: {}", timestamp(grant.created_at))?;
    writeln!(writer, "Expires: {}", timestamp(grant.expires_at))?;
    writeln!(writer, "Status: {}", status(grant))?;
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
                        "    Scope: PREFIX {invocation} * (additional arguments allowed)"
                    )?,
                    ArgumentPolicy::Any => unreachable!(),
                }
            }
        }
    }
    Ok(())
}

fn status(grant: &Grant) -> &'static str {
    if grant.revoked {
        "revoked"
    } else if grant.active {
        "active"
    } else {
        "expired"
    }
}

fn scope(executable: &AllowedExecutable) -> String {
    let arguments = match &executable.argument_policy {
        ArgumentPolicy::Any => &[][..],
        ArgumentPolicy::Exact(arguments) | ArgumentPolicy::Prefix(arguments) => arguments,
    };
    let mut command = std::iter::once(executable.name.as_str())
        .chain(arguments.iter().map(String::as_str))
        .map(quote_argument)
        .collect::<Vec<_>>()
        .join(" ");
    if !matches!(executable.argument_policy, ArgumentPolicy::Exact(_)) {
        command.push_str(" *");
    }
    command
}

fn scopes(grant: &Grant) -> String {
    grant
        .allowed_executables
        .iter()
        .map(scope)
        .collect::<Vec<_>>()
        .join(", ")
}

fn directory(grant: &Grant) -> String {
    match &grant.directory {
        Some(scope) if scope.recursive => format!("{}/*", scope.path.trim_end_matches('/')),
        Some(scope) => scope.path.clone(),
        None => "any".into(),
    }
}

pub(super) fn terminal_width() -> usize {
    let mut size = std::mem::MaybeUninit::<libc::winsize>::uninit();
    // SAFETY: ioctl writes a winsize into valid storage on success.
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, size.as_mut_ptr()) } == 0 {
        // SAFETY: the successful ioctl initialized size.
        let columns = unsafe { size.assume_init() }.ws_col;
        if columns > 0 {
            return usize::from(columns);
        }
    }
    100
}

pub(super) fn list(writer: &mut impl Write, grants: &[Grant], width: usize) -> io::Result<()> {
    if grants.is_empty() {
        return writeln!(writer, "No delegation grants.");
    }
    let commands: Vec<_> = grants.iter().map(scopes).collect();
    let show_directory = grants.iter().any(|grant| grant.directory.is_some());
    let directories: Vec<_> = grants.iter().map(directory).collect();
    let directory_width = directories.iter().map(String::len).max().unwrap().max(3);
    let name_width = grants
        .iter()
        .map(|grant| grant.name.len())
        .max()
        .unwrap()
        .max(4);
    let command_width = commands.iter().map(String::len).max().unwrap().max(7);
    // ASCII has predictable terminal width. Use labeled rows for long or
    // Unicode values so names and scopes stay complete without misaligned columns.
    let table = name_width
        + command_width
        + 19
        + 7
        + 6
        + if show_directory {
            directory_width + 2
        } else {
            0
        }
        <= width
        && grants.iter().all(|grant| grant.name.is_ascii())
        && commands.iter().all(|command| command.is_ascii())
        && directories.iter().all(|directory| directory.is_ascii());
    if table {
        let directory_header = if show_directory {
            format!("  {:directory_width$}", "DIR")
        } else {
            String::new()
        };
        writeln!(
            writer,
            "{:name_width$}  {:command_width$}{directory_header}  {:19}  STATUS",
            "NAME", "COMMAND", "EXPIRES (UTC)"
        )?;
        writeln!(
            writer,
            "{}  {}{}  {}  {}",
            "─".repeat(name_width),
            "─".repeat(command_width),
            if show_directory {
                format!("  {}", "─".repeat(directory_width))
            } else {
                String::new()
            },
            "─".repeat(19),
            "─".repeat(7)
        )?;
        for ((grant, command), directory) in grants.iter().zip(&commands).zip(&directories) {
            let expires = timestamp(grant.expires_at);
            let expires = expires.strip_suffix(" UTC").unwrap_or(&expires);
            let directory_cell = if show_directory {
                format!("  {directory:directory_width$}")
            } else {
                String::new()
            };
            writeln!(
                writer,
                "{:name_width$}  {command:command_width$}{directory_cell}  {expires:19}  {}",
                grant.name,
                status(grant)
            )?;
        }
    } else {
        for (index, grant) in grants.iter().enumerate() {
            if index > 0 {
                writeln!(writer)?;
            }
            writeln!(writer, "{}  [{}]", grant.name, status(grant))?;
            for executable in &grant.allowed_executables {
                writeln!(writer, "  Command: {}", scope(executable))?;
            }
            if show_directory {
                writeln!(writer, "  Directory: {}", directory(grant))?;
            }
            writeln!(writer, "  Expires: {}", timestamp(grant.expires_at))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, argument_policy: ArgumentPolicy) -> Grant {
        Grant {
            name: name.into(),
            allowed_executables: vec![AllowedExecutable {
                name: "docker".into(),
                path: "/nix/store/example/bin/docker".into(),
                argument_policy,
            }],
            created_at: 0.0,
            expires_at: 60.0,
            revoked: false,
            active: true,
            directory: None,
        }
    }

    #[test]
    fn issued_grant_is_exactly_the_compact_credential_block() {
        let grant = record(
            "compose-codex",
            ArgumentPolicy::Prefix(vec!["compose".into()]),
        );
        let mut output = Vec::new();
        issued_grant(&mut output, &grant, "test-credential").unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "delegated-sudo grant compose-codex:\n",
                "- command: docker compose *\n",
                "- dir: any\n",
                "- token: test-credential\n",
                "- expires: 1970-01-01 00:01:00 UTC\n",
            )
        );
    }

    #[test]
    fn issued_grant_preserves_names_and_all_command_scopes() {
        let mut grant = record(
            "Docker Compose:",
            ArgumentPolicy::Exact(vec![
                "compose".into(),
                "--file".into(),
                "a b.yml".into(),
                "up".into(),
            ]),
        );
        grant.allowed_executables.push(AllowedExecutable {
            name: "systemctl".into(),
            path: "/nix/store/example/bin/systemctl".into(),
            argument_policy: ArgumentPolicy::Any,
        });
        let mut output = Vec::new();
        issued_grant(&mut output, &grant, "test-credential").unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "delegated-sudo grant Docker Compose::\n",
                "- command: docker compose --file 'a b.yml' up, systemctl *\n",
                "- dir: any\n",
                "- token: test-credential\n",
                "- expires: 1970-01-01 00:01:00 UTC\n",
            )
        );
    }

    #[test]
    fn directory_scope_is_explicit_in_issued_and_detailed_grants() {
        for (path, recursive, displayed) in [
            ("/srv/app", false, "/srv/app"),
            ("/srv/app", true, "/srv/app/*"),
            ("/", true, "/*"),
            ("/srv/my app", true, "/srv/my app/*"),
        ] {
            let mut grant = record("project", ArgumentPolicy::Prefix(vec!["compose".into()]));
            grant.directory = Some(crate::model::DirectoryScope {
                path: path.into(),
                recursive,
            });
            let mut output = Vec::new();
            issued_grant(&mut output, &grant, "test-credential").unwrap();
            assert_eq!(
                String::from_utf8(output).unwrap(),
                format!(
                    "delegated-sudo grant project:\n- command: docker compose *\n- dir: {displayed}\n- token: test-credential\n- expires: 1970-01-01 00:01:00 UTC\n"
                )
            );
            let mut output = Vec::new();
            super::grant(&mut output, &grant).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains(&format!("Directory: {displayed}\n")));
            assert!(!output.contains("token:") && !output.contains("inode"));
        }
    }

    #[test]
    fn mixed_list_keeps_directory_scope_visible_in_table_and_narrow_rows() {
        let mut scoped = record("project", ArgumentPolicy::Any);
        scoped.directory = Some(crate::model::DirectoryScope {
            path: "/srv/app".into(),
            recursive: true,
        });
        let grants = [scoped, record("unrestricted", ArgumentPolicy::Any)];
        let mut output = Vec::new();
        list(&mut output, &grants, 120).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.lines().next().unwrap().contains("DIR"));
        assert!(
            output
                .lines()
                .any(|line| line.starts_with("project ") && line.contains("/srv/app/*"))
        );
        assert!(
            output
                .lines()
                .any(|line| line.starts_with("unrestricted ") && line.contains("any"))
        );

        let mut output = Vec::new();
        list(&mut output, &grants, 40).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "project  [active]\n",
                "  Command: docker *\n",
                "  Directory: /srv/app/*\n",
                "  Expires: 1970-01-01 00:01:00 UTC\n",
                "\n",
                "unrestricted  [active]\n",
                "  Command: docker *\n",
                "  Directory: any\n",
                "  Expires: 1970-01-01 00:01:00 UTC\n",
            )
        );
    }

    #[test]
    fn list_has_complete_command_names_expirations_and_statuses() {
        let active = record(
            "compose-codex",
            ArgumentPolicy::Prefix(vec!["compose".into()]),
        );
        let mut expired = record("expired", ArgumentPolicy::Exact(vec!["ps".into()]));
        expired.active = false;
        let mut revoked = record("revoked", ArgumentPolicy::Any);
        revoked.revoked = true;
        let mut output = Vec::new();
        list(&mut output, &[active, expired, revoked], 100).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(
            output,
            concat!(
                "NAME           COMMAND           EXPIRES (UTC)        STATUS\n",
                "─────────────  ────────────────  ───────────────────  ───────\n",
                "compose-codex  docker compose *  1970-01-01 00:01:00  active\n",
                "expired        docker ps         1970-01-01 00:01:00  expired\n",
                "revoked        docker *          1970-01-01 00:01:00  revoked\n",
            )
        );
        assert!(!output.contains("Token:") && !output.contains("/nix/store/"));
    }

    #[test]
    fn narrow_and_unicode_lists_preserve_full_names_and_scopes() {
        let record = record(
            "Docker Compose Кодекс",
            ArgumentPolicy::Prefix(vec!["compose".into(), "--file".into(), "a b.yml".into()]),
        );
        for width in [40, 100] {
            let mut output = Vec::new();
            list(&mut output, std::slice::from_ref(&record), width).unwrap();
            assert_eq!(
                String::from_utf8(output).unwrap(),
                concat!(
                    "Docker Compose Кодекс  [active]\n",
                    "  Command: docker compose --file 'a b.yml' *\n",
                    "  Expires: 1970-01-01 00:01:00 UTC\n",
                )
            );
        }
    }

    #[test]
    fn empty_list_has_a_clear_message() {
        let mut output = Vec::new();
        list(&mut output, &[], 80).unwrap();
        assert_eq!(output, b"No delegation grants.\n");
    }

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
                "Scope: PREFIX docker compose up * (additional arguments allowed)\n",
            ),
        ] {
            let record = Grant {
                name: "docker-compose-codex".into(),
                allowed_executables: vec![crate::model::AllowedExecutable {
                    name: "docker".into(),
                    path: "/nix/store/example/bin/docker".into(),
                    argument_policy,
                }],
                created_at: 0.0,
                expires_at: 60.0,
                revoked: false,
                active: true,
                directory: None,
            };
            let mut output = Vec::new();
            grant(&mut output, &record).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains(expected));
            assert!(!output.contains("Token:"));
        }
    }
}
