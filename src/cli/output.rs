//! Human-readable grants; credentials appear only on creation and renewal.

use super::style::{Role, Theme};
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

pub(super) fn issued_grant(
    writer: &mut impl Write,
    grant: &Grant,
    token: &str,
    theme: Theme,
) -> io::Result<()> {
    writeln!(
        writer,
        "{} {}:",
        theme.paint(Role::Command, "delegated-sudo grant"),
        theme.paint(Role::Name, &grant.name),
    )?;
    writeln!(
        writer,
        "{} {}",
        theme.paint(Role::Heading, "- command:"),
        scopes(grant, theme)
    )?;
    writeln!(
        writer,
        "{} {}",
        theme.paint(Role::Heading, "- dir:"),
        theme.paint(Role::Path, &directory(grant))
    )?;
    // Keep the credential itself unstyled so copying it never includes ANSI codes.
    writeln!(writer, "{} {token}", theme.paint(Role::Heading, "- token:"))?;
    writeln!(
        writer,
        "{} {}",
        theme.paint(Role::Heading, "- expires:"),
        theme.paint(Role::Value, &timestamp(grant.expires_at))
    )
}

pub(super) fn grant(writer: &mut impl Write, grant: &Grant, theme: Theme) -> io::Result<()> {
    writeln!(
        writer,
        "{} {}",
        theme.paint(Role::Heading, "Name:"),
        theme.paint(Role::Name, &grant.name)
    )?;
    writeln!(
        writer,
        "{} {}",
        theme.paint(Role::Heading, "Commands:"),
        grant
            .allowed_executables
            .iter()
            .map(|item| theme.paint(Role::Command, &item.name))
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(
        writer,
        "{} {}",
        theme.paint(Role::Heading, "Directory:"),
        theme.paint(Role::Path, &directory(grant))
    )?;
    writeln!(
        writer,
        "{} {}",
        theme.paint(Role::Heading, "Created:"),
        theme.paint(Role::Value, &timestamp(grant.created_at))
    )?;
    writeln!(
        writer,
        "{} {}",
        theme.paint(Role::Heading, "Expires:"),
        theme.paint(Role::Value, &timestamp(grant.expires_at))
    )?;
    writeln!(
        writer,
        "{} {}",
        theme.paint(Role::Heading, "Status:"),
        styled_status(grant, theme)
    )?;
    for executable in &grant.allowed_executables {
        writeln!(
            writer,
            "  {}: {}",
            theme.paint(Role::Command, &executable.name),
            theme.paint(Role::Path, &executable.path)
        )?;
        match &executable.argument_policy {
            ArgumentPolicy::Any => writeln!(
                writer,
                "    {} {} arguments and subcommands (shell syntax rejected)",
                theme.paint(Role::Heading, "Scope:"),
                theme.paint(Role::Option, "ANY"),
            )?,
            ArgumentPolicy::Exact(_) | ArgumentPolicy::Prefix(_) => {
                let invocation = invocation(executable, theme);
                match &executable.argument_policy {
                    ArgumentPolicy::Exact(_) => writeln!(
                        writer,
                        "    {} {} {invocation}",
                        theme.paint(Role::Heading, "Scope:"),
                        theme.paint(Role::Option, "EXACT")
                    )?,
                    ArgumentPolicy::Prefix(_) => writeln!(
                        writer,
                        "    {} {} {invocation} {} (additional arguments allowed)",
                        theme.paint(Role::Heading, "Scope:"),
                        theme.paint(Role::Option, "PREFIX"),
                        theme.paint(Role::Option, "*"),
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

fn styled_status(grant: &Grant, theme: Theme) -> String {
    let role = if grant.revoked {
        Role::Error
    } else if grant.active {
        Role::Success
    } else {
        Role::Warning
    };
    theme.paint(role, status(grant))
}

fn invocation(executable: &AllowedExecutable, theme: Theme) -> String {
    let arguments = match &executable.argument_policy {
        ArgumentPolicy::Any => &[][..],
        ArgumentPolicy::Exact(arguments) | ArgumentPolicy::Prefix(arguments) => arguments,
    };
    let mut parts = vec![theme.paint(Role::Command, &quote_argument(&executable.name))];
    parts.extend(arguments.iter().map(|argument| {
        let role = if argument.starts_with('-') {
            Role::Option
        } else {
            Role::Value
        };
        theme.paint(role, &quote_argument(argument))
    }));
    parts.join(" ")
}

fn scope(executable: &AllowedExecutable, theme: Theme) -> String {
    let mut command = invocation(executable, theme);
    if !matches!(executable.argument_policy, ArgumentPolicy::Exact(_)) {
        command.push(' ');
        command.push_str(&theme.paint(Role::Option, "*"));
    }
    command
}

fn scopes(grant: &Grant, theme: Theme) -> String {
    grant
        .allowed_executables
        .iter()
        .map(|executable| scope(executable, theme))
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

pub(super) fn list(
    writer: &mut impl Write,
    grants: &[Grant],
    width: usize,
    theme: Theme,
) -> io::Result<()> {
    if grants.is_empty() {
        return writeln!(
            writer,
            "{}",
            theme.paint(Role::Muted, "No delegation grants.")
        );
    }
    // Width calculations use plain values; ANSI escapes must not shift columns.
    let commands: Vec<_> = grants
        .iter()
        .map(|grant| scopes(grant, Theme::plain()))
        .collect();
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
        let header = format!(
            "{:name_width$}  {:command_width$}{directory_header}  {:19}  STATUS",
            "NAME", "COMMAND", "EXPIRES (UTC)"
        );
        writeln!(writer, "{}", theme.paint(Role::Heading, &header))?;
        let separator = format!(
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
        );
        writeln!(writer, "{}", theme.paint(Role::Muted, &separator))?;
        for ((grant, command), directory) in grants.iter().zip(&commands).zip(&directories) {
            let expires = timestamp(grant.expires_at);
            let expires = expires.strip_suffix(" UTC").unwrap_or(&expires);
            let directory_cell = if show_directory {
                format!(
                    "  {}",
                    theme.paint(Role::Path, &format!("{directory:directory_width$}"))
                )
            } else {
                String::new()
            };
            writeln!(
                writer,
                "{}  {}{}{directory_cell}  {}  {}",
                theme.paint(Role::Name, &format!("{:name_width$}", grant.name)),
                scopes(grant, theme),
                " ".repeat(command_width - command.len()),
                theme.paint(Role::Value, &format!("{expires:19}")),
                styled_status(grant, theme),
            )?;
        }
    } else {
        for (index, grant) in grants.iter().enumerate() {
            if index > 0 {
                writeln!(writer)?;
            }
            writeln!(
                writer,
                "{}  [{}]",
                theme.paint(Role::Name, &grant.name),
                styled_status(grant, theme)
            )?;
            for executable in &grant.allowed_executables {
                writeln!(
                    writer,
                    "  {} {}",
                    theme.paint(Role::Heading, "Command:"),
                    scope(executable, theme)
                )?;
            }
            if show_directory {
                writeln!(
                    writer,
                    "  {} {}",
                    theme.paint(Role::Heading, "Directory:"),
                    theme.paint(Role::Path, &directory(grant))
                )?;
            }
            writeln!(
                writer,
                "  {} {}",
                theme.paint(Role::Heading, "Expires:"),
                theme.paint(Role::Value, &timestamp(grant.expires_at))
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_styles(value: &str) -> String {
        let mut plain = String::new();
        let mut characters = value.chars();
        while let Some(character) = characters.next() {
            if character == '\x1b' {
                assert_eq!(characters.next(), Some('['));
                for control in characters.by_ref() {
                    if ('@'..='~').contains(&control) {
                        break;
                    }
                }
            } else {
                plain.push(character);
            }
        }
        plain
    }

    fn assert_only_styles_changed(plain: Vec<u8>, colored: Vec<u8>) -> String {
        let plain = String::from_utf8(plain).unwrap();
        let colored = String::from_utf8(colored).unwrap();
        assert!(!plain.contains('\x1b'));
        assert!(colored.contains("\x1b["));
        assert_eq!(strip_styles(&colored), plain);
        colored
    }

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
        issued_grant(&mut output, &grant, "test-credential", Theme::plain()).unwrap();
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
        issued_grant(&mut output, &grant, "test-credential", Theme::plain()).unwrap();
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
            issued_grant(&mut output, &grant, "test-credential", Theme::plain()).unwrap();
            assert_eq!(
                String::from_utf8(output).unwrap(),
                format!(
                    "delegated-sudo grant project:\n- command: docker compose *\n- dir: {displayed}\n- token: test-credential\n- expires: 1970-01-01 00:01:00 UTC\n"
                )
            );
            let mut output = Vec::new();
            super::grant(&mut output, &grant, Theme::plain()).unwrap();
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
        list(&mut output, &grants, 120, Theme::plain()).unwrap();
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
        list(&mut output, &grants, 40, Theme::plain()).unwrap();
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
        list(
            &mut output,
            &[active, expired, revoked],
            100,
            Theme::plain(),
        )
        .unwrap();
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
            list(
                &mut output,
                std::slice::from_ref(&record),
                width,
                Theme::plain(),
            )
            .unwrap();
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
        list(&mut output, &[], 80, Theme::plain()).unwrap();
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
            grant(&mut output, &record, Theme::plain()).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains(expected));
            assert!(!output.contains("Token:"));
        }
    }

    #[test]
    fn colors_preserve_issued_and_detailed_values_without_styling_credentials() {
        let mut record = record(
            "Docker Compose Кодекс",
            ArgumentPolicy::Prefix(vec![
                "compose".into(),
                "--file".into(),
                "/srv/my project/compose.yml".into(),
                "don't".into(),
                "".into(),
            ]),
        );
        record.directory = Some(crate::model::DirectoryScope {
            path: "/srv/my project".into(),
            recursive: true,
        });
        let token = "test-only-credential";
        let mut plain = Vec::new();
        let mut colored = Vec::new();
        issued_grant(&mut plain, &record, token, Theme::plain()).unwrap();
        issued_grant(&mut colored, &record, token, Theme::new(true)).unwrap();
        let colored = assert_only_styles_changed(plain, colored);
        assert_eq!(colored.matches(token).count(), 1);
        assert!(colored.contains(&format!(" {token}\n")));
        assert!(colored.contains("\x1b[1;36mdocker\x1b[0m compose "));
        assert!(colored.contains("\x1b[33m--file\x1b[0m '/srv/my project/compose.yml' "));

        let mut plain = Vec::new();
        let mut colored = Vec::new();
        grant(&mut plain, &record, Theme::plain()).unwrap();
        grant(&mut colored, &record, Theme::new(true)).unwrap();
        let colored = assert_only_styles_changed(plain, colored);
        assert!(!colored.contains(token));
    }

    #[test]
    fn colors_preserve_table_alignment_and_narrow_or_unicode_layouts() {
        let mut active = record(
            "compose",
            ArgumentPolicy::Prefix(vec!["compose".into(), "--file".into(), "app.yml".into()]),
        );
        active.directory = Some(crate::model::DirectoryScope {
            path: "/srv/app".into(),
            recursive: true,
        });
        let mut expired = record("expired", ArgumentPolicy::Exact(vec!["ps".into()]));
        expired.active = false;
        let mut revoked = record("revoked", ArgumentPolicy::Any);
        revoked.revoked = true;
        let ascii = [active, expired, revoked];
        for width in [40, 160] {
            let mut plain = Vec::new();
            let mut colored = Vec::new();
            list(&mut plain, &ascii, width, Theme::plain()).unwrap();
            list(&mut colored, &ascii, width, Theme::new(true)).unwrap();
            assert_only_styles_changed(plain, colored);
        }
        let unicode = [record("Docker Compose Кодекс", ArgumentPolicy::Any)];
        let mut plain = Vec::new();
        let mut colored = Vec::new();
        list(&mut plain, &unicode, 160, Theme::plain()).unwrap();
        list(&mut colored, &unicode, 160, Theme::new(true)).unwrap();
        assert_only_styles_changed(plain, colored);
    }
}
