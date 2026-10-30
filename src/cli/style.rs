//! Terminal-only presentation; redirected output keeps its original bytes.

use std::ffi::OsStr;
use std::io::{self, IsTerminal};
use std::ops::Range;

#[derive(Clone, Copy)]
pub(super) enum Role {
    Heading,
    Command,
    Name,
    Option,
    Path,
    Value,
    Muted,
    Success,
    Warning,
    Error,
}

impl Role {
    fn code(self) -> &'static str {
        match self {
            Self::Heading => "1",
            Self::Command => "1;36",
            Self::Name => "1;35",
            Self::Option => "33",
            Self::Path => "94",
            Self::Value => "32",
            Self::Muted => "2",
            Self::Success => "32",
            Self::Warning => "33",
            Self::Error => "31",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Theme {
    enabled: bool,
}

impl Theme {
    pub(super) const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub(super) const fn plain() -> Self {
        Self::new(false)
    }

    pub(super) fn stdout() -> Self {
        Self::new(permits_color(
            io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").as_deref(),
            std::env::var_os("TERM").as_deref(),
            std::env::var_os("CLICOLOR").as_deref(),
        ))
    }

    pub(super) fn paint(self, role: Role, value: &str) -> String {
        if self.enabled && !value.is_empty() {
            format!("\x1b[{}m{value}\x1b[0m", role.code())
        } else {
            value.into()
        }
    }

    pub(super) fn help(self, text: &str) -> String {
        if !self.enabled {
            return text.into();
        }
        text.split_inclusive('\n')
            .map(|line| self.help_line(line))
            .collect()
    }

    fn help_line(self, line: &str) -> String {
        let title = line.trim_end().split(" (").next().unwrap_or_default();
        if !line.starts_with(char::is_whitespace)
            && title.chars().any(char::is_alphabetic)
            && title
                .chars()
                .filter(|ch| ch.is_alphabetic())
                .all(char::is_uppercase)
        {
            let content = line.trim_end_matches('\n');
            return self.paint(Role::Heading, content)
                + if line.ends_with('\n') { "\n" } else { "" };
        }

        let ranges = token_ranges(line);
        let tokens: Vec<_> = ranges.iter().map(|range| &line[range.clone()]).collect();
        let program = tokens.iter().position(|token| *token == "delegated-sudo");
        let name = program.and_then(|start| {
            (tokens.get(start + 1) == Some(&"grant")
                && matches!(
                    tokens.get(start + 2).copied(),
                    Some("create" | "show" | "extend" | "revoke" | "delete")
                ))
            .then_some(start + 3)
        });
        let executable = tokens
            .iter()
            .position(|token| *token == "--" || *token == "Command:")
            .map(|index| index + 1);
        let mut output = String::with_capacity(line.len());
        let mut cursor = 0;
        for (index, range) in ranges.iter().enumerate() {
            output.push_str(&line[cursor..range.start]);
            let token = tokens[index];
            let bare = token.trim_matches(['`', '\'', '"', ',', '.', ':', '(', ')']);
            let role = if index == 0 && token.ends_with(':') {
                Some(Role::Heading)
            } else if Some(index) == name && !token.starts_with(['-', '[']) {
                Some(Role::Name)
            } else if bare.starts_with('-') {
                Some(Role::Option)
            } else if bare.contains("<NAME>") {
                Some(Role::Name)
            } else if bare == "sudo"
                || bare == "delegated-sudo"
                || bare.contains("<COMMAND>")
                || Some(index) == executable
                || (program.is_some_and(|start| index > start && index <= start + 2)
                    && matches!(
                        bare,
                        "grant"
                            | "create"
                            | "show"
                            | "list"
                            | "extend"
                            | "revoke"
                            | "delete"
                            | "exec"
                            | "help"
                    ))
            {
                Some(Role::Command)
            } else if bare.starts_with('/') || bare.contains("<PATH>") {
                Some(Role::Path)
            } else if (bare.starts_with('<') && bare.ends_with('>'))
                || bare == "[ARGUMENTS...]"
                || executable.is_some_and(|start| index > start)
            {
                Some(Role::Value)
            } else {
                None
            };
            if let Some(role) = role {
                output.push_str(&self.paint(role, token));
            } else {
                output.push_str(token);
            }
            cursor = range.end;
        }
        output.push_str(&line[cursor..]);
        output
    }
}

fn permits_color(
    terminal: bool,
    no_color: Option<&OsStr>,
    term: Option<&OsStr>,
    clicolor: Option<&OsStr>,
) -> bool {
    terminal
        && !no_color.is_some_and(|value| !value.is_empty())
        && term != Some(OsStr::new("dumb"))
        && clicolor != Some(OsStr::new("0"))
}

// Keep quoted example values intact without reserializing or interpreting them.
fn token_ranges(line: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = None;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        let beginning = start.is_none();
        if beginning {
            if ch.is_whitespace() {
                continue;
            }
            start = Some(index);
        }
        if escaped {
            escaped = false;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
        } else if quote == Some(ch) {
            quote = None;
        } else if beginning && matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if quote.is_none() && ch.is_whitespace() {
            ranges.push(start.take().unwrap()..index);
        }
    }
    if let Some(start) = start {
        ranges.push(start..line.len());
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_policy_respects_output_destination_and_user_preferences() {
        let text = OsStr::new("1");
        assert!(permits_color(true, None, None, None));
        assert!(!permits_color(false, None, None, None));
        assert!(!permits_color(true, Some(text), None, None));
        assert!(!permits_color(true, None, Some(OsStr::new("dumb")), None));
        assert!(!permits_color(true, None, None, Some(OsStr::new("0"))));
        assert!(permits_color(true, Some(OsStr::new("")), None, None));
    }

    #[test]
    fn example_highlighting_preserves_quoted_unicode_and_spacing() {
        let example = "  sudo delegated-sudo grant create 'Мій грант' --ttl 30d --dir '/srv/my app' --recursive --allow-args -- docker compose up -d\n";
        assert_eq!(Theme::plain().help(example), example);
        let output = Theme::new(true).help(example);
        assert!(output.contains("\x1b[1;36mdelegated-sudo\x1b[0m"));
        assert!(output.contains("\x1b[1;35m'Мій грант'\x1b[0m"));
        assert!(output.contains("\x1b[33m--allow-args\x1b[0m"));
        assert!(output.contains("\x1b[94m'/srv/my app'\x1b[0m"));
        let mut plain = output;
        for role in [
            Role::Command,
            Role::Name,
            Role::Option,
            Role::Path,
            Role::Value,
        ] {
            plain = plain.replace(&format!("\x1b[{}m", role.code()), "");
        }
        assert_eq!(plain.replace("\x1b[0m", ""), example);
    }
}
