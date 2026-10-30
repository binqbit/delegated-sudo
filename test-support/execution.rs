//! Root execution, input/output preservation, and executable boundary checks.

use crate::Result;
use crate::harness::{Harness, PROBE, SecretGrant, check, denied, succeeded};
use crate::storage::row;
use nix::unistd::{Gid, Uid, chown};
use serde_json::{Value, json};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;

pub(crate) fn execution(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    check(
        succeeded(harness.cli(&["exec", "id", "-u"], false, Some(&grant.token))?)?.trim() == "0",
        "delegated command did not run as root",
    )?;
    let input = b"stdin reaches the command\n";
    check(
        succeeded(harness.cli_with(&["exec", "cat"], false, Some(&grant.token), input, &[])?)?
            .as_bytes()
            == input,
        "token transport consumed command stdin",
    )?;
    let environment = [
        ("PATH", "/home/agent/fake-bin:/run/current-system/sw/bin"),
        ("HOME", "/home/agent"),
        ("LD_PRELOAD", "/nonexistent-user-library.so"),
        ("BASH_ENV", "/home/agent/untrusted-shell-init"),
        ("DELEGATED_TEST_UNTRUSTED", "must not reach root"),
    ];
    let output = harness.cli_with(
        &["exec", PROBE, "--probe", "argument with spaces"],
        false,
        Some(&grant.token),
        b"",
        &environment,
    )?;
    check(
        String::from_utf8_lossy(&output.stderr).contains("probe stderr"),
        "command stderr was not preserved",
    )?;
    let report: Value = serde_json::from_str(&succeeded(output)?)?;
    check(
        report["uid"] == 0 && report["gid"] == 0,
        "command identity is not root",
    )?;
    check(
        report["groups"]
            .as_array()
            .is_some_and(|groups| groups.iter().all(|group| group == 0)),
        "client supplementary groups reached the root command",
    )?;
    check(
        report["cwd"].as_str() == harness.agent.home.to_str(),
        "working directory was not preserved",
    )?;
    check(
        report["args"] == json!(["argument with spaces"]),
        "command arguments were changed",
    )?;
    check(report["env"]["HOME"] == "/root", "root HOME was not set")?;
    for variable in ["LD_PRELOAD", "BASH_ENV", "DELEGATED_TEST_UNTRUSTED"] {
        check(
            report["env"].get(variable).is_none(),
            "untrusted client environment reached root",
        )?;
    }
    let output = harness.cli(
        &["exec", PROBE, "--probe", "--fail"],
        false,
        Some(&grant.token),
    )?;
    check(
        output.status.code() == Some(37),
        "command exit status was not preserved",
    )?;
    Ok(())
}

pub(crate) fn denials(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    denied(harness.cli(
        &["exec", "id", "-u"],
        false,
        Some(&format!("dst_{}", "a".repeat(64))),
    )?)?;
    let fake_bin = harness.agent.home.join("fake-bin");
    fs::create_dir_all(&fake_bin)?;
    chown(
        &fake_bin,
        Some(Uid::from_raw(harness.agent.uid)),
        Some(Gid::from_raw(harness.agent.gid)),
    )?;
    let fake_id = fake_bin.join("id");
    fs::copy(std::env::current_exe()?, &fake_id)?;
    fs::set_permissions(&fake_id, fs::Permissions::from_mode(0o755))?;
    chown(
        &fake_id,
        Some(Uid::from_raw(harness.agent.uid)),
        Some(Gid::from_raw(harness.agent.gid)),
    )?;
    let path = format!("{}:/run/current-system/sw/bin", fake_bin.display());
    check(
        succeeded(harness.cli_with(
            &["exec", "id", "-u"],
            false,
            Some(&grant.token),
            b"",
            &[("PATH", &path)],
        )?)?
        .trim()
            == "0",
        "client PATH changed the granted executable",
    )?;
    let fake_id = fake_id
        .to_str()
        .ok_or_else(|| io::Error::other("invalid fixture path"))?;
    denied(harness.cli(&["exec", fake_id, "--probe"], false, Some(&grant.token))?)?;
    for command in [fake_id, "delegated-sudo"] {
        denied(harness.cli(
            &[
                "grant",
                "create",
                "rejected-executable",
                "--commands",
                command,
                "--ttl",
                "60m",
            ],
            true,
            None,
        )?)?;
    }
    let stored = row(grant)?;
    // Use valid token syntax so rejection exercises credential verification.
    let hash_as_token = format!("dst_{}", stored.token_hash);
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&hash_as_token))?)
}
