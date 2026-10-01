//! An exact grant authorizes only its complete ordered argument vector.

use crate::Result;
use crate::harness::{Harness, PROBE, check, denied, succeeded};
use serde_json::{Value, json};
use std::fs;
use std::io;

pub(crate) fn commands(harness: &Harness) -> Result<()> {
    let id = harness.create_command(&["id", "-u"], "60m")?;
    check(
        succeeded(harness.cli(&["exec", "id", "-u"], false, Some(&id.token))?)?.trim() == "0",
        "exact id invocation did not run as root",
    )?;
    // -g is a valid invocation that the target would accept.
    denied(harness.cli(&["exec", "id", "-g"], false, Some(&id.token))?)?;
    let pinned = fs::canonicalize("/run/current-system/sw/bin/id")?;
    let pinned = pinned
        .to_str()
        .ok_or_else(|| io::Error::other("invalid canonical id path"))?;
    check(
        succeeded(harness.cli(&["exec", pinned, "-u"], false, Some(&id.token))?)?.trim() == "0",
        "canonical Nix multicall path did not execute the granted id applet",
    )?;

    let probe = harness.create_command(&[PROBE, "--probe", "first", "second", ""], "60m")?;
    let output = succeeded(harness.cli(
        &["exec", PROBE, "--probe", "first", "second", ""],
        false,
        Some(&probe.token),
    )?)?;
    let report: Value = serde_json::from_str(&output)?;
    check(
        report["args"] == json!(["first", "second", ""]),
        "exact vector lost order or empty arguments",
    )?;
    for arguments in [
        vec!["exec", PROBE, "--probe", "second", "first", ""],
        vec!["exec", PROBE, "--probe", "first", "second", "", "extra"],
        vec!["exec", PROBE, "--probe", "first", "second"],
    ] {
        denied(harness.cli(&arguments, false, Some(&probe.token))?)?;
    }
    Ok(())
}
