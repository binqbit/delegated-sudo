//! Explicit argument-prefix grants open only the suffix after a fixed command.

use crate::Result;
use crate::harness::{Harness, PROBE, check, denied, succeeded};
use serde_json::{Value, json};

pub(crate) fn command(harness: &Harness) -> Result<()> {
    let grant = Harness::creation_response(succeeded(harness.cli(
        &[
            "grant",
            "create",
            "explicit-prefix",
            "--ttl",
            "60m",
            "--allow-args",
            "--",
            PROBE,
            "--probe",
            "first",
            "second",
        ],
        true,
        None,
    )?)?)?;
    for suffix in [vec![], vec!["more words", "", "last"]] {
        let mut arguments = vec!["exec", PROBE, "--probe", "first", "second"];
        arguments.extend_from_slice(&suffix);
        let output = succeeded(harness.cli(&arguments, false, Some(&grant.token))?)?;
        let report: Value = serde_json::from_str(&output)?;
        let mut expected = vec!["first", "second"];
        expected.extend_from_slice(&suffix);
        check(
            report["args"] == json!(expected),
            "permitted prefix suffix was altered or rejected",
        )?;
    }
    // The probe itself accepts these arguments. They must fail because the
    // required prefix was omitted or reordered.
    for arguments in [
        vec!["exec", PROBE, "--probe", "first"],
        vec!["exec", PROBE, "--probe", "second", "first"],
    ] {
        denied(harness.cli(&arguments, false, Some(&grant.token))?)?;
    }
    denied(harness.cli(
        &["exec", PROBE, "--probe", "first", "second", "$(whoami)"],
        false,
        Some(&grant.token),
    )?)
}
