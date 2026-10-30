//! Representative CLI attempts to escape executable and shell-syntax policy.

use crate::Result;
use crate::harness::{CLI, Harness, PROBE, SecretGrant, check, denied};
use std::path::Path;

const MARKER: &str = "/run/delegated-sudo-unauthorized-command";

pub(crate) fn rejected_commands(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    check(
        !Path::new(MARKER).exists(),
        "unexpected injection fixture already exists",
    )?;
    // A command string must not be interpreted as a shell invocation.
    let injected = format!("id; touch {MARKER}");
    for command in [injected.as_str(), "id -u"] {
        denied(harness.cli(&["exec", command], false, Some(&grant.token))?)?;
    }
    check(
        !Path::new(MARKER).exists(),
        "shell command text executed through executable authorization",
    )?;

    // The probe would accept this literal argument and return success. Thus a
    // failure here comes from the CLI policy, not the target's argument parser.
    let argument = "safe;unsafe";
    denied(harness.cli(
        &["exec", PROBE, "--probe", argument],
        false,
        Some(&grant.token),
    )?)?;
    denied(harness.cli(
        &[
            "grant",
            "create",
            "rejected-injection",
            "--ttl",
            "60m",
            "--",
            PROBE,
            "--probe",
            argument,
        ],
        true,
        None,
    )?)?;

    // This valid administrative invocation would succeed if exec bypassed the
    // grant's executable restriction and launched delegated-sudo as root.
    denied(harness.cli(&["exec", CLI, "grant", "list"], false, Some(&grant.token))?)?;
    // id and touch may share one Nix coreutils binary; a bare ungranted applet
    // must still be rejected. Canonical id invocation is exercised in exact.rs.
    denied(harness.cli(&["exec", "touch", MARKER], false, Some(&grant.token))?)?;
    check(
        !Path::new(MARKER).exists(),
        "an ungranted executable created its marker",
    )
}
