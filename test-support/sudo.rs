//! Exercise ordinary sudo passwords, cached timestamps, and token-only access.

use crate::Result;
use crate::harness::{CLI, Harness, SecretGrant, check, denied, succeeded};

const ADMIN_PASSWORD: &str = "vm-admin-password\n";

pub(crate) fn sudo_boundary(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    denied(harness.sudo(
        &harness.agent,
        &["-n", "-k", "--", CLI, "grant", "list"],
        b"",
    )?)?;
    denied(harness.sudo(
        &harness.agent,
        &[
            "-n",
            "-k",
            "--",
            "/run/current-system/sw/bin/sh",
            "-c",
            "exit 0",
        ],
        b"",
    )?)?;
    // Establish a real normal-sudo cache and prove it works for other commands.
    // Reset separately: sudo -k with a command intentionally does not refresh
    // the credential cache, so it cannot establish the condition being tested.
    succeeded(harness.sudo(&harness.admin, &["-k"], b"")?)?;
    succeeded(harness.sudo(
        &harness.admin,
        &["-S", "-p", "", "--", "/run/current-system/sw/bin/true"],
        ADMIN_PASSWORD.as_bytes(),
    )?)?;
    succeeded(harness.sudo(
        &harness.admin,
        &["-n", "--", "/run/current-system/sw/bin/true"],
        b"",
    )?)?;
    let cached_attempt = harness.sudo(&harness.admin, &["-n", "--", CLI, "grant", "list"], b"")?;
    check(
        !cached_attempt.status.success(),
        "cached ordinary-sudo timestamp authorized grant management without a fresh password",
    )?;
    denied(cached_attempt)?;
    let output = succeeded(harness.sudo(
        &harness.admin,
        &["-S", "-p", "", "--", CLI, "grant", "list"],
        ADMIN_PASSWORD.as_bytes(),
    )?)?;
    check(
        output.contains(&grant.id),
        "ordinary password-authenticated sudo did not administer grants",
    )?;
    let second_attempt = harness.sudo(&harness.admin, &["-n", "--", CLI, "grant", "list"], b"")?;
    check(
        !second_attempt.status.success(),
        "grant management reused authentication from the preceding administrative invocation",
    )?;
    denied(second_attempt)
}
