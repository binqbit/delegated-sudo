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
    // Both supported administrative paths must honor the existing session.
    let store_path = std::fs::canonicalize(CLI)?;
    let store_path = store_path
        .to_str()
        .ok_or("installed executable path is not UTF-8")?;
    for path in [CLI, store_path] {
        let output =
            succeeded(harness.sudo(&harness.admin, &["-n", "--", path, "grant", "list"], b"")?)?;
        check(
            output.contains(&grant.name),
            "cached sudo credentials did not authorize grant management",
        )?;
    }
    let created = Harness::creation_response(succeeded(harness.sudo(
        &harness.admin,
        &[
            "-n",
            "--",
            CLI,
            "grant",
            "create",
            "sudo-cache",
            "--ttl",
            "1m",
            "--",
            "id",
        ],
        b"",
    )?)?)?;
    let renewed = Harness::creation_response(succeeded(harness.sudo(
        &harness.admin,
        &[
            "-n",
            "--",
            CLI,
            "grant",
            "extend",
            &created.name,
            "--ttl",
            "1m",
        ],
        b"",
    )?)?)?;
    check(
        renewed.name == created.name && renewed.token != created.token,
        "cached sudo grant renewal did not preserve the name and rotate the token",
    )?;
    succeeded(harness.sudo(
        &harness.admin,
        &["-n", "--", CLI, "grant", "delete", &created.name],
        b"",
    )?)?;
    // Password authentication is still required when no cached session exists.
    succeeded(harness.sudo(&harness.admin, &["-k"], b"")?)?;
    denied(harness.sudo(&harness.admin, &["-n", "--", CLI, "grant", "list"], b"")?)?;
    let output = succeeded(harness.sudo(
        &harness.admin,
        &["-S", "-p", "", "--", CLI, "grant", "list"],
        ADMIN_PASSWORD.as_bytes(),
    )?)?;
    check(
        output.contains(&grant.name),
        "ordinary password-authenticated sudo did not administer grants",
    )?;
    // Authenticating for a grant also establishes a normal reusable session.
    succeeded(harness.sudo(&harness.admin, &["-n", "--", CLI, "grant", "list"], b"")?)?;
    succeeded(harness.sudo(
        &harness.admin,
        &["-n", "--", "/run/current-system/sw/bin/true"],
        b"",
    )?)?;
    Ok(())
}
