//! Black-box named-grant administration, expiration, renewal and deletion.

use crate::Result;
use crate::harness::{Harness, SecretGrant, check, denied, succeeded};
use crate::storage::row;
use std::collections::HashSet;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now() -> Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}

fn executes(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    check(
        succeeded(harness.cli(&["exec", "id", "-u"], false, Some(&grant.token))?)?.trim() == "0",
        "named grant did not execute its permitted command as root",
    )
}

pub(crate) fn administration(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    for arguments in [vec!["grant", "list"], vec!["grant", "show", &grant.name]] {
        let output = succeeded(harness.cli(&arguments, true, None)?)?;
        check(
            output.contains(&grant.name),
            "administrative output omitted the grant name",
        )?;
        check(
            !output.contains(&grant.token),
            "administrative inspection disclosed a token",
        )?;
    }
    for arguments in [
        vec![
            "grant",
            "create",
            "unauthorized",
            "--commands",
            "sh",
            "--ttl",
            "60m",
        ],
        vec!["grant", "show", &grant.name],
    ] {
        denied(harness.cli(&arguments, false, None)?)?;
    }
    denied(harness.cli_with(
        &[
            "grant",
            "create",
            "spoofed-root",
            "--commands",
            "sh",
            "--ttl",
            "60m",
        ],
        false,
        None,
        b"",
        &[("SUDO_UID", "0"), ("SUDO_USER", "root")],
    )?)?;
    Ok(())
}

fn renew(harness: &Harness, grant: &SecretGrant, ttl: &str, seconds: f64) -> Result<SecretGrant> {
    let original = row(grant)?;
    let before = now()?;
    let renewed = Harness::creation_response(succeeded(harness.cli(
        &["grant", "extend", &grant.name, "--ttl", ttl],
        true,
        None,
    )?)?)?;
    let after = now()?;
    let stored = row(&renewed)?;
    check(renewed.name == grant.name, "renewal changed the grant name")?;
    check(
        renewed.token != grant.token,
        "renewal did not rotate the token",
    )?;
    check(
        stored.expires_at >= before + seconds && stored.expires_at <= after + seconds,
        "renewal did not set the expiration from the current time",
    )?;
    check(
        stored.created_at == original.created_at
            && stored.allowed_executables == original.allowed_executables,
        "renewal changed grant identity or command permissions",
    )?;
    check(
        stored.token_hash != original.token_hash,
        "renewal kept the previous token hash",
    )?;
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&grant.token))?)?;
    executes(harness, &renewed)?;
    Ok(renewed)
}

pub(crate) fn expiration_and_extension(harness: &Harness) -> Result<()> {
    // A long active lifetime makes adding to the previous deadline observably
    // different from resetting it to one hour from the current time.
    let active = harness.create("id", "30d")?;
    let renewed = renew(harness, &active, "60m", 3600.0)?;
    let stored = row(&renewed)?;
    denied(harness.cli(
        &["grant", "extend", &renewed.name, "--ttl", "31d"],
        true,
        None,
    )?)?;
    check(
        row(&renewed)?.token_hash == stored.token_hash
            && row(&renewed)?.expires_at == stored.expires_at,
        "rejected renewal modified the grant",
    )?;
    executes(harness, &renewed)?;
    denied(harness.cli(
        &[
            "grant",
            "create",
            "too-long",
            "--commands",
            "id",
            "--ttl",
            "31d",
        ],
        true,
        None,
    )?)?;

    let expired = harness.create("id", "1s")?;
    let remaining = row(&expired)?.expires_at - now()?;
    check(
        remaining <= 1.0,
        "expiration fixture exceeds its time bound",
    )?;
    thread::sleep(Duration::from_secs_f64(remaining.max(0.0) + 0.05));
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&expired.token))?)?;
    check(
        succeeded(harness.cli(&["grant", "show", &expired.name], true, None)?)?
            .contains("Status: expired"),
        "expired grant was not marked expired",
    )?;
    let renewed_expired = renew(harness, &expired, "30d", 30.0 * 86400.0)?;
    revocation(harness, &renewed_expired)?;
    denied(harness.cli(
        &["grant", "extend", &renewed_expired.name, "--ttl", "1d"],
        true,
        None,
    )?)?;
    Ok(())
}

pub(crate) fn names_and_deletion(harness: &Harness) -> Result<()> {
    denied(harness.cli(
        &["grant", "create", "--commands", "id", "--ttl", "60m"],
        true,
        None,
    )?)?;
    denied(harness.cli(
        &["grant", "create", "missing-command", "--ttl", "60m"],
        true,
        None,
    )?)?;
    denied(harness.cli(&["grant", "show", "missing-command"], true, None)?)?;
    let name = "Docker Compose Кодекс";
    let grant = harness.create_named(name, "id", "30d")?;
    check(
        grant.name == name,
        "creation changed the user-supplied name",
    )?;
    denied(harness.cli(
        &["grant", "create", name, "--commands", "cat", "--ttl", "60m"],
        true,
        None,
    )?)?;
    executes(harness, &grant)?;
    succeeded(harness.cli(&["grant", "delete", name], true, None)?)?;
    denied(harness.cli(&["grant", "show", name], true, None)?)?;
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&grant.token))?)?;
    denied(harness.cli(&["grant", "delete", name], true, None)?)?;
    let replacement = harness.create_named(name, "id", "1s")?;
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&grant.token))?)?;
    let remaining = row(&replacement)?.expires_at - now()?;
    thread::sleep(Duration::from_secs_f64(remaining.max(0.0) + 0.05));
    succeeded(harness.cli(&["grant", "delete", name], true, None)?)?;
    denied(harness.cli(&["grant", "show", name], true, None)?)?;
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&replacement.token))?)?;
    Ok(())
}

pub(crate) fn listing(harness: &Harness) -> Result<()> {
    let mut expected = HashSet::new();
    for _ in 0..105 {
        expected.insert(harness.create("id", "60m")?.name);
    }
    let output = succeeded(harness.cli(&["grant", "list"], true, None)?)?;
    for name in expected {
        let occurrences = output
            .split_whitespace()
            .filter(|word| *word == name)
            .count();
        check(
            occurrences == 1,
            "grant listing omitted or repeated a named entry",
        )?;
    }
    Ok(())
}

pub(crate) fn revocation(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    succeeded(harness.cli(&["grant", "revoke", &grant.name], true, None)?)?;
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&grant.token))?)
}
