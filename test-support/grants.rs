//! Black-box grant administration, expiration, listing and revocation checks.

use crate::Result;
use crate::harness::{Harness, SecretGrant, check, denied, succeeded};
use crate::storage::row;
use std::collections::HashSet;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn administration(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    for arguments in [vec!["grant", "list"], vec!["grant", "show", &grant.id]] {
        let output = succeeded(harness.cli(&arguments, true, None)?)?;
        check(
            output.contains(&grant.id),
            "administrative output omitted the grant",
        )?;
        check(
            !output.contains(&grant.token),
            "administrative inspection disclosed a token",
        )?;
    }
    for arguments in [
        vec!["grant", "create", "--commands", "sh", "--ttl", "60m"],
        vec!["grant", "show", &grant.id],
    ] {
        denied(harness.cli(&arguments, false, None)?)?;
    }
    denied(harness.cli_with(
        &["grant", "create", "--commands", "sh", "--ttl", "60m"],
        false,
        None,
        b"",
        &[("SUDO_UID", "0"), ("SUDO_USER", "root")],
    )?)?;
    Ok(())
}

pub(crate) fn expiration_and_extension(harness: &Harness) -> Result<()> {
    let extended = harness.create("id", "2s")?;
    let original_deadline = row(&extended)?.expires_at;
    succeeded(harness.cli(
        &["grant", "extend", &extended.id, "--ttl", "60m"],
        true,
        None,
    )?)?;
    let expired = harness.create("id", "1s")?;
    check(
        succeeded(harness.cli(&["exec", "id", "-u"], false, Some(&expired.token))?)?.trim() == "0",
        "short-lived grant failed before its expiration",
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
    let remaining = original_deadline.max(row(&expired)?.expires_at) - now;
    check(
        remaining <= 2.0,
        "expiration fixture exceeds its time bound",
    )?;
    thread::sleep(Duration::from_secs_f64(remaining.max(0.0) + 0.05));
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&expired.token))?)?;
    check(
        succeeded(harness.cli(&["exec", "id", "-u"], false, Some(&extended.token))?)?.trim() == "0",
        "extended grant stopped working at its original expiration",
    )
}

pub(crate) fn listing(harness: &Harness) -> Result<()> {
    let mut expected = HashSet::new();
    for _ in 0..105 {
        expected.insert(harness.create("id", "60m")?.id);
    }
    let output = succeeded(harness.cli(&["grant", "list"], true, None)?)?;
    let ids: Vec<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("Grant ID: "))
        .collect();
    let unique: HashSet<_> = ids.iter().copied().collect();
    check(ids.len() == unique.len(), "grant listing repeated an entry")?;
    check(
        expected.iter().all(|id| unique.contains(id.as_str())),
        "grant listing omitted entries after the first page",
    )
}

pub(crate) fn revocation(harness: &Harness, grant: &SecretGrant) -> Result<()> {
    succeeded(harness.cli(&["grant", "revoke", &grant.id], true, None)?)?;
    denied(harness.cli(&["exec", "id", "-u"], false, Some(&grant.token))?)
}
