//! Working-directory grants exercised through the installed CLI and real sudo.

use crate::Result;
use crate::harness::{Harness, PROBE, SecretGrant, check, denied, succeeded};
use crate::storage::row;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

fn in_directory(harness: &Harness, directory: &Path) -> Harness {
    let mut located = harness.clone();
    located.agent.home = directory.to_owned();
    located
}

fn create(harness: &Harness, name: &str, directory: &str, recursive: bool) -> Result<SecretGrant> {
    let mut arguments = vec!["grant", "create", name, "--ttl", "60m", "--dir", directory];
    if recursive {
        arguments.push("--recursive");
    }
    arguments.extend(["--", "id", "-u"]);
    Harness::creation_response(succeeded(harness.cli(&arguments, true, None)?)?)
}

fn executes(harness: &Harness, grant: &SecretGrant, directory: &Path) -> Result<()> {
    let located = in_directory(harness, directory);
    check(
        succeeded(located.cli(&["exec", "id", "-u"], false, Some(&grant.token))?)?.trim() == "0",
        "directory grant did not execute in an authorized working directory",
    )
}

fn rejects(harness: &Harness, grant: &SecretGrant, directory: &Path) -> Result<()> {
    let located = in_directory(harness, directory);
    denied(located.cli(&["exec", "id", "-u"], false, Some(&grant.token))?)
}

pub(crate) fn restrictions(harness: &Harness) -> Result<()> {
    let fixture = harness.agent.home.join("directory-grants");
    fs::create_dir(&fixture)?;
    let root = fixture.join("project");
    let nested = root.join("nested");
    let sibling = fixture.join("project-other");
    let outside = fixture.join("outside");
    fs::create_dir(&root)?;
    fs::create_dir(&nested)?;
    fs::create_dir(&sibling)?;
    fs::create_dir(&outside)?;
    let root_text = root.to_str().ok_or("invalid directory fixture path")?;

    let exact = create(harness, "directory-exact", root_text, false)?;
    executes(harness, &exact, &root)?;
    rejects(harness, &exact, &nested)?;
    rejects(harness, &exact, &outside)?;
    let exact_alias = fixture.join("alias-root");
    symlink(&root, &exact_alias)?;
    executes(harness, &exact, &exact_alias)?;

    let relative = create(
        &in_directory(harness, &fixture),
        "directory-relative",
        "project",
        false,
    )?;
    executes(harness, &relative, &root)?;
    rejects(harness, &relative, &fixture)?;
    rejects(harness, &relative, &nested)?;

    let tree = create(harness, "directory-tree", root_text, true)?;
    executes(harness, &tree, &root)?;
    executes(harness, &tree, &nested)?;
    rejects(harness, &tree, &sibling)?;
    rejects(harness, &tree, &outside)?;
    rejects(harness, &tree, &root.join("../outside"))?;
    let legacy = create(
        harness,
        "directory-legacy",
        &format!("{root_text}/*"),
        false,
    )?;
    executes(harness, &legacy, &nested)?;
    rejects(harness, &legacy, &outside)?;
    denied(in_directory(harness, &outside).cli_with(
        &["exec", "id", "-u"],
        false,
        Some(&tree.token),
        b"",
        &[("PWD", root_text)],
    )?)?;

    let alias = fixture.join("alias-inside");
    symlink(&nested, &alias)?;
    executes(harness, &tree, &alias)?;
    let escape = root.join("alias-outside");
    symlink(&outside, &escape)?;
    rejects(harness, &tree, &escape)?;

    let probe = Harness::creation_response(succeeded(harness.cli(
        &[
            "grant",
            "create",
            "directory-cwd-probe",
            "--ttl",
            "60m",
            "--dir",
            root_text,
            "--recursive",
            "--",
            PROBE,
            "--probe",
        ],
        true,
        None,
    )?)?)?;
    for directory in [&nested, &alias] {
        let output = succeeded(in_directory(harness, directory).cli(
            &["exec", PROBE, "--probe"],
            false,
            Some(&probe.token),
        )?)?;
        let report: serde_json::Value = serde_json::from_str(&output)?;
        check(
            report["uid"] == 0 && report["cwd"] == serde_json::json!(fs::canonicalize(&nested)?),
            "directory-restricted execution changed the authorized working directory",
        )?;
    }

    let unrestricted = harness.create_command(&["id", "-u"], "60m")?;
    for directory in [&root, &nested, &outside, &sibling] {
        executes(harness, &unrestricted, directory)?;
    }

    let stored = row(&tree)?;
    let renewed = Harness::creation_response(succeeded(harness.cli(
        &["grant", "extend", &tree.name, "--ttl", "1d"],
        true,
        None,
    )?)?)?;
    check(
        renewed.name == tree.name && renewed.token != tree.token,
        "directory-restricted renewal did not preserve the name and rotate the token",
    )?;
    check(
        row(&renewed)?.allowed_executables == stored.allowed_executables
            && row(&renewed)?.directory == stored.directory
            && stored.directory.is_some(),
        "directory-restricted renewal changed the command or working directory scope",
    )?;
    rejects(harness, &tree, &root)?;
    executes(harness, &renewed, &root)?;
    executes(harness, &renewed, &nested)?;
    rejects(harness, &renewed, &outside)?;

    // Holding the old directory under a different name prevents inode reuse.
    let moved = fixture.join("original-project");
    fs::rename(&root, &moved)?;
    fs::create_dir(&root)?;
    fs::create_dir(&nested)?;
    rejects(harness, &exact, &root)?;
    rejects(harness, &renewed, &root)?;
    rejects(harness, &renewed, &nested)?;
    rejects(harness, &exact, &moved)?;
    rejects(harness, &renewed, &moved.join("nested"))?;
    executes(harness, &unrestricted, &root)?;

    let file = fixture.join("regular-file");
    fs::write(&file, b"not a directory")?;
    for invalid in [fixture.join("missing"), file] {
        let invalid = invalid.to_str().ok_or("invalid directory fixture path")?;
        denied(harness.cli(
            &[
                "grant",
                "create",
                "directory-invalid",
                "--ttl",
                "60m",
                "--dir",
                invalid,
                "--",
                "id",
                "-u",
            ],
            true,
            None,
        )?)?;
        denied(harness.cli(&["grant", "show", "directory-invalid"], true, None)?)?;
    }
    denied(harness.cli(
        &[
            "grant",
            "create",
            "directory-empty-recursive",
            "--ttl",
            "60m",
            "--dir",
            "",
            "--recursive",
            "--",
            "id",
            "-u",
        ],
        true,
        None,
    )?)?;
    denied(harness.cli(&["grant", "show", "directory-empty-recursive"], true, None)?)?;
    Ok(())
}
