//! Argument-policy tests are independent of root privileges and installed tools.
use crate::model::{AdminResponse, AllowedExecutable, ArgumentPolicy};
use crate::policy::{self, StoredGrant};
use crate::{application, input_policy, storage};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}
fn record(argument_policy: ArgumentPolicy) -> StoredGrant {
    StoredGrant {
        name: "docker-test".into(),
        allowed_executables: vec![AllowedExecutable {
            name: "docker".into(),
            path: "/nix/store/example/bin/docker".into(),
            argument_policy,
        }],
        directory: None,
        created_at: 1000.0,
        expires_at: 1060.0,
        revoked: false,
    }
}
fn accepts(record: &StoredGrant, arguments: &[String]) -> bool {
    input_policy::invocation("docker", arguments).is_ok()
        && policy::authorize(record, "docker", arguments, 1001.0).is_ok()
}

#[test]
fn exact_policy_requires_the_complete_vector_without_normalization() {
    let expected = args(&["compose", "up", "-d"]);
    let grant = record(ArgumentPolicy::Exact(expected.clone()));
    assert!(accepts(&grant, &expected));
    assert!(policy::authorize(&grant, "/nix/store/example/bin/docker", &expected, 1001.0).is_ok());
    for denied in [
        &[][..],
        &["compose", "up"],
        &["compose", "up", "--detach"],
        &["compose", "down", "-d"],
        &["compose", "up", "-d", "--build"],
        &["compose", "-d", "up"],
        &["compose up", "-d"],
        &["compose", "up", "-d", ""],
    ] {
        assert!(
            !accepts(&grant, &args(denied)),
            "unexpected match: {denied:?}"
        );
    }
}

#[test]
fn exact_empty_arguments_and_argument_boundaries_are_preserved() {
    let empty = record(ArgumentPolicy::Exact(Vec::new()));
    assert!(accepts(&empty, &[]));
    assert!(!accepts(&empty, &args(&[""])));
    let boundaries = record(ArgumentPolicy::Exact(args(&["a b", "c", ""])));
    assert!(accepts(&boundaries, &args(&["a b", "c", ""])));
    assert!(!accepts(&boundaries, &args(&["a", "b c", ""])));
    assert!(!accepts(&boundaries, &args(&["a b", "c"])));
}

#[test]
fn embedded_and_nonterminal_asterisks_do_not_expand_permissions() {
    for literal in [
        args(&["*.yml"]),
        args(&["*", "literal"]),
        args(&["--name=*"]),
    ] {
        let grant = record(policy::argument_policy(literal.clone()));
        assert!(accepts(&grant, &literal));
        let mut extra_arguments = literal;
        extra_arguments.push("extra".into());
        assert!(!accepts(&grant, &extra_arguments));
    }
}

#[test]
fn prefix_policy_allows_suffixes_but_never_changes_the_fixed_prefix() {
    let grant = record(policy::argument_policy(args(&["compose", "up", "-d", "*"])));
    for accepted in [
        args(&["compose", "up", "-d"]),
        args(&["compose", "up", "-d", "--build"]),
        args(&["compose", "up", "-d", "service", ""]),
    ] {
        assert!(accepts(&grant, &accepted));
    }
    for denied in [
        args(&["compose", "up"]),
        args(&["compose", "down", "-d"]),
        args(&["compose", "-d", "up"]),
        args(&["compose", "up", "-d", ";id"]),
    ] {
        assert!(!accepts(&grant, &denied));
    }
}

#[test]
fn shell_grammar_is_rejected_at_creation_and_execution_boundaries() {
    let forbidden = [
        ";",
        "a|b",
        "&&",
        "x&y",
        "<input",
        ">output",
        "`id`",
        "$(id)",
        "${HOME}",
        "a\nb",
        "a\rb",
        "a\tb",
        "nul\0",
        "\u{7f}",
        "\u{85}",
        "quoted';'literal",
        "escaped\\;",
    ];
    let store = storage::Store::in_memory();
    for value in forbidden {
        assert!(input_policy::executable(&format!("docker{value}")).is_err());
        for argument_policy in [
            ArgumentPolicy::Exact(args(&[value])),
            ArgumentPolicy::Prefix(args(&[value])),
        ] {
            assert!(
                application::create_grant(
                    &store,
                    "invalid".into(),
                    record(argument_policy).allowed_executables,
                    None,
                    60,
                    1000.0
                )
                .is_err()
            );
        }
        assert!(!accepts(&record(ArgumentPolicy::Any), &args(&[value])));
    }
    assert!(store.page(None).unwrap().is_empty());
    assert!(
        input_policy::invocation(
            "docker",
            &args(&[
                "",
                "a b",
                "українська",
                "*.yml",
                "$HOME",
                "'literal'",
                "\"literal\""
            ])
        )
        .is_ok()
    );
}

#[test]
fn persisted_argument_policies_keep_their_authorization_scope() {
    let store = storage::Store::in_memory();
    for (index, (mode, permitted, rejected)) in [
        (ArgumentPolicy::Any, args(&["compose", "down"]), None),
        (
            ArgumentPolicy::Exact(Vec::new()),
            Vec::new(),
            Some(args(&[""])),
        ),
        (
            ArgumentPolicy::Prefix(args(&["compose"])),
            args(&["compose", "up"]),
            Some(args(&["run"])),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let AdminResponse::Created { grant, .. } = application::create_grant(
            &store,
            format!("test-{index}"),
            record(mode).allowed_executables,
            None,
            60,
            1000.0,
        )
        .unwrap() else {
            panic!("unexpected creation result")
        };
        let saved = store.find(&grant.name).unwrap();
        assert!(accepts(&saved, &permitted));
        if let Some(rejected) = rejected {
            assert!(!accepts(&saved, &rejected));
        }
    }
}

#[test]
fn malformed_persisted_argument_policies_fail_closed() {
    for policy in [
        serde_json::json!({"mode": "unknown"}),
        serde_json::json!({"mode": "exact"}),
        serde_json::json!({"mode": "prefix", "arguments": "compose up"}),
        serde_json::json!({"mode": "exact", "arguments": [], "unexpected": true}),
        serde_json::Value::Null,
    ] {
        let executable = serde_json::json!({
            "name": "docker", "path": "/nix/store/example/bin/docker", "argument_policy": policy,
        });
        assert!(serde_json::from_value::<AllowedExecutable>(executable).is_err());
    }
}
