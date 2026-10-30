//! Tests across domain, persistence, and process boundaries.
use crate::model::{AdminResponse, AllowedExecutable, ArgumentPolicy, Grant, Request};
use crate::{application, credentials, execution, policy, storage};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

fn allowed() -> Vec<AllowedExecutable> {
    vec![AllowedExecutable {
        name: "id".into(),
        path: "/nix/store/example-coreutils/bin/id".into(),
        argument_policy: ArgumentPolicy::Any,
    }]
}
fn create(store: &storage::Store, timestamp: f64) -> (Grant, credentials::SecretToken) {
    match application::create_grant(
        store,
        format!("test-{}", timestamp),
        allowed(),
        60,
        timestamp,
    )
    .unwrap()
    {
        AdminResponse::Created { grant, token } => (grant, token),
        _ => panic!("unexpected creation result"),
    }
}

#[test]
fn ttl_validation_has_finite_bounds() {
    for (input, expected) in [
        ("1s", 1),
        ("60m", 3600),
        ("2h", 7200),
        ("30d", policy::MAX_TTL),
    ] {
        assert_eq!(policy::parse_ttl(input).unwrap(), expected);
    }
    for input in [
        "",
        "0s",
        "01m",
        "-1s",
        "+1s",
        "1.5h",
        "1 h",
        "1H",
        "31d",
        "2592001s",
        "999999999999999s",
        "яs",
    ] {
        assert!(
            policy::parse_ttl(input).is_err(),
            "unexpected valid TTL: {input}"
        );
    }
}

#[test]
fn grants_store_only_hashes_and_match_exact_executables() {
    let store = storage::Store::in_memory();
    let (grant, token) = create(&store, 1000.0);
    assert_eq!(
        store.saved_hash(&grant.name),
        credentials::lookup_hash(token.expose()).unwrap()
    );
    assert!(
        !serde_json::to_string(&grant)
            .unwrap()
            .contains(token.expose())
    );
    let record = store.find_hash(&token.hash()).unwrap().unwrap();
    for command in ["id", "/nix/store/example-coreutils/bin/id"] {
        assert!(policy::authorize(&record, command, &[], 1001.0).is_ok());
    }
    for command in ["/tmp/id", "./id", "/run/current-system/sw/bin/id", "sh"] {
        assert!(policy::authorize(&record, command, &[], 1001.0).is_err());
    }
    assert!(policy::authorize(&record, "id", &[], 1060.0).is_err());
    assert!(credentials::lookup_hash(&format!("{}x", token.expose())).is_err());
}

#[test]
fn renewal_rotates_tokens_and_sets_a_new_deadline_from_now() {
    let store = storage::Store::in_memory();
    let (original, mut old_token) = create(&store, 1000.0);
    let before = serde_json::to_string(&original.allowed_executables).unwrap();
    // Active renewal can shorten the remaining lifetime; renewal at/after expiry
    // revives the same named grant. Every renewal invalidates the previous token.
    for (timestamp, ttl, seconds) in [
        (1010.0, "1s", 1.0),
        (1011.0, "30d", policy::MAX_TTL as f64),
        (3_000_000.0, "60m", 3600.0),
    ] {
        let AdminResponse::Extended { grant, token } = application::dispatch(
            &store,
            Request::Extend {
                name: original.name.clone(),
                ttl: ttl.into(),
            },
            timestamp,
        )
        .unwrap() else {
            panic!("unexpected renewal result")
        };
        assert_eq!(grant.name, original.name);
        assert_eq!(grant.created_at, original.created_at);
        assert_eq!(
            serde_json::to_string(&grant.allowed_executables).unwrap(),
            before
        );
        assert_eq!(grant.expires_at, timestamp + seconds);
        assert!(grant.active);
        assert!(store.find_hash(&old_token.hash()).unwrap().is_none());
        let current = store.find_hash(&token.hash()).unwrap().unwrap();
        assert!(policy::authorize(&current, "id", &[], timestamp).is_ok());
        assert!(policy::authorize(&current, "id", &[], grant.expires_at).is_err());
        old_token = token;
    }
}

#[test]
fn invalid_renewal_leaves_the_token_and_deadline_unchanged() {
    let store = storage::Store::in_memory();
    let (grant, token) = create(&store, 1000.0);
    for name in [grant.name.as_str(), "missing"] {
        for ttl in ["0s", "31d", "invalid"] {
            assert!(
                application::dispatch(
                    &store,
                    Request::Extend {
                        name: name.into(),
                        ttl: ttl.into()
                    },
                    1010.0
                )
                .is_err()
            );
        }
    }
    assert_eq!(
        store.find(&grant.name).unwrap().expires_at,
        grant.expires_at
    );
    assert!(store.find_hash(&token.hash()).unwrap().is_some());
    application::dispatch(
        &store,
        Request::Revoke {
            name: grant.name.clone(),
        },
        1010.0,
    )
    .unwrap();
    assert!(
        application::dispatch(
            &store,
            Request::Extend {
                name: grant.name.clone(),
                ttl: "1d".into()
            },
            1010.0
        )
        .is_err()
    );
    assert_eq!(
        store.find(&grant.name).unwrap().expires_at,
        grant.expires_at
    );
    assert!(policy::authorize(&store.find(&grant.name).unwrap(), "id", &[], 1010.0).is_err());
}

#[test]
fn unique_names_are_required_and_duplicate_creation_preserves_the_original() {
    let store = storage::Store::in_memory();
    let (grant, token) = create(&store, 1000.0);
    let error = application::create_grant(&store, grant.name.clone(), allowed(), 100, 1100.0)
        .err()
        .unwrap();
    assert!(error.to_string().contains("already exists"));
    assert_eq!(
        store.find(&grant.name).unwrap().expires_at,
        grant.expires_at
    );
    assert!(store.find_hash(&token.hash()).unwrap().is_some());
    for name in [
        "",
        " ",
        "-option",
        " leading",
        "trailing ",
        "line\nbreak",
        "escape\x1b",
        "hidden\u{202e}",
    ] {
        assert!(application::create_grant(&store, name.into(), allowed(), 60, 1000.0).is_err());
    }
    assert!(policy::validate_name(&"a".repeat(81)).is_err());
    assert!(policy::validate_name(&"і".repeat(80)).is_ok());
    for name in [
        "Docker Compose Codex",
        "Розгортання",
        "O'Reilly",
        "Case",
        "case",
    ] {
        application::create_grant(&store, name.into(), allowed(), 60, 1000.0).unwrap();
        assert_eq!(store.find(name).unwrap().name, name);
    }
}

#[test]
fn deletion_removes_expired_or_active_grants_and_invalidates_tokens() {
    let store = storage::Store::in_memory();
    for timestamp in [1010.0, 2000.0] {
        let (grant, token) = create(&store, 1000.0);
        let response = application::dispatch(
            &store,
            Request::Delete {
                name: grant.name.clone(),
            },
            timestamp,
        )
        .unwrap();
        assert!(matches!(response, AdminResponse::Deleted { name } if name == grant.name));
        assert!(store.find(&grant.name).is_err());
        assert!(store.find_hash(&token.hash()).unwrap().is_none());
        assert!(
            application::dispatch(&store, Request::Delete { name: grant.name }, timestamp).is_err()
        );
        assert!(store.page(None).unwrap().is_empty());
    }
}

#[test]
fn list_paginates_without_losing_or_repeating_records() {
    let store = storage::Store::in_memory();
    for index in 0..205 {
        application::create_grant(&store, format!("test-{index}"), allowed(), 60, 1000.0).unwrap();
    }
    let mut cursor = None;
    let mut ids = std::collections::HashSet::new();
    loop {
        let AdminResponse::List {
            grants,
            next_cursor,
        } = application::list_grants(&store, cursor.as_deref(), 1000.0).unwrap()
        else {
            panic!("unexpected list result")
        };
        for grant in grants {
            assert!(ids.insert(grant.name));
        }
        cursor = next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(ids.len(), 205);
}

#[test]
fn oversized_grant_is_rejected_before_persistence() {
    let store = storage::Store::in_memory();
    let commands = vec![AllowedExecutable {
        name: "id".into(),
        path: "/nix/store/example-coreutils/bin/id".into(),
        argument_policy: ArgumentPolicy::Exact(vec!["x".repeat(64 * 1024)]),
    }];
    assert!(application::create_grant(&store, "oversized".into(), commands, 60, 1000.0).is_err());
    assert!(store.page(None).unwrap().is_empty());
}

#[test]
fn exclusive_lock_blocks_shared_access_until_the_owner_closes() {
    // SAFETY: memfd_create returns a fresh anonymous descriptor for this test.
    let raw =
        unsafe { libc::memfd_create(c"delegated-sudo-lock-test".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(raw >= 0);
    let first = unsafe { File::from_raw_fd(raw) };
    let second = OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/self/fd/{}", first.as_raw_fd()))
        .unwrap();
    storage::lock_exclusive(&first).unwrap();
    assert_eq!(
        unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
        -1
    );
    assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
    drop(first);
    assert_eq!(
        unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
        0
    );
}

#[test]
#[ignore = "subprocess fixture invoked by execution_preserves_granted_argv0_and_sanitizes_environment_and_fds"]
fn execution_child_probe() {
    assert_eq!(
        std::env::args_os().next().as_deref(),
        Some(OsStr::new("delegation-argv0-probe"))
    );
    for (key, expected) in [
        ("HOME", "/root"),
        ("USER", "root"),
        ("LOGNAME", "root"),
        ("LANG", "C.UTF-8"),
        ("PATH", "/run/current-system/sw/bin:/run/wrappers/bin"),
    ] {
        assert_eq!(std::env::var(key).unwrap(), expected);
    }
    assert_eq!(std::env::vars_os().count(), 5);
    assert!(fs::read_dir("/proc/self/fd").unwrap().all(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_str()
            .unwrap()
            .parse::<i32>()
            .unwrap()
            < 64
    }));
}

#[test]
fn execution_preserves_granted_argv0_and_sanitizes_environment_and_fds() {
    let file = File::open("/dev/null").unwrap();
    // SAFETY: duplicate a valid fd; adopt only its successful, fresh duplicate.
    let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 64) };
    assert!(raw >= 64);
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let allowed = AllowedExecutable {
        name: "delegation-argv0-probe".into(),
        path: std::env::current_exe().unwrap().to_str().unwrap().into(),
        argument_policy: ArgumentPolicy::Any,
    };
    let arguments = [
        "--exact",
        "backend_tests::execution_child_probe",
        "--ignored",
        "--nocapture",
    ]
    .map(str::to_owned);
    let output = execution::command(&allowed, &arguments).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    assert!(unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } >= 0);
}
