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
    match application::create_grant(store, allowed(), 60, timestamp).unwrap() {
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
        ("7d", policy::MAX_TTL),
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
        "8d",
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
        store.saved_hash(&grant.id),
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
fn extension_is_additive_and_never_revives_grants() {
    let store = storage::Store::in_memory();
    let (grant, _) = create(&store, 1000.0);
    let extend = |ttl: &str, timestamp| {
        application::dispatch(
            &store,
            Request::Extend {
                id: grant.id.clone(),
                ttl: ttl.into(),
            },
            timestamp,
        )
    };
    match extend("30s", 1010.0).unwrap() {
        AdminResponse::Grant(grant) => assert_eq!(grant.expires_at, 1090.0),
        _ => panic!("unexpected extension result"),
    }
    assert!(extend("7d", 1010.0).is_err());
    assert!(extend("30s", 1090.0).is_err());
    application::dispatch(
        &store,
        Request::Revoke {
            id: grant.id.clone(),
        },
        1010.0,
    )
    .unwrap();
    assert!(extend("30s", 1010.0).is_err());
    assert!(policy::authorize(&store.find(&grant.id).unwrap(), "id", &[], 1010.0).is_err());
}

#[test]
fn list_paginates_without_losing_or_repeating_records() {
    let store = storage::Store::in_memory();
    for _ in 0..205 {
        create(&store, 1000.0);
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
            assert!(ids.insert(grant.id));
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
    assert!(application::create_grant(&store, commands, 60, 1000.0).is_err());
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
