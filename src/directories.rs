//! Initial working-directory restrictions, verified against open directory FDs.
//!
//! This is an invocation check, not a filesystem sandbox. The authorized cwd is
//! pinned through exec; later program actions or concurrent directory moves are
//! not confined. Mutable path traversal is checked by openat2, and any resolution
//! failure (including a rename race reported as EAGAIN) denies the invocation.

use crate::model::DirectoryScope;
use crate::policy::{GrantError, Result};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredDirectory {
    pub scope: DirectoryScope,
    pub device: u64,
    pub inode: u64,
}

fn validate_text(value: &str) -> Result<()> {
    if value.is_empty()
        || value.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
        })
    {
        return Err(GrantError(
            "Directory must be a nonempty path without control characters or invisible formatting",
        ));
    }
    Ok(())
}

fn open_directory(base: RawFd, path: &Path, resolve: u64) -> Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| GrantError("Invalid directory path"))?;
    // SAFETY: open_how contains integer fields and requires zero initialization
    // for forward compatibility. All reserved fields remain zero.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = resolve;
    // SAFETY: the C string and open_how are valid for the syscall. The kernel
    // validates the base descriptor and returns a fresh descriptor on success.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            base,
            path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(GrantError(
            "Unable to verify directory access; the directory may be missing, replaced, or outside the grant",
        ));
    }
    // SAFETY: a successful openat2 gave us exclusive ownership of this FD.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn physical_path(directory: &File) -> Result<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .map_err(|_| GrantError("Unable to determine the actual working directory"))
}

fn identity(directory: &File) -> Result<(u64, u64)> {
    let metadata = directory
        .metadata()
        .map_err(|_| GrantError("Unable to verify directory identity"))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn root_directory(path: &Path) -> Result<File> {
    let directory = open_directory(
        libc::AT_FDCWD,
        path,
        libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )?;
    // Verify the physical location as well as the object. A renamed ancestor or
    // symlink substituted for an ancestor must not silently relocate the grant.
    if physical_path(&directory)? != path {
        return Err(GrantError(
            "The granted directory has moved or been replaced",
        ));
    }
    Ok(directory)
}

pub(crate) fn resolve(value: &str) -> Result<StoredDirectory> {
    validate_text(value)?;
    let (path, recursive) = match value.strip_suffix("/*") {
        Some("") => ("/", true),
        Some(path) => (path, true),
        None => (value, false),
    };
    if path.contains('*') {
        return Err(GrantError(
            "Directory supports only a final /* to include the directory and its descendants",
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|_| GrantError("Grant directory must be an existing directory"))?;
    let path = canonical
        .to_str()
        .ok_or(GrantError("Grant directory path must be valid UTF-8"))?;
    validate_text(path)?;
    let directory = root_directory(&canonical)?;
    let (device, inode) = identity(&directory)?;
    Ok(StoredDirectory {
        scope: DirectoryScope {
            path: path.into(),
            recursive,
        },
        device,
        inode,
    })
}

fn authorize_cwd(directory: &StoredDirectory, cwd: File) -> Result<File> {
    let root_path = Path::new(&directory.scope.path);
    let root = root_directory(root_path)?;
    if identity(&root)? != (directory.device, directory.inode) {
        return Err(GrantError(
            "The granted directory has moved or been replaced",
        ));
    }
    let cwd_identity = identity(&cwd)?;
    if cwd_identity == (directory.device, directory.inode) {
        return Ok(cwd);
    }
    if !directory.scope.recursive {
        return Err(GrantError("Working directory does not match this grant"));
    }
    let cwd_path = physical_path(&cwd)?;
    let relative = cwd_path.strip_prefix(root_path).map_err(|_| {
        GrantError("Working directory is outside this grant's permitted directory tree")
    })?;
    // Path::strip_prefix compares path components, not textual prefixes. The
    // kernel then independently verifies traversal beneath the pinned root.
    let verified = open_directory(
        root.as_raw_fd(),
        relative,
        libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS,
    )?;
    if identity(&verified)? != cwd_identity {
        return Err(GrantError("Working directory changed during authorization"));
    }
    Ok(cwd)
}

pub(crate) fn authorize(directory: Option<&StoredDirectory>) -> Result<Option<File>> {
    let Some(directory) = directory else {
        return Ok(None);
    };
    let cwd = open_directory(libc::AT_FDCWD, Path::new("."), libc::RESOLVE_NO_MAGICLINKS)?;
    authorize_cwd(directory, cwd).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, symlink};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "delegated-sudo-directory-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }

        fn directory(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir_all(&path).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn cwd(path: &Path) -> File {
        open_directory(libc::AT_FDCWD, path, libc::RESOLVE_NO_MAGICLINKS).unwrap()
    }

    fn scope(path: &Path, recursive: bool) -> StoredDirectory {
        let value = format!("{}{}", path.display(), if recursive { "/*" } else { "" });
        resolve(&value).unwrap()
    }

    #[test]
    fn resolution_canonicalizes_relative_paths_and_symlink_aliases() {
        let fixture = Fixture::new();
        let actual = fixture.directory("directory with spaces; punctuation");
        let alias = fixture.0.join("alias");
        symlink(&actual, &alias).unwrap();
        assert_eq!(scope(&alias, false).scope.path, actual.to_str().unwrap());
        let current = fs::canonicalize(".").unwrap();
        assert_eq!(resolve(".").unwrap().scope.path, current.to_str().unwrap());
        assert!(resolve("./*").unwrap().scope.recursive);
        let root = resolve("/*").unwrap();
        assert_eq!(root.scope.path, "/");
        assert!(root.scope.recursive);
        assert!(authorize(None).unwrap().is_none());
    }

    #[test]
    fn invalid_or_unreadable_directory_definitions_are_rejected() {
        let fixture = Fixture::new();
        let file = fixture.0.join("file");
        fs::write(&file, b"not a directory").unwrap();
        assert!(resolve(file.to_str().unwrap()).is_err());
        assert!(resolve(fixture.0.join("missing").to_str().unwrap()).is_err());
        for value in [
            "",
            "*",
            "a/**",
            "a/*/child",
            "a*b",
            "a\nb",
            "a\0b",
            "a\u{202e}b",
        ] {
            assert!(
                resolve(value).is_err(),
                "unexpected valid directory: {value:?}"
            );
        }
        let invisible = fixture.directory("hidden\u{200b}");
        let alias = fixture.0.join("visible-alias");
        symlink(invisible, &alias).unwrap();
        assert!(resolve(alias.to_str().unwrap()).is_err());
    }

    #[test]
    fn exact_scope_accepts_aliases_but_rejects_children_and_outside_paths() {
        let fixture = Fixture::new();
        let root = fixture.directory("project");
        let child = fixture.directory("project/child");
        let sibling = fixture.directory("project-other");
        let alias = fixture.0.join("project-alias");
        symlink(&root, &alias).unwrap();
        let grant = scope(&root, false);
        assert!(authorize_cwd(&grant, cwd(&root)).is_ok());
        assert!(authorize_cwd(&grant, cwd(&alias)).is_ok());
        for denied in [child, sibling, fixture.0.clone()] {
            assert!(authorize_cwd(&grant, cwd(&denied)).is_err());
        }
    }

    #[test]
    fn recursive_scope_accepts_actual_descendants_and_rejects_escapes() {
        let fixture = Fixture::new();
        let root = fixture.directory("project");
        let child = fixture.directory("project/one/two");
        let outside = fixture.directory("project-other");
        let alias_inside = fixture.0.join("alias-inside");
        let alias_outside = root.join("alias-outside");
        symlink(&child, &alias_inside).unwrap();
        symlink(&outside, &alias_outside).unwrap();
        let grant = scope(&root, true);
        for permitted in [&root, &child, &alias_inside] {
            assert!(authorize_cwd(&grant, cwd(permitted)).is_ok());
        }
        for denied in [
            outside,
            alias_outside,
            root.join("../project-other"),
            fixture.0.clone(),
        ] {
            assert!(authorize_cwd(&grant, cwd(&denied)).is_err());
        }
    }

    #[test]
    fn replacing_or_moving_the_granted_root_invalidates_the_scope() {
        let fixture = Fixture::new();
        let root = fixture.directory("project");
        let grant = scope(&root, true);
        let moved = fixture.0.join("moved");
        fs::rename(&root, &moved).unwrap();
        assert!(authorize_cwd(&grant, cwd(&moved)).is_err());
        fs::create_dir(&root).unwrap();
        assert!(authorize_cwd(&grant, cwd(&root)).is_err());
        assert!(authorize_cwd(&grant, cwd(&moved)).is_err());
    }

    #[test]
    fn parent_symlink_substitution_does_not_relocate_the_grant() {
        let fixture = Fixture::new();
        let root = fixture.directory("parent/project");
        let grant = scope(&root, true);
        let moved = fixture.0.join("moved-parent");
        fs::rename(fixture.0.join("parent"), &moved).unwrap();
        symlink(&moved, fixture.0.join("parent")).unwrap();
        assert!(authorize_cwd(&grant, cwd(&moved.join("project"))).is_err());
    }

    #[test]
    fn authorized_cwd_descriptor_keeps_the_same_object_after_path_replacement() {
        let fixture = Fixture::new();
        let root = fixture.directory("project");
        let child = fixture.directory("project/child");
        let grant = scope(&root, true);
        let pinned = authorize_cwd(&grant, cwd(&child)).unwrap();
        let original_identity = identity(&pinned).unwrap();
        let moved = root.join("moved");
        fs::rename(&child, &moved).unwrap();
        fs::create_dir(&child).unwrap();
        assert_eq!(identity(&pinned).unwrap(), original_identity);
        assert_eq!(physical_path(&pinned).unwrap(), moved);
        assert_ne!(identity(&pinned).unwrap(), identity(&cwd(&child)).unwrap());
        // SAFETY: pinned remains open and F_GETFD only queries its flags.
        assert_ne!(
            unsafe { libc::fcntl(pinned.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
}
