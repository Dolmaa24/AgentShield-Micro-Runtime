//! Landlock: unprivileged, path-based filesystem and network confinement.
//!
//! # Why this and not a seccomp filter on `openat`
//!
//! seccomp sees a filename as a userspace pointer, and dereferencing it in a
//! filter is unsound — another thread can rewrite the buffer between the check
//! and the kernel's own copy, which is a time-of-check race the attacker
//! controls the timing of. Landlock evaluates in the LSM hooks, after the
//! kernel has resolved the path and against the resolved result, so there is no
//! window to race and symlinks and bind mounts are already accounted for.
//!
//! It also costs nothing per syscall: the check is a walk up the already-cached
//! dentry chain, not a round trip to a userspace supervisor. That is the
//! difference between a sandbox with a fixed startup cost and one that taxes
//! every file operation, which for a build or a test run is millions of them.
//!
//! # ABI negotiation is not optional
//!
//! Each Landlock release adds access bits. Passing a bit the running kernel
//! does not know returns `EINVAL` and the ruleset is never created — so a
//! binary built against a newer header silently fails to confine anything on an
//! older kernel. The version is queried first and the requested rights are
//! masked to it, and the negotiated version is reported to the caller so
//! "confined, but this kernel cannot restrict network" is a visible state
//! rather than an assumption.

use std::ffi::{c_char, c_int, c_long, c_void, CString};
use std::path::Path;

pub use crate::landlock_abi::handled_net_for_abi;
use crate::landlock_abi::net_rights_to_handle;
use crate::profile::{Access, EnforceError, Profile};

const SYS_LANDLOCK_CREATE_RULESET: c_long = 444;
const SYS_LANDLOCK_ADD_RULE: c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: c_int = 1;

// Filesystem access rights, in the order the ABI introduced them.
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
/// ABI 2: linking or renaming across directories.
const FS_REFER: u64 = 1 << 13;
/// ABI 3: truncating a file, which ABI 1 and 2 could not see at all — meaning
/// on those kernels `> file` can empty a file the ruleset denies writing.
const FS_TRUNCATE: u64 = 1 << 14;
/// ABI 5: ioctls on device files.
const FS_IOCTL_DEV: u64 = 1 << 15;

const O_PATH: c_int = 0o10000000;
const O_CLOEXEC: c_int = 0o2000000;
const O_DIRECTORY: c_int = 0o200000;

#[repr(C)]
#[derive(Default, Debug)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

// Packed in the kernel header; the layout has to match exactly or the kernel
// reads `parent_fd` out of padding.
#[repr(C, packed)]
#[derive(Debug)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

extern "C" {
    fn syscall(num: c_long, ...) -> c_long;
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
}

/// Everything a read-only subtree needs.
const READ_RIGHTS: u64 = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;

/// Everything a writable subtree needs, including creation and removal.
const WRITE_RIGHTS: u64 = READ_RIGHTS
    | FS_WRITE_FILE
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_CHAR
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SOCK
    | FS_MAKE_FIFO
    | FS_MAKE_BLOCK
    | FS_MAKE_SYM
    | FS_REFER
    | FS_TRUNCATE;

/// Paths every process needs to read to start and resolve names.
const BASE_READ: &[&str] =
    &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev", "/sys/devices"];

/// The set of rights the running kernel understands.
///
/// Requesting more than this makes ruleset creation fail outright, so the
/// binary must adapt to the kernel rather than the other way round.
pub fn handled_fs_for_abi(abi: u32) -> u64 {
    let mut fs = FS_EXECUTE
        | FS_WRITE_FILE
        | FS_READ_FILE
        | FS_READ_DIR
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM;
    if abi >= 2 {
        fs |= FS_REFER;
    }
    if abi >= 3 {
        fs |= FS_TRUNCATE;
    }
    if abi >= 5 {
        fs |= FS_IOCTL_DEV;
    }
    fs
}

/// Query the kernel's Landlock ABI version.
pub fn abi_version() -> Result<u32, EnforceError> {
    // SAFETY: the version query takes a null attr and zero size by contract.
    let rc = unsafe {
        syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        return Err(EnforceError::Unavailable {
            feature: "landlock",
            detail: std::io::Error::last_os_error().to_string(),
        });
    }
    Ok(rc as u32)
}

/// What a successful [`apply`] actually managed to enforce.
#[derive(Clone, Copy, Debug)]
pub struct Applied {
    pub abi: u32,
    /// False on ABI 1 and 2, where the kernel cannot see truncation — so
    /// `> file` can empty a file whose write access was denied.
    pub truncate_enforced: bool,
    /// False below ABI 4, where Landlock cannot restrict network at all.
    pub network_enforced: bool,
}

/// Create and populate a ruleset without applying it, returning the fd and the
/// negotiated ABI.
///
/// Building a ruleset restricts nobody — only `landlock_restrict_self` does.
/// That split is what lets all the allocating work (canonicalising paths,
/// opening directory descriptors) happen in the parent, leaving the child with
/// one syscall. See [`super::Prepared`].
pub fn build_ruleset(p: &Profile) -> Result<(c_int, u32), EnforceError> {
    let p = p.canonicalized();
    let abi = abi_version()?;
    if abi == 0 {
        return Err(EnforceError::Unavailable {
            feature: "landlock",
            detail: "kernel reports ABI 0".into(),
        });
    }

    let handled_fs = handled_fs_for_abi(abi);
    let handled_net = net_rights_to_handle(&p, abi);

    let attr = RulesetAttr { handled_access_fs: handled_fs, handled_access_net: handled_net };
    // SAFETY: `attr` is a valid, correctly sized struct that outlives the call.
    let ruleset_fd = unsafe {
        syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(EnforceError::Rejected {
            stage: "landlock_create_ruleset",
            detail: std::io::Error::last_os_error().to_string(),
        });
    }
    let ruleset_fd = ruleset_fd as c_int;

    let populate = (|| -> Result<(), EnforceError> {
        for dir in BASE_READ {
            // Missing base directories are not an error: a container image may
            // legitimately have no /lib64.
            let _ = add_path(ruleset_fd, Path::new(dir), READ_RIGHTS & handled_fs);
        }
        add_grants(ruleset_fd, &p, handled_fs)?;
        Ok(())
    })();

    if let Err(e) = populate {
        // SAFETY: live fd, closed exactly once on this path.
        unsafe { close_fd(ruleset_fd) };
        return Err(e);
    }
    Ok((ruleset_fd, abi))
}

/// `landlock_restrict_self` with a raw errno, for use after `fork`.
///
/// # Safety
/// `fd` must be a live ruleset descriptor. Safe post-fork: one syscall, no
/// allocation.
pub unsafe fn restrict_self_raw(fd: c_int) -> Result<(), i32> {
    // SAFETY: caller guarantees the fd is a live ruleset.
    let rc = unsafe { syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0u32) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }
    Ok(())
}

/// # Safety
/// `fd` must be live and not already closed.
pub unsafe fn close_fd(fd: c_int) {
    // SAFETY: caller guarantees the fd is live and closed exactly once.
    unsafe { close(fd) };
}

/// Apply the profile's filesystem and network scope to the current process.
pub fn apply(p: &Profile) -> Result<Applied, EnforceError> {
    let p = p.canonicalized();
    let abi = abi_version()?;
    if abi == 0 {
        return Err(EnforceError::Unavailable {
            feature: "landlock",
            detail: "kernel reports ABI 0".into(),
        });
    }

    let handled_fs = handled_fs_for_abi(abi);
    let handled_net = net_rights_to_handle(&p, abi);

    let attr = RulesetAttr { handled_access_fs: handled_fs, handled_access_net: handled_net };
    // SAFETY: `attr` is a valid, correctly sized struct that outlives the call.
    let ruleset_fd = unsafe {
        syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(EnforceError::Rejected {
            stage: "landlock_create_ruleset",
            detail: std::io::Error::last_os_error().to_string(),
        });
    }
    let ruleset_fd = ruleset_fd as c_int;

    let result = (|| -> Result<(), EnforceError> {
        for dir in BASE_READ {
            // Missing base directories are not an error: a container image may
            // legitimately have no /lib64.
            let _ = add_path(ruleset_fd, Path::new(dir), READ_RIGHTS & handled_fs);
        }
        add_grants(ruleset_fd, &p, handled_fs)?;

        super::seccomp::set_no_new_privs()?;

        // SAFETY: `ruleset_fd` is a live fd from create_ruleset.
        let rc = unsafe { syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
        if rc != 0 {
            return Err(EnforceError::Rejected {
                stage: "landlock_restrict_self",
                detail: std::io::Error::last_os_error().to_string(),
            });
        }
        Ok(())
    })();

    // SAFETY: `ruleset_fd` is live and closed exactly once. The restriction
    // survives the fd; the kernel holds its own reference.
    unsafe { close(ruleset_fd) };
    result?;

    Ok(Applied { abi, truncate_enforced: abi >= 3, network_enforced: abi >= 4 && handled_net != 0 })
}

/// Add every path the profile grants, at the rights its access level means.
///
/// The list comes from [`Profile::fs_grants`] and nothing is derived here, so
/// this backend cannot come to disagree with Seatbelt or the gVisor mount set
/// about what a profile allows. Only the base system directories — which are
/// this backend's own business — are handled separately by the callers.
fn add_grants(ruleset_fd: c_int, p: &Profile, handled_fs: u64) -> Result<(), EnforceError> {
    for g in p.fs_grants() {
        let rights = match g.access {
            Access::Read => READ_RIGHTS,
            Access::Write => WRITE_RIGHTS,
        };
        add_path(ruleset_fd, &g.path, rights & handled_fs)?;
    }
    Ok(())
}

fn add_path(ruleset_fd: c_int, path: &Path, rights: u64) -> Result<(), EnforceError> {
    if rights == 0 {
        return Ok(());
    }
    let c =
        CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| EnforceError::Rejected {
            stage: "landlock_add_rule",
            detail: format!("path contains a NUL: {path:?}"),
        })?;

    // O_PATH opens the directory without read permission on it, which is what
    // lets a ruleset name a directory the process is not otherwise allowed to
    // open.
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
    let fd = unsafe { open(c.as_ptr(), O_PATH | O_CLOEXEC | O_DIRECTORY) };
    if fd < 0 {
        return Err(EnforceError::Rejected {
            stage: "landlock_add_rule",
            detail: format!("cannot open {}: {}", path.display(), std::io::Error::last_os_error()),
        });
    }

    let rule = PathBeneathAttr { allowed_access: rights, parent_fd: fd };
    // SAFETY: `rule` outlives the call and matches the kernel's packed layout.
    let rc = unsafe {
        syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &rule as *const PathBeneathAttr as *const c_void,
            0u32,
        )
    };
    // SAFETY: `fd` is live and closed exactly once; the kernel copied what it
    // needs during add_rule.
    unsafe { close(fd) };

    if rc != 0 {
        return Err(EnforceError::Rejected {
            stage: "landlock_add_rule",
            detail: format!("{}: {}", path.display(), std::io::Error::last_os_error()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::landlock_abi::{NET_BIND_TCP, NET_CONNECT_TCP};

    #[test]
    fn write_access_contains_read_access() {
        // `Profile::fs_grants` promises this, and the other backends rely on it:
        // a path a command can write is a path it can read back. Checked against
        // the constants, so changing one without the other fails here.
        assert_eq!(WRITE_RIGHTS & READ_RIGHTS, READ_RIGHTS);
        assert_ne!(WRITE_RIGHTS, READ_RIGHTS, "Write must grant something Read does not");
        assert_eq!(READ_RIGHTS & (FS_WRITE_FILE | FS_MAKE_REG | FS_REMOVE_FILE), 0);
    }

    #[test]
    fn abi_gating_adds_rights_in_the_right_order() {
        let a1 = handled_fs_for_abi(1);
        let a2 = handled_fs_for_abi(2);
        let a3 = handled_fs_for_abi(3);
        let a5 = handled_fs_for_abi(5);

        assert_eq!(a1 & FS_REFER, 0, "REFER is ABI 2");
        assert_ne!(a2 & FS_REFER, 0);
        assert_eq!(a2 & FS_TRUNCATE, 0, "TRUNCATE is ABI 3");
        assert_ne!(a3 & FS_TRUNCATE, 0);
        assert_eq!(a3 & FS_IOCTL_DEV, 0, "IOCTL_DEV is ABI 5");
        assert_ne!(a5 & FS_IOCTL_DEV, 0);

        // Each version is a superset of the one before, so masking to an older
        // kernel can only ever remove rights.
        assert_eq!(a1 & a2, a1);
        assert_eq!(a2 & a3, a2);
    }

    #[test]
    fn network_rights_need_abi_four() {
        assert_eq!(handled_net_for_abi(3), 0);
        assert_ne!(handled_net_for_abi(4) & NET_CONNECT_TCP, 0);
        assert_ne!(handled_net_for_abi(4) & NET_BIND_TCP, 0);
    }

    #[test]
    fn write_rights_are_a_superset_of_read_rights() {
        assert_eq!(WRITE_RIGHTS & READ_RIGHTS, READ_RIGHTS);
    }

    #[test]
    fn write_rights_include_truncate() {
        // Without this, `> file` empties a file the ruleset denies writing.
        assert_ne!(WRITE_RIGHTS & FS_TRUNCATE, 0);
    }

    #[test]
    fn the_packed_rule_struct_matches_the_kernel_layout() {
        // 8 bytes of access plus 4 of fd, with no tail padding.
        assert_eq!(std::mem::size_of::<PathBeneathAttr>(), 12);
        assert_eq!(std::mem::size_of::<RulesetAttr>(), 16);
    }
}
