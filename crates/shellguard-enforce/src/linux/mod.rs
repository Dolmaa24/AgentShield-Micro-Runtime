//! Linux confinement: Landlock for paths, seccomp-BPF for capabilities.
//!
//! The two are complementary and neither is sufficient. Landlock scopes the
//! filesystem but has nothing to say about loading a kernel module; seccomp
//! removes whole syscalls but cannot express a path. Applied together they
//! cover what a single mechanism cannot.

pub mod landlock;
pub mod seccomp;

use std::ffi::c_int;

use crate::profile::{EnforceError, Profile};

/// What was actually enforced, so a caller can log the difference between
/// "confined" and "confined as far as this kernel allows".
#[derive(Clone, Copy, Debug)]
pub struct Applied {
    pub landlock: Option<landlock::Applied>,
    pub seccomp: bool,
}

/// Confine the current process. Irreversible.
///
/// Landlock goes first: it needs to `open` the directories it scopes, and
/// doing that after installing a filter would mean the filter has to permit
/// exactly the operations being locked down.
///
/// A kernel without Landlock is not a hard failure — seccomp still applies and
/// the caller is told what was lost — because refusing to run at all on an
/// older kernel means the sandbox gets removed rather than downgraded. Callers
/// that need the filesystem scope should check the result and refuse there,
/// where the decision is visible.
pub fn apply(p: &Profile) -> Result<Applied, EnforceError> {
    let landlock = match landlock::apply(p) {
        Ok(a) => Some(a),
        Err(EnforceError::Unavailable { .. }) => None,
        Err(e) => return Err(e),
    };
    seccomp::apply(p)?;
    Ok(Applied { landlock, seccomp: true })
}

/// Confinement built ahead of time, so applying it allocates nothing.
///
/// # Why this exists
///
/// The natural way to confine a child is `Command::pre_exec`, which runs
/// between `fork` and `exec`. Only async-signal-safe work is permitted there:
/// after forking a multi-threaded process the child inherits a copy of the
/// allocator's locks, which another thread may have held at the instant of the
/// fork, so a single `malloc` can deadlock the child permanently. That is a
/// rare, load-dependent hang — the worst kind to debug, and the worst kind to
/// have here, because a child wedged before `exec` is a child that never got
/// confined and never reported why.
///
/// So everything that allocates — canonicalising paths, opening directory file
/// descriptors, assembling the BPF program — happens in the parent, here.
/// [`Prepared::apply_in_child`] then makes nothing but syscalls.
#[derive(Debug)]
pub struct Prepared {
    /// A populated Landlock ruleset. Creating and filling one restricts nobody;
    /// only `landlock_restrict_self` does, and that happens in the child.
    ruleset_fd: Option<c_int>,
    bpf: Vec<seccomp::SockFilter>,
    /// The negotiated Landlock ABI, or `None` if the kernel has no Landlock.
    pub landlock_abi: Option<u32>,
}

impl Prepared {
    pub fn new(p: &Profile) -> Result<Self, EnforceError> {
        let (ruleset_fd, landlock_abi) = match landlock::build_ruleset(p) {
            Ok((fd, abi)) => (Some(fd), Some(abi)),
            Err(EnforceError::Unavailable { .. }) => (None, None),
            Err(e) => return Err(e),
        };

        let arch = seccomp::native_arch();
        if arch == 0 {
            return Err(EnforceError::Unsupported("this architecture"));
        }
        Ok(Prepared { ruleset_fd, bpf: seccomp::build_filter(arch), landlock_abi })
    }

    /// Apply in a freshly forked child, before `exec`.
    ///
    /// # Safety
    ///
    /// Must be called between `fork` and `exec` in the child. Makes only
    /// syscalls and returns a raw errno rather than a formatted error, for the
    /// same async-signal-safety reason.
    pub unsafe fn apply_in_child(&self) -> Result<(), i32> {
        // SAFETY: every callee below is syscall-only and post-fork safe.
        unsafe {
            seccomp::set_no_new_privs_raw()?;
            if let Some(fd) = self.ruleset_fd {
                landlock::restrict_self_raw(fd)?;
            }
            seccomp::install_filter_raw(&self.bpf)?;
        }
        Ok(())
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(fd) = self.ruleset_fd.take() {
            // SAFETY: the fd came from landlock_create_ruleset and is closed
            // exactly once. A restriction already applied to a child outlives
            // this — the kernel holds its own reference.
            unsafe { landlock::close_fd(fd) };
        }
    }
}
