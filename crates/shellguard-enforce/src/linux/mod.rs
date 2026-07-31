//! Linux confinement: Landlock for paths, seccomp-BPF for capabilities.
//!
//! The two are complementary and neither is sufficient. Landlock scopes the
//! filesystem but has nothing to say about loading a kernel module; seccomp
//! removes whole syscalls but cannot express a path. Applied together they
//! cover what a single mechanism cannot.

pub mod landlock;
pub mod seccomp;

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
