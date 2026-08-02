//! Isolated execution backends stronger than a host sandbox.
//!
//! Three, none of which can be exercised end to end on this machine — the two
//! Linux ones have no Linux host and the macOS one has no guest kernel image.
//! What *is* exercised is everything up to the launch: configuration building,
//! validation against the real framework where one exists, and availability
//! detection. That is deliberate rather than a consolation. Configuration is
//! where these things actually go wrong — a mistyped share tag, a memory size
//! below the platform minimum, a seccomp profile that omits a syscall the
//! runtime needs — and it is the part that can be checked in microseconds
//! instead of seconds.
//!
//! Each backend reports [`crate::runtime::Availability::Unavailable`] with a
//! specific reason rather than failing at launch, so a deployment learns that
//! `runsc` is not on `PATH` at start-up rather than on the first command that
//! needed it.

pub mod firecracker;
pub mod gvisor;
pub mod vz;

pub use firecracker::FirecrackerRuntime;
pub use gvisor::GvisorRuntime;
pub use vz::VzRuntime;

use crate::local::LocalRuntime;
use crate::runtime::{Isolation, Runtime};

/// Every backend compiled into this build, strongest isolation first.
pub fn all() -> Vec<Box<dyn Runtime>> {
    let mut v: Vec<Box<dyn Runtime>> = vec![
        Box::new(FirecrackerRuntime::default()),
        Box::new(VzRuntime::default()),
        Box::new(GvisorRuntime::default()),
        Box::new(LocalRuntime::new()),
    ];
    v.sort_by_key(|r| std::cmp::Reverse(r.isolation()));
    v
}

/// The strongest available backend at or above `minimum`.
///
/// Returns `None` rather than silently downgrading. A caller that asked for a
/// virtual machine and got a process sandbox has been given something with a
/// different threat model under the same name, which is worse than an error.
pub fn strongest_available(minimum: Isolation) -> Option<Box<dyn Runtime>> {
    all().into_iter().find(|r| r.isolation() >= minimum && r.availability().is_ready())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backends_are_ordered_strongest_first() {
        let all = all();
        for w in all.windows(2) {
            assert!(w[0].isolation() >= w[1].isolation());
        }
        assert_eq!(all.last().unwrap().name(), "local");
    }

    #[test]
    fn every_unavailable_backend_says_why() {
        for r in all() {
            if let Some(reason) = r.availability().reason() {
                assert!(!reason.is_empty(), "{} gave an empty reason", r.name());
            }
        }
    }

    #[test]
    fn a_sandbox_is_available_here_but_a_vm_is_not() {
        // The honest state of this machine: the local backend works, and
        // nothing stronger is configured.
        assert!(strongest_available(Isolation::Sandbox).is_some());
        assert!(
            strongest_available(Isolation::Virtual).is_none(),
            "a VM backend claimed to be ready without a guest image"
        );
    }

    #[test]
    fn asking_for_more_isolation_than_exists_returns_none_rather_than_downgrading() {
        let r = strongest_available(Isolation::Virtual);
        assert!(r.is_none() || r.unwrap().isolation() >= Isolation::Virtual);
    }
}
