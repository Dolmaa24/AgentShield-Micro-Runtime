//! Kernel-level confinement — the part of this system that is actually a
//! security boundary.
//!
//! `shellguard-gate` decides *before* a command runs, by reading it. That is
//! fast and it is useful, and it is not sound: static analysis of shell is
//! undecidable, and `eval "$(curl x)"` is a one-line proof. Everything the gate
//! lets through still has to run somewhere it cannot do damage, and that
//! somewhere is here.
//!
//! The division of labour is deliberate:
//!
//! | | gate | enforce |
//! |---|---|---|
//! | when | before execution | at each syscall |
//! | sees | the command text | what actually happened |
//! | cost | tens of microseconds | fixed setup, ~zero per syscall |
//! | can be fooled by | any dynamic construction | nothing in userspace |
//! | gives | a reason a human can read | a kill |
//!
//! The gate exists because a kill with no explanation is unusable for an agent
//! that has to decide what to do next. Enforcement exists because an
//! explanation with no kill is a suggestion.
//!
//! # Platform support
//!
//! | | macOS | Linux |
//! |---|---|---|
//! | filesystem scope | Seatbelt SBPL | Landlock ABI 1+ |
//! | syscall removal | — | seccomp-BPF |
//! | network scope | Seatbelt, coarse | Landlock ABI 4+ |
//! | entitlement needed | none | none |
//!
//! macOS has no unprivileged equivalent of seccomp: fine-grained syscall
//! interception there is Endpoint Security, which needs an Apple-granted
//! entitlement. The honest summary is that Linux confinement here is stronger,
//! and a deployment that wants Linux-grade isolation on a Mac should run the
//! commands in a Linux VM through Virtualization.framework rather than trust
//! Seatbelt to be equivalent. See DESIGN.md § 6.

mod profile;
mod syscalls;

pub use profile::{EnforceError, Profile};
pub use syscalls::DENIED as DENIED_SYSCALLS;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

/// Whether this build has a confinement backend at all.
pub const fn supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux"))
}

/// A short description of the backend in use, for logs and `--version` output.
pub fn backend() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "seatbelt"
    }
    #[cfg(target_os = "linux")]
    {
        "landlock+seccomp"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "none"
    }
}

/// Confine the current process according to `profile`. Irreversible.
///
/// Prefer confining a child instead — see [`macos::command`] — so that a
/// supervisor stays outside the sandbox and can still record what happened to
/// a command that gets killed inside it.
pub fn apply(profile: &Profile) -> Result<(), EnforceError> {
    #[cfg(target_os = "macos")]
    {
        macos::apply(profile)
    }
    #[cfg(target_os = "linux")]
    {
        linux::apply(profile).map(|_| ())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = profile;
        Err(EnforceError::Unsupported(std::env::consts::OS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_platform_has_a_backend() {
        assert!(supported(), "no confinement backend for {}", std::env::consts::OS);
        assert_ne!(backend(), "none");
    }
}
