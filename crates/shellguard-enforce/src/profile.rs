//! The platform-independent description of a confinement.
//!
//! A [`Profile`] is derived from the capabilities the gate's decision granted,
//! and then compiled into whatever the host can enforce: an SBPL profile on
//! macOS, a Landlock ruleset plus a seccomp filter on Linux.
//!
//! The direction matters. Profiles are built by *widening* a closed default,
//! never by narrowing an open one. A capability the ruleset did not grant is
//! one nobody has to remember to remove.

use std::path::{Path, PathBuf};

use shellguard_policy::Capability;

/// What a confined command may do.
#[derive(Clone, Debug)]
pub struct Profile {
    /// The one directory the command may write to.
    pub workspace: PathBuf,
    /// Extra readable subtrees, beyond the platform's own runtime files.
    pub read_paths: Vec<PathBuf>,
    /// Extra writable subtrees.
    pub write_paths: Vec<PathBuf>,
    /// A *private* scratch directory, writable if set.
    ///
    /// Never the shared system temp directory. `/tmp` holds other processes'
    /// files and is a classic pivot: a command that can write a predictable
    /// path there can feed input to something outside the sandbox that reads
    /// it. A capability grant widens the profile to the workspace only; the
    /// runtime supplies a per-execution directory here, via
    /// [`Profile::with_private_tmp`].
    pub tmp: Option<PathBuf>,

    pub allow_network: bool,
    pub allow_listen: bool,
    /// Whether the command may execute other programs. Almost always true —
    /// a shell pipeline is several programs — but a profile for a single known
    /// binary can turn it off.
    pub allow_exec: bool,
    pub allow_fork: bool,

    /// Cap on processes, for the fork-bomb case. Enforced by cgroups on Linux;
    /// unenforceable through Seatbelt alone on macOS, where it needs an
    /// `RLIMIT_NPROC` on the child instead.
    pub max_processes: u32,
    /// Memory cap in bytes, 0 for unlimited.
    pub max_memory_bytes: u64,
}

impl Profile {
    /// The most restrictive profile: read the workspace, write nothing, no
    /// network.
    pub fn locked_down(workspace: impl Into<PathBuf>) -> Self {
        Profile {
            workspace: workspace.into(),
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            tmp: None,
            allow_network: false,
            allow_listen: false,
            allow_exec: true,
            allow_fork: true,
            max_processes: 256,
            max_memory_bytes: 2 * 1024 * 1024 * 1024,
        }
    }

    /// Widen a locked-down profile by exactly the capabilities that were
    /// granted, and nothing else.
    pub fn from_capabilities(workspace: impl Into<PathBuf>, caps: &[Capability]) -> Self {
        let mut p = Profile::locked_down(workspace);
        for c in caps {
            match c {
                Capability::FsWrite | Capability::FsDelete => {
                    p.write_paths.push(p.workspace.clone());
                }
                Capability::NetConnect => p.allow_network = true,
                Capability::NetListen => {
                    p.allow_network = true;
                    p.allow_listen = true;
                }
                Capability::ProcSpawn => {
                    p.allow_exec = true;
                    p.allow_fork = true;
                }
                // Package installs write into the workspace and fetch over the
                // network, and their build scripts need a scratch directory.
                Capability::PackageInstall => {
                    p.allow_network = true;
                    p.write_paths.push(p.workspace.clone());
                }
                Capability::VcsHistoryRewrite => {
                    p.write_paths.push(p.workspace.clone());
                }
                // These are never granted by widening a profile. A command
                // that needs them is one the gate should have escalated to a
                // human, and a sandbox that can be configured to permit kernel
                // module loading is not a sandbox.
                Capability::PrivEsc
                | Capability::KernelModule
                | Capability::DeviceWrite
                | Capability::SandboxEscape
                | Capability::ShellEscape
                | Capability::CredentialAccess
                | Capability::FsRead
                | Capability::ProcSignal => {}
            }
        }
        p.write_paths.sort();
        p.write_paths.dedup();
        p
    }

    /// Attach a private scratch directory, which the caller owns and removes.
    pub fn with_private_tmp(mut self, dir: impl Into<PathBuf>) -> Self {
        self.tmp = Some(dir.into());
        self
    }

    /// Every path the command may write, including the workspace.
    pub fn writable(&self) -> Vec<&Path> {
        let mut v: Vec<&Path> = self.write_paths.iter().map(|p| p.as_path()).collect();
        if let Some(t) = &self.tmp {
            v.push(t.as_path());
        }
        v
    }

    /// Resolve every path in the profile through symlinks.
    ///
    /// Both backends match on the kernel's view of a path, so a profile
    /// carrying `/tmp` on macOS — where it is a symlink to `/private/tmp` —
    /// grants access to a path the kernel never sees. The rule silently never
    /// fires, which is the worst way for a confinement to be wrong.
    pub fn canonicalized(&self) -> Profile {
        fn canon(p: &Path) -> PathBuf {
            p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
        }
        Profile {
            workspace: canon(&self.workspace),
            read_paths: self.read_paths.iter().map(|p| canon(p)).collect(),
            write_paths: self.write_paths.iter().map(|p| canon(p)).collect(),
            tmp: self.tmp.as_deref().map(canon),
            ..self.clone()
        }
    }
}

/// What went wrong applying a profile.
#[derive(Debug)]
pub enum EnforceError {
    /// The platform has no backend compiled in.
    Unsupported(&'static str),
    /// The kernel refused the profile.
    Rejected { stage: &'static str, detail: String },
    /// The kernel lacks the feature.
    Unavailable { feature: &'static str, detail: String },
}

impl std::fmt::Display for EnforceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnforceError::Unsupported(p) => write!(f, "no confinement backend for {p}"),
            EnforceError::Rejected { stage, detail } => {
                write!(f, "kernel rejected the profile at {stage}: {detail}")
            }
            EnforceError::Unavailable { feature, detail } => {
                write!(f, "{feature} is unavailable: {detail}")
            }
        }
    }
}

impl std::error::Error for EnforceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locked_down_profile_grants_no_writes_and_no_network() {
        let p = Profile::locked_down("/ws");
        assert!(p.write_paths.is_empty());
        assert!(!p.allow_network);
        assert!(!p.allow_listen);
    }

    #[test]
    fn capabilities_widen_only_what_they_name() {
        let p = Profile::from_capabilities("/ws", &[Capability::FsRead]);
        assert!(p.writable().is_empty(), "fs.read must not grant writes");
        assert!(!p.allow_network);

        let p = Profile::from_capabilities("/ws", &[Capability::FsWrite]);
        assert!(p.writable().iter().any(|w| w.ends_with("ws")));
        assert!(!p.allow_network, "fs.write must not grant network");

        let p = Profile::from_capabilities("/ws", &[Capability::NetConnect]);
        assert!(p.allow_network);
        assert!(!p.allow_listen, "connect must not grant listen");
        assert!(p.writable().is_empty(), "net.connect must not grant writes");
    }

    #[test]
    fn dangerous_capabilities_never_widen_a_profile() {
        // If this ever starts widening, a rule that grants `priv.esc` to
        // explain a verdict would also configure the sandbox to permit it.
        for c in [
            Capability::PrivEsc,
            Capability::KernelModule,
            Capability::DeviceWrite,
            Capability::SandboxEscape,
            Capability::ShellEscape,
        ] {
            let p = Profile::from_capabilities("/ws", &[c]);
            let locked = Profile::locked_down("/ws");
            assert!(p.writable().is_empty(), "{c:?} granted writes");
            assert_eq!(p.allow_network, locked.allow_network, "{c:?} granted network");
        }
    }

    #[test]
    fn no_capability_grants_the_shared_temp_directory() {
        // Found by a runtime test: granting fs.write used to hand over the
        // system temp directory, so a write to /tmp was permitted. /tmp is
        // shared with every other process on the machine.
        let shared = std::env::temp_dir();
        for c in [Capability::FsWrite, Capability::FsDelete, Capability::PackageInstall] {
            let p = Profile::from_capabilities("/ws", &[c]);
            assert!(
                !p.writable().iter().any(|w| *w == shared.as_path()),
                "{c:?} granted the shared temp directory"
            );
        }
        // A private one, supplied by the runtime, is granted.
        let p = Profile::from_capabilities("/ws", &[Capability::FsWrite])
            .with_private_tmp("/ws/.scratch-1234");
        assert!(p.writable().iter().any(|w| w.ends_with(".scratch-1234")));
    }

    #[test]
    fn listen_implies_connect_but_not_the_reverse() {
        let p = Profile::from_capabilities("/ws", &[Capability::NetListen]);
        assert!(p.allow_network && p.allow_listen);
    }

    #[test]
    fn writable_paths_are_deduplicated() {
        let p = Profile::from_capabilities(
            "/ws",
            &[Capability::FsWrite, Capability::FsDelete, Capability::VcsHistoryRewrite],
        );
        let ws: Vec<_> = p.write_paths.iter().filter(|w| w.ends_with("ws")).collect();
        assert_eq!(ws.len(), 1, "the workspace was added more than once");
    }
}
