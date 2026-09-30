//! gVisor (`runsc`) containers.
//!
//! # What "seccomp and Landlock inside the container" actually means here
//!
//! Worth being exact, because the two halves do not both survive the trip.
//!
//! **seccomp does.** The OCI runtime spec carries a seccomp profile and
//! `runsc` applies it to the sandboxed process. The profile is generated from
//! the same [`shellguard_enforce::DENIED_SYSCALLS`] list the Linux seccomp-BPF
//! filter uses, so the two cannot drift.
//!
//! **Landlock does not.** gVisor implements the Linux syscall surface itself
//! in userspace and does not implement `landlock_create_ruleset` and friends —
//! a ruleset built inside a gVisor sandbox would fail at creation, and code
//! that ignored that failure would believe it was confined when it was not.
//! The filesystem scoping is achieved instead through the OCI mount set: the
//! root is read-only, `/proc` and `/sys` are masked, and the only host paths
//! that appear are the ones [`Profile::fs_grants`] lists — each mounted `ro` or
//! `rw` according to its [`Access`]. That is the same *effect* by a different
//! mechanism, and calling it Landlock would misdescribe the threat model.
//!
//! "Same effect" is a claim that used to be made in this comment and checked
//! nowhere, and it was false: the workspace was mounted writable for a profile
//! that granted no writes, while Seatbelt and Landlock made it read-only. Seatbelt,
//! Landlock and this mount set now all translate the one list `fs_grants`
//! returns and derive nothing of their own, and `tests::parity_*` holds the
//! translation to it.
//!
//! What is *not* the same, by design: the host's `/usr`, `/etc` and friends. Under
//! Landlock they are readable directly; here the container's system files are the
//! bundle's own root filesystem, and the host's are never mounted.
//!
//! gVisor's own interception is the stronger boundary in any case. Every
//! syscall is serviced by the Sentry rather than the host kernel, so the host
//! kernel's syscall surface — the thing seccomp exists to shrink — is barely
//! reachable to begin with.
//!
//! Nothing here has run: `runsc` is Linux-only and there is no Linux host in
//! this repository's development environment. Bundle generation is tested
//! against the OCI schema.

use std::path::{Path, PathBuf};

use shellguard_enforce::{Access, Profile};

use crate::json;
use crate::runtime::{Availability, ExecResult, Isolation, Payload, Runtime, RuntimeError};

/// Paths a container should never see, whatever it runs.
///
/// `/proc/kcore` is the host's physical memory; `/sys/firmware` carries enough
/// to fingerprint or attack the host. Masking is cheap and the list is the
/// standard one every container runtime uses, for good reason.
const MASKED_PATHS: &[&str] = &[
    "/proc/acpi",
    "/proc/asound",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];

const READONLY_PATHS: &[&str] =
    &["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"];

#[derive(Clone, Debug)]
pub struct GvisorRuntime {
    /// The `runsc` binary.
    pub binary: PathBuf,
    /// A prepared root filesystem directory.
    pub rootfs: Option<PathBuf>,
    /// Where the workspace mount appears inside the container.
    pub guest_workspace: PathBuf,
    /// `ptrace` or `systrap`. systrap is faster where the host supports it.
    pub platform: String,
    pub pids_limit: u32,
    pub memory_limit_bytes: u64,
}

impl Default for GvisorRuntime {
    fn default() -> Self {
        GvisorRuntime {
            binary: PathBuf::from("runsc"),
            rootfs: None,
            guest_workspace: PathBuf::from("/workspace"),
            platform: "systrap".to_string(),
            pids_limit: 256,
            memory_limit_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// A host path mounted into the container.
#[derive(Debug)]
struct BindMount {
    dest: PathBuf,
    source: PathBuf,
    access: Access,
}

impl GvisorRuntime {
    /// The host paths to mount, from the profile's grants and nothing else.
    ///
    /// The workspace appears at [`guest_workspace`](Self::guest_workspace), and
    /// anything granted beneath it appears beneath it there; other grants keep
    /// their own absolute path. The private scratch directory is *not* bound: it
    /// is represented by the container's own `/tmp` tmpfs, which is private to
    /// the container and needs no host directory.
    ///
    /// Parents come before children, as a mount table requires. If two grants
    /// land on one destination (only possible for a hand-built profile that
    /// grants a host path equal to the guest workspace), the *lower* access
    /// wins: failing closed for a path is better than failing open.
    fn bind_mounts(&self, profile: &Profile) -> Vec<BindMount> {
        let mut out: Vec<BindMount> = Vec::new();
        for g in profile.fs_grants() {
            if profile.tmp.as_deref() == Some(g.path.as_path()) {
                continue;
            }
            let dest = match g.path.strip_prefix(&profile.workspace) {
                Ok(rel) if rel.as_os_str().is_empty() => self.guest_workspace.clone(),
                Ok(rel) => self.guest_workspace.join(rel),
                Err(_) => g.path.clone(),
            };
            out.push(BindMount { dest, source: g.path, access: g.access });
        }
        out.sort_by(|a, b| a.dest.cmp(&b.dest).then(a.access.cmp(&b.access)));
        out.dedup_by(|later, first| later.dest == first.dest);
        out
    }

    pub fn with_rootfs(mut self, rootfs: impl Into<PathBuf>) -> Self {
        self.rootfs = Some(rootfs.into());
        self
    }

    pub fn with_limits(mut self, pids: u32, memory_bytes: u64) -> Self {
        self.pids_limit = pids;
        self.memory_limit_bytes = memory_bytes;
        self
    }

    /// The OCI runtime `config.json` for one execution.
    pub fn oci_config(&self, payload: &Payload) -> String {
        let ws = self.guest_workspace.to_string_lossy().into_owned();
        let mut s = String::with_capacity(4096);

        s.push_str("{\"ociVersion\":\"1.0.2\",");

        // ---- process
        s.push_str("\"process\":{");
        s.push_str("\"terminal\":false,");
        // Unprivileged. Root inside a container that shares a workspace mount
        // with the host can still ruin the workspace, and gVisor does not
        // change that.
        s.push_str("\"user\":{\"uid\":65534,\"gid\":65534},");
        s.push_str("\"args\":[\"/bin/sh\",\"-c\",");
        s.push_str(&json::quote(&payload.command));
        s.push_str("],");

        s.push_str("\"env\":[");
        let mut env: Vec<(String, String)> = vec![
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("HOME".into(), ws.clone()),
            ("TMPDIR".into(), "/tmp".into()),
            ("TERM".into(), "dumb".into()),
            ("CI".into(), "1".into()),
        ];
        env.extend(payload.env.iter().cloned());
        for (i, (k, v)) in env.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json::quote(&format!("{k}={v}")));
        }
        s.push_str("],");

        s.push_str(&format!("\"cwd\":{},", json::quote(&ws)));

        // Every capability dropped. A container that needs CAP_SYS_ADMIN to
        // run a build is a container doing something else.
        s.push_str(
            "\"capabilities\":{\"bounding\":[],\"effective\":[],\"inheritable\":[],\"permitted\":[],\"ambient\":[]},",
        );
        s.push_str("\"noNewPrivileges\":true,");
        s.push_str(&format!(
            "\"rlimits\":[{{\"type\":\"RLIMIT_NPROC\",\"hard\":{n},\"soft\":{n}}}]",
            n = self.pids_limit
        ));
        s.push_str("},");

        // ---- root
        let rootfs = self.rootfs.as_deref().unwrap_or(Path::new("rootfs"));
        s.push_str("\"root\":{");
        s.push_str(&format!("\"path\":{},", json::quote(&rootfs.to_string_lossy())));
        s.push_str("\"readonly\":true},");

        s.push_str("\"hostname\":\"shellguard\",");

        // ---- mounts
        //
        // Only what the profile grants. `nosuid` and `nodev` on every bind, so a
        // setuid binary or device node planted in a granted directory cannot be
        // used from inside; `ro` unless the grant is a write.
        let mut mounts: Vec<String> = vec![
            "{\"destination\":\"/proc\",\"type\":\"proc\",\"source\":\"proc\"}".to_string(),
            "{\"destination\":\"/dev\",\"type\":\"tmpfs\",\"source\":\"tmpfs\",\"options\":[\"nosuid\",\"strictatime\",\"mode=755\",\"size=65536k\"]}".to_string(),
        ];
        // The private scratch directory, as a tmpfs private to the container.
        // Present only when the profile has one: under Seatbelt and Landlock a
        // profile with no scratch directory has nowhere writable to put temp
        // files, and inventing one here would be a writable path they lack.
        if payload.profile.tmp.is_some() {
            mounts.push(
                "{\"destination\":\"/tmp\",\"type\":\"tmpfs\",\"source\":\"tmpfs\",\"options\":[\"nosuid\",\"nodev\",\"mode=1777\"]}".to_string(),
            );
        }
        for b in self.bind_mounts(&payload.profile) {
            let mode = match b.access {
                Access::Read => "ro",
                Access::Write => "rw",
            };
            mounts.push(format!(
                "{{\"destination\":{},\"type\":\"bind\",\"source\":{},\"options\":[\"rbind\",\"{mode}\",\"nosuid\",\"nodev\"]}}",
                json::quote(&b.dest.to_string_lossy()),
                json::quote(&b.source.to_string_lossy()),
            ));
        }
        s.push_str("\"mounts\":[");
        s.push_str(&mounts.join(","));
        s.push_str("],");

        // ---- linux
        s.push_str("\"linux\":{");
        s.push_str(
            "\"namespaces\":[{\"type\":\"pid\"},{\"type\":\"ipc\"},{\"type\":\"uts\"},{\"type\":\"mount\"}",
        );
        if !payload.profile.allow_network {
            // An unshared network namespace with no interfaces configured is a
            // container that cannot reach anything.
            s.push_str(",{\"type\":\"network\"}");
        }
        s.push_str("],");

        s.push_str(&format!(
            "\"resources\":{{\"pids\":{{\"limit\":{}}},\"memory\":{{\"limit\":{}}}}},",
            self.pids_limit, self.memory_limit_bytes
        ));

        s.push_str("\"maskedPaths\":[");
        for (i, p) in MASKED_PATHS.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json::quote(p));
        }
        s.push_str("],\"readonlyPaths\":[");
        for (i, p) in READONLY_PATHS.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json::quote(p));
        }
        s.push_str("],");

        s.push_str(&self.seccomp_json());
        s.push_str("}}");
        s
    }

    /// The OCI seccomp profile, from the same denylist the BPF filter uses.
    fn seccomp_json(&self) -> String {
        let mut s = String::with_capacity(1024);
        s.push_str("\"seccomp\":{");
        // Allow by default and kill the named syscalls, matching the BPF
        // filter's shape and for the same reason: an allowlist that breaks
        // `cargo build` gets switched off. See `linux::seccomp`.
        s.push_str("\"defaultAction\":\"SCMP_ACT_ALLOW\",");
        s.push_str("\"architectures\":[\"SCMP_ARCH_X86_64\",\"SCMP_ARCH_AARCH64\"],");
        s.push_str("\"syscalls\":[{\"action\":\"SCMP_ACT_KILL_PROCESS\",\"names\":[");
        for (i, name) in shellguard_enforce::DENIED_SYSCALLS.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json::quote(name));
        }
        s.push_str("]}]}");
        s
    }

    /// The argv that would launch this bundle.
    pub fn launch_argv(&self, bundle: &Path, id: &str) -> Vec<String> {
        vec![
            self.binary.to_string_lossy().into_owned(),
            format!("--platform={}", self.platform),
            "--network=none".to_string(),
            "run".to_string(),
            "--bundle".to_string(),
            bundle.to_string_lossy().into_owned(),
            id.to_string(),
        ]
    }

    fn binary_on_path(&self) -> bool {
        if self.binary.is_absolute() {
            return self.binary.exists();
        }
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d.join(&self.binary).exists()))
            .unwrap_or(false)
    }
}

impl Runtime for GvisorRuntime {
    fn name(&self) -> &'static str {
        "gvisor"
    }

    fn isolation(&self) -> Isolation {
        Isolation::Paravirtual
    }

    fn availability(&self) -> Availability {
        if !cfg!(target_os = "linux") {
            return Availability::Unavailable("gVisor requires Linux".into());
        }
        if !self.binary_on_path() {
            return Availability::Unavailable(format!("{} is not on PATH", self.binary.display()));
        }
        if self.rootfs.is_none() {
            return Availability::Unavailable("no container rootfs configured".into());
        }
        Availability::Ready
    }

    fn execute(&self, payload: &Payload) -> Result<ExecResult, RuntimeError> {
        if let Availability::Unavailable(why) = self.availability() {
            return Err(RuntimeError::Unavailable(why));
        }
        let _ = payload;
        Err(RuntimeError::Unavailable(
            "the gVisor launch path is unverified; see DESIGN.md § 12".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellguard_enforce::Profile;
    use std::time::Duration;

    fn payload(net: bool) -> Payload {
        let ws = PathBuf::from("/srv/agent/ws");
        let mut profile = Profile::locked_down(&ws);
        profile.allow_network = net;
        Payload::new("echo hi", ws, profile).with_timeout(Duration::from_secs(5))
    }

    fn parsed(net: bool) -> json::Json {
        let s = GvisorRuntime::default().with_rootfs("/srv/rootfs").oci_config(&payload(net));
        json::parse(&s).unwrap_or_else(|e| panic!("{e}\n{s}"))
    }

    #[test]
    fn the_bundle_is_valid_oci_json() {
        let v = parsed(false);
        assert_eq!(v.get("ociVersion").and_then(json::Json::as_str), Some("1.0.2"));
        assert!(v.get("process").is_some());
        assert!(v.get("root").is_some());
        assert!(v.get("linux").is_some());
    }

    #[test]
    fn the_root_is_read_only_and_the_workspace_is_the_only_host_path_mounted() {
        let v = parsed(false);
        assert_eq!(
            v.get("root").and_then(|r| r.get("readonly")).and_then(json::Json::as_bool),
            Some(true)
        );
        let mounts = v.get("mounts").and_then(json::Json::as_array).unwrap();
        let binds: Vec<&json::Json> = mounts
            .iter()
            .filter(|m| m.get("type").and_then(json::Json::as_str) == Some("bind"))
            .collect();
        assert_eq!(binds.len(), 1, "exactly one host path should be mounted in");
        assert_eq!(binds[0].get("source").and_then(json::Json::as_str), Some("/srv/agent/ws"));
        // This profile is `locked_down`: it grants no writes. This test used to
        // be named "only the workspace is writable" and never looked at `rw`
        // versus `ro`, which is how the workspace came to be writable here while
        // Seatbelt and Landlock made it read-only.
        let opts_all: Vec<&str> = binds[0]
            .get("options")
            .and_then(json::Json::as_array)
            .unwrap()
            .iter()
            .filter_map(json::Json::as_str)
            .collect();
        assert!(opts_all.contains(&"ro") && !opts_all.contains(&"rw"), "{opts_all:?}");
        let opts: Vec<&str> = binds[0]
            .get("options")
            .and_then(json::Json::as_array)
            .unwrap()
            .iter()
            .filter_map(json::Json::as_str)
            .collect();
        assert!(opts.contains(&"nosuid"), "{opts:?}");
        assert!(opts.contains(&"nodev"), "{opts:?}");
    }

    #[test]
    fn every_capability_is_dropped() {
        let v = parsed(false);
        let caps = v.get("process").and_then(|p| p.get("capabilities")).unwrap();
        for set in ["bounding", "effective", "inheritable", "permitted", "ambient"] {
            assert_eq!(
                caps.get(set).and_then(json::Json::as_array).map(<[_]>::len),
                Some(0),
                "{set} is not empty"
            );
        }
        assert_eq!(
            v.get("process").and_then(|p| p.get("noNewPrivileges")).and_then(json::Json::as_bool),
            Some(true)
        );
    }

    #[test]
    fn the_seccomp_profile_carries_the_same_denylist_as_the_bpf_filter() {
        // One list, so the two backends cannot drift apart and quietly protect
        // against different things.
        let v = parsed(false);
        let names: Vec<&str> = v
            .get("linux")
            .and_then(|l| l.get("seccomp"))
            .and_then(|s| s.get("syscalls"))
            .and_then(json::Json::as_array)
            .unwrap()[0]
            .get("names")
            .and_then(json::Json::as_array)
            .unwrap()
            .iter()
            .filter_map(json::Json::as_str)
            .collect();

        assert_eq!(names.len(), shellguard_enforce::DENIED_SYSCALLS.len());
        for want in shellguard_enforce::DENIED_SYSCALLS {
            assert!(names.contains(want), "{want} is missing from the OCI profile");
        }
        assert!(names.contains(&"io_uring_setup"), "the io_uring hole is open");
    }

    #[test]
    fn the_kill_action_actually_kills() {
        let v = parsed(false);
        let rule = &v
            .get("linux")
            .and_then(|l| l.get("seccomp"))
            .and_then(|s| s.get("syscalls"))
            .and_then(json::Json::as_array)
            .unwrap()[0];
        assert_eq!(rule.get("action").and_then(json::Json::as_str), Some("SCMP_ACT_KILL_PROCESS"));
    }

    #[test]
    fn the_network_namespace_appears_only_when_network_is_denied() {
        let has_netns = |net: bool| {
            parsed(net)
                .get("linux")
                .and_then(|l| l.get("namespaces"))
                .and_then(json::Json::as_array)
                .unwrap()
                .iter()
                .any(|n| n.get("type").and_then(json::Json::as_str) == Some("network"))
        };
        assert!(has_netns(false), "a no-network profile should unshare the netns");
        assert!(!has_netns(true), "a network-granted profile should not");
    }

    #[test]
    fn host_memory_and_firmware_are_masked() {
        let v = parsed(false);
        let masked: Vec<&str> = v
            .get("linux")
            .and_then(|l| l.get("maskedPaths"))
            .and_then(json::Json::as_array)
            .unwrap()
            .iter()
            .filter_map(json::Json::as_str)
            .collect();
        assert!(masked.contains(&"/proc/kcore"), "host physical memory is readable");
        assert!(masked.contains(&"/sys/firmware"));
    }

    #[test]
    fn a_command_with_quotes_survives_into_the_bundle() {
        let r = GvisorRuntime::default().with_rootfs("/srv/rootfs");
        let mut p = payload(false);
        p.command = r#"echo "a\"b"; printf '\n'"#.to_string();
        let v = json::parse(&r.oci_config(&p)).unwrap();
        let args: Vec<&str> = v
            .get("process")
            .and_then(|pr| pr.get("args"))
            .and_then(json::Json::as_array)
            .unwrap()
            .iter()
            .filter_map(json::Json::as_str)
            .collect();
        assert_eq!(args, vec!["/bin/sh", "-c", p.command.as_str()]);
    }

    #[test]
    fn the_launch_argv_disables_host_networking() {
        let argv = GvisorRuntime::default().launch_argv(Path::new("/tmp/bundle"), "abc");
        assert!(argv.iter().any(|a| a == "--network=none"), "{argv:?}");
        assert!(argv.iter().any(|a| a.starts_with("--platform=")), "{argv:?}");
        assert_eq!(argv.last().map(String::as_str), Some("abc"));
    }

    #[test]
    fn it_is_unavailable_here_and_says_why() {
        let a = GvisorRuntime::default().availability();
        assert!(!a.is_ready());
        assert!(a.reason().unwrap().contains("Linux") || a.reason().unwrap().contains("PATH"));
    }

    // ------------------------------------------------------- mount / profile

    /// One `bind` mount, as the OCI config states it.
    #[derive(Debug)]
    struct Bind {
        dest: String,
        source: String,
        opts: Vec<String>,
    }

    impl Bind {
        fn writable(&self) -> bool {
            self.opts.iter().any(|o| o == "rw") && !self.opts.iter().any(|o| o == "ro")
        }
    }

    fn binds(config: &str) -> Vec<Bind> {
        let v = json::parse(config).unwrap_or_else(|e| panic!("{e}\n{config}"));
        v.get("mounts")
            .and_then(json::Json::as_array)
            .unwrap()
            .iter()
            .filter(|m| m.get("type").and_then(json::Json::as_str) == Some("bind"))
            .map(|m| Bind {
                dest: m.get("destination").and_then(json::Json::as_str).unwrap().to_string(),
                source: m.get("source").and_then(json::Json::as_str).unwrap().to_string(),
                opts: m
                    .get("options")
                    .and_then(json::Json::as_array)
                    .unwrap()
                    .iter()
                    .filter_map(json::Json::as_str)
                    .map(String::from)
                    .collect(),
            })
            .collect()
    }

    fn config_for(profile: Profile) -> String {
        let ws = PathBuf::from("/srv/agent/ws");
        let payload = Payload::new("echo hi", ws, profile).with_timeout(Duration::from_secs(5));
        GvisorRuntime::default().with_rootfs("/srv/rootfs").oci_config(&payload)
    }

    #[test]
    fn a_read_only_profile_gets_a_read_only_workspace() {
        // The workspace is readable and not writable under Landlock and
        // Seatbelt when nothing granted a write. It must not be writable here.
        let b = binds(&config_for(Profile::locked_down("/srv/agent/ws")));
        assert_eq!(b.len(), 1);
        assert!(!b[0].writable(), "a read-only profile got a writable workspace: {:?}", b[0]);
        assert!(b[0].opts.iter().any(|o| o == "ro"), "{:?}", b[0]);
    }

    #[test]
    fn a_profile_that_grants_writes_gets_a_writable_workspace() {
        let p =
            Profile::from_capabilities("/srv/agent/ws", &[shellguard_policy::Capability::FsWrite]);
        let b = binds(&config_for(p));
        assert_eq!(b.len(), 1);
        assert!(b[0].writable(), "{:?}", b[0]);
    }

    // ---------------------------------------------------------------- parity

    use shellguard_policy::Capability;
    use std::collections::BTreeSet;

    fn all_capabilities() -> Vec<Capability> {
        use Capability::*;
        let all = vec![
            FsRead,
            FsWrite,
            FsDelete,
            NetConnect,
            NetListen,
            ProcSpawn,
            ProcSignal,
            PrivEsc,
            DeviceWrite,
            KernelModule,
            ShellEscape,
            PackageInstall,
            VcsHistoryRewrite,
            CredentialAccess,
            SandboxEscape,
        ];
        // A compile-time guard: a new capability makes this match non-exhaustive,
        // so the parity run below cannot silently skip it.
        for c in &all {
            match c {
                FsRead | FsWrite | FsDelete | NetConnect | NetListen | ProcSpawn | ProcSignal
                | PrivEsc | DeviceWrite | KernelModule | ShellEscape | PackageInstall
                | VcsHistoryRewrite | CredentialAccess | SandboxEscape => {}
            }
        }
        all
    }

    /// A spread of profiles: nothing granted, each capability alone, all of them
    /// together, each with and without a private scratch directory, and
    /// hand-built ones with extra and nested paths.
    fn profiles() -> Vec<(String, Profile)> {
        const WS: &str = "/srv/agent/ws";
        let mut v: Vec<(String, Profile)> = vec![("locked down".into(), Profile::locked_down(WS))];
        for c in all_capabilities() {
            v.push((format!("{c:?}"), Profile::from_capabilities(WS, &[c])));
        }
        v.push(("every capability".into(), Profile::from_capabilities(WS, &all_capabilities())));

        let with_scratch: Vec<_> = v
            .iter()
            .map(|(n, p)| {
                (format!("{n} + scratch"), p.clone().with_private_tmp("/var/scratch/exec-1"))
            })
            .collect();
        v.extend(with_scratch);

        let mut extra = Profile::locked_down(WS).with_private_tmp("/var/scratch/exec-2");
        extra.read_paths = vec!["/data/reference".into(), "/srv/agent/ws/vendor".into()];
        extra.write_paths = vec!["/data/cache".into(), "/srv/agent/ws/build/out".into()];
        v.push(("extra read and write paths, some nested in the workspace".into(), extra));

        let mut writable_ws = Profile::from_capabilities(WS, &[Capability::FsWrite]);
        writable_ws.read_paths = vec!["/srv/agent/ws/docs".into(), "/opt/tools".into()];
        v.push(("writable workspace + read-only extras".into(), writable_ws));
        v
    }

    fn sources(binds: &[Bind], writable: bool) -> BTreeSet<String> {
        binds.iter().filter(|b| b.writable() == writable).map(|b| b.source.clone()).collect()
    }

    fn granted(p: &Profile, access: Access) -> BTreeSet<String> {
        p.fs_grants()
            .into_iter()
            .filter(|g| g.access == access && p.tmp.as_deref() != Some(g.path.as_path()))
            .map(|g| g.path.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn parity_the_container_writes_exactly_what_the_profile_grants_writes_to() {
        for (name, p) in profiles() {
            let b = binds(&config_for(p.clone()));
            assert_eq!(
                sources(&b, true),
                granted(&p, Access::Write),
                "{name}: writable host paths differ from the profile's write grants"
            );
        }
    }

    #[test]
    fn parity_the_container_reads_exactly_what_the_profile_grants_reads_to() {
        for (name, p) in profiles() {
            let b = binds(&config_for(p.clone()));
            assert_eq!(
                sources(&b, false),
                granted(&p, Access::Read),
                "{name}: read-only host paths differ from the profile's read grants"
            );
        }
    }

    #[test]
    fn parity_no_host_path_appears_that_the_profile_did_not_grant() {
        for (name, p) in profiles() {
            let all_grants: BTreeSet<String> =
                p.fs_grants().iter().map(|g| g.path.to_string_lossy().into_owned()).collect();
            for b in binds(&config_for(p.clone())) {
                assert!(
                    all_grants.contains(&b.source),
                    "{name}: {} is mounted but was never granted",
                    b.source
                );
            }
        }
    }

    #[test]
    fn parity_the_hosts_own_system_directories_are_never_mounted() {
        // Landlock reads the host's /usr and /etc directly. A container gets the
        // bundle's root instead, and must not have the host's mounted over it.
        for (name, p) in profiles() {
            for b in binds(&config_for(p.clone())) {
                for sys in [
                    "/", "/usr", "/etc", "/bin", "/lib", "/lib64", "/sbin", "/proc", "/sys",
                    "/dev", "/root", "/home",
                ] {
                    assert_ne!(
                        b.source, sys,
                        "{name}: the host's {sys} is mounted into the container"
                    );
                }
            }
        }
    }

    #[test]
    fn parity_every_bind_is_nosuid_and_nodev() {
        for (name, p) in profiles() {
            for b in binds(&config_for(p.clone())) {
                assert!(
                    b.opts.iter().any(|o| o == "nosuid") && b.opts.iter().any(|o| o == "nodev"),
                    "{name}: {b:?}"
                );
            }
        }
    }

    #[test]
    fn parity_every_bind_says_ro_or_rw_and_never_both_or_neither() {
        for (name, p) in profiles() {
            for b in binds(&config_for(p.clone())) {
                let ro = b.opts.iter().any(|o| o == "ro");
                let rw = b.opts.iter().any(|o| o == "rw");
                assert!(ro ^ rw, "{name}: {b:?}");
            }
        }
    }

    #[test]
    fn parity_the_private_scratch_is_a_container_tmpfs_and_never_a_host_bind() {
        for (name, p) in profiles() {
            let cfg = config_for(p.clone());
            let v = json::parse(&cfg).unwrap();
            let mounts = v.get("mounts").and_then(json::Json::as_array).unwrap();
            let tmpfs_at_tmp = mounts
                .iter()
                .filter(|m| {
                    m.get("destination").and_then(json::Json::as_str) == Some("/tmp")
                        && m.get("type").and_then(json::Json::as_str) == Some("tmpfs")
                })
                .count();
            assert_eq!(tmpfs_at_tmp, usize::from(p.tmp.is_some()), "{name}");

            if let Some(t) = &p.tmp {
                let t = t.to_string_lossy();
                assert!(
                    binds(&cfg).iter().all(|b| b.source != t),
                    "{name}: the host scratch directory was bound into the container"
                );
            }
        }
    }

    #[test]
    fn parity_a_profile_with_no_scratch_directory_has_no_writable_temp_anywhere() {
        // Seatbelt and Landlock give such a profile no writable temp location, so
        // the container must not invent one.
        let cfg = config_for(Profile::locked_down("/srv/agent/ws"));
        let v = json::parse(&cfg).unwrap();
        let mounts = v.get("mounts").and_then(json::Json::as_array).unwrap();
        assert!(
            !mounts
                .iter()
                .any(|m| m.get("destination").and_then(json::Json::as_str) == Some("/tmp")),
            "a writable /tmp exists although the profile has no scratch directory"
        );
    }

    #[test]
    fn parity_network_is_denied_exactly_when_the_profile_denies_it() {
        for (name, p) in profiles() {
            let v = json::parse(&config_for(p.clone())).unwrap();
            let has_netns = v
                .get("linux")
                .and_then(|l| l.get("namespaces"))
                .and_then(json::Json::as_array)
                .unwrap()
                .iter()
                .any(|n| n.get("type").and_then(json::Json::as_str) == Some("network"));
            assert_eq!(has_netns, !p.allow_network, "{name}");
        }
    }

    #[test]
    fn parity_mounts_are_ordered_parents_first_with_no_destination_twice() {
        for (name, p) in profiles() {
            let b = binds(&config_for(p.clone()));
            let dests: Vec<&str> = b.iter().map(|x| x.dest.as_str()).collect();
            let unique: BTreeSet<&&str> = dests.iter().collect();
            assert_eq!(
                unique.len(),
                dests.len(),
                "{name}: a destination is mounted twice: {dests:?}"
            );

            for (i, d) in dests.iter().enumerate() {
                for later in &dests[i + 1..] {
                    assert!(
                        !Path::new(d).starts_with(later),
                        "{name}: {d} is mounted before its parent {later}: {dests:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn parity_the_workspace_lands_at_the_guest_workspace_and_nested_grants_beneath_it() {
        let mut p = Profile::locked_down("/srv/agent/ws");
        p.write_paths.push("/srv/agent/ws/build/out".into());
        p.read_paths.push("/srv/agent/ws/docs".into());
        let b = binds(&config_for(p));
        let by_src = |s: &str| {
            b.iter().find(|x| x.source == s).unwrap_or_else(|| panic!("{s} not mounted: {b:?}"))
        };

        assert_eq!(by_src("/srv/agent/ws").dest, "/workspace");
        assert_eq!(by_src("/srv/agent/ws/docs").dest, "/workspace/docs");
        assert_eq!(by_src("/srv/agent/ws/build/out").dest, "/workspace/build/out");
        assert!(by_src("/srv/agent/ws/build/out").writable());
        assert!(!by_src("/srv/agent/ws/docs").writable());
        assert!(
            !by_src("/srv/agent/ws").writable(),
            "a nested write grant must not make its parent writable"
        );
    }

    #[test]
    fn parity_grants_outside_the_workspace_keep_their_own_path() {
        let mut p = Profile::locked_down("/srv/agent/ws");
        p.read_paths.push("/data/reference".into());
        p.write_paths.push("/data/cache".into());
        let b = binds(&config_for(p));
        let dest_of = |s: &str| b.iter().find(|x| x.source == s).unwrap().dest.clone();
        assert_eq!(dest_of("/data/reference"), "/data/reference");
        assert_eq!(dest_of("/data/cache"), "/data/cache");
    }

    #[test]
    fn parity_a_destination_collision_resolves_to_the_lower_access() {
        // A hand-built profile granting a host path equal to the guest workspace.
        // Fail closed: the path keeps the access that lets it do less.
        let mut p = Profile::locked_down("/srv/agent/ws");
        p.write_paths.push("/workspace".into());
        let b = binds(&config_for(p));
        let at: Vec<_> = b.iter().filter(|x| x.dest == "/workspace").collect();
        assert_eq!(at.len(), 1, "{b:?}");
        assert!(!at[0].writable(), "a collision resolved towards more access: {:?}", at[0]);
    }

    #[test]
    fn parity_the_guests_working_directory_and_home_are_the_workspace_mount() {
        let v = json::parse(&config_for(Profile::locked_down("/srv/agent/ws"))).unwrap();
        let process = v.get("process").unwrap();
        assert_eq!(process.get("cwd").and_then(json::Json::as_str), Some("/workspace"));
        let home = process
            .get("env")
            .and_then(json::Json::as_array)
            .unwrap()
            .iter()
            .filter_map(json::Json::as_str)
            .find(|e| e.starts_with("HOME="))
            .unwrap();
        assert_eq!(home, "HOME=/workspace");
    }
}
