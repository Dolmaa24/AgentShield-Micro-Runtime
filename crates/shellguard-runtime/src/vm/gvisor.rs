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
//! root is read-only, only the workspace is mounted writable, and `/proc` and
//! `/sys` are masked. That is the same *effect* by a different mechanism, and
//! calling it Landlock would misdescribe the threat model.
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

impl GvisorRuntime {
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
        s.push_str("\"mounts\":[");
        s.push_str("{\"destination\":\"/proc\",\"type\":\"proc\",\"source\":\"proc\"},");
        s.push_str(
            "{\"destination\":\"/dev\",\"type\":\"tmpfs\",\"source\":\"tmpfs\",\"options\":[\"nosuid\",\"strictatime\",\"mode=755\",\"size=65536k\"]},",
        );
        s.push_str(
            "{\"destination\":\"/tmp\",\"type\":\"tmpfs\",\"source\":\"tmpfs\",\"options\":[\"nosuid\",\"nodev\",\"mode=1777\"]},",
        );
        // The workspace, and nothing else from the host. `nosuid` and `nodev`
        // so a setuid binary or device node planted in the workspace cannot be
        // used from inside.
        s.push_str("{\"destination\":");
        s.push_str(&json::quote(&ws));
        s.push_str(",\"type\":\"bind\",\"source\":");
        s.push_str(&json::quote(&payload.workspace.to_string_lossy()));
        s.push_str(",\"options\":[\"rbind\",\"rw\",\"nosuid\",\"nodev\"]}");
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
    fn the_root_is_read_only_and_only_the_workspace_is_writable() {
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
}
