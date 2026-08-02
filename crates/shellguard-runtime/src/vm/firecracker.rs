//! Firecracker microVMs.
//!
//! # Why the config file rather than the HTTP API
//!
//! Firecracker is normally driven by PUTs to a REST API on a unix socket.
//! For a one-shot microVM that is a lot of machinery — an HTTP client, a
//! socket dance, ordering constraints between endpoints — to arrive at a state
//! that `--config-file` expresses in one JSON document, atomically, before the
//! VM exists. The API earns its keep when a VM is reconfigured while running,
//! and these are ephemeral: they boot, run one command, and die.
//!
//! # Where the confinement comes from
//!
//! The guest runs a real Linux kernel, so `shellguard-enforce`'s seccomp-BPF
//! filter and Landlock ruleset apply *inside* it, enforced by the guest kernel
//! against the guest's own process. That is worth being precise about: the VM
//! boundary protects the host from the guest, and the in-guest confinement
//! protects the workspace from the command. They are different boundaries and
//! removing either leaves a real gap — a command with root in the guest can
//! still ruin the workspace that was mounted into it.
//!
//! Nothing here has run against Firecracker: there is no Linux host in this
//! repository's development environment. Config generation is tested against
//! the documented schema.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::json;
use crate::runtime::{Availability, ExecResult, Isolation, Payload, Runtime, RuntimeError};

#[derive(Clone, Debug)]
pub struct FirecrackerRuntime {
    /// The `firecracker` binary.
    pub binary: PathBuf,
    /// Uncompressed guest kernel — Firecracker boots vmlinux, not bzImage.
    pub kernel: Option<PathBuf>,
    /// Root filesystem image containing the guest agent.
    pub rootfs: Option<PathBuf>,
    pub vcpus: u32,
    pub memory_mib: u32,
    /// vsock context id for the guest. 0, 1 and 2 are reserved.
    pub guest_cid: u32,
    pub boot_args: String,
}

impl Default for FirecrackerRuntime {
    fn default() -> Self {
        FirecrackerRuntime {
            binary: PathBuf::from("firecracker"),
            kernel: None,
            rootfs: None,
            vcpus: 2,
            memory_mib: 1024,
            guest_cid: 3,
            // `reboot=k panic=1` so a guest that panics dies immediately
            // instead of sitting at a prompt holding a slot; `i8042.no*`
            // removes a device probe that is pure boot latency in a microVM.
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux \
                        i8042.nopnp i8042.dumbkbd init=/sbin/agent-init"
                .to_string(),
        }
    }
}

impl FirecrackerRuntime {
    pub fn with_kernel(mut self, kernel: impl Into<PathBuf>) -> Self {
        self.kernel = Some(kernel.into());
        self
    }

    pub fn with_rootfs(mut self, rootfs: impl Into<PathBuf>) -> Self {
        self.rootfs = Some(rootfs.into());
        self
    }

    pub fn with_resources(mut self, vcpus: u32, memory_mib: u32) -> Self {
        self.vcpus = vcpus;
        self.memory_mib = memory_mib;
        self
    }

    /// The `--config-file` document.
    pub fn config_json(&self, vsock_uds: &Path) -> String {
        let kernel = self.kernel.as_deref().unwrap_or(Path::new(""));
        let rootfs = self.rootfs.as_deref().unwrap_or(Path::new(""));

        let mut s = String::with_capacity(768);
        s.push('{');

        s.push_str("\"boot-source\":{");
        s.push_str(&format!("\"kernel_image_path\":{}", json::quote(&kernel.to_string_lossy())));
        s.push_str(&format!(",\"boot_args\":{}", json::quote(&self.boot_args)));
        s.push_str("},");

        // Read-write, because the guest agent needs somewhere to work. The
        // image is per-VM and discarded, so this does not persist between
        // executions — see `Warm::healthy` in the pool for why that matters.
        s.push_str("\"drives\":[{");
        s.push_str("\"drive_id\":\"rootfs\"");
        s.push_str(&format!(",\"path_on_host\":{}", json::quote(&rootfs.to_string_lossy())));
        s.push_str(",\"is_root_device\":true");
        s.push_str(",\"is_read_only\":false");
        s.push_str("}],");

        s.push_str("\"machine-config\":{");
        s.push_str(&format!("\"vcpu_count\":{}", self.vcpus));
        s.push_str(&format!(",\"mem_size_mib\":{}", self.memory_mib));
        // SMT off: a microVM sharing a physical core with another tenant is a
        // side-channel surface, and there is no benefit at these core counts.
        s.push_str(",\"smt\":false");
        s.push_str("},");

        // No network device at all. The control channel is vsock, so a guest
        // that needs no network gets no interface — the strongest possible
        // network policy, and free.
        s.push_str("\"vsock\":{");
        s.push_str(&format!("\"guest_cid\":{}", self.guest_cid));
        s.push_str(&format!(",\"uds_path\":{}", json::quote(&vsock_uds.to_string_lossy())));
        s.push('}');

        s.push('}');
        s
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

impl Runtime for FirecrackerRuntime {
    fn name(&self) -> &'static str {
        "firecracker"
    }

    fn isolation(&self) -> Isolation {
        Isolation::Virtual
    }

    fn availability(&self) -> Availability {
        if !cfg!(target_os = "linux") {
            return Availability::Unavailable("Firecracker requires Linux with KVM".into());
        }
        if !self.binary_on_path() {
            return Availability::Unavailable(format!("{} is not on PATH", self.binary.display()));
        }
        if !Path::new("/dev/kvm").exists() {
            return Availability::Unavailable("/dev/kvm is not present".into());
        }
        if self.kernel.is_none() || self.rootfs.is_none() {
            return Availability::Unavailable("no guest kernel or rootfs configured".into());
        }
        Availability::Ready
    }

    fn execute(&self, payload: &Payload) -> Result<ExecResult, RuntimeError> {
        if let Availability::Unavailable(why) = self.availability() {
            return Err(RuntimeError::Unavailable(why));
        }
        // Reaching here requires a Linux host with KVM, a kernel and a rootfs.
        // The launch path is written but has never run; rather than pretend
        // otherwise, it says so.
        let _ = payload;
        Err(RuntimeError::Unavailable(
            "the Firecracker launch path is unverified; see DESIGN.md § 12".into(),
        ))
    }
}

/// Seconds of headroom over the payload timeout, for boot and teardown.
pub const BOOT_HEADROOM: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FirecrackerRuntime {
        FirecrackerRuntime::default()
            .with_kernel("/var/lib/fc/vmlinux")
            .with_rootfs("/var/lib/fc/rootfs.ext4")
            .with_resources(4, 2048)
    }

    fn parsed() -> json::Json {
        let s = cfg().config_json(Path::new("/run/fc/vsock.sock"));
        json::parse(&s).unwrap_or_else(|e| panic!("{e}: {s}"))
    }

    #[test]
    fn the_config_matches_the_documented_schema() {
        let v = parsed();
        assert_eq!(
            v.get("boot-source")
                .and_then(|b| b.get("kernel_image_path"))
                .and_then(json::Json::as_str),
            Some("/var/lib/fc/vmlinux")
        );
        let drives = v.get("drives").and_then(json::Json::as_array).unwrap();
        assert_eq!(drives.len(), 1);
        assert_eq!(drives[0].get("is_root_device").and_then(json::Json::as_bool), Some(true));
        assert_eq!(
            v.get("machine-config").and_then(|m| m.get("vcpu_count")).and_then(json::Json::as_i64),
            Some(4)
        );
        assert_eq!(
            v.get("machine-config")
                .and_then(|m| m.get("mem_size_mib"))
                .and_then(json::Json::as_i64),
            Some(2048)
        );
    }

    #[test]
    fn there_is_no_network_device() {
        // The strongest network policy available, and free: a guest with no
        // interface cannot reach anything, whatever it runs.
        let v = parsed();
        assert!(v.get("network-interfaces").is_none());
        assert!(v.get("vsock").is_some(), "the control channel must still exist");
    }

    #[test]
    fn simultaneous_multithreading_is_disabled() {
        // A microVM sharing a physical core with another tenant is a
        // side-channel surface.
        let v = parsed();
        assert_eq!(
            v.get("machine-config").and_then(|m| m.get("smt")).and_then(json::Json::as_bool),
            Some(false)
        );
    }

    #[test]
    fn boot_args_make_a_panicking_guest_die_rather_than_hang() {
        let v = parsed();
        let args = v
            .get("boot-source")
            .and_then(|b| b.get("boot_args"))
            .and_then(json::Json::as_str)
            .unwrap();
        assert!(args.contains("panic=1"), "{args}");
        assert!(args.contains("reboot=k"), "{args}");
    }

    #[test]
    fn a_path_with_a_quote_cannot_break_the_config() {
        let r = FirecrackerRuntime::default().with_kernel("/tmp/k\"evil").with_rootfs("/tmp/r");
        let s = r.config_json(Path::new("/tmp/v.sock"));
        let v = json::parse(&s).unwrap_or_else(|e| panic!("injection broke the config: {e}"));
        assert_eq!(
            v.get("boot-source")
                .and_then(|b| b.get("kernel_image_path"))
                .and_then(json::Json::as_str),
            Some("/tmp/k\"evil")
        );
    }

    #[test]
    fn it_is_unavailable_here_and_says_why() {
        let a = FirecrackerRuntime::default().availability();
        assert!(!a.is_ready());
        let why = a.reason().unwrap();
        assert!(why.contains("Linux") || why.contains("PATH"), "{why}");
    }

    #[test]
    fn missing_images_are_reported_before_launch() {
        // Only reachable on Linux; elsewhere the OS check fires first.
        if cfg!(target_os = "linux") {
            let a = FirecrackerRuntime::default().availability();
            assert!(!a.is_ready());
        }
    }
}
