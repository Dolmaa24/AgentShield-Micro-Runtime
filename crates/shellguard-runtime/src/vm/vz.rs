//! macOS guests via Virtualization.framework.
//!
//! Rust builds the configuration and interprets the result; the Swift helper in
//! `swift/vzrunner.swift` drives the framework. See that file for why the split
//! exists.
//!
//! # What is verified here and what is not
//!
//! Configuration building, validation and the availability probe are exercised
//! against the real framework — `VZVirtualMachineConfiguration.validate()`
//! catches missing kernels, impossible memory sizes and bad share tags in
//! microseconds, without booting anything.
//!
//! Booting is **not** verified, because it needs a guest kernel image this
//! repository does not ship, and a guest agent to run commands. The wire
//! protocol that agent must speak is specified in [`GUEST_PROTOCOL`] so the
//! missing piece is a matter of building an image rather than of guessing.
//!
//! # On the latency target
//!
//! A cold boot here is roughly half a second to a second and a half for a
//! minimal Linux guest, so this runtime cannot meet a 200 ms target per
//! command and no amount of tuning will change that. It meets it through
//! [`crate::pool`], where slots are booted ahead of demand — see that module
//! for why that is the only real implementation rather than a way around the
//! requirement.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::json;
use crate::runtime::{
    run_capturing, unique_temp_name, Availability, ExecResult, Isolation, Payload, Runtime,
    RuntimeError,
};

/// What an in-guest agent must implement.
///
/// Documented as a constant so it ships with the code that depends on it rather
/// than in a README nobody reads while writing the guest side.
pub const GUEST_PROTOCOL: &str = "\
Listen on the configured vsock port. Frames both ways are a 4-byte big-endian
length followed by that many bytes of JSON.

request  {\"command\": <shell source>, \"timeout_ms\": <u64>}
response {\"exit_code\": <i32|null>, \"timed_out\": <bool>,
          \"stdout\": <string>, \"stderr\": <string>}

The guest shares the workspace over virtio-fs under the tag `workspace`; mount
it before serving. Exit after one command: guests are ephemeral, and a guest
that serves a second command has become shared state between two executions.";

/// Path to the compiled Swift helper, if the build produced one.
pub fn helper_path() -> Option<PathBuf> {
    option_env!("SHELLGUARD_VZRUNNER").map(PathBuf::from).filter(|p| p.exists())
}

#[derive(Clone, Debug)]
pub struct VzRuntime {
    /// Guest kernel image. Without one there is nothing to boot.
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub cpus: usize,
    pub memory_mb: u64,
    pub vsock_port: u32,
    pub cmdline: String,
}

impl Default for VzRuntime {
    fn default() -> Self {
        VzRuntime {
            kernel: None,
            initrd: None,
            cpus: 2,
            memory_mb: 1024,
            vsock_port: 1024,
            // `console=hvc0` so boot failures reach the serial port instead of
            // vanishing; `quiet` is deliberately absent for the same reason.
            cmdline: "console=hvc0 root=/dev/vda rw init=/sbin/agent-init".to_string(),
        }
    }
}

impl VzRuntime {
    pub fn with_kernel(mut self, kernel: impl Into<PathBuf>) -> Self {
        self.kernel = Some(kernel.into());
        self
    }

    pub fn with_initrd(mut self, initrd: impl Into<PathBuf>) -> Self {
        self.initrd = Some(initrd.into());
        self
    }

    pub fn with_resources(mut self, cpus: usize, memory_mb: u64) -> Self {
        self.cpus = cpus;
        self.memory_mb = memory_mb;
        self
    }

    /// The JSON the Swift helper consumes.
    pub fn config_json(&self, payload: &Payload) -> String {
        let kernel = self.kernel.as_deref().unwrap_or(Path::new("")).to_string_lossy().into_owned();
        let mut s = String::with_capacity(512);
        s.push('{');
        s.push_str(&format!("\"kernel\":{}", json::quote(&kernel)));
        if let Some(i) = &self.initrd {
            s.push_str(&format!(",\"initrd\":{}", json::quote(&i.to_string_lossy())));
        }
        s.push_str(&format!(",\"cmdline\":{}", json::quote(&self.cmdline)));
        s.push_str(&format!(",\"cpus\":{}", self.cpus));
        s.push_str(&format!(",\"memoryMB\":{}", self.memory_mb));
        s.push_str(&format!(",\"vsockPort\":{}", self.vsock_port));
        s.push_str(&format!(",\"command\":{}", json::quote(&payload.command)));
        s.push_str(&format!(",\"timeoutMs\":{}", payload.timeout.as_millis()));

        // The workspace is the only share. A guest that could see more of the
        // host filesystem would make the VM boundary pointless — the isolation
        // is only as narrow as what is mounted into it.
        s.push_str(",\"shares\":[{");
        s.push_str(&format!("\"tag\":{}", json::quote("workspace")));
        s.push_str(&format!(",\"path\":{}", json::quote(&payload.workspace.to_string_lossy())));
        s.push_str(",\"readOnly\":false");
        s.push_str("}]");
        s.push('}');
        s
    }

    /// Ask the framework whether this configuration is buildable, without
    /// booting it.
    pub fn validate(&self, payload: &Payload) -> Result<(), RuntimeError> {
        let helper = helper_path()
            .ok_or_else(|| RuntimeError::Unavailable("the Swift helper was not built".into()))?;

        let dir = scratch_dir()?;
        let cfg_path = dir.join(unique_temp_name("vz-config") + ".json");
        std::fs::write(&cfg_path, self.config_json(payload))?;

        let out = Command::new(&helper).arg("validate").arg(&cfg_path).output()?;
        let _ = std::fs::remove_file(&cfg_path);

        let body = String::from_utf8_lossy(&out.stdout);
        let parsed = json::parse(body.trim())
            .map_err(|e| RuntimeError::Protocol(format!("helper said {body:?}: {e}")))?;

        if parsed.get("valid").and_then(json::Json::as_bool) == Some(true) {
            Ok(())
        } else {
            let why = parsed
                .get("error")
                .and_then(json::Json::as_str)
                .unwrap_or("no reason given")
                .to_string();
            Err(RuntimeError::Unavailable(why))
        }
    }

    /// Whether the framework reports hardware virtualisation as usable.
    fn probe(helper: &Path) -> Availability {
        match Command::new(helper).arg("probe").output() {
            Ok(out) => {
                let body = String::from_utf8_lossy(&out.stdout);
                match json::parse(body.trim()) {
                    Ok(v) if v.get("supported").and_then(json::Json::as_bool) == Some(true) => {
                        Availability::Ready
                    }
                    _ => Availability::Unavailable(
                        "Virtualization.framework reports no hardware support here".into(),
                    ),
                }
            }
            Err(e) => Availability::Unavailable(format!("could not run the helper: {e}")),
        }
    }
}

impl Runtime for VzRuntime {
    fn name(&self) -> &'static str {
        "vz"
    }

    fn isolation(&self) -> Isolation {
        Isolation::Virtual
    }

    fn availability(&self) -> Availability {
        if !cfg!(target_os = "macos") {
            return Availability::Unavailable("Virtualization.framework is macOS only".into());
        }
        let Some(helper) = helper_path() else {
            return Availability::Unavailable(
                "the Swift helper was not built; is swiftc installed?".into(),
            );
        };
        // A configured kernel is what separates "could work" from "will work",
        // and it is the piece this repository does not ship.
        if self.kernel.is_none() {
            return Availability::Unavailable(
                "no guest kernel configured; set VzRuntime::with_kernel".into(),
            );
        }
        VzRuntime::probe(&helper)
    }

    fn execute(&self, payload: &Payload) -> Result<ExecResult, RuntimeError> {
        let helper = helper_path()
            .ok_or_else(|| RuntimeError::Unavailable("the Swift helper was not built".into()))?;
        if self.kernel.is_none() {
            return Err(RuntimeError::Unavailable("no guest kernel configured".into()));
        }

        let t0 = Instant::now();
        let dir = scratch_dir()?;
        let cfg_path = dir.join(unique_temp_name("vz-config") + ".json");
        std::fs::write(&cfg_path, self.config_json(payload))?;

        let mut cmd = Command::new(&helper);
        cmd.arg("run").arg(&cfg_path);

        // The helper's own budget is the payload's plus boot headroom, so a
        // guest that never comes up is killed by us rather than hanging.
        let outer = payload.timeout + Duration::from_secs(90);
        let raw = run_capturing(cmd, outer)?;
        let _ = std::fs::remove_file(&cfg_path);

        if raw.timed_out {
            return Ok(ExecResult { acquire: t0.elapsed(), ..raw });
        }

        let body = String::from_utf8_lossy(&raw.stdout);
        let parsed = json::parse(body.trim()).map_err(|e| {
            RuntimeError::Protocol(format!(
                "helper returned {body:?} ({e}); stderr: {}",
                String::from_utf8_lossy(&raw.stderr)
            ))
        })?;

        Ok(ExecResult {
            exit_code: parsed.get("exitCode").and_then(json::Json::as_i64).map(|v| v as i32),
            timed_out: parsed.get("timedOut").and_then(json::Json::as_bool).unwrap_or(false),
            stdout: parsed
                .get("stdout")
                .and_then(json::Json::as_str)
                .unwrap_or_default()
                .as_bytes()
                .to_vec(),
            stderr: parsed
                .get("stderr")
                .and_then(json::Json::as_str)
                .unwrap_or_default()
                .as_bytes()
                .to_vec(),
            acquire: Duration::from_secs_f64(
                parsed.get("bootMs").and_then(json::Json::as_f64).unwrap_or(0.0) / 1000.0,
            ),
            run: t0.elapsed(),
        })
    }
}

fn scratch_dir() -> Result<PathBuf, RuntimeError> {
    let dir = std::env::temp_dir().join("shellguard-vz");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellguard_enforce::Profile;

    fn payload() -> Payload {
        let ws = std::env::temp_dir().join("shellguard-vz-ws");
        std::fs::create_dir_all(&ws).unwrap();
        Payload::new("echo hello", ws.clone(), Profile::locked_down(ws))
            .with_timeout(Duration::from_secs(5))
    }

    fn fake_kernel() -> PathBuf {
        let p = std::env::temp_dir().join("shellguard-vz/fake-kernel");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"not a real kernel, but a real file").unwrap();
        p
    }

    #[test]
    fn the_config_is_well_formed_json() {
        let r = VzRuntime::default().with_kernel("/tmp/k");
        let s = r.config_json(&payload());
        let v = json::parse(&s).unwrap_or_else(|e| panic!("{e}: {s}"));
        assert_eq!(v.get("kernel").and_then(json::Json::as_str), Some("/tmp/k"));
        assert_eq!(v.get("cpus").and_then(json::Json::as_i64), Some(2));
        assert_eq!(v.get("memoryMB").and_then(json::Json::as_i64), Some(1024));
        assert_eq!(v.get("timeoutMs").and_then(json::Json::as_i64), Some(5000));
    }

    #[test]
    fn only_the_workspace_is_shared_into_the_guest() {
        // A guest that could see more of the host would make the VM boundary
        // pointless.
        let r = VzRuntime::default().with_kernel("/tmp/k");
        let p = payload();
        let v = json::parse(&r.config_json(&p)).unwrap();
        let shares = v.get("shares").and_then(json::Json::as_array).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].get("tag").and_then(json::Json::as_str), Some("workspace"));
        assert_eq!(
            shares[0].get("path").and_then(json::Json::as_str),
            Some(p.workspace.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn a_command_with_quotes_survives_the_json_round_trip() {
        let r = VzRuntime::default().with_kernel("/tmp/k");
        let mut p = payload();
        p.command = r#"echo "a\"b" && printf '\n\t'"#.to_string();
        let v = json::parse(&r.config_json(&p)).unwrap();
        assert_eq!(v.get("command").and_then(json::Json::as_str), Some(p.command.as_str()));
    }

    #[test]
    fn without_a_kernel_it_reports_why_rather_than_failing_obscurely() {
        let r = VzRuntime::default();
        let a = r.availability();
        assert!(!a.is_ready());
        assert!(a.reason().unwrap().contains("kernel"), "{a:?}");
    }

    // The tests below need the Swift helper, which needs swiftc at build time.
    // They skip rather than fail when it is absent, so a machine without Swift
    // still gets a green suite for everything that does not need it.

    #[test]
    fn the_framework_accepts_a_valid_configuration() {
        let Some(_) = helper_path() else {
            eprintln!("skipping: the Swift helper was not built");
            return;
        };
        let r = VzRuntime::default().with_kernel(fake_kernel()).with_resources(2, 512);
        r.validate(&payload()).unwrap_or_else(|e| panic!("validation failed: {e}"));
    }

    #[test]
    fn the_framework_rejects_an_impossible_configuration() {
        // Real validation, not our own checks: 1 MiB is below the framework's
        // minimum and only it knows that.
        let Some(_) = helper_path() else {
            eprintln!("skipping: the Swift helper was not built");
            return;
        };
        let r = VzRuntime::default().with_kernel(fake_kernel()).with_resources(2, 1);
        let err = r.validate(&payload()).unwrap_err();
        assert!(format!("{err}").contains("memorySize"), "{err}");
    }

    #[test]
    fn a_missing_kernel_file_is_caught_before_boot() {
        let Some(_) = helper_path() else {
            eprintln!("skipping: the Swift helper was not built");
            return;
        };
        let r = VzRuntime::default().with_kernel("/tmp/definitely-not-a-kernel-xyz");
        let err = r.validate(&payload()).unwrap_err();
        assert!(format!("{err}").contains("kernel not found"), "{err}");
    }

    #[test]
    fn hardware_virtualisation_is_available_on_this_host() {
        let Some(h) = helper_path() else {
            eprintln!("skipping: the Swift helper was not built");
            return;
        };
        assert_eq!(VzRuntime::probe(&h), Availability::Ready);
    }

    #[test]
    fn the_guest_protocol_is_documented() {
        // The missing piece is a guest image, not a guess about the interface.
        assert!(GUEST_PROTOCOL.contains("vsock"));
        assert!(GUEST_PROTOCOL.contains("exit_code"));
        assert!(GUEST_PROTOCOL.contains("workspace"));
    }
}
