//! The local runtime: a confined subprocess on the host kernel.
//!
//! This is the one that runs by default, and for most commands it should be.
//! Isolation is a kernel sandbox rather than a virtual machine, so a kernel bug
//! is a full escape — but it starts in a couple of milliseconds, and paired
//! with a checkpoint it makes the common failure (a command that damages the
//! workspace) both contained and undoable. Reserving a VM for the commands that
//! actually warrant one is what keeps the whole system usable.
//!
//! The environment is built from nothing rather than inherited. A supervisor's
//! environment is where `AWS_SECRET_ACCESS_KEY` and `GITHUB_TOKEN` live, and
//! passing it into a command the agent wrote would hand over every credential
//! the operator has — a confinement that scopes the filesystem and then leaks
//! the environment has protected nothing worth protecting.

use std::process::Command;
use std::time::Instant;

use shellguard_enforce::Profile;

use crate::runtime::{
    run_capturing, Availability, ExecResult, Isolation, Payload, Runtime, RuntimeError,
};

#[derive(Debug, Default)]
pub struct LocalRuntime;

impl LocalRuntime {
    pub fn new() -> Self {
        LocalRuntime
    }
}

impl Runtime for LocalRuntime {
    fn name(&self) -> &'static str {
        "local"
    }

    fn isolation(&self) -> Isolation {
        Isolation::Sandbox
    }

    fn availability(&self) -> Availability {
        #[cfg(target_os = "macos")]
        {
            if std::path::Path::new("/usr/bin/sandbox-exec").exists() {
                Availability::Ready
            } else {
                Availability::Unavailable("/usr/bin/sandbox-exec is missing".into())
            }
        }
        #[cfg(target_os = "linux")]
        {
            Availability::Ready
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Availability::Unavailable(format!("no backend for {}", std::env::consts::OS))
        }
    }

    fn execute(&self, payload: &Payload) -> Result<ExecResult, RuntimeError> {
        let t0 = Instant::now();

        // A scratch directory of this execution's own, rather than the shared
        // system one. Removed when the guard drops, whatever the outcome.
        let scratch = Scratch::new()?;
        let confined = Payload {
            profile: payload.profile.clone().with_private_tmp(scratch.path()),
            ..payload.clone()
        };

        let mut cmd = self.build(&confined)?;
        base_env(&mut cmd, &confined);
        cmd.env("TMPDIR", scratch.path());
        let acquire = t0.elapsed();

        let mut result = run_capturing(cmd, confined.timeout)?;
        result.acquire = acquire;
        Ok(result)
    }
}

/// A private scratch directory, removed on drop.
struct Scratch {
    path: std::path::PathBuf,
}

impl Scratch {
    fn new() -> Result<Self, RuntimeError> {
        let path =
            std::env::temp_dir().join(crate::runtime::unique_temp_name("shellguard-scratch"));
        std::fs::create_dir_all(&path)?;
        Ok(Scratch { path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl LocalRuntime {
    #[cfg(target_os = "macos")]
    fn build(&self, payload: &Payload) -> Result<Command, RuntimeError> {
        // Confine a child, not ourselves: the supervisor stays outside so it
        // can still record what happened to a command killed inside.
        let argv = shellguard_enforce::macos::command(
            &payload.profile,
            "/bin/sh",
            &["-c", &payload.command],
        )?;
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd.current_dir(&payload.workspace);
        Ok(cmd)
    }

    #[cfg(target_os = "linux")]
    fn build(&self, payload: &Payload) -> Result<Command, RuntimeError> {
        use std::os::unix::process::CommandExt;

        // Built here, in the parent, where allocating is safe. The child then
        // makes syscalls only — see `shellguard_enforce::linux::Prepared`.
        let prepared = shellguard_enforce::linux::Prepared::new(&payload.profile)?;

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(&payload.command);
        cmd.current_dir(&payload.workspace);

        // SAFETY: the closure runs between fork and exec. It allocates nothing
        // and makes only syscalls, which is the requirement there.
        unsafe {
            cmd.pre_exec(move || {
                prepared.apply_in_child().map_err(std::io::Error::from_raw_os_error)
            });
        }
        Ok(cmd)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn build(&self, _payload: &Payload) -> Result<Command, RuntimeError> {
        Err(RuntimeError::Unavailable(format!("no backend for {}", std::env::consts::OS)))
    }
}

/// A minimal environment, built from nothing.
pub(crate) fn base_env(cmd: &mut Command, payload: &Payload) {
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin");
    // HOME points at the workspace, not the real one. Tools that write dotfiles
    // then write them somewhere the checkpoint covers, and a command that goes
    // looking for `~/.aws/credentials` finds nothing.
    cmd.env("HOME", &payload.workspace);
    cmd.env("TMPDIR", std::env::temp_dir());
    cmd.env("LANG", "C.UTF-8");
    // Non-interactive: a command that tries to open a pager or prompt should
    // fail rather than hang holding a slot.
    cmd.env("TERM", "dumb");
    cmd.env("CI", "1");
    cmd.env("DEBIAN_FRONTEND", "noninteractive");
    cmd.env("GIT_TERMINAL_PROMPT", "0");

    for (k, v) in &payload.env {
        cmd.env(k, v);
    }
}

/// The profile a payload should get when nothing more specific is known.
pub fn default_profile(workspace: impl Into<std::path::PathBuf>) -> Profile {
    Profile::locked_down(workspace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellguard_policy::Capability;
    use std::path::PathBuf;
    use std::time::Duration;

    fn workspace() -> PathBuf {
        let ws = std::env::temp_dir().join("shellguard-local-runtime/ws");
        std::fs::create_dir_all(&ws).unwrap();
        ws.canonicalize().unwrap()
    }

    fn payload(cmd: &str, caps: &[Capability]) -> Payload {
        let ws = workspace();
        Payload::new(cmd, ws.clone(), Profile::from_capabilities(ws, caps))
            .with_timeout(Duration::from_secs(30))
    }

    #[test]
    fn the_runtime_is_available_here() {
        let r = LocalRuntime::new();
        assert!(r.availability().is_ready(), "{:?}", r.availability());
        assert_eq!(r.isolation(), Isolation::Sandbox);
    }

    #[test]
    fn runs_a_command_and_captures_output() {
        let r = LocalRuntime::new();
        let res = r.execute(&payload("echo hello from the sandbox", &[])).unwrap();
        assert!(res.ok(), "stderr: {}", String::from_utf8_lossy(&res.stderr));
        assert_eq!(String::from_utf8_lossy(&res.stdout).trim(), "hello from the sandbox");
    }

    #[test]
    fn reports_a_nonzero_exit() {
        let r = LocalRuntime::new();
        let res = r.execute(&payload("exit 7", &[])).unwrap();
        assert_eq!(res.exit_code, Some(7));
        assert!(!res.ok());
    }

    #[test]
    fn a_write_outside_the_workspace_is_blocked() {
        // The confinement is real, not decorative.
        let marker = std::env::temp_dir().join("shellguard-local-should-not-exist");
        let _ = std::fs::remove_file(&marker);

        let r = LocalRuntime::new();
        let res = r
            .execute(&payload(
                &format!("echo pwned > {}", marker.display()),
                &[Capability::FsWrite],
            ))
            .unwrap();

        assert!(!res.ok(), "the write outside the workspace succeeded");
        assert!(!marker.exists());
    }

    #[test]
    fn a_write_inside_the_workspace_succeeds_when_granted() {
        let ws = workspace();
        let target = ws.join("allowed.txt");
        let _ = std::fs::remove_file(&target);

        let r = LocalRuntime::new();
        let res = r.execute(&payload("echo ok > allowed.txt", &[Capability::FsWrite])).unwrap();

        assert!(res.ok(), "stderr: {}", String::from_utf8_lossy(&res.stderr));
        assert_eq!(std::fs::read_to_string(&target).unwrap().trim(), "ok");
        let _ = std::fs::remove_file(&target);
    }

    #[test]
    fn the_supervisors_environment_does_not_leak_in() {
        // The whole point of building the environment from nothing.
        std::env::set_var("SHELLGUARD_FAKE_SECRET", "hunter2");
        let r = LocalRuntime::new();
        let res = r.execute(&payload("echo \"[$SHELLGUARD_FAKE_SECRET]\"", &[])).unwrap();
        assert_eq!(String::from_utf8_lossy(&res.stdout).trim(), "[]");
        std::env::remove_var("SHELLGUARD_FAKE_SECRET");
    }

    #[test]
    fn explicit_environment_is_passed_through() {
        let r = LocalRuntime::new();
        let mut p = payload("echo \"[$MY_VAR]\"", &[]);
        p.env.push(("MY_VAR".into(), "value".into()));
        let res = r.execute(&p).unwrap();
        assert_eq!(String::from_utf8_lossy(&res.stdout).trim(), "[value]");
    }

    #[test]
    fn home_points_at_the_workspace_not_the_real_home() {
        let r = LocalRuntime::new();
        let res = r.execute(&payload("echo $HOME", &[])).unwrap();
        let home = String::from_utf8_lossy(&res.stdout).trim().to_string();
        assert_eq!(home, workspace().display().to_string());
    }

    #[test]
    fn a_hanging_command_is_killed_at_the_timeout() {
        let r = LocalRuntime::new();
        let mut p = payload("sleep 60", &[]);
        p.timeout = Duration::from_millis(300);
        let t = Instant::now();
        let res = r.execute(&p).unwrap();
        assert!(res.timed_out);
        assert!(t.elapsed() < Duration::from_secs(10), "took {:?}", t.elapsed());
    }

    #[test]
    fn a_private_scratch_directory_is_writable_and_then_gone() {
        let r = LocalRuntime::new();
        let res = r
            .execute(&payload(
                "echo scratch > \"$TMPDIR/f\"; cat \"$TMPDIR/f\"; echo \"$TMPDIR\"",
                &[Capability::FsWrite],
            ))
            .unwrap();
        assert!(res.ok(), "stderr: {}", String::from_utf8_lossy(&res.stderr));

        let out = String::from_utf8_lossy(&res.stdout);
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some("scratch"));
        let dir = PathBuf::from(lines.next().expect("TMPDIR line").trim());

        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("shellguard-scratch-"));
        assert!(!dir.exists(), "the scratch directory outlived the execution");
    }

    #[test]
    fn one_executions_scratch_is_not_another_s() {
        let r = LocalRuntime::new();
        let a = r.execute(&payload("echo $TMPDIR", &[])).unwrap();
        let b = r.execute(&payload("echo $TMPDIR", &[])).unwrap();
        assert_ne!(a.stdout, b.stdout, "two executions shared a scratch directory");
    }

    #[test]
    fn acquisition_is_fast_enough_to_be_uninteresting() {
        // Reported separately from run time so a slow command cannot be
        // mistaken for slow isolation.
        let r = LocalRuntime::new();
        let res = r.execute(&payload("true", &[])).unwrap();
        assert!(res.acquire < Duration::from_millis(50), "acquisition took {:?}", res.acquire);
    }
}
