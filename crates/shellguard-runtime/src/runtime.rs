//! The execution runtime abstraction.
//!
//! A runtime is somewhere a command can run with a [`Profile`] applied. There
//! are four, in increasing order of isolation and cost:
//!
//! | runtime | isolation | start cost | verified here |
//! |---|---|---|---|
//! | [`crate::local`] | kernel sandbox, shared kernel | ~1–3 ms | yes |
//! | [`crate::vm::gvisor`] | user-space kernel | ~50–150 ms | no Linux host |
//! | [`crate::vm::firecracker`] | hardware VM, own kernel | ~125 ms cold | no Linux host |
//! | [`crate::vm::vz`] | hardware VM, own kernel | ~0.5–1.5 s cold | no guest kernel |
//!
//! The interface is the same for all of them so the choice is a deployment
//! decision rather than a code change, and so a fast local runtime can be used
//! for the overwhelming majority of commands that a checkpoint already makes
//! recoverable.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use shellguard_enforce::Profile;

/// What to run.
#[derive(Clone, Debug)]
pub struct Payload {
    /// Shell source. Passed to the guest's shell, not to `exec` — the gate has
    /// already judged it as shell.
    pub command: String,
    pub workspace: PathBuf,
    /// The confinement derived from the gate's decision.
    pub profile: Profile,
    pub timeout: Duration,
    /// Extra environment. Deliberately additive to a minimal base rather than
    /// inheriting the supervisor's environment, which is full of credentials.
    pub env: Vec<(String, String)>,
}

impl Payload {
    pub fn new(
        command: impl Into<String>,
        workspace: impl Into<PathBuf>,
        profile: Profile,
    ) -> Self {
        Payload {
            command: command.into(),
            workspace: workspace.into(),
            profile,
            timeout: Duration::from_secs(120),
            env: Vec::new(),
        }
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }
}

/// What happened.
#[derive(Clone, Debug, Default)]
pub struct ExecResult {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Time to get an execution slot ready. This is the number the sub-200 ms
    /// target is about, and it is reported separately from the command's own
    /// runtime precisely so the two cannot be confused.
    pub acquire: Duration,
    /// Time the command itself ran.
    pub run: Duration,
}

impl ExecResult {
    pub fn ok(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }

    pub fn outcome(&self) -> crate::rollback::ExecOutcome {
        crate::rollback::ExecOutcome { exit_code: self.exit_code, timed_out: self.timed_out }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Availability {
    Ready,
    /// Present but not usable, with the reason. Reported rather than hidden:
    /// "gVisor is unavailable because runsc is not on PATH" is actionable and
    /// "isolation failed" is not.
    Unavailable(String),
}

impl Availability {
    pub fn is_ready(&self) -> bool {
        matches!(self, Availability::Ready)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Availability::Ready => None,
            Availability::Unavailable(r) => Some(r),
        }
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Unavailable(String),
    Spawn(std::io::Error),
    Enforce(shellguard_enforce::EnforceError),
    Protocol(String),
    /// The audit log is required and could not be written, so the command was
    /// not run. Distinct from the others because nothing went wrong with the
    /// command: it was stopped on purpose, before it started.
    Audit(String),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::Unavailable(r) => write!(f, "runtime unavailable: {r}"),
            RuntimeError::Spawn(e) => write!(f, "could not start: {e}"),
            RuntimeError::Enforce(e) => write!(f, "confinement failed: {e}"),
            RuntimeError::Protocol(m) => write!(f, "runtime protocol error: {m}"),
            RuntimeError::Audit(m) => write!(f, "audit log unavailable: {m}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<std::io::Error> for RuntimeError {
    fn from(e: std::io::Error) -> Self {
        RuntimeError::Spawn(e)
    }
}

impl From<shellguard_enforce::EnforceError> for RuntimeError {
    fn from(e: shellguard_enforce::EnforceError) -> Self {
        RuntimeError::Enforce(e)
    }
}

/// Somewhere a confined command can run.
pub trait Runtime: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &'static str;

    /// Whether this runtime can be used here, and if not, why.
    fn availability(&self) -> Availability;

    fn execute(&self, payload: &Payload) -> Result<ExecResult, RuntimeError>;

    /// Isolation strength, for choosing between what is available.
    fn isolation(&self) -> Isolation;
}

/// How strongly a runtime separates the command from the host.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Isolation {
    /// Kernel sandbox, shared kernel. A kernel bug is a full escape.
    Sandbox,
    /// User-space kernel intercepting syscalls (gVisor).
    Paravirtual,
    /// Hardware virtualisation with its own kernel.
    Virtual,
}

impl Isolation {
    pub fn as_str(self) -> &'static str {
        match self {
            Isolation::Sandbox => "sandbox",
            Isolation::Paravirtual => "paravirtual",
            Isolation::Virtual => "virtual",
        }
    }
}

/// Run a prepared command, capturing output, with a timeout.
///
/// Output is drained on threads. A child that fills the pipe buffer while the
/// parent waits on `wait()` deadlocks — the classic way a subprocess helper
/// works in testing and hangs the first time a command is chatty.
pub(crate) fn run_capturing(
    mut cmd: Command,
    timeout: Duration,
) -> Result<ExecResult, RuntimeError> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

    let start = Instant::now();
    let mut child = cmd.spawn()?;

    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = out_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = err_pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let status = wait_timeout(&mut child, timeout);
    let timed_out = status.is_none();
    if timed_out {
        let _ = child.kill();
        let _ = child.wait();
    }

    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();

    Ok(ExecResult {
        exit_code: status.and_then(|s| s.code()),
        timed_out,
        stdout,
        stderr,
        acquire: Duration::ZERO,
        run: start.elapsed(),
    })
}

pub(crate) fn wait_timeout(
    child: &mut Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    let mut backoff = Duration::from_micros(200);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(backoff);
        // Back off so a short command is noticed almost immediately while a
        // long one does not spin a core for minutes.
        backoff = (backoff * 2).min(Duration::from_millis(20));
    }
}

/// A temp name unlikely to collide, without a random-number dependency.
///
/// A fixed filename here would be two bugs: concurrent callers clobber each
/// other's file, and a predictable path in a shared directory is somewhere an
/// attacker can plant a symlink before the write.
pub(crate) fn unique_temp_name(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{prefix}-{}-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed), nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output_and_exit_code() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "echo out; echo err >&2; exit 3"]);
        let r = run_capturing(c, Duration::from_secs(10)).unwrap();
        assert_eq!(r.exit_code, Some(3));
        assert!(!r.timed_out);
        assert_eq!(String::from_utf8_lossy(&r.stdout).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&r.stderr).trim(), "err");
        assert!(!r.ok());
    }

    #[test]
    fn a_chatty_command_does_not_deadlock() {
        // Far more than a pipe buffer. Without the reader threads this hangs.
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "for i in $(seq 1 20000); do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done"]);
        let r = run_capturing(c, Duration::from_secs(30)).unwrap();
        assert_eq!(r.exit_code, Some(0));
        assert!(r.stdout.len() > 600_000, "only got {} bytes", r.stdout.len());
    }

    #[test]
    fn a_hanging_command_times_out_and_is_killed() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "sleep 60"]);
        let t = Instant::now();
        let r = run_capturing(c, Duration::from_millis(200)).unwrap();
        assert!(r.timed_out);
        assert_eq!(r.exit_code, None);
        assert!(t.elapsed() < Duration::from_secs(10), "took {:?}", t.elapsed());
    }

    #[test]
    fn isolation_is_ordered_by_strength() {
        assert!(Isolation::Sandbox < Isolation::Paravirtual);
        assert!(Isolation::Paravirtual < Isolation::Virtual);
    }

    #[test]
    fn availability_carries_a_reason() {
        let a = Availability::Unavailable("runsc is not on PATH".into());
        assert!(!a.is_ready());
        assert_eq!(a.reason(), Some("runsc is not on PATH"));
        assert_eq!(Availability::Ready.reason(), None);
    }
}
