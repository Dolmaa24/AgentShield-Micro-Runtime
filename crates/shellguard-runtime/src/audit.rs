//! An append-only record of what was judged, what ran, and what was undone.
//!
//! # Why this exists
//!
//! The checkpoint answers "can I get my files back". It does not answer "what
//! was the agent trying to do, how often, and did the gate catch it" — and a
//! rolled-back command leaves no trace on disk by design. Without a record,
//! the only evidence that a defence worked is the absence of damage, which is
//! also what a defence that never fired looks like.
//!
//! # One line per event, JSON
//!
//! | `kind`     | written when                                                   |
//! |------------|----------------------------------------------------------------|
//! | `header`   | first line of every file, including after rotation             |
//! | `evaluate` | a command was judged and nothing was asked to run              |
//! | `refused`  | a command was submitted for execution and the gate stopped it  |
//! | `start`    | a command is about to run — **before** the checkpoint          |
//! | `finish`   | that command has ended (same `id` as its `start`)             |
//! | `error`    | that command could not be run to completion (same `id`)        |
//!
//! Execution is two records rather than one for a reason: a process that dies
//! mid-command never writes its `finish`, and a `start` with no matching
//! `finish` is exactly the trace such a death should leave. It is also what
//! lets [`AuditConfig::required`] mean something — the record that must
//! succeed is the one written *before* the command runs.
//!
//! # What is deliberately not recorded
//!
//! A log of every command is only useful if it is safe to keep, and commands
//! and their output carry credentials.
//!
//! * Output is not recorded unless [`AuditConfig::verbose`] is set.
//! * Command text, rule reasons, and anything else derived from what the agent
//!   wrote pass through [`crate::redact`] first. That is best-effort — see the
//!   caveats there — which is why output is off by default rather than merely
//!   redacted.
//! * The environment is never recorded.
//! * The file is created mode `0600`, and an existing file that is writable by
//!   its group or by others is refused: an audit log anyone can edit proves
//!   nothing.
//!
//! # What the log cannot tell you
//!
//! Only commands submitted to an engine holding this log appear in it. A
//! command run any other way is invisible here, and a quiet log is therefore
//! not evidence of a quiet agent. Every file's header says so in its own
//! `coverage` field, so the caveat travels with the data.
//!
//! # Concurrency and growth
//!
//! Every shellguard CLI invocation is its own process, so in-process locking
//! is not enough. Each write takes an `flock` on a sidecar file, checks the
//! size, rotates if needed, and appends the whole line in a single `write`.
//! Rotation is by size, keeps a fixed number of old files, and starts each new
//! file with a header.
//!
//! # Failure
//!
//! Failing to write a record is never silent. Failures are counted
//! ([`AuditLog::failures`]) and remembered ([`AuditLog::last_error`]), and the
//! engine surfaces them on the run. Whether a failure also *stops the command*
//! is a policy choice, not a constant: by default it does not (a full disk
//! should not make every command fail), and with [`AuditConfig::required`] it
//! does (an unauditable command does not run).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use shellguard_gate::{Decision, ReloadError, ReloadMode, ReloadReport};

use crate::engine::GuardedRun;
use crate::redact;

/// Bump when a field changes meaning or is removed. Adding a field does not.
pub const SCHEMA_VERSION: u32 = 1;

/// Below this, one record could exceed the file and rotation would churn.
pub const MIN_MAX_BYTES: u64 = 128 * 1024;

const COVERAGE: &str = "records only commands submitted to an engine holding this log; \
                        a command run any other way does not appear here";

/// How an audit log behaves.
#[derive(Clone, Debug)]
pub struct AuditConfig {
    pub path: PathBuf,
    /// Who opened the log: `"cli"`, `"ffi"`, `"library"`. Goes in the header.
    pub source: String,
    /// Rotate once a file would exceed this. Clamped up to [`MIN_MAX_BYTES`].
    pub max_bytes: u64,
    /// Rotated files to keep (`audit.jsonl.1` … `.N`). Zero keeps none.
    pub keep: usize,
    /// Also record the command's stdout and stderr (redacted, capped).
    pub verbose: bool,
    /// Refuse to run a command whose `start` record cannot be written.
    pub required: bool,
    /// Longest command recorded, in bytes after redaction.
    pub max_command: usize,
    /// Longest stdout or stderr recorded, in bytes after redaction.
    pub max_output: usize,
}

impl AuditConfig {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        AuditConfig {
            path: path.into(),
            source: "library".into(),
            max_bytes: 8 * 1024 * 1024,
            keep: 5,
            verbose: false,
            required: false,
            max_command: 8 * 1024,
            max_output: 16 * 1024,
        }
    }

    pub fn source(mut self, s: impl Into<String>) -> Self {
        self.source = s.into();
        self
    }
    pub fn verbose(mut self, yes: bool) -> Self {
        self.verbose = yes;
        self
    }
    pub fn required(mut self, yes: bool) -> Self {
        self.required = yes;
        self
    }
    pub fn rotate_at(mut self, bytes: u64, keep: usize) -> Self {
        self.max_bytes = bytes;
        self.keep = keep;
        self
    }
}

/// An open audit log. Cheap to share by reference; safe across threads and
/// processes.
#[derive(Debug)]
pub struct AuditLog {
    cfg: AuditConfig,
    lock_path: PathBuf,
    seq: AtomicU64,
    failures: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl AuditLog {
    /// Open (creating if needed) the log, and write its header.
    ///
    /// Errors here are configuration errors and are always loud, whatever
    /// [`AuditConfig::required`] says: someone who asked for a log at a path
    /// that cannot be written to has made a mistake worth telling them about
    /// before the first command, not after the hundredth.
    pub fn open(mut cfg: AuditConfig) -> io::Result<AuditLog> {
        cfg.max_bytes = cfg.max_bytes.max(MIN_MAX_BYTES);

        let Some(name) = cfg.path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "audit path has no file name"));
        };
        if let Some(parent) = cfg.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let lock_path = cfg.path.with_file_name(format!("{name}.lock"));

        let log = AuditLog {
            cfg,
            lock_path,
            seq: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            last_error: Mutex::new(None),
        };
        log.check_target()?;
        // Writes the header, and proves the file is writable.
        log.with_file(|_, _| Ok(()))?;
        Ok(log)
    }

    pub fn path(&self) -> &Path {
        &self.cfg.path
    }
    pub fn config(&self) -> &AuditConfig {
        &self.cfg
    }
    pub fn verbose(&self) -> bool {
        self.cfg.verbose
    }
    pub fn required(&self) -> bool {
        self.cfg.required
    }

    /// How many records failed to write since this log was opened.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// The most recent write failure, if any.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|g| g.clone())
    }

    /// A fresh id linking a `start` to its `finish`.
    pub fn new_id(&self) -> String {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        format!(
            "{:x}-{:x}-{:x}",
            std::process::id(),
            nanos,
            self.seq.fetch_add(1, Ordering::Relaxed)
        )
    }

    // ---------------------------------------------------------------- records

    /// A command was judged and not asked to run.
    pub fn evaluated(&self, command: &str, d: &Decision, workspace: &Path) -> io::Result<()> {
        let mut r = self.rec("evaluate");
        r.path("workspace", workspace);
        self.command_field(&mut r, command);
        self.decision_fields(&mut r, d);
        self.emit(r)
    }

    /// A command was submitted for execution and the gate stopped it.
    pub fn refused(&self, command: &str, d: &Decision, workspace: &Path) -> io::Result<()> {
        let mut r = self.rec("refused");
        r.path("workspace", workspace);
        self.command_field(&mut r, command);
        r.bool("ran", false);
        self.decision_fields(&mut r, d);
        self.emit(r)
    }

    /// A command is about to run. Write this *before* the checkpoint.
    pub fn started(
        &self,
        id: &str,
        command: &str,
        d: &Decision,
        workspace: &Path,
        runtime: &str,
    ) -> io::Result<()> {
        let mut r = self.rec("start");
        r.str("id", id);
        r.path("workspace", workspace);
        r.str("runtime", runtime);
        self.command_field(&mut r, command);
        self.decision_fields(&mut r, d);
        self.emit(r)
    }

    /// The command that `started` announced has ended.
    ///
    /// `start_logged` says whether its `start` made it to disk. If not, this
    /// record carries the command and decision itself, so a run whose `start`
    /// failed is still fully described.
    pub fn finished(
        &self,
        id: &str,
        run: &GuardedRun,
        workspace: &Path,
        start_logged: bool,
    ) -> io::Result<()> {
        let mut r = self.rec("finish");
        r.str("id", id);
        if !start_logged {
            r.path("workspace", workspace);
            self.command_field(&mut r, &run.command);
            self.decision_fields(&mut r, &run.decision);
        }

        if let Some(e) = &run.exec {
            match e.exit_code {
                Some(c) => r.int("exit_code", c as i64),
                None => r.null("exit_code"),
            }
            r.bool("timed_out", e.timed_out);
            r.float("acquire_ms", e.acquire.as_secs_f64() * 1000.0);
            r.float("run_ms", e.run.as_secs_f64() * 1000.0);
            if self.cfg.verbose {
                self.output_field(&mut r, "stdout", &e.stdout);
                self.output_field(&mut r, "stderr", &e.stderr);
            }
        }

        if let Some(g) = &run.guard {
            r.bool("rolled_back", g.rolled_back());
            self.text_list(&mut r, "rollback_reasons", g.rollback_reasons.iter());
            self.text_list(&mut r, "health_failures", g.health.failures.iter());
            let changed: Vec<String> =
                g.changed_protected.iter().map(|p| p.to_string_lossy().into_owned()).collect();
            self.text_list(&mut r, "changed_protected", changed.iter());
            r.int("untracked_captured", g.checkpoint.untracked.len() as i64);
            r.float("checkpoint_ms", g.checkpoint.took.as_secs_f64() * 1000.0);
        }
        self.emit(r)
    }

    /// The command could not be run to completion.
    pub fn errored(
        &self,
        id: &str,
        error: &str,
        command: &str,
        workspace: &Path,
        start_logged: bool,
    ) -> io::Result<()> {
        let mut r = self.rec("error");
        r.str("id", id);
        if !start_logged {
            r.path("workspace", workspace);
            self.command_field(&mut r, command);
        }
        self.text(&mut r, "error", error);
        self.emit(r)
    }

    /// The rules were replaced, or an attempt to replace them was refused.
    ///
    /// Written for refusals too: someone pushing a malformed policy, or one that
    /// quietly removes a restriction, is precisely the event an audit trail is
    /// for. The record carries the SHA-256 of the text offered, so a policy that
    /// was applied can later be matched to the file that was applied.
    ///
    /// Unlike a `start`, this is written *after* the change and is best-effort
    /// whatever [`AuditConfig::required`] says: `required` guards commands the
    /// agent asks to run, and a reload is an operator's act that an agent cannot
    /// trigger.
    pub fn policy_reloaded(
        &self,
        text: &str,
        mode: ReloadMode,
        result: &Result<ReloadReport, ReloadError>,
    ) -> io::Result<()> {
        let mut r = self.rec("policy");
        r.str("sha256", &crate::sha256::hex(&crate::sha256::hash(text.as_bytes())));
        r.int("bytes", text.len() as i64);
        r.str(
            "mode",
            match mode {
                ReloadMode::Strict => "strict",
                ReloadMode::AllowWeakening => "allow-weakening",
            },
        );

        let diff = match result {
            Ok(rep) => {
                r.str("outcome", "applied");
                r.str("before", &format!("{:016x}", rep.before));
                r.str("after", &format!("{:016x}", rep.after));
                r.int("rules", rep.rules as i64);
                r.bool("changed", rep.changed());
                Some(&rep.diff)
            }
            Err(ReloadError::Weakens(d)) => {
                r.str("outcome", "rejected");
                self.text(&mut r, "error", &result.as_ref().unwrap_err().to_string());
                Some(d)
            }
            Err(e @ ReloadError::Invalid(_)) => {
                r.str("outcome", "rejected");
                self.text(&mut r, "error", &e.to_string());
                None
            }
        };

        if let Some(d) = diff {
            self.text_list(&mut r, "added", d.added.iter());
            self.text_list(&mut r, "removed", d.removed.iter());
            self.text_list(&mut r, "modified", d.changed.iter());
            self.text_list(&mut r, "weakened", d.weakened.iter());
            r.str("default_before", d.default_before.as_str());
            r.str("default_after", d.default_after.as_str());
        }
        self.emit(r)
    }

    // ------------------------------------------------------------- field help

    fn rec(&self, kind: &str) -> Rec {
        let ms = now_ms();
        let mut r = Rec::new();
        r.str("kind", kind);
        r.str("time", &iso8601(ms));
        r.int("ts_ms", ms as i64);
        r.int("pid", std::process::id() as i64);
        r
    }

    fn command_field(&self, r: &mut Rec, command: &str) {
        let (clean, cut) = redact::redact_capped(command, self.cfg.max_command);
        let (json, cut2) = quote_capped(&clean, self.cfg.max_command * 2);
        r.raw("command", &json);
        if cut || cut2 {
            r.bool("command_truncated", true);
        }
    }

    fn output_field(&self, r: &mut Rec, key: &str, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        let (clean, cut) = redact::redact_capped(&text, self.cfg.max_output);
        let (json, cut2) = quote_capped(&clean, self.cfg.max_output * 2);
        r.raw(key, &json);
        if cut || cut2 || text.len() > self.cfg.max_output * 4 {
            r.bool(&format!("{key}_truncated"), true);
        }
    }

    /// A short free-text field: redacted and capped, never trusted.
    fn text(&self, r: &mut Rec, key: &str, value: &str) {
        let clean = redact::redact(value);
        let (json, _) = quote_capped(&clean, 2048);
        r.raw(key, &json);
    }

    fn text_list<'a>(&self, r: &mut Rec, key: &str, items: impl Iterator<Item = &'a String>) {
        let mut arr = String::from("[");
        for (i, s) in items.take(64).enumerate() {
            if i > 0 {
                arr.push(',');
            }
            let clean = redact::redact(s);
            arr.push_str(&quote_capped(&clean, 2048).0);
        }
        arr.push(']');
        r.raw(key, &arr);
    }

    fn decision_fields(&self, r: &mut Rec, d: &Decision) {
        r.str("verdict", d.verdict.as_str());
        // Which ruleset judged it. With reloadable rules, "denied by rule X"
        // does not say which version of X; the `policy` record maps this to the
        // text that was loaded.
        r.str("policy", &format!("{:016x}", d.policy_fingerprint));
        r.bool("complete", d.incomplete.is_none());
        if let Some(i) = &d.incomplete {
            self.text(r, "incomplete", &i.to_string());
        }
        r.int("gate_ns", d.elapsed.as_nanos().min(i64::MAX as u128) as i64);

        let mut caps = String::from("[");
        for (i, c) in d.capabilities.iter().enumerate() {
            if i > 0 {
                caps.push(',');
            }
            caps.push_str(&quote_capped(c.as_str(), 128).0);
        }
        caps.push(']');
        r.raw("capabilities", &caps);

        // Bounded: a pathological command can trip a rule per word.
        let mut f = String::from("[");
        for (i, x) in d.findings.iter().take(64).enumerate() {
            if i > 0 {
                f.push(',');
            }
            f.push_str("{\"rule\":");
            f.push_str(&quote_capped(&x.rule_id, 256).0);
            f.push_str(",\"verdict\":");
            f.push_str(&quote_capped(x.verdict.as_str(), 16).0);
            f.push_str(",\"reason\":");
            f.push_str(&quote_capped(&redact::redact(&x.reason), 512).0);
            if let Some(p) = &x.program {
                f.push_str(",\"program\":");
                f.push_str(&quote_capped(&redact::redact(p), 256).0);
            }
            if let Some(v) = x.via {
                f.push_str(",\"via\":");
                f.push_str(&quote_capped(v, 64).0);
            }
            f.push('}');
        }
        f.push(']');
        r.raw("findings", &f);
        r.int("findings_total", d.findings.len() as i64);
    }

    // ------------------------------------------------------------------- disk

    fn header(&self) -> String {
        let ms = now_ms();
        let mut r = Rec::new();
        r.str("kind", "header");
        r.int("schema", SCHEMA_VERSION as i64);
        r.str("time", &iso8601(ms));
        r.int("ts_ms", ms as i64);
        r.str("tool", "shellguard");
        r.str("version", env!("CARGO_PKG_VERSION"));
        r.str("source", &self.cfg.source);
        r.int("pid", std::process::id() as i64);
        r.str("os", std::env::consts::OS);
        r.str("backend", shellguard_enforce::backend());
        r.bool("verbose", self.cfg.verbose);
        r.bool("required", self.cfg.required);
        r.str("coverage", COVERAGE);
        r.finish()
    }

    /// Refuse to write through a symlink or into a file others can edit.
    ///
    /// The symlink check is a check-then-open and therefore races; it stops the
    /// accident and the lazy attack, not a determined local one. A log in a
    /// directory only its owner can write to has no such window, which is the
    /// deployment this is written for.
    fn check_target(&self) -> io::Result<()> {
        match std::fs::symlink_metadata(&self.cfg.path) {
            Ok(m) if m.file_type().is_symlink() => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is a symlink; refusing to write an audit log through it",
                    self.cfg.path.display()
                ),
            )),
            Ok(m) if !m.is_file() => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", self.cfg.path.display()),
            )),
            #[cfg(unix)]
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                if m.permissions().mode() & 0o022 != 0 {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "{} is writable by its group or by others; an audit log anyone can edit proves nothing (chmod 600 it)",
                            self.cfg.path.display()
                        ),
                    ))
                } else {
                    Ok(())
                }
            }
            #[cfg(not(unix))]
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Run `f` on the log file under the cross-process lock, having rotated if
    /// `incoming` more bytes would overflow it, and having written the header
    /// if the file is new.
    fn with_file<T>(&self, f: impl FnOnce(&mut File, u64) -> io::Result<T>) -> io::Result<T> {
        self.with_file_sized(0, f)
    }

    fn with_file_sized<T>(
        &self,
        incoming: u64,
        f: impl FnOnce(&mut File, u64) -> io::Result<T>,
    ) -> io::Result<T> {
        let _guard = lock::acquire(&self.lock_path)?;
        self.check_target()?;

        let mut file = self.open_append()?;
        let mut len = file.metadata()?.len();

        if len > 0 && len + incoming > self.cfg.max_bytes {
            drop(file);
            self.rotate()?;
            file = self.open_append()?;
            len = file.metadata()?.len();
        }
        if len == 0 {
            let mut h = self.header();
            h.push('\n');
            file.write_all(h.as_bytes())?;
            len = h.len() as u64;
        }
        f(&mut file, len)
    }

    fn open_append(&self) -> io::Result<File> {
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(&self.cfg.path)
    }

    /// `path` → `path.1` → … → `path.keep`, dropping what falls off the end.
    fn rotate(&self) -> io::Result<()> {
        let numbered = |n: usize| {
            let mut s = self.cfg.path.as_os_str().to_os_string();
            s.push(format!(".{n}"));
            PathBuf::from(s)
        };
        let keep = self.cfg.keep;
        if keep == 0 {
            return std::fs::remove_file(&self.cfg.path);
        }
        let oldest = numbered(keep);
        if oldest.exists() {
            std::fs::remove_file(&oldest)?;
        }
        for n in (1..keep).rev() {
            let from = numbered(n);
            if from.exists() {
                std::fs::rename(&from, numbered(n + 1))?;
            }
        }
        std::fs::rename(&self.cfg.path, numbered(1))
    }

    /// Write one record, counting and remembering a failure rather than
    /// hiding it.
    fn emit(&self, rec: Rec) -> io::Result<()> {
        let mut line = rec.finish();
        line.push('\n');
        let result = self.with_file_sized(line.len() as u64, |f, _| f.write_all(line.as_bytes()));
        if let Err(e) = &result {
            self.failures.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut g) = self.last_error.lock() {
                *g = Some(e.to_string());
            }
        }
        result
    }
}

// --------------------------------------------------------------------- locking

#[cfg(unix)]
mod lock {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    const LOCK_UN: i32 = 8;

    pub struct Guard(File);

    /// Block until this process holds the exclusive lock.
    ///
    /// The lock file is opened for append, never truncated, and is separate
    /// from the log itself: rotation renames the log out from under an fd, and
    /// a lock on the renamed file would exclude nobody.
    pub fn acquire(path: &Path) -> io::Result<Guard> {
        let f = OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
        loop {
            // SAFETY: `f` is an open file for the duration of the call, and
            // `flock` reads no memory.
            if unsafe { flock(f.as_raw_fd(), LOCK_EX) } == 0 {
                return Ok(Guard(f));
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: as above. Closing the file would release the lock anyway;
            // the explicit unlock just does not depend on that.
            unsafe { flock(self.0.as_raw_fd(), LOCK_UN) };
        }
    }
}

#[cfg(not(unix))]
mod lock {
    use std::io;
    use std::path::Path;

    pub struct Guard;

    /// No cross-process lock off Unix; concurrent writers may interleave.
    pub fn acquire(_: &Path) -> io::Result<Guard> {
        Ok(Guard)
    }
}

// ----------------------------------------------------------------- JSON output

/// A JSON object being written, one key at a time.
struct Rec {
    s: String,
    first: bool,
}

impl Rec {
    fn new() -> Rec {
        Rec { s: String::with_capacity(512), first: true }
    }

    fn key(&mut self, k: &str) {
        self.s.push(if self.first { '{' } else { ',' });
        self.first = false;
        self.s.push('"');
        self.s.push_str(k);
        self.s.push_str("\":");
    }

    /// A value that is already valid JSON.
    fn raw(&mut self, k: &str, json: &str) {
        self.key(k);
        self.s.push_str(json);
    }

    fn str(&mut self, k: &str, v: &str) {
        let q = quote_capped(v, 4096).0;
        self.raw(k, &q);
    }

    fn path(&mut self, k: &str, p: &Path) {
        let s = p.to_string_lossy();
        self.str(k, &s);
    }

    fn bool(&mut self, k: &str, v: bool) {
        self.raw(k, if v { "true" } else { "false" });
    }

    fn int(&mut self, k: &str, v: i64) {
        self.raw(k, &v.to_string());
    }

    fn float(&mut self, k: &str, v: f64) {
        self.raw(k, &format!("{v:.3}"));
    }

    fn null(&mut self, k: &str) {
        self.raw(k, "null");
    }

    fn finish(mut self) -> String {
        if self.first {
            self.s.push('{');
        }
        self.s.push('}');
        self.s
    }
}

/// Quote `s` as a JSON string, stopping before its escaped form exceeds `cap`
/// bytes. Returns whether anything was dropped.
///
/// Capping the *escaped* text, and never mid-escape, is what makes the result
/// always valid JSON and the record's size bounded — a kilobyte of control
/// characters escapes to six.
///
/// Besides the characters JSON requires escaping, this escapes DEL, the C1
/// controls and U+2028/2029. None is illegal in JSON, but a line-oriented
/// reader — Python's `str.splitlines` is the notable one — treats several of
/// them as line breaks, and a record split in two is a record an attacker
/// controls the second half of.
fn quote_capped(s: &str, cap: usize) -> (String, bool) {
    let mut out = String::with_capacity(s.len().min(cap) + 2);
    out.push('"');
    let mut cut = false;
    for c in s.chars() {
        let before = out.len();
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20
                || c == '\u{7f}'
                || ('\u{80}'..='\u{9f}').contains(&c)
                || c == '\u{2028}'
                || c == '\u{2029}' =>
            {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
        if out.len() + 1 > cap {
            out.truncate(before);
            cut = true;
            break;
        }
    }
    out.push('"');
    (out, cut)
}

// ------------------------------------------------------------------------ time

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// `2026-08-03T01:02:03.456Z`, without a date library.
fn iso8601(ms: u128) -> String {
    let secs = (ms / 1000) as i64;
    let millis = (ms % 1000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);

    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);

    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use shellguard_gate::{Gate, GateConfig, Worker};
    use std::sync::Arc;

    const GH: &str = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";

    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Dir {
            let d = std::env::temp_dir().join(crate::runtime::unique_temp_name("shellguard-audit"));
            std::fs::create_dir_all(&d).unwrap();
            Dir(d.canonicalize().unwrap())
        }
        fn log(&self) -> PathBuf {
            self.0.join("audit.jsonl")
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn decide(cmd: &str) -> Decision {
        let ws = std::env::temp_dir();
        let mut cfg = GateConfig::from_env(&ws);
        cfg.cwd = ws;
        Gate::with_default_policy(cfg).evaluate(cmd, &mut Worker::new())
    }

    fn lines(path: &Path) -> Vec<json::Json> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| json::parse(l).unwrap_or_else(|e| panic!("not JSON: {e}\n{l}")))
            .collect()
    }

    fn s<'a>(v: &'a json::Json, k: &str) -> Option<&'a str> {
        v.get(k).and_then(json::Json::as_str)
    }

    // ----------------------------------------------------------------- time

    #[test]
    fn timestamps_match_known_instants() {
        // Reference values computed independently with Python's datetime.
        for (ms, want) in [
            (0u128, "1970-01-01T00:00:00.000Z"),
            (951_782_400_000, "2000-02-29T00:00:00.000Z"),
            (1_700_000_000_123, "2023-11-14T22:13:20.123Z"),
            (1_709_164_800_000, "2024-02-29T00:00:00.000Z"),
            (4_102_444_800_000, "2100-01-01T00:00:00.000Z"),
        ] {
            assert_eq!(iso8601(ms), want);
        }
    }

    // -------------------------------------------------------------- quoting

    #[test]
    fn quoted_output_is_always_valid_json() {
        let nasty = "a\"b\\c\nd\re\tf\u{0}\u{1b}[31m\u{7f}\u{85}\u{2028}\u{2029}é😀";
        let (q, cut) = quote_capped(nasty, 10_000);
        assert!(!cut);
        let v = json::parse(&q).unwrap();
        assert_eq!(v.as_str(), Some(nasty), "round trip lost information");
    }

    #[test]
    fn quoted_output_contains_no_character_a_line_splitter_would_split_on() {
        let (q, _) = quote_capped("a\nb\u{85}c\u{2028}d\u{2029}e\u{b}f\u{c}g\u{1c}h", 10_000);
        for bad in ['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}', '\u{b}', '\u{c}', '\u{1c}'] {
            assert!(!q.contains(bad), "{bad:?} survived unescaped in {q:?}");
        }
    }

    #[test]
    fn capping_never_splits_an_escape_and_bounds_the_size() {
        let (q, cut) = quote_capped(&"\u{1}".repeat(1000), 100);
        assert!(cut);
        assert!(q.len() <= 100 + 1, "escaped size exceeded the cap: {}", q.len());
        assert!(json::parse(&q).is_ok(), "cap produced invalid JSON: {q}");
    }

    // ----------------------------------------------------------------- open

    #[test]
    fn a_new_log_starts_with_a_header_that_states_its_coverage() {
        let d = Dir::new();
        let _log = AuditLog::open(AuditConfig::new(d.log()).source("test")).unwrap();
        let recs = lines(&d.log());
        assert_eq!(recs.len(), 1);
        let h = &recs[0];
        assert_eq!(s(h, "kind"), Some("header"));
        assert_eq!(h.get("schema").and_then(json::Json::as_i64), Some(SCHEMA_VERSION as i64));
        assert_eq!(s(h, "source"), Some("test"));
        assert!(s(h, "coverage").unwrap().contains("only commands submitted"));
    }

    #[cfg(unix)]
    #[test]
    fn the_log_and_its_lock_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
        log.evaluated("ls", &decide("ls"), &d.0).unwrap();
        for p in [d.log(), d.0.join("audit.jsonl.lock")] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} is {:o}", p.display(), mode);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_writable_log_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dir::new();
        std::fs::write(d.log(), "").unwrap();
        for mode in [0o660, 0o606, 0o666, 0o620] {
            std::fs::set_permissions(d.log(), std::fs::Permissions::from_mode(mode)).unwrap();
            let e = AuditLog::open(AuditConfig::new(d.log())).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "mode {mode:o}");
        }
        // Readable by others is a different matter, and allowed.
        std::fs::set_permissions(d.log(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(AuditLog::open(AuditConfig::new(d.log())).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_log_path_is_refused() {
        let d = Dir::new();
        let target = d.0.join("elsewhere");
        std::fs::write(&target, "precious\n").unwrap();
        std::os::unix::fs::symlink(&target, d.log()).unwrap();
        let e = AuditLog::open(AuditConfig::new(d.log())).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "precious\n",
            "wrote through the link"
        );
    }

    #[test]
    fn missing_parent_directories_are_created() {
        let d = Dir::new();
        let deep = d.0.join("a/b/c/audit.jsonl");
        assert!(AuditLog::open(AuditConfig::new(&deep)).is_ok());
        assert!(deep.exists());
    }

    #[test]
    fn a_directory_is_not_a_log() {
        let d = Dir::new();
        let e = AuditLog::open(AuditConfig::new(&d.0)).unwrap_err();
        assert_ne!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn reopening_appends_and_does_not_repeat_the_header() {
        let d = Dir::new();
        for _ in 0..3 {
            let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
            log.evaluated("ls", &decide("ls"), &d.0).unwrap();
        }
        let recs = lines(&d.log());
        assert_eq!(recs.iter().filter(|r| s(r, "kind") == Some("header")).count(), 1);
        assert_eq!(recs.iter().filter(|r| s(r, "kind") == Some("evaluate")).count(), 3);
    }

    // -------------------------------------------------------------- records

    #[test]
    fn an_evaluation_records_the_verdict_and_the_rules_that_fired() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
        log.evaluated("rm -rf /etc", &decide("rm -rf /etc"), &d.0).unwrap();

        let r = &lines(&d.log())[1];
        assert_eq!(s(r, "kind"), Some("evaluate"));
        assert_eq!(s(r, "verdict"), Some("deny"));
        assert_eq!(s(r, "command"), Some("rm -rf /etc"));
        assert!(r.get("ts_ms").and_then(json::Json::as_i64).unwrap() > 1_600_000_000_000);
        assert!(s(r, "time").unwrap().ends_with('Z'));
        assert!(r.get("findings_total").and_then(json::Json::as_i64).unwrap() >= 1);
        let f = r.get("findings").and_then(json::Json::as_array).unwrap();
        assert!(!f.is_empty());
        assert!(s(&f[0], "rule").is_some() && s(&f[0], "reason").is_some());
    }

    #[test]
    fn a_refusal_says_the_command_did_not_run() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
        log.refused("rm -rf /etc", &decide("rm -rf /etc"), &d.0).unwrap();
        let r = &lines(&d.log())[1];
        assert_eq!(s(r, "kind"), Some("refused"));
        assert_eq!(r.get("ran").and_then(json::Json::as_bool), Some(false));
    }

    #[test]
    fn credentials_in_a_command_never_reach_the_file() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
        let cmd = format!(
            "curl -H 'Authorization: Bearer abcdef1234567890' https://u:hunter2@h/x && echo {GH}"
        );
        log.evaluated(&cmd, &decide(&cmd), &d.0).unwrap();

        let raw = std::fs::read_to_string(d.log()).unwrap();
        for secret in ["abcdef1234567890", "hunter2", GH] {
            assert!(!raw.contains(secret), "`{secret}` reached the audit file");
        }
        assert!(raw.contains("[REDACTED]"));
    }

    #[test]
    fn a_very_long_command_is_capped_and_flagged() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
        let cmd = format!("echo {}", "word ".repeat(20_000));
        log.evaluated(&cmd, &decide("echo hi"), &d.0).unwrap();
        let r = &lines(&d.log())[1];
        assert_eq!(r.get("command_truncated").and_then(json::Json::as_bool), Some(true));
        assert!(s(r, "command").unwrap().len() <= log.config().max_command);
    }

    #[test]
    fn ids_are_unique() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
        let ids: std::collections::HashSet<_> = (0..1000).map(|_| log.new_id()).collect();
        assert_eq!(ids.len(), 1000);
    }

    // ---------------------------------------------------- finish and error

    fn fake_run(cmd: &str) -> GuardedRun {
        use crate::runtime::ExecResult;
        use std::time::Duration;
        GuardedRun {
            command: cmd.to_string(),
            decision: decide(cmd),
            exec: Some(ExecResult {
                exit_code: Some(3),
                timed_out: false,
                stdout: b"out".to_vec(),
                stderr: b"err".to_vec(),
                acquire: Duration::from_micros(1500),
                run: Duration::from_millis(12),
            }),
            guard: None,
            audit_error: None,
        }
    }

    #[test]
    fn a_finish_whose_start_was_lost_carries_the_command_itself() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
        let run = fake_run("ls -la");
        log.finished("abc", &run, &d.0, false).unwrap();

        let r = &lines(&d.log())[1];
        assert_eq!(s(r, "id"), Some("abc"));
        assert_eq!(s(r, "command"), Some("ls -la"), "a lone finish must stand on its own");
        assert_eq!(s(r, "verdict"), Some(run.decision.verdict.as_str()));
        assert_eq!(r.get("exit_code").and_then(json::Json::as_i64), Some(3));
    }

    #[test]
    fn a_finish_whose_start_was_logged_does_not_repeat_the_command() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
        log.finished("abc", &fake_run("ls -la"), &d.0, true).unwrap();
        let r = &lines(&d.log())[1];
        assert!(r.get("command").is_none() && r.get("verdict").is_none());
        assert_eq!(r.get("exit_code").and_then(json::Json::as_i64), Some(3));
    }

    #[test]
    fn output_appears_only_when_verbose() {
        for verbose in [false, true] {
            let d = Dir::new();
            let log = AuditLog::open(AuditConfig::new(d.log()).verbose(verbose)).unwrap();
            log.finished("x", &fake_run("ls"), &d.0, true).unwrap();
            let r = &lines(&d.log())[1];
            assert_eq!(r.get("stdout").is_some(), verbose);
            assert_eq!(r.get("stderr").is_some(), verbose);
            if verbose {
                assert_eq!(s(r, "stdout"), Some("out"));
            }
        }
    }

    #[test]
    fn an_error_record_redacts_what_the_error_says() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log())).unwrap();
        log.errored("e1", &format!("could not start: token={GH}"), "ls", &d.0, true).unwrap();
        let raw = std::fs::read_to_string(d.log()).unwrap();
        assert!(!raw.contains(GH));
        assert_eq!(s(&lines(&d.log())[1], "kind"), Some("error"));
    }

    // ------------------------------------------------------------- rotation

    #[test]
    fn the_log_rotates_and_every_file_starts_with_a_header() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log()).rotate_at(MIN_MAX_BYTES, 3)).unwrap();
        let dec = decide("ls");
        for _ in 0..2500 {
            log.evaluated("ls -la", &dec, &d.0).unwrap();
        }

        let mut files = vec![d.log()];
        for n in 1..=3 {
            files.push(d.0.join(format!("audit.jsonl.{n}")));
        }
        for f in &files {
            assert!(f.exists(), "{} missing after rotation", f.display());
            let recs = lines(f);
            assert_eq!(s(&recs[0], "kind"), Some("header"), "{} has no header", f.display());
            let len = std::fs::metadata(f).unwrap().len();
            assert!(len <= MIN_MAX_BYTES, "{} grew to {len}", f.display());
        }
        assert!(!d.0.join("audit.jsonl.4").exists(), "more rotated files kept than configured");
    }

    #[test]
    fn rotation_with_no_files_kept_still_bounds_the_log() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log()).rotate_at(MIN_MAX_BYTES, 0)).unwrap();
        let dec = decide("ls");
        for _ in 0..2500 {
            log.evaluated("ls -la", &dec, &d.0).unwrap();
        }
        assert!(std::fs::metadata(d.log()).unwrap().len() <= MIN_MAX_BYTES);
        assert!(!d.0.join("audit.jsonl.1").exists());
    }

    #[test]
    fn rotation_loses_no_records_within_the_files_kept() {
        let d = Dir::new();
        let log = AuditLog::open(AuditConfig::new(d.log()).rotate_at(MIN_MAX_BYTES, 50)).unwrap();
        let dec = decide("ls");
        let n = 1500;
        for i in 0..n {
            log.evaluated(&format!("echo {i}"), &dec, &d.0).unwrap();
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut paths = vec![d.log()];
        paths.extend((1..=50).map(|k| d.0.join(format!("audit.jsonl.{k}"))));
        for p in paths.iter().filter(|p| p.exists()) {
            for r in lines(p) {
                if let Some(c) = s(&r, "command") {
                    assert!(seen.insert(c.to_string()), "`{c}` recorded twice");
                }
            }
        }
        assert_eq!(seen.len(), n, "records were lost across rotation");
    }

    // ---------------------------------------------------------- concurrency

    #[test]
    fn concurrent_writers_never_interleave_or_lose_a_record() {
        // Each thread opens its *own* AuditLog on the same path, which is what
        // separate processes do; the flock is the only thing keeping them apart.
        let d = Dir::new();
        let path = Arc::new(d.log());
        let ws = Arc::new(d.0.clone());
        let threads = 8;
        let each = 250;

        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let (path, ws) = (path.clone(), ws.clone());
                std::thread::spawn(move || {
                    let log = AuditLog::open(
                        AuditConfig::new(path.as_ref()).rotate_at(MIN_MAX_BYTES, 100),
                    )
                    .unwrap();
                    let dec = decide("ls");
                    for i in 0..each {
                        log.evaluated(&format!("echo t{t}-{i}"), &dec, &ws).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let mut seen = std::collections::BTreeSet::new();
        let mut paths = vec![d.log()];
        paths.extend((1..=100).map(|k| d.0.join(format!("audit.jsonl.{k}"))));
        for p in paths.iter().filter(|p| p.exists()) {
            for r in lines(p) {
                if let Some(c) = s(&r, "command") {
                    assert!(seen.insert(c.to_string()), "`{c}` written twice");
                }
            }
        }
        assert_eq!(seen.len(), threads * each, "records were lost or corrupted");
    }

    // -------------------------------------------------------------- failure

    #[test]
    fn a_failed_write_is_counted_and_remembered_not_hidden() {
        let d = Dir::new();
        let sub = d.0.join("sub");
        let log = AuditLog::open(AuditConfig::new(sub.join("audit.jsonl"))).unwrap();
        assert_eq!(log.failures(), 0);

        // Pull the directory out from under it.
        std::fs::remove_dir_all(&sub).unwrap();
        let r = log.evaluated("ls", &decide("ls"), &d.0);

        assert!(r.is_err());
        assert_eq!(log.failures(), 1);
        assert!(log.last_error().is_some());
    }
}
