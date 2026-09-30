//! Gate, checkpoint, execute, verify, roll back — the whole sequence.
//!
//! Everything below this point is a component; this is the thing a caller
//! actually wants. The order is the design:
//!
//! 1. **Judge before doing anything else.** A denied command costs a
//!    checkpoint of nothing, and taking one first would mean paying for the
//!    commands most worth refusing.
//! 2. **Checkpoint before executing**, never after. A checkpoint taken
//!    afterwards records the damage.
//! 3. **Derive the sandbox profile from the decision.** The gate already
//!    worked out which capabilities the command wants; using anything broader
//!    would discard that work, and every command would get the profile the
//!    most demanding one needs.
//! 4. **Verify, then roll back if warranted.** Exit status alone is a poor
//!    signal — plenty of damaging commands exit zero — so health checks and
//!    protected-file digests are consulted too.

use std::path::{Path, PathBuf};
use std::time::Duration;

use shellguard_enforce::Profile;
use shellguard_gate::{Decision, Gate, GateConfig, ReloadError, ReloadMode, ReloadReport, Worker};
use shellguard_policy::Verdict;

use crate::audit::AuditLog;
use crate::json;
use crate::local::LocalRuntime;
use crate::rollback::{GuardOutcome, HealthCheck, RollbackPolicy, StateManager};
use crate::runtime::{ExecResult, Payload, Runtime, RuntimeError};

/// Everything that happened to one command.
#[derive(Debug)]
pub struct GuardedRun {
    pub command: String,
    pub decision: Decision,
    /// Absent when the gate refused, which is the point of refusing.
    pub exec: Option<ExecResult>,
    /// Absent when nothing ran, so there was nothing to guard.
    pub guard: Option<GuardOutcome>,
    /// Why this run could not be fully recorded in the audit log, if it could
    /// not. Never set when no audit log is configured. A best-effort log that
    /// fails must not do so silently: a gap in the record that nobody is told
    /// about reads as completeness.
    pub audit_error: Option<String>,
}

impl GuardedRun {
    pub fn ran(&self) -> bool {
        self.exec.is_some()
    }

    pub fn rolled_back(&self) -> bool {
        self.guard.as_ref().is_some_and(GuardOutcome::rolled_back)
    }

    /// The whole record as JSON, which is what non-Rust callers consume.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(1024);
        s.push_str("{\"decision\":");
        s.push_str(&self.decision.to_json(&self.command));

        s.push_str(&format!(",\"ran\":{}", self.ran()));
        match &self.audit_error {
            Some(e) => s.push_str(&format!(",\"audit_error\":{}", json::quote(e))),
            None => s.push_str(",\"audit_error\":null"),
        }

        match &self.exec {
            Some(e) => {
                s.push_str(",\"execution\":{");
                match e.exit_code {
                    Some(c) => s.push_str(&format!("\"exit_code\":{c}")),
                    None => s.push_str("\"exit_code\":null"),
                }
                s.push_str(&format!(",\"timed_out\":{}", e.timed_out));
                s.push_str(&format!(
                    ",\"stdout\":{}",
                    json::quote(&String::from_utf8_lossy(&e.stdout))
                ));
                s.push_str(&format!(
                    ",\"stderr\":{}",
                    json::quote(&String::from_utf8_lossy(&e.stderr))
                ));
                s.push_str(&format!(",\"acquire_ms\":{:.3}", e.acquire.as_secs_f64() * 1000.0));
                s.push_str(&format!(",\"run_ms\":{:.3}", e.run.as_secs_f64() * 1000.0));
                s.push('}');
            }
            None => s.push_str(",\"execution\":null"),
        }

        match &self.guard {
            Some(g) => {
                s.push_str(",\"rollback\":{");
                s.push_str(&format!("\"rolled_back\":{}", g.rolled_back()));
                s.push_str(",\"reasons\":[");
                for (i, r) in g.rollback_reasons.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&json::quote(r));
                }
                s.push_str("],\"health_failures\":[");
                for (i, f) in g.health.failures.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&json::quote(f));
                }
                s.push_str("],\"changed_protected\":[");
                for (i, p) in g.changed_protected.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&json::quote(&p.to_string_lossy()));
                }
                s.push_str("],\"checkpoint\":{");
                s.push_str(&format!("\"untracked_captured\":{}", g.checkpoint.untracked.len()));
                s.push_str(&format!(
                    ",\"took_ms\":{:.3}",
                    g.checkpoint.took.as_secs_f64() * 1000.0
                ));
                s.push('}');
                if let Some(r) = &g.rollback {
                    s.push_str(&format!(
                        ",\"restored\":{{\"tracked\":{},\"head_reset\":{},\"untracked\":{},\"removed\":{}}}",
                        r.restored_tracked,
                        r.head_reset,
                        r.untracked_restored.len(),
                        r.untracked_removed.len()
                    ));
                }
                s.push('}');
            }
            None => s.push_str(",\"rollback\":null"),
        }

        s.push('}');
        s
    }
}

/// The full pipeline, configured once and used repeatedly.
pub struct Engine {
    gate: Gate,
    runtime: Box<dyn Runtime>,
    rollback: RollbackPolicy,
    health: Vec<HealthCheck>,
    workspace: PathBuf,
    timeout: Duration,
    /// Run commands the gate escalates rather than refusing outright.
    ///
    /// Off by default: `Ask` means a human should look, and a library that
    /// quietly runs those has replaced a decision with a default.
    run_on_ask: bool,
    audit: Option<AuditLog>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("workspace", &self.workspace)
            .field("runtime", &self.runtime.name())
            .field("run_on_ask", &self.run_on_ask)
            .field("audit", &self.audit.as_ref().map(AuditLog::path))
            .finish()
    }
}

impl Engine {
    /// An engine with the built-in ruleset and the local runtime.
    pub fn new(workspace: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let workspace = workspace.as_ref().canonicalize().map_err(RuntimeError::Spawn)?;
        let mut cfg = GateConfig::from_env(&workspace);
        cfg.cwd = workspace.clone();
        Ok(Engine {
            gate: Gate::with_default_policy(cfg),
            runtime: Box::new(LocalRuntime::new()),
            rollback: RollbackPolicy::default(),
            health: Vec::new(),
            workspace,
            timeout: Duration::from_secs(120),
            run_on_ask: false,
            audit: None,
        })
    }

    pub fn with_gate(mut self, gate: Gate) -> Self {
        self.gate = gate;
        self
    }

    pub fn with_runtime(mut self, runtime: Box<dyn Runtime>) -> Self {
        self.runtime = runtime;
        self
    }

    pub fn with_rollback_policy(mut self, policy: RollbackPolicy) -> Self {
        self.rollback = policy;
        self
    }

    pub fn with_health_checks(mut self, checks: Vec<HealthCheck>) -> Self {
        self.health = checks;
        self
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn run_on_ask(mut self, yes: bool) -> Self {
        self.run_on_ask = yes;
        self
    }

    /// Record every judgment and execution to `log`.
    pub fn with_audit(mut self, log: AuditLog) -> Self {
        self.audit = Some(log);
        self
    }

    /// [`with_audit`](Self::with_audit) for an engine already behind a handle.
    pub fn set_audit(&mut self, log: AuditLog) {
        self.audit = Some(log);
    }

    pub fn audit(&self) -> Option<&AuditLog> {
        self.audit.as_ref()
    }

    /// Replace the ruleset of this running engine with the policy in `text`.
    ///
    /// Atomic: a command is judged by the old rules or the new ones, never a
    /// mixture. A malformed policy, or (in [`ReloadMode::Strict`]) one that
    /// lowers protection, is refused and the previous rules stay in force.
    /// Every attempt — applied or refused — is written to the audit log when one
    /// is attached. Takes the policy *text*, not a path, so the caller decides
    /// what was reviewed.
    pub fn reload_policy(&self, text: &str, mode: ReloadMode) -> Result<ReloadReport, ReloadError> {
        let result = self.gate.reload_text(text, mode);
        if let Some(a) = &self.audit {
            let _ = a.policy_reloaded(text, mode, &result);
        }
        result
    }

    /// Identifies the ruleset in force; it is also on every [`Decision`].
    pub fn policy_fingerprint(&self) -> u64 {
        self.gate.policy_fingerprint()
    }

    /// Records that failed to write since the log was attached; zero with none.
    pub fn audit_failures(&self) -> u64 {
        self.audit.as_ref().map_or(0, AuditLog::failures)
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn runtime_name(&self) -> &'static str {
        self.runtime.name()
    }

    /// Judge a command without running it.
    pub fn evaluate(&self, command: &str) -> Decision {
        let d = self.judge(command);
        if let Some(a) = &self.audit {
            // A judgment has no side effect to protect, so a failed record is
            // counted (see `audit_failures`) and never blocks the answer.
            let _ = a.evaluated(command, &d, &self.workspace);
        }
        d
    }

    /// The gate's answer, unrecorded — for callers that record it themselves.
    fn judge(&self, command: &str) -> Decision {
        let mut w = Worker::new();
        self.gate.evaluate(command, &mut w)
    }

    /// Build the sandbox profile from the gate's decision.
    ///
    /// Capabilities come from the rules that fired, which narrows the profile
    /// to what the command was recognised as wanting. The subtlety is what
    /// happens when *no* rule fires, which for agent-authored input is the
    /// common case: the capability set is empty, and a profile built from an
    /// empty set can write nothing at all — so `echo x > file` inside the
    /// workspace fails at the kernel.
    ///
    /// That is a misreading of what `Confine` means. Confinement scopes a
    /// command *to* the workspace; it does not forbid the workspace. An
    /// unclassified command therefore gets the ordinary working profile —
    /// the workspace readable and writable, and nothing else, no network.
    /// Narrower profiles still come from rules that actually recognised the
    /// command, and `Allow` verdicts keep whatever the matching rule granted.
    pub fn profile_for(&self, decision: &Decision) -> Profile {
        let mut profile = Profile::from_capabilities(&self.workspace, &decision.capabilities);
        if decision.verdict >= Verdict::Confine && profile.writable().is_empty() {
            profile.write_paths.push(self.workspace.clone());
        }
        profile
    }

    /// Whether a verdict should proceed to execution.
    fn should_run(&self, v: Verdict) -> bool {
        match v {
            Verdict::Allow | Verdict::Confine => true,
            Verdict::Ask => self.run_on_ask,
            Verdict::Deny => false,
        }
    }

    /// The whole sequence.
    ///
    /// With an audit log attached the command is announced (`start`) before the
    /// checkpoint is taken and concluded (`finish` or `error`) afterwards. If
    /// the log is [required](crate::audit::AuditConfig::required) and the
    /// announcement cannot be written, the command does not run.
    pub fn execute_with_rollback(&self, command: &str) -> Result<GuardedRun, RuntimeError> {
        let decision = self.judge(command);

        if !self.should_run(decision.verdict) {
            let audit_error = self
                .audit
                .as_ref()
                .and_then(|a| a.refused(command, &decision, &self.workspace).err())
                .map(|e| format!("refusal record: {e}"));
            return Ok(GuardedRun {
                command: command.to_string(),
                decision,
                exec: None,
                guard: None,
                audit_error,
            });
        }

        let mut audit_errors: Vec<String> = Vec::new();
        let mut run_id: Option<String> = None;
        let mut start_logged = false;
        if let Some(a) = &self.audit {
            let id = a.new_id();
            match a.started(&id, command, &decision, &self.workspace, self.runtime.name()) {
                Ok(()) => start_logged = true,
                Err(e) if a.required() => {
                    return Err(RuntimeError::Audit(format!(
                        "the command was not run because it could not be recorded: {e}"
                    )));
                }
                Err(e) => audit_errors.push(format!("start record: {e}")),
            }
            run_id = Some(id);
        }

        match self.run_guarded(command, &decision) {
            Ok((exec, guard)) => {
                let mut run = GuardedRun {
                    command: command.to_string(),
                    decision,
                    exec: Some(exec),
                    guard: Some(guard),
                    audit_error: None,
                };
                if let (Some(a), Some(id)) = (&self.audit, &run_id) {
                    if let Err(e) = a.finished(id, &run, &self.workspace, start_logged) {
                        audit_errors.push(format!("finish record: {e}"));
                    }
                }
                if !audit_errors.is_empty() {
                    run.audit_error = Some(audit_errors.join("; "));
                }
                Ok(run)
            }
            Err(err) => {
                if let (Some(a), Some(id)) = (&self.audit, &run_id) {
                    // Already failing; a second failure has nowhere better to go
                    // than the counter.
                    let _ = a.errored(id, &err.to_string(), command, &self.workspace, start_logged);
                }
                Err(err)
            }
        }
    }

    /// Checkpoint, execute, verify. Everything after the decision to run.
    fn run_guarded(
        &self,
        command: &str,
        decision: &Decision,
    ) -> Result<(ExecResult, GuardOutcome), RuntimeError> {
        let state = StateManager::open(&self.workspace, self.rollback.clone())
            .map_err(|e| RuntimeError::Protocol(e.to_string()))?;
        let checkpoint = state.checkpoint().map_err(|e| RuntimeError::Protocol(e.to_string()))?;

        let profile = self.profile_for(decision);
        let payload = Payload::new(command, &self.workspace, profile).with_timeout(self.timeout);

        let exec = self.runtime.execute(&payload)?;
        let guard = state
            .finish(checkpoint, exec.outcome(), &self.health)
            .map_err(|e| RuntimeError::Protocol(e.to_string()))?;
        Ok((exec, guard))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    struct Repo {
        dir: PathBuf,
    }

    impl Repo {
        fn new(name: &str) -> Repo {
            let dir = std::env::temp_dir().join(format!("shellguard-engine-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let r = Repo { dir: dir.canonicalize().unwrap() };
            r.git(&["init", "-q", "-b", "main", "."]);
            r.git(&["config", "user.email", "t@example.com"]);
            r.git(&["config", "user.name", "test"]);
            std::fs::write(r.dir.join("tracked.txt"), "original\n").unwrap();
            r.git(&["add", "-A"]);
            r.git(&["commit", "-qm", "init"]);
            r
        }

        fn git(&self, args: &[&str]) {
            let out = Command::new("git").args(args).current_dir(&self.dir).output().unwrap();
            assert!(out.status.success(), "git {args:?}");
        }

        fn read(&self, rel: &str) -> Option<String> {
            std::fs::read_to_string(self.dir.join(rel)).ok()
        }

        fn engine(&self) -> Engine {
            Engine::new(&self.dir).unwrap().with_timeout(Duration::from_secs(30))
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_benign_command_runs() {
        let r = Repo::new("benign");
        let run = r.engine().execute_with_rollback("echo hello").unwrap();
        assert!(run.ran());
        assert!(!run.rolled_back());
        let e = run.exec.unwrap();
        assert_eq!(e.exit_code, Some(0));
        assert_eq!(String::from_utf8_lossy(&e.stdout).trim(), "hello");
    }

    #[test]
    fn a_denied_command_never_executes() {
        let r = Repo::new("denied");
        let run = r.engine().execute_with_rollback("rm -rf /etc").unwrap();
        assert_eq!(run.decision.verdict, Verdict::Deny);
        assert!(!run.ran(), "a denied command must not run");
        assert!(run.exec.is_none());
        // And nothing was checkpointed, because nothing needed undoing.
        assert!(run.guard.is_none());
    }

    #[test]
    fn an_escalated_command_does_not_run_by_default() {
        let r = Repo::new("ask");
        let run = r.engine().execute_with_rollback("git push --force origin main").unwrap();
        assert_eq!(run.decision.verdict, Verdict::Ask);
        assert!(!run.ran(), "`ask` means a human should look, not run it anyway");
    }

    #[test]
    fn an_escalated_command_runs_when_the_caller_opts_in() {
        let r = Repo::new("ask-optin");
        let run = r
            .engine()
            .run_on_ask(true)
            .execute_with_rollback("echo $UNSET_VARIABLE_MAKES_THIS_ask")
            .unwrap();
        // Whatever the verdict, opting in means it is allowed to proceed.
        assert!(run.decision.verdict < Verdict::Deny);
    }

    #[test]
    fn a_failed_health_check_rolls_the_workspace_back() {
        let r = Repo::new("health-rollback");
        let engine = r.engine().with_health_checks(vec![HealthCheck::Command {
            argv: vec!["false".into()],
            timeout: Duration::from_secs(5),
        }]);

        let run = engine.execute_with_rollback("echo damaged > tracked.txt").unwrap();
        assert!(run.ran());
        assert!(run.rolled_back(), "the failing health check should have triggered a rollback");
        assert_eq!(r.read("tracked.txt").as_deref(), Some("original\n"));
    }

    #[test]
    fn a_protected_file_change_rolls_back_even_on_success() {
        // Exit status alone is a poor signal: this command succeeds.
        let r = Repo::new("protected-rollback");
        let engine = r.engine().with_rollback_policy(RollbackPolicy {
            protected: vec![PathBuf::from("tracked.txt")],
            ..Default::default()
        });

        let run = engine.execute_with_rollback("echo tampered > tracked.txt").unwrap();
        assert!(run.exec.as_ref().unwrap().ok(), "the command itself succeeded");
        assert!(run.rolled_back());
        assert_eq!(r.read("tracked.txt").as_deref(), Some("original\n"));
    }

    #[test]
    fn an_unclassified_command_can_still_work_in_its_own_workspace() {
        // Confinement scopes a command *to* the workspace; it does not forbid
        // the workspace. Without this, every command no rule recognises — the
        // common case for agent-authored input — fails at the kernel on its
        // first write.
        let r = Repo::new("unclassified-can-write");
        let run = r.engine().execute_with_rollback("echo produced > output.txt").unwrap();
        assert!(run.ran());
        let e = run.exec.as_ref().unwrap();
        assert!(e.ok(), "stderr: {}", String::from_utf8_lossy(&e.stderr));
        assert_eq!(r.read("output.txt").as_deref(), Some("produced\n"));
    }

    #[test]
    fn an_unclassified_command_still_cannot_write_outside_the_workspace() {
        // The other half: widening to the workspace must not widen further.
        let marker = std::env::temp_dir().join("shellguard-engine-should-not-exist");
        let _ = std::fs::remove_file(&marker);
        let r = Repo::new("unclassified-cannot-escape");
        let run = r
            .engine()
            .execute_with_rollback(&format!("echo pwned > {}", marker.display()))
            .unwrap();
        if run.ran() {
            assert!(!run.exec.as_ref().unwrap().ok(), "the escape succeeded");
        }
        assert!(!marker.exists(), "a file was written outside the workspace");
    }

    #[test]
    fn the_json_record_is_well_formed_and_complete() {
        let r = Repo::new("json");
        let run = r.engine().execute_with_rollback("echo hi").unwrap();
        let s = run.to_json();
        let v = json::parse(&s).unwrap_or_else(|e| panic!("{e}\n{s}"));

        assert!(v.get("decision").is_some());
        assert_eq!(v.get("ran").and_then(json::Json::as_bool), Some(true));
        let ex = v.get("execution").unwrap();
        assert_eq!(ex.get("exit_code").and_then(json::Json::as_i64), Some(0));
        assert_eq!(ex.get("stdout").and_then(json::Json::as_str), Some("hi\n"));
        let rb = v.get("rollback").unwrap();
        assert_eq!(rb.get("rolled_back").and_then(json::Json::as_bool), Some(false));
    }

    #[test]
    fn the_json_record_of_a_denial_says_nothing_ran() {
        let r = Repo::new("json-denied");
        let run = r.engine().execute_with_rollback("rm -rf /etc").unwrap();
        let v = json::parse(&run.to_json()).unwrap();
        assert_eq!(v.get("ran").and_then(json::Json::as_bool), Some(false));
        assert_eq!(v.get("execution"), Some(&json::Json::Null));
        assert_eq!(
            v.get("decision").and_then(|d| d.get("verdict")).and_then(json::Json::as_str),
            Some("deny")
        );
    }

    #[test]
    fn evaluate_does_not_execute() {
        let r = Repo::new("eval-only");
        let e = r.engine();
        let d = e.evaluate("echo written > tracked.txt");
        assert!(d.verdict <= Verdict::Deny);
        assert_eq!(
            r.read("tracked.txt").as_deref(),
            Some("original\n"),
            "evaluate ran the command"
        );
    }

    // ------------------------------------------------------------- auditing

    use crate::audit::{AuditConfig, AuditLog};
    use crate::runtime::{Availability, Isolation};

    const TOKEN: &str = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";

    /// A log in a directory of its own, outside the workspace: a log inside it
    /// would be an untracked file, and the checkpoint would capture it.
    struct LogDir(PathBuf);

    impl LogDir {
        fn new(name: &str) -> LogDir {
            let d = std::env::temp_dir().join(format!("shellguard-auditlog-{name}"));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            LogDir(d.canonicalize().unwrap())
        }
        fn file(&self) -> PathBuf {
            self.0.join("audit.jsonl")
        }
        fn open(&self, cfg: impl FnOnce(AuditConfig) -> AuditConfig) -> AuditLog {
            AuditLog::open(cfg(AuditConfig::new(self.file()).source("test"))).unwrap()
        }
        fn records(&self) -> Vec<json::Json> {
            std::fs::read_to_string(self.file())
                .unwrap()
                .lines()
                .map(|l| json::parse(l).unwrap_or_else(|e| panic!("{e}: {l}")))
                .collect()
        }
        fn of_kind(&self, kind: &str) -> Vec<json::Json> {
            self.records()
                .into_iter()
                .filter(|r| r.get("kind").and_then(json::Json::as_str) == Some(kind))
                .collect()
        }
    }

    impl Drop for LogDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn str_of<'a>(v: &'a json::Json, k: &str) -> Option<&'a str> {
        v.get(k).and_then(json::Json::as_str)
    }

    #[derive(Debug)]
    struct BrokenRuntime;

    impl Runtime for BrokenRuntime {
        fn name(&self) -> &'static str {
            "broken"
        }
        fn availability(&self) -> Availability {
            Availability::Ready
        }
        fn isolation(&self) -> Isolation {
            Isolation::Sandbox
        }
        fn execute(&self, _: &Payload) -> Result<ExecResult, RuntimeError> {
            Err(RuntimeError::Unavailable("deliberately broken for a test".into()))
        }
    }

    #[test]
    fn an_audited_run_leaves_a_start_and_a_finish_sharing_one_id() {
        let r = Repo::new("audit-pair");
        let l = LogDir::new("pair");
        let engine = r.engine().with_audit(l.open(|c| c));

        let run = engine.execute_with_rollback("echo hello").unwrap();
        assert!(run.ran());
        assert!(run.audit_error.is_none(), "{:?}", run.audit_error);

        let (start, finish) = (&l.of_kind("start")[0], &l.of_kind("finish")[0]);
        assert_eq!(str_of(start, "id"), str_of(finish, "id"));
        assert!(str_of(start, "id").is_some_and(|i| !i.is_empty()));
        assert_eq!(str_of(start, "command"), Some("echo hello"));
        assert_eq!(str_of(start, "runtime"), Some("local"));
        assert_eq!(finish.get("exit_code").and_then(json::Json::as_i64), Some(0));
        assert_eq!(finish.get("rolled_back").and_then(json::Json::as_bool), Some(false));
        // The command is stated once, on the start; the finish points at it.
        assert!(finish.get("command").is_none());
        // And the order on disk is the order things happened.
        let kinds: Vec<String> =
            l.records().iter().filter_map(|x| str_of(x, "kind").map(String::from)).collect();
        assert_eq!(kinds, ["header", "start", "finish"]);
    }

    #[test]
    fn a_denied_command_is_recorded_as_refused_and_never_started() {
        let r = Repo::new("audit-refused");
        let l = LogDir::new("refused");
        let engine = r.engine().with_audit(l.open(|c| c));

        let run = engine.execute_with_rollback("rm -rf /etc").unwrap();
        assert!(!run.ran());

        assert_eq!(l.of_kind("refused").len(), 1);
        assert_eq!(str_of(&l.of_kind("refused")[0], "verdict"), Some("deny"));
        assert!(l.of_kind("start").is_empty(), "a denied command was announced as running");
        assert!(l.of_kind("finish").is_empty());
    }

    #[test]
    fn an_escalated_command_that_is_not_run_is_still_recorded() {
        let r = Repo::new("audit-ask");
        let l = LogDir::new("ask");
        let engine = r.engine().with_audit(l.open(|c| c));
        let run = engine.execute_with_rollback("git push --force origin main").unwrap();
        assert!(!run.ran());
        assert_eq!(str_of(&l.of_kind("refused")[0], "verdict"), Some("ask"));
    }

    #[test]
    fn evaluating_is_recorded_and_still_does_not_execute() {
        let r = Repo::new("audit-eval");
        let l = LogDir::new("eval");
        let engine = r.engine().with_audit(l.open(|c| c));

        engine.evaluate("echo written > tracked.txt");

        assert_eq!(l.of_kind("evaluate").len(), 1);
        assert!(l.of_kind("start").is_empty());
        assert_eq!(r.read("tracked.txt").as_deref(), Some("original\n"));
    }

    #[test]
    fn a_rollback_and_its_reasons_are_in_the_record() {
        let r = Repo::new("audit-rollback");
        let l = LogDir::new("rollback");
        let engine = r
            .engine()
            .with_rollback_policy(RollbackPolicy {
                protected: vec![PathBuf::from("tracked.txt")],
                ..Default::default()
            })
            .with_audit(l.open(|c| c));

        let run = engine.execute_with_rollback("echo tampered > tracked.txt").unwrap();
        assert!(run.rolled_back());

        let f = &l.of_kind("finish")[0];
        assert_eq!(f.get("rolled_back").and_then(json::Json::as_bool), Some(true));
        let reasons = f.get("rollback_reasons").and_then(json::Json::as_array).unwrap();
        assert!(reasons.iter().any(|x| x.as_str().is_some_and(|s| s.contains("tracked.txt"))));
        let changed = f.get("changed_protected").and_then(json::Json::as_array).unwrap();
        assert_eq!(changed.len(), 1);
    }

    #[test]
    fn output_is_not_recorded_unless_asked_for() {
        let r = Repo::new("audit-quiet");
        let l = LogDir::new("quiet");
        // The output is assembled by printf, so "zxyyqv" exists only in stdout
        // and never in the command text that is recorded.
        let run = r
            .engine()
            .with_audit(l.open(|c| c))
            .execute_with_rollback("printf 'zx%sqv' yy")
            .unwrap();
        let exec = run.exec.as_ref().unwrap_or_else(|| {
            panic!(
                "did not run: verdict={:?} incomplete={:?} elapsed={:?}",
                run.decision.verdict, run.decision.incomplete, run.decision.elapsed
            )
        });
        let stdout = String::from_utf8_lossy(&exec.stdout).to_string();
        assert_eq!(stdout, "zxyyqv", "the command did not produce the marker output");
        let raw = std::fs::read_to_string(l.file()).unwrap();
        assert!(!raw.contains("zxyyqv"), "stdout was recorded by default: {raw}");
        assert!(l.of_kind("finish")[0].get("stdout").is_none());
    }

    #[test]
    fn verbose_output_is_recorded_and_redacted() {
        let r = Repo::new("audit-verbose");
        let l = LogDir::new("verbose");
        let engine = r.engine().with_audit(l.open(|c| c.verbose(true)));
        // Both the marker and the token are assembled by printf, so neither
        // appears in the command text — only stdout can be the source of them.
        engine.execute_with_rollback(&format!("printf 'zx%sqv %s' yy {}", TOKEN)).unwrap();

        let raw = std::fs::read_to_string(l.file()).unwrap();
        assert!(!raw.contains(TOKEN), "a credential in stdout reached the audit file");
        let out = str_of(&l.of_kind("finish")[0], "stdout").unwrap().to_string();
        assert!(out.contains("zxyyqv"), "{out}");
        assert!(out.contains("[REDACTED]"), "{out}");
    }

    #[test]
    fn a_runtime_failure_is_recorded_as_an_error_against_the_same_id() {
        let r = Repo::new("audit-error");
        let l = LogDir::new("error");
        let engine = r.engine().with_runtime(Box::new(BrokenRuntime)).with_audit(l.open(|c| c));

        let err = engine.execute_with_rollback("echo hi").unwrap_err();
        assert!(matches!(err, RuntimeError::Unavailable(_)));

        let (start, error) = (&l.of_kind("start")[0], &l.of_kind("error")[0]);
        assert_eq!(str_of(start, "id"), str_of(error, "id"));
        assert!(str_of(error, "error").unwrap().contains("deliberately broken"));
        assert!(l.of_kind("finish").is_empty());
    }

    #[test]
    fn a_required_log_that_cannot_be_written_stops_the_command() {
        let r = Repo::new("audit-required");
        let l = LogDir::new("required");
        let engine = r.engine().with_audit(l.open(|c| c.required(true)));

        // The log's directory disappears after it was opened.
        std::fs::remove_dir_all(&l.0).unwrap();
        let err = engine.execute_with_rollback("echo ran > marker.txt").unwrap_err();

        assert!(matches!(err, RuntimeError::Audit(_)), "{err:?}");
        assert!(err.to_string().contains("not run"), "{err}");
        assert!(
            r.read("marker.txt").is_none(),
            "the command ran although it could not be recorded"
        );
        assert!(engine.audit_failures() >= 1);
    }

    #[test]
    fn a_best_effort_log_that_cannot_be_written_reports_it_and_still_runs() {
        let r = Repo::new("audit-besteffort");
        let l = LogDir::new("besteffort");
        let engine = r.engine().with_audit(l.open(|c| c));

        std::fs::remove_dir_all(&l.0).unwrap();
        let run = engine.execute_with_rollback("echo ran > marker.txt").unwrap();

        assert!(run.ran());
        assert_eq!(r.read("marker.txt").as_deref(), Some("ran\n"));
        let why = run.audit_error.as_deref().expect("a failed record must be reported");
        assert!(why.contains("start record") && why.contains("finish record"), "{why}");
        assert!(engine.audit_failures() >= 2);

        // And it reaches the JSON callers actually read.
        let v = json::parse(&run.to_json()).unwrap();
        assert!(v.get("audit_error").and_then(json::Json::as_str).is_some());
    }

    #[test]
    fn with_no_audit_log_there_is_no_audit_error() {
        let r = Repo::new("audit-none");
        let run = r.engine().execute_with_rollback("echo hi").unwrap();
        assert!(run.audit_error.is_none());
        let v = json::parse(&run.to_json()).unwrap();
        assert_eq!(v.get("audit_error"), Some(&json::Json::Null));
        assert_eq!(r.engine().audit_failures(), 0);
    }

    #[test]
    fn the_log_file_is_not_swept_into_the_checkpoint_or_rolled_back() {
        // A log kept *inside* the workspace is an untracked file, and a
        // rollback that restored it would erase the record of the rollback.
        // Documented behaviour is "keep the log outside the workspace"; this
        // pins that a log outside is untouched by a rollback.
        let r = Repo::new("audit-survives");
        let l = LogDir::new("survives");
        let engine = r
            .engine()
            .with_rollback_policy(RollbackPolicy {
                protected: vec![PathBuf::from("tracked.txt")],
                ..Default::default()
            })
            .with_audit(l.open(|c| c));
        let run = engine.execute_with_rollback("echo tampered > tracked.txt").unwrap();
        assert!(run.rolled_back());
        assert_eq!(l.of_kind("finish").len(), 1, "the record of the rollback did not survive it");
    }

    #[test]
    fn a_command_cannot_tamper_with_the_log_it_is_recorded_in() {
        // The integrity of an audit log rests on the writer being outside the
        // thing it records, and it is held by two independent layers. Both are
        // exercised, because a test that only lets the gate refuse the command
        // says nothing about the kernel:
        //
        //  * by default the gate escalates a write outside the workspace, so
        //    the command never runs;
        //  * with `run_on_ask` the command is forced past the gate, and it is
        //    the kernel sandbox alone that must stop it.
        //
        // "tamxpered" is assembled by printf, so it appears only in what the
        // command would write, never in the command text the log records.
        for forced_past_the_gate in [false, true] {
            let name = format!("audit-tamper-{forced_past_the_gate}");
            let r = Repo::new(&name);
            let l = LogDir::new(&name);
            let engine = r.engine().run_on_ask(forced_past_the_gate).with_audit(l.open(|c| c));

            let cmd = format!("printf 'tam%spered' x >> {}", l.file().display());
            let run = engine.execute_with_rollback(&cmd).unwrap();

            let after = std::fs::read_to_string(l.file()).unwrap();
            assert!(
                !after.contains("tamxpered"),
                "forced={forced_past_the_gate}: a command wrote into its own audit log"
            );
            for line in after.lines() {
                assert!(json::parse(line).is_ok(), "corrupt line: {line}");
            }

            if forced_past_the_gate {
                let e = run.exec.as_ref().expect("run_on_ask should have let it run");
                assert!(!e.ok(), "the write into the log reported success");
            } else {
                assert!(!run.ran(), "the gate should have stopped a write outside the workspace");
            }
        }
    }

    // ------------------------------------------------------------ hot reload

    /// The built-in rules plus one more: a strengthening, so it reloads under
    /// [`ReloadMode::Strict`].
    fn default_plus_deny_echo() -> String {
        format!(
            "{}\n\nrule test.no-echo deny\n  reason echo is forbidden in this test\n  program echo\n  cap fs.read\nend\n",
            shellguard_policy::DEFAULT_POLICY_TEXT
        )
    }

    #[test]
    fn a_reloaded_policy_governs_the_next_execution() {
        let r = Repo::new("reload-effect");
        let engine = r.engine();

        let run = engine.execute_with_rollback("echo ran > marker.txt").unwrap();
        assert!(run.ran());
        assert_eq!(r.read("marker.txt").as_deref(), Some("ran\n"));
        std::fs::remove_file(r.dir.join("marker.txt")).unwrap();

        let before = engine.policy_fingerprint();
        engine.reload_policy(&default_plus_deny_echo(), ReloadMode::Strict).unwrap();
        assert_ne!(engine.policy_fingerprint(), before);

        let run = engine.execute_with_rollback("echo ran > marker.txt").unwrap();
        assert!(!run.ran(), "the new rule did not take effect");
        assert_eq!(run.decision.verdict, Verdict::Deny);
        assert!(r.read("marker.txt").is_none(), "a command the new policy forbids ran");
    }

    #[test]
    fn a_refused_reload_leaves_execution_behaviour_alone() {
        let r = Repo::new("reload-refused");
        let engine = r.engine();
        let before = engine.policy_fingerprint();

        // Valid, but nearly empty: drops every restriction the built-in has.
        let err =
            engine.reload_policy("version 1\ndefault allow\n", ReloadMode::Strict).unwrap_err();
        assert!(matches!(err, ReloadError::Weakens(_)), "{err}");
        assert!(engine.reload_policy("garbage", ReloadMode::AllowWeakening).is_err());

        assert_eq!(engine.policy_fingerprint(), before);
        assert_eq!(engine.evaluate("rm -rf /etc").verdict, Verdict::Deny);
    }

    #[test]
    fn decisions_and_reloads_form_a_chain_the_audit_log_can_be_followed_along() {
        let r = Repo::new("reload-chain");
        let l = LogDir::new("reload-chain");
        let engine = r.engine().with_audit(l.open(|c| c));
        let text = default_plus_deny_echo();

        engine.evaluate("ls");
        let fp0 = format!("{:016x}", engine.policy_fingerprint());
        engine.reload_policy(&text, ReloadMode::Strict).unwrap();
        let fp1 = format!("{:016x}", engine.policy_fingerprint());
        engine.evaluate("ls");
        engine.execute_with_rollback("echo hi").unwrap(); // refused under the new rule

        let recs = l.records();
        let kinds: Vec<_> = recs.iter().filter_map(|x| str_of(x, "kind")).collect();
        assert_eq!(kinds, ["header", "evaluate", "policy", "evaluate", "refused"]);

        // Before the reload: judged by fp0.
        assert_eq!(str_of(&recs[1], "policy"), Some(fp0.as_str()));
        // The reload record links old -> new, and names the text that was loaded.
        let p = &recs[2];
        assert_eq!(str_of(p, "outcome"), Some("applied"));
        assert_eq!(str_of(p, "before"), Some(fp0.as_str()));
        assert_eq!(str_of(p, "after"), Some(fp1.as_str()));
        assert_eq!(str_of(p, "mode"), Some("strict"));
        assert_eq!(
            str_of(p, "sha256"),
            Some(crate::sha256::hex(&crate::sha256::hash(text.as_bytes())).as_str())
        );
        assert_eq!(p.get("bytes").and_then(json::Json::as_i64), Some(text.len() as i64));
        let added = p.get("added").and_then(json::Json::as_array).unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].as_str(), Some("test.no-echo"));
        // After it: judged by fp1, including the refusal.
        assert_eq!(str_of(&recs[3], "policy"), Some(fp1.as_str()));
        assert_eq!(str_of(&recs[4], "policy"), Some(fp1.as_str()));
        assert_eq!(str_of(&recs[4], "verdict"), Some("deny"));
    }

    #[test]
    fn refused_reloads_are_recorded_too_and_say_why() {
        let r = Repo::new("reload-audit-refused");
        let l = LogDir::new("reload-audit-refused");
        let engine = r.engine().with_audit(l.open(|c| c));

        let weakening = "version 1\ndefault allow\n";
        assert!(engine.reload_policy(weakening, ReloadMode::Strict).is_err());
        assert!(engine.reload_policy("not a policy", ReloadMode::Strict).is_err());

        let pol = l.of_kind("policy");
        assert_eq!(pol.len(), 2);

        assert_eq!(str_of(&pol[0], "outcome"), Some("rejected"));
        assert!(str_of(&pol[0], "error").unwrap().contains("lower protection"));
        let weakened = pol[0].get("weakened").and_then(json::Json::as_array).unwrap();
        assert!(!weakened.is_empty(), "what would have been weakened was not recorded");
        assert!(!pol[0].get("removed").and_then(json::Json::as_array).unwrap().is_empty());

        assert_eq!(str_of(&pol[1], "outcome"), Some("rejected"));
        assert!(str_of(&pol[1], "error").unwrap().contains("previous policy still in force"));
        assert!(pol[1].get("weakened").is_none(), "an unparseable policy has no diff to record");
    }

    #[test]
    fn allowing_weakening_is_visible_in_the_record() {
        let r = Repo::new("reload-audit-weaken");
        let l = LogDir::new("reload-audit-weaken");
        let engine = r.engine().with_audit(l.open(|c| c));

        engine.reload_policy("version 1\ndefault confine\n", ReloadMode::AllowWeakening).unwrap();
        let p = &l.of_kind("policy")[0];
        assert_eq!(str_of(p, "outcome"), Some("applied"));
        assert_eq!(str_of(p, "mode"), Some("allow-weakening"));
        assert!(
            !p.get("weakened").and_then(json::Json::as_array).unwrap().is_empty(),
            "a weakening that was allowed must still say what it weakened"
        );
    }

    #[test]
    fn a_reload_without_an_audit_log_still_works() {
        let r = Repo::new("reload-no-audit");
        let engine = r.engine();
        assert!(engine.reload_policy(&default_plus_deny_echo(), ReloadMode::Strict).is_ok());
        assert_eq!(engine.audit_failures(), 0);
    }
}
