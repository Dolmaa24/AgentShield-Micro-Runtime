//! C ABI for shellguard.
//!
//! The realistic integration is not a Rust program. It is an agent harness in
//! Python or TypeScript that has just had a model produce a shell command and
//! needs an answer before running it, so the boundary that matters is this one.
//!
//! Two rules shape everything here.
//!
//! **Nothing unwinds across the boundary.** A Rust panic crossing into C is
//! undefined behaviour, so every entry point is wrapped in `catch_unwind` and
//! returns a safe value instead. In release builds `panic = "abort"` makes this
//! moot — the process dies rather than corrupting anything — but the guard is
//! what makes the debug build safe too, and a sandbox whose FFI layer is only
//! sound in release is not sound.
//!
//! **A bad command is a decision, not an error.** `sg_evaluate` returns a
//! `Deny` decision for input that does not parse, rather than NULL. Returning
//! an error there would put the caller in the position of choosing what to do
//! about it, and the answer they reach for under deadline pressure is to run
//! the command.
//!
//! See `include/agent_sandbox.h` for the C declarations.

// The opaque handle types are named for C, not for Rust. `sg_gate` is what
// appears in the header and in every caller's source, and renaming it here to
// satisfy Rust's convention would leave the two spellings to be kept in sync
// by hand for no benefit.
#![allow(non_camel_case_types)]

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::Duration;

use shellguard_gate::{Decision, Gate, GateConfig, Worker};
use shellguard_policy::Verdict;

#[derive(Debug)]
pub struct sg_gate {
    gate: Gate,
}

#[derive(Debug)]
pub struct sg_worker {
    worker: Worker,
}

#[derive(Debug)]
pub struct sg_decision {
    verdict: i32,
    elapsed_ns: u64,
    complete: bool,
    json: CString,
    findings: Vec<(CString, CString)>,
}

fn verdict_code(v: Verdict) -> i32 {
    match v {
        Verdict::Allow => 0,
        Verdict::Confine => 1,
        Verdict::Ask => 2,
        Verdict::Deny => 3,
    }
}

/// Build a C string, falling back to an empty one rather than failing.
///
/// Interior NULs can only reach here from command text, and losing the tail of
/// an excerpt is a strictly better outcome than losing the decision.
fn cstring(s: &str) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

fn build_decision(command: &str, d: &Decision) -> sg_decision {
    sg_decision {
        verdict: verdict_code(d.verdict),
        elapsed_ns: d.elapsed.as_nanos().min(u64::MAX as u128) as u64,
        complete: d.incomplete.is_none(),
        json: cstring(&d.to_json(command)),
        findings: d.findings.iter().map(|f| (cstring(&f.rule_id), cstring(&f.reason))).collect(),
    }
}

/// # Safety
/// `s` must be NULL or a valid NUL-terminated C string.
unsafe fn opt_str<'a>(s: *const c_char) -> Option<&'a CStr> {
    if s.is_null() {
        None
    } else {
        // SAFETY: the caller guarantees a valid NUL-terminated string.
        Some(unsafe { CStr::from_ptr(s) })
    }
}

/// # Safety
/// `workspace` must be a valid NUL-terminated C string. `policy_path` must be
/// NULL or one. `err_out` must be NULL or a writable `char*`.
#[no_mangle]
pub unsafe extern "C" fn sg_gate_new(
    workspace: *const c_char,
    policy_path: *const c_char,
    deadline_ms: u64,
    err_out: *mut *mut c_char,
) -> *mut sg_gate {
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: contract above.
        let ws = unsafe { opt_str(workspace) }
            .ok_or_else(|| "workspace must not be NULL".to_string())?
            .to_str()
            .map_err(|_| "workspace is not valid UTF-8".to_string())?;

        let mut cfg = GateConfig::from_env(PathBuf::from(ws));
        if deadline_ms > 0 {
            cfg.deadline = Duration::from_millis(deadline_ms);
        }

        // SAFETY: contract above.
        let gate = match unsafe { opt_str(policy_path) } {
            None => Gate::with_default_policy(cfg),
            Some(p) => {
                let path = p.to_str().map_err(|_| "policy path is not valid UTF-8".to_string())?;
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read {path}: {e}"))?;
                let policy =
                    shellguard_policy::parse_policy(&text).map_err(|e| format!("{path}: {e}"))?;
                Gate::new(policy.compile(), cfg)
            }
        };
        Ok::<_, String>(Box::into_raw(Box::new(sg_gate { gate })))
    }));

    match result {
        Ok(Ok(ptr)) => ptr,
        Ok(Err(msg)) => {
            // SAFETY: caller guarantees `err_out` is NULL or writable.
            unsafe { write_err(err_out, &msg) };
            std::ptr::null_mut()
        }
        Err(_) => {
            // SAFETY: as above.
            unsafe { write_err(err_out, "panic while building the gate") };
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `err_out` must be NULL or point to a writable `char*`.
unsafe fn write_err(err_out: *mut *mut c_char, msg: &str) {
    if err_out.is_null() {
        return;
    }
    let c = cstring(msg);
    // SAFETY: caller guarantees the pointer is writable.
    unsafe { *err_out = c.into_raw() };
}

/// # Safety
/// `gate` must be NULL or a pointer from [`sg_gate_new`], not yet freed.
#[no_mangle]
pub unsafe extern "C" fn sg_gate_free(gate: *mut sg_gate) {
    if gate.is_null() {
        return;
    }
    // SAFETY: caller guarantees the pointer came from Box::into_raw here.
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(gate) })));
}

#[no_mangle]
pub extern "C" fn sg_worker_new() -> *mut sg_worker {
    match catch_unwind(|| Box::into_raw(Box::new(sg_worker { worker: Worker::new() }))) {
        Ok(p) => p,
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `worker` must be NULL or a pointer from [`sg_worker_new`], not yet freed.
#[no_mangle]
pub unsafe extern "C" fn sg_worker_free(worker: *mut sg_worker) {
    if worker.is_null() {
        return;
    }
    // SAFETY: caller guarantees provenance.
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(worker) })));
}

/// # Safety
/// `worker` must be NULL or a valid pointer from [`sg_worker_new`].
#[no_mangle]
pub unsafe extern "C" fn sg_worker_invalidate_cache(worker: *mut sg_worker) {
    if worker.is_null() {
        return;
    }
    // SAFETY: caller guarantees validity and exclusive access.
    let w = unsafe { &mut *worker };
    let _ = catch_unwind(AssertUnwindSafe(|| w.worker.invalidate_cache()));
}

/// # Safety
/// `gate` and `worker` must be valid pointers from their constructors and not
/// freed. `command` must be a valid NUL-terminated C string. `worker` must not
/// be used concurrently from another thread.
#[no_mangle]
pub unsafe extern "C" fn sg_evaluate(
    gate: *const sg_gate,
    worker: *mut sg_worker,
    command: *const c_char,
) -> *mut sg_decision {
    if gate.is_null() || worker.is_null() || command.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: contract above.
    let g = unsafe { &*gate };
    // SAFETY: contract above, including the no-sharing requirement.
    let w = unsafe { &mut *worker };
    // SAFETY: contract above.
    let raw = unsafe { CStr::from_ptr(command) };

    let result = catch_unwind(AssertUnwindSafe(|| {
        let Ok(src) = raw.to_str() else {
            // Not UTF-8. Refusing is the only defensible answer: the bytes
            // cannot be parsed as shell, so nothing can be said about them,
            // and "nothing can be said" is not a reason to run something.
            let d = Decision {
                verdict: Verdict::Deny,
                findings: Vec::new(),
                capabilities: Vec::new(),
                commands: Vec::new(),
                incomplete: Some(shellguard_gate::Incomplete::Parse(
                    "command is not valid UTF-8".into(),
                )),
                elapsed: Duration::ZERO,
            };
            return build_decision("", &d);
        };
        let d = g.gate.evaluate(src, &mut w.worker);
        build_decision(src, &d)
    }));

    match result {
        Ok(d) => Box::into_raw(Box::new(d)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `decision` must be NULL or a pointer from [`sg_evaluate`], not yet freed.
#[no_mangle]
pub unsafe extern "C" fn sg_decision_free(decision: *mut sg_decision) {
    if decision.is_null() {
        return;
    }
    // SAFETY: caller guarantees provenance.
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(decision) })));
}

/// # Safety
/// `decision` must be NULL or a valid pointer from [`sg_evaluate`].
#[no_mangle]
pub unsafe extern "C" fn sg_decision_verdict(decision: *const sg_decision) -> i32 {
    // SAFETY: the contract on this function is exactly `as_ref`'s.
    match unsafe { decision.as_ref() } {
        // A NULL decision reads as Deny, not Allow. A caller that forgets to
        // null-check gets the safe answer.
        None => 3,
        Some(d) => d.verdict,
    }
}

/// # Safety
/// `decision` must be NULL or a valid pointer from [`sg_evaluate`].
#[no_mangle]
pub unsafe extern "C" fn sg_decision_elapsed_ns(decision: *const sg_decision) -> u64 {
    // SAFETY: the contract on this function is exactly `as_ref`'s.
    unsafe { decision.as_ref() }.map_or(0, |d| d.elapsed_ns)
}

/// # Safety
/// `decision` must be NULL or a valid pointer from [`sg_evaluate`].
#[no_mangle]
pub unsafe extern "C" fn sg_decision_complete(decision: *const sg_decision) -> i32 {
    // SAFETY: the contract on this function is exactly `as_ref`'s.
    unsafe { decision.as_ref() }.map_or(0, |d| i32::from(d.complete))
}

/// # Safety
/// `decision` must be NULL or a valid pointer. The returned string is owned by
/// the decision and valid until [`sg_decision_free`].
#[no_mangle]
pub unsafe extern "C" fn sg_decision_json(decision: *const sg_decision) -> *const c_char {
    // SAFETY: the contract on this function is exactly `as_ref`'s.
    match unsafe { decision.as_ref() } {
        None => std::ptr::null(),
        Some(d) => d.json.as_ptr(),
    }
}

/// # Safety
/// `decision` must be NULL or a valid pointer from [`sg_evaluate`].
#[no_mangle]
pub unsafe extern "C" fn sg_decision_finding_count(decision: *const sg_decision) -> usize {
    // SAFETY: the contract on this function is exactly `as_ref`'s.
    unsafe { decision.as_ref() }.map_or(0, |d| d.findings.len())
}

/// # Safety
/// `decision` must be NULL or a valid pointer. The returned string is owned by
/// the decision and valid until [`sg_decision_free`].
#[no_mangle]
pub unsafe extern "C" fn sg_decision_finding_rule(
    decision: *const sg_decision,
    index: usize,
) -> *const c_char {
    // SAFETY: the contract on this function is exactly `as_ref`'s.
    match unsafe { decision.as_ref() }.and_then(|d| d.findings.get(index)) {
        Some((rule, _)) => rule.as_ptr(),
        None => std::ptr::null(),
    }
}

/// # Safety
/// `decision` must be NULL or a valid pointer. The returned string is owned by
/// the decision and valid until [`sg_decision_free`].
#[no_mangle]
pub unsafe extern "C" fn sg_decision_finding_reason(
    decision: *const sg_decision,
    index: usize,
) -> *const c_char {
    // SAFETY: the contract on this function is exactly `as_ref`'s.
    match unsafe { decision.as_ref() }.and_then(|d| d.findings.get(index)) {
        Some((_, reason)) => reason.as_ptr(),
        None => std::ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn sg_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn sg_backend() -> *const c_char {
    #[cfg(target_os = "macos")]
    {
        c"seatbelt".as_ptr()
    }
    #[cfg(target_os = "linux")]
    {
        c"landlock+seccomp".as_ptr()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        c"none".as_ptr()
    }
}

/// # Safety
/// `s` must be NULL or a pointer returned through an out-parameter of this
/// library, not yet freed.
#[no_mangle]
pub unsafe extern "C" fn sg_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: caller guarantees the pointer came from CString::into_raw here.
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { CString::from_raw(s) })));
}

#[cfg(test)]
mod tests {
    // Every call below crosses the C boundary, so this module is
    // wall-to-wall `unsafe`. Every pointer comes from a constructor in
    // this file and is freed exactly once, which the fixture enforces;
    // annotating each block would be twenty copies of that sentence.
    #![allow(clippy::undocumented_unsafe_blocks)]

    use super::*;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    struct Fixture {
        gate: *mut sg_gate,
        worker: *mut sg_worker,
    }

    impl Fixture {
        fn new() -> Self {
            let ws = std::env::temp_dir().join("shellguard-ffi-tests/ws");
            std::fs::create_dir_all(&ws).unwrap();
            let wsc = c(ws.to_str().unwrap());
            let mut err: *mut c_char = std::ptr::null_mut();
            let gate = unsafe { sg_gate_new(wsc.as_ptr(), std::ptr::null(), 0, &mut err) };
            assert!(!gate.is_null(), "gate_new failed");
            assert!(err.is_null());
            Fixture { gate, worker: sg_worker_new() }
        }

        fn eval(&self, cmd: &str) -> *mut sg_decision {
            let s = c(cmd);
            unsafe { sg_evaluate(self.gate, self.worker, s.as_ptr()) }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                sg_worker_free(self.worker);
                sg_gate_free(self.gate);
            }
        }
    }

    #[test]
    fn evaluates_and_reports_a_verdict() {
        let f = Fixture::new();
        let d = f.eval("rm -rf /etc");
        assert!(!d.is_null());
        unsafe {
            assert_eq!(sg_decision_verdict(d), 3);
            assert_eq!(sg_decision_complete(d), 1);
            assert!(sg_decision_finding_count(d) > 0);
            let rule = CStr::from_ptr(sg_decision_finding_rule(d, 0)).to_str().unwrap();
            assert!(rule.starts_with("destructive."), "{rule}");
            let reason = CStr::from_ptr(sg_decision_finding_reason(d, 0)).to_str().unwrap();
            assert!(!reason.is_empty());
            sg_decision_free(d);
        }

        let d = f.eval("git status");
        unsafe {
            assert_eq!(sg_decision_verdict(d), 0);
            sg_decision_free(d);
        }
    }

    #[test]
    fn json_is_well_formed_and_carries_the_command() {
        let f = Fixture::new();
        let d = f.eval("rm -rf /etc");
        unsafe {
            let json = CStr::from_ptr(sg_decision_json(d)).to_str().unwrap();
            assert!(json.starts_with('{') && json.ends_with('}'), "{json}");
            assert!(json.contains("\"verdict\":\"deny\""), "{json}");
            assert!(json.contains("\"command\":\"rm -rf /etc\""), "{json}");
            assert!(json.contains("\"findings\":["), "{json}");
            sg_decision_free(d);
        }
    }

    #[test]
    fn json_escapes_control_characters_from_the_command() {
        // The command text is attacker-influenced and ends up in logs.
        let f = Fixture::new();
        let d = f.eval("echo \"a\tb\" && rm -rf /etc");
        unsafe {
            let json = CStr::from_ptr(sg_decision_json(d)).to_str().unwrap();
            assert!(!json.contains('\t'), "raw tab survived into JSON: {json}");
            assert!(json.contains("\\t"), "{json}");
            sg_decision_free(d);
        }
    }

    #[test]
    fn unparseable_input_denies_rather_than_erroring() {
        let f = Fixture::new();
        let d = f.eval("echo $(unterminated");
        assert!(!d.is_null(), "a bad command must be a decision, not a NULL");
        unsafe {
            assert_eq!(sg_decision_verdict(d), 3);
            assert_eq!(sg_decision_complete(d), 0);
            sg_decision_free(d);
        }
    }

    #[test]
    fn null_arguments_are_handled_and_read_as_deny() {
        let f = Fixture::new();
        let s = c("ls");
        unsafe {
            assert!(sg_evaluate(std::ptr::null(), f.worker, s.as_ptr()).is_null());
            assert!(sg_evaluate(f.gate, std::ptr::null_mut(), s.as_ptr()).is_null());
            assert!(sg_evaluate(f.gate, f.worker, std::ptr::null()).is_null());

            // A caller that skips the null check must not get Allow.
            assert_eq!(sg_decision_verdict(std::ptr::null()), 3);
            assert_eq!(sg_decision_complete(std::ptr::null()), 0);
            assert_eq!(sg_decision_finding_count(std::ptr::null()), 0);
            assert!(sg_decision_json(std::ptr::null()).is_null());
            assert!(sg_decision_finding_rule(std::ptr::null(), 0).is_null());

            // Freeing NULL is a no-op, as C callers will expect.
            sg_decision_free(std::ptr::null_mut());
            sg_gate_free(std::ptr::null_mut());
            sg_worker_free(std::ptr::null_mut());
            sg_string_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn out_of_range_finding_index_returns_null() {
        let f = Fixture::new();
        let d = f.eval("rm -rf /etc");
        unsafe {
            let n = sg_decision_finding_count(d);
            assert!(sg_decision_finding_rule(d, n).is_null());
            assert!(sg_decision_finding_reason(d, n + 100).is_null());
            sg_decision_free(d);
        }
    }

    #[test]
    fn a_bad_workspace_reports_an_error_string() {
        let mut err: *mut c_char = std::ptr::null_mut();
        let g = unsafe { sg_gate_new(std::ptr::null(), std::ptr::null(), 0, &mut err) };
        assert!(g.is_null());
        assert!(!err.is_null());
        unsafe {
            let msg = CStr::from_ptr(err).to_str().unwrap();
            assert!(msg.contains("workspace"), "{msg}");
            sg_string_free(err);
        }
    }

    #[test]
    fn a_bad_policy_path_reports_an_error_string() {
        let ws = c("/tmp");
        let bad = c("/nonexistent/policy.file");
        let mut err: *mut c_char = std::ptr::null_mut();
        let g = unsafe { sg_gate_new(ws.as_ptr(), bad.as_ptr(), 0, &mut err) };
        assert!(g.is_null());
        assert!(!err.is_null());
        unsafe {
            let msg = CStr::from_ptr(err).to_str().unwrap();
            assert!(msg.contains("cannot read"), "{msg}");
            sg_string_free(err);
        }
    }

    #[test]
    fn a_deadline_of_one_millisecond_is_honoured() {
        let ws = c("/tmp");
        let mut err: *mut c_char = std::ptr::null_mut();
        let g = unsafe { sg_gate_new(ws.as_ptr(), std::ptr::null(), 1, &mut err) };
        assert!(!g.is_null());
        unsafe {
            sg_gate_free(g);
        }
    }

    #[test]
    fn version_and_backend_are_readable() {
        unsafe {
            let v = CStr::from_ptr(sg_version()).to_str().unwrap();
            assert!(!v.is_empty());
            let b = CStr::from_ptr(sg_backend()).to_str().unwrap();
            assert!(["seatbelt", "landlock+seccomp", "none"].contains(&b), "{b}");
        }
    }

    #[test]
    fn a_worker_can_be_reused_across_many_evaluations() {
        let f = Fixture::new();
        for _ in 0..200 {
            let d = f.eval("sudo timeout 5 rm -rf /etc");
            unsafe {
                assert_eq!(sg_decision_verdict(d), 3);
                sg_decision_free(d);
            }
        }
        unsafe { sg_worker_invalidate_cache(f.worker) };
        let d = f.eval("git status");
        unsafe {
            assert_eq!(sg_decision_verdict(d), 0);
            sg_decision_free(d);
        }
    }
}

// ---------------------------------------------------------------- engine
//
// The gate answers "should this run". The engine answers "run it, and put the
// workspace back if it goes wrong", which is what an agent harness actually
// needs. Both are exposed because they are different questions: a harness may
// want to judge a command, show the reason to a model, and never execute it.
//
// Results cross as JSON rather than as a struct with twenty accessors. The
// shape is already an interface the CLI publishes, one serialiser is easier to
// keep honest than two, and a caller in Python or Node has a JSON parser to
// hand while it does not have a C struct layout.

/// Roll back when the command exits non-zero.
///
/// Off by default: a failing command is not by itself a reason to discard the
/// work it did, and a half-finished refactor is often worth keeping.
pub const SG_ROLLBACK_ON_FAILURE: u32 = 1 << 0;

/// Run commands the gate escalates instead of stopping at them.
///
/// Off by default. `Ask` means a human should look, and a harness that runs
/// those anyway has replaced a decision with a default. Set it when there is
/// genuinely a human in the loop, or when the containment and rollback layers
/// are considered sufficient for the escalated class.
pub const SG_RUN_ON_ASK: u32 = 1 << 1;

/// Also record the command's stdout and stderr in the audit log (redacted).
///
/// Off by default: output is where credentials most often appear, and a log
/// that records it has to be protected like the credentials themselves.
pub const SG_AUDIT_VERBOSE: u32 = 1 << 0;

/// Refuse to run a command whose audit record cannot be written.
///
/// Off by default, because a full disk should not stop every command. Set it
/// when an unaudited command is worse than a refused one.
pub const SG_AUDIT_REQUIRED: u32 = 1 << 1;

#[derive(Debug)]
pub struct sg_engine {
    engine: shellguard_runtime::Engine,
}

/// Create an engine rooted at `workspace`.
///
/// # Safety
/// `workspace` must be a valid NUL-terminated C string. `protected` may be
/// NULL, or a NUL-terminated string of newline-separated paths that must not
/// change. `err_out` must be NULL or a writable `char*`.
#[no_mangle]
pub unsafe extern "C" fn sg_engine_new(
    workspace: *const c_char,
    protected: *const c_char,
    timeout_ms: u64,
    flags: u32,
    err_out: *mut *mut c_char,
) -> *mut sg_engine {
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: contract above.
        let ws = unsafe { opt_str(workspace) }
            .ok_or_else(|| "workspace must not be NULL".to_string())?
            .to_str()
            .map_err(|_| "workspace is not valid UTF-8".to_string())?;

        let mut engine = shellguard_runtime::Engine::new(ws).map_err(|e| e.to_string())?;
        if timeout_ms > 0 {
            engine = engine.with_timeout(Duration::from_millis(timeout_ms));
        }

        // SAFETY: contract above.
        let protected_paths: Vec<std::path::PathBuf> = match unsafe { opt_str(protected) } {
            None => Vec::new(),
            Some(list) => list
                .to_str()
                .map_err(|_| "protected list is not valid UTF-8")?
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(std::path::PathBuf::from)
                .collect(),
        };

        // `on_nonzero_exit` is off in the library default, because a failing
        // command is not by itself a reason to discard the work it did — a
        // half-finished refactor is often worth keeping. A harness that wants
        // all-or-nothing semantics asks for them here.
        let rollback_on_failure = flags & SG_ROLLBACK_ON_FAILURE != 0;
        if rollback_on_failure || !protected_paths.is_empty() {
            engine = engine.with_rollback_policy(shellguard_runtime::RollbackPolicy {
                protected: protected_paths,
                on_nonzero_exit: rollback_on_failure,
                ..Default::default()
            });
        }
        if flags & SG_RUN_ON_ASK != 0 {
            engine = engine.run_on_ask(true);
        }

        Ok::<_, String>(Box::into_raw(Box::new(sg_engine { engine })))
    }));

    match result {
        Ok(Ok(p)) => p,
        Ok(Err(msg)) => {
            // SAFETY: contract above.
            unsafe { write_err(err_out, &msg) };
            std::ptr::null_mut()
        }
        Err(_) => {
            // SAFETY: contract above.
            unsafe { write_err(err_out, "panic while building the engine") };
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `engine` must be NULL or a pointer from [`sg_engine_new`], not yet freed.
#[no_mangle]
pub unsafe extern "C" fn sg_engine_free(engine: *mut sg_engine) {
    if engine.is_null() {
        return;
    }
    // SAFETY: caller guarantees provenance.
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(engine) })));
}

/// The runtime backend in use, e.g. "local". Borrowed, valid for the process.
///
/// # Safety
/// `engine` must be NULL or a valid pointer from [`sg_engine_new`].
#[no_mangle]
pub unsafe extern "C" fn sg_engine_runtime(engine: *const sg_engine) -> *const c_char {
    // SAFETY: the contract on this function is exactly `as_ref`'s.
    match unsafe { engine.as_ref() } {
        None => std::ptr::null(),
        Some(e) => match e.engine.runtime_name() {
            "local" => c"local".as_ptr(),
            "vz" => c"vz".as_ptr(),
            "firecracker" => c"firecracker".as_ptr(),
            "gvisor" => c"gvisor".as_ptr(),
            _ => c"unknown".as_ptr(),
        },
    }
}

/// Attach an audit log to an engine. Returns 0, or -1 with a message in
/// `err_out` (for [`sg_string_free`]).
///
/// Failing to open the log is always an error here, whatever `flags` say:
/// `SG_AUDIT_REQUIRED` governs what happens when a *write* fails later, not
/// whether a log that cannot be opened at all is acceptable. Unknown flag bits
/// are rejected rather than ignored, so a typo does not silently turn a
/// requirement off.
///
/// # Safety
/// `engine` must be NULL or a valid pointer from [`sg_engine_new`]; `path` a
/// valid NUL-terminated C string; `err_out` NULL or a writable `char*`. Not
/// safe to call concurrently with any other call on the same engine.
#[no_mangle]
pub unsafe extern "C" fn sg_engine_set_audit(
    engine: *mut sg_engine,
    path: *const c_char,
    flags: u32,
    err_out: *mut *mut c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: contract above.
        let e = unsafe { engine.as_mut() }.ok_or("engine must not be NULL")?;
        // SAFETY: contract above.
        let p = unsafe { opt_str(path) }
            .ok_or("audit path must not be NULL")?
            .to_str()
            .map_err(|_| "audit path is not valid UTF-8")?;
        if flags & !(SG_AUDIT_VERBOSE | SG_AUDIT_REQUIRED) != 0 {
            return Err(format!(
                "unknown audit flags {:#x}",
                flags & !(SG_AUDIT_VERBOSE | SG_AUDIT_REQUIRED)
            ));
        }

        let cfg = shellguard_runtime::audit::AuditConfig::new(p)
            .source("ffi")
            .verbose(flags & SG_AUDIT_VERBOSE != 0)
            .required(flags & SG_AUDIT_REQUIRED != 0);
        let log = shellguard_runtime::audit::AuditLog::open(cfg)
            .map_err(|err| format!("cannot open audit log {p}: {err}"))?;
        e.engine.set_audit(log);
        Ok::<_, String>(())
    }));

    match result {
        Ok(Ok(())) => 0,
        Ok(Err(msg)) => {
            // SAFETY: contract above.
            unsafe { write_err(err_out, &msg) };
            -1
        }
        Err(_) => {
            // SAFETY: contract above.
            unsafe { write_err(err_out, "panic while opening the audit log") };
            -1
        }
    }
}

/// How many audit records failed to write since the log was attached. Zero for
/// NULL or an engine with no log.
///
/// A best-effort log that starts failing is otherwise silent; this is the
/// number to alert on.
///
/// # Safety
/// `engine` must be NULL or a valid pointer from [`sg_engine_new`].
#[no_mangle]
pub unsafe extern "C" fn sg_engine_audit_failures(engine: *const sg_engine) -> u64 {
    // SAFETY: the contract on this function is exactly `as_ref`'s.
    unsafe { engine.as_ref() }.map_or(0, |e| e.engine.audit_failures())
}

/// Judge a command without running it. Returns owned JSON for
/// [`sg_string_free`], or NULL if an argument was unusable.
///
/// # Safety
/// `engine` must be valid and `command` a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn sg_engine_eval_json(
    engine: *const sg_engine,
    command: *const c_char,
) -> *mut c_char {
    if engine.is_null() || command.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: contract above.
    let e = unsafe { &*engine };
    // SAFETY: contract above.
    let raw = unsafe { CStr::from_ptr(command) };

    let out = catch_unwind(AssertUnwindSafe(|| {
        let Ok(src) = raw.to_str() else {
            // Not UTF-8, so it cannot be parsed as shell and nothing can be
            // said about it. Refusing is the only defensible answer.
            return cstring(
                r#"{"verdict":"deny","complete":false,"incomplete":"command is not valid UTF-8","findings":[],"capabilities":[]}"#,
            );
        };
        cstring(&e.engine.evaluate(src).to_json(src))
    }));

    match out {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Gate, checkpoint, execute, verify, roll back. Returns owned JSON for
/// [`sg_string_free`], or NULL if an argument was unusable.
///
/// A command the gate refuses does not run, and that is reported in the JSON
/// as `"ran": false` rather than as an error — refusing is a successful
/// outcome, not a failure of the call.
///
/// # Safety
/// `engine` must be valid and `command` a valid NUL-terminated C string. Not
/// safe to call concurrently on one engine from several threads.
#[no_mangle]
pub unsafe extern "C" fn sg_engine_execute_json(
    engine: *const sg_engine,
    command: *const c_char,
) -> *mut c_char {
    if engine.is_null() || command.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: contract above.
    let e = unsafe { &*engine };
    // SAFETY: contract above.
    let raw = unsafe { CStr::from_ptr(command) };

    let out = catch_unwind(AssertUnwindSafe(|| {
        let Ok(src) = raw.to_str() else {
            return cstring(
                r#"{"error":"command is not valid UTF-8","ran":false,"execution":null,"rollback":null}"#,
            );
        };
        match e.engine.execute_with_rollback(src) {
            Ok(run) => cstring(&run.to_json()),
            Err(err) => {
                let mut s = String::from("{\"error\":");
                s.push_str(&json_escape(&err.to_string()));
                s.push_str(",\"ran\":false,\"execution\":null,\"rollback\":null}");
                cstring(&s)
            }
        }
    }));

    match out {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Minimal JSON string escaping for the error path above.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod audit_tests {
    // Same reasoning as `tests` above: every call crosses the C boundary, and
    // every pointer comes from a constructor in this module and is freed once.
    #![allow(clippy::undocumented_unsafe_blocks)]

    use super::*;
    use shellguard_runtime::json;
    use std::path::Path;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// A scratch directory holding a workspace and, beside it, the log's own.
    struct Sandbox {
        root: PathBuf,
    }

    impl Sandbox {
        fn new(name: &str) -> Sandbox {
            let root = std::env::temp_dir()
                .join(format!("shellguard-ffi-audit-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("ws")).unwrap();
            Sandbox { root: root.canonicalize().unwrap() }
        }
        fn ws(&self) -> PathBuf {
            self.root.join("ws")
        }
        fn log_dir(&self) -> PathBuf {
            self.root.join("log")
        }
        fn log(&self) -> PathBuf {
            self.log_dir().join("audit.jsonl")
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn new_engine(ws: &Path) -> *mut sg_engine {
        let w = c(ws.to_str().unwrap());
        let mut err: *mut c_char = std::ptr::null_mut();
        let e = unsafe { sg_engine_new(w.as_ptr(), std::ptr::null(), 0, 0, &mut err) };
        assert!(!e.is_null(), "sg_engine_new failed");
        e
    }

    fn set_audit(e: *mut sg_engine, path: &Path, flags: u32) -> Result<(), String> {
        let p = c(path.to_str().unwrap());
        let mut err: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { sg_engine_set_audit(e, p.as_ptr(), flags, &mut err) };
        if rc == 0 {
            assert!(err.is_null());
            Ok(())
        } else {
            assert!(!err.is_null(), "failure with no message");
            let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_string();
            unsafe { sg_string_free(err) };
            Err(msg)
        }
    }

    fn execute(e: *mut sg_engine, cmd: &str) -> json::Json {
        let s = c(cmd);
        let out = unsafe { sg_engine_execute_json(e, s.as_ptr()) };
        assert!(!out.is_null());
        let text = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        unsafe { sg_string_free(out) };
        json::parse(&text).unwrap_or_else(|e| panic!("{e}: {text}"))
    }

    fn kinds(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap()
            .lines()
            .map(|l| {
                json::parse(l)
                    .unwrap()
                    .get("kind")
                    .and_then(json::Json::as_str)
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn an_audited_engine_records_what_it_runs() {
        let sb = Sandbox::new("records");
        let e = new_engine(&sb.ws());
        set_audit(e, &sb.log(), 0).unwrap();

        let v = execute(e, "echo hello");
        assert_eq!(v.get("ran").and_then(json::Json::as_bool), Some(true));
        assert_eq!(v.get("audit_error"), Some(&json::Json::Null));
        assert_eq!(kinds(&sb.log()), ["header", "start", "finish"]);
        assert_eq!(unsafe { sg_engine_audit_failures(e) }, 0);

        unsafe { sg_engine_free(e) };
    }

    #[test]
    fn the_header_says_the_log_was_opened_through_the_c_abi() {
        let sb = Sandbox::new("source");
        let e = new_engine(&sb.ws());
        set_audit(e, &sb.log(), SG_AUDIT_VERBOSE | SG_AUDIT_REQUIRED).unwrap();
        let header = std::fs::read_to_string(sb.log()).unwrap();
        let h = json::parse(header.lines().next().unwrap()).unwrap();
        assert_eq!(h.get("source").and_then(json::Json::as_str), Some("ffi"));
        assert_eq!(h.get("verbose").and_then(json::Json::as_bool), Some(true));
        assert_eq!(h.get("required").and_then(json::Json::as_bool), Some(true));
        unsafe { sg_engine_free(e) };
    }

    #[test]
    fn bad_arguments_are_errors_with_messages_not_crashes() {
        let sb = Sandbox::new("badargs");
        let e = new_engine(&sb.ws());
        let good = sb.log();

        // NULL engine.
        let p = c(good.to_str().unwrap());
        let mut err: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { sg_engine_set_audit(std::ptr::null_mut(), p.as_ptr(), 0, &mut err) };
        assert_eq!(rc, -1);
        unsafe { sg_string_free(err) };

        // NULL path.
        let mut err: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { sg_engine_set_audit(e, std::ptr::null(), 0, &mut err) };
        assert_eq!(rc, -1);
        unsafe { sg_string_free(err) };

        // NULL err_out is tolerated.
        let rc = unsafe { sg_engine_set_audit(e, std::ptr::null(), 0, std::ptr::null_mut()) };
        assert_eq!(rc, -1);

        // Unknown flag bits are refused, not ignored.
        let msg = set_audit(e, &good, 1 << 7).unwrap_err();
        assert!(msg.contains("unknown audit flags"), "{msg}");
        assert!(!good.exists(), "a rejected call still created the log");

        // A directory is not a log.
        assert!(set_audit(e, &sb.ws(), 0).is_err());

        unsafe { sg_engine_free(e) };
    }

    #[test]
    fn audit_failures_of_a_null_or_unaudited_engine_is_zero() {
        assert_eq!(unsafe { sg_engine_audit_failures(std::ptr::null()) }, 0);
        let sb = Sandbox::new("nolog");
        let e = new_engine(&sb.ws());
        assert_eq!(unsafe { sg_engine_audit_failures(e) }, 0);
        unsafe { sg_engine_free(e) };
    }

    #[test]
    fn a_best_effort_log_that_fails_is_reported_in_the_result_and_the_counter() {
        let sb = Sandbox::new("besteffort");
        let e = new_engine(&sb.ws());
        set_audit(e, &sb.log(), 0).unwrap();
        std::fs::remove_dir_all(sb.log_dir()).unwrap();

        let v = execute(e, "echo ran > marker.txt");
        assert_eq!(v.get("ran").and_then(json::Json::as_bool), Some(true));
        assert!(v.get("audit_error").and_then(json::Json::as_str).is_some(), "{v:?}");
        assert!(sb.ws().join("marker.txt").exists());
        assert!(unsafe { sg_engine_audit_failures(e) } >= 2);

        unsafe { sg_engine_free(e) };
    }

    #[test]
    fn a_required_log_that_fails_refuses_the_command() {
        let sb = Sandbox::new("required");
        let e = new_engine(&sb.ws());
        set_audit(e, &sb.log(), SG_AUDIT_REQUIRED).unwrap();
        std::fs::remove_dir_all(sb.log_dir()).unwrap();

        let v = execute(e, "echo ran > marker.txt");
        assert_eq!(v.get("ran").and_then(json::Json::as_bool), Some(false));
        let why = v.get("error").and_then(json::Json::as_str).expect("an error message");
        assert!(why.contains("not run"), "{why}");
        assert!(
            !sb.ws().join("marker.txt").exists(),
            "the command ran although it could not be recorded"
        );

        unsafe { sg_engine_free(e) };
    }
}
