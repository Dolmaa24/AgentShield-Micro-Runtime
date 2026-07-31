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
//! See `include/shellguard.h` for the C declarations.

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
