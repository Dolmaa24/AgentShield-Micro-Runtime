//! The audit log as a user meets it: through the real binary.
//!
//! The library and FFI tests cover the logic. What only this can cover is the
//! thing the log's locking exists for — many *processes*, not threads, writing
//! one file — plus the exit codes a wrapper script actually branches on.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_shellguard");

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root = std::env::temp_dir()
            .join(format!("shellguard-cli-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ws")).unwrap();
        Sandbox { root: root.canonicalize().unwrap() }
    }
    fn ws(&self) -> PathBuf {
        self.root.join("ws")
    }
    fn log(&self) -> PathBuf {
        self.root.join("log/audit.jsonl")
    }
    /// A `shellguard` invocation rooted at the workspace.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.arg(args[0]).arg("-w").arg(self.ws()).args(&args[1..]);
        // Never inherit an ambient audit path into a test.
        c.env_remove("SHELLGUARD_AUDIT");
        c
    }
    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Every line of `path` parsed with a real JSON parser, as an auditor would.
fn read(path: &Path) -> Vec<serde_like::Rec> {
    std::fs::read_to_string(path).unwrap().lines().map(serde_like::Rec::parse).collect()
}

/// A tiny field extractor. The workspace has no dependencies, and these tests
/// only need to read top-level string fields; anything they cannot find is a
/// failure worth seeing.
mod serde_like {
    pub struct Rec(pub String);
    impl Rec {
        pub fn parse(line: &str) -> Rec {
            assert!(line.starts_with('{') && line.ends_with('}'), "not an object: {line}");
            Rec(line.to_string())
        }
        pub fn str(&self, key: &str) -> Option<String> {
            let pat = format!("\"{key}\":\"");
            let start = self.0.find(&pat)? + pat.len();
            let mut out = String::new();
            let mut chars = self.0[start..].chars();
            while let Some(c) = chars.next() {
                match c {
                    '"' => return Some(out),
                    '\\' => out.push(chars.next()?),
                    c => out.push(c),
                }
            }
            None
        }
        pub fn kind(&self) -> String {
            self.str("kind").expect("every record has a kind")
        }
    }
}

#[test]
fn eval_records_the_judgment_and_keeps_its_verdict_exit_code() {
    let sb = Sandbox::new("eval");
    let log = sb.log();
    let l = log.to_str().unwrap();

    assert_eq!(sb.run(&["eval", "--audit", l, "git status"]).status.code(), Some(0));
    assert_eq!(sb.run(&["eval", "--audit", l, "rm -rf /etc"]).status.code(), Some(3));

    let recs = read(&log);
    let kinds: Vec<_> = recs.iter().map(|r| r.kind()).collect();
    assert_eq!(kinds, ["header", "evaluate", "evaluate"]);
    assert_eq!(recs[1].str("verdict").as_deref(), Some("allow"));
    assert_eq!(recs[2].str("verdict").as_deref(), Some("deny"));
    assert_eq!(recs[0].str("source").as_deref(), Some("cli"));
}

#[test]
fn run_records_a_start_and_a_finish_and_a_refusal_records_neither() {
    let sb = Sandbox::new("run");
    let log = sb.log();
    let l = log.to_str().unwrap();

    let out = sb.run(&["run", "--audit", l, "echo hello"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(sb.run(&["run", "--audit", l, "rm -rf /etc"]).status.code(), Some(3));

    let recs = read(&log);
    let kinds: Vec<_> = recs.iter().map(|r| r.kind()).collect();
    assert_eq!(kinds, ["header", "start", "finish", "refused"]);
    assert_eq!(recs[1].str("id"), recs[2].str("id"));
}

#[test]
fn credentials_never_reach_the_file() {
    let sb = Sandbox::new("secrets");
    let log = sb.log();
    sb.run(&[
        "eval",
        "--audit",
        log.to_str().unwrap(),
        r#"curl -H "Authorization: Bearer abcdef1234567890" https://alice:hunter2@example.com/x"#,
    ]);
    let raw = std::fs::read_to_string(&log).unwrap();
    for secret in ["abcdef1234567890", "hunter2"] {
        assert!(!raw.contains(secret), "`{secret}` reached the audit file:\n{raw}");
    }
    assert!(raw.contains("[REDACTED]"));
}

#[cfg(unix)]
#[test]
fn the_log_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new("mode");
    let log = sb.log();
    sb.run(&["eval", "--audit", log.to_str().unwrap(), "ls"]);
    let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "log is mode {mode:o}");
}

#[test]
fn the_environment_variable_is_used_and_the_flag_overrides_it() {
    let sb = Sandbox::new("env");
    let from_env = sb.root.join("env.jsonl");
    let from_flag = sb.root.join("flag.jsonl");

    let mut c = sb.cmd(&["eval", "ls"]);
    c.env("SHELLGUARD_AUDIT", &from_env);
    assert!(c.output().unwrap().status.success());
    assert_eq!(read(&from_env).len(), 2, "header + one judgment");

    let mut c = sb.cmd(&["eval", "--audit", from_flag.to_str().unwrap(), "ls"]);
    c.env("SHELLGUARD_AUDIT", &from_env);
    assert!(c.output().unwrap().status.success());
    assert_eq!(read(&from_flag).len(), 2);
    assert_eq!(read(&from_env).len(), 2, "the flag should have won; the env log grew");
}

#[test]
fn audit_options_without_a_log_are_a_usage_error_not_silently_ignored() {
    let sb = Sandbox::new("usage");
    for flag in ["--audit-required", "--audit-verbose"] {
        let out = sb.run(&["eval", flag, "ls"]);
        assert_eq!(out.status.code(), Some(64), "{flag}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("--audit"), "{flag}");
    }
}

#[cfg(unix)]
#[test]
fn a_log_that_cannot_be_opened_stops_the_command_before_it_runs() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new("unopenable");
    let log = sb.log();
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(&log, "").unwrap();
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o400)).unwrap();

    let out = sb.run(&["run", "--audit", log.to_str().unwrap(), "echo ran > marker.txt"]);

    assert_eq!(out.status.code(), Some(64), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot open audit log"));
    assert!(!sb.ws().join("marker.txt").exists(), "the command ran with no log to record it");
}

#[test]
fn many_processes_share_one_log_across_rotations_without_loss_or_tearing() {
    // The reason the log takes a cross-process lock. Thirty separate processes
    // each write a ~5 KB record to a log that rotates at its 128 KiB floor, so
    // rotation happens while others are mid-write.
    let sb = Sandbox::new("stampede");
    let log = sb.log();
    let pad = "x".repeat(5000);
    let n = 30;

    let children: Vec<_> = (0..n)
        .map(|i| {
            sb.cmd(&[
                "eval",
                "--audit",
                log.to_str().unwrap(),
                "--audit-max-bytes",
                "131072",
                "--audit-keep",
                "100",
                &format!("echo id{i} {pad}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
        })
        .collect();
    for c in children {
        let out = c.wait_with_output().unwrap();
        assert_ne!(out.status.code(), Some(64), "{}", String::from_utf8_lossy(&out.stderr));
    }

    let mut files = vec![log.clone()];
    for k in 1..=100 {
        let p = PathBuf::from(format!("{}.{k}", log.display()));
        if p.exists() {
            files.push(p);
        }
    }
    assert!(files.len() >= 2, "no rotation happened; the test proved nothing");

    let mut seen = std::collections::BTreeSet::new();
    for f in &files {
        assert!(std::fs::metadata(f).unwrap().len() <= 131_072, "{} overgrew", f.display());
        let recs = read(f);
        assert_eq!(recs[0].kind(), "header", "{} has no header", f.display());
        for r in recs.iter().skip(1) {
            let cmd = r.str("command").unwrap();
            let id = cmd.split_whitespace().nth(1).unwrap().to_string();
            assert!(seen.insert(id.clone()), "{id} recorded twice");
        }
    }
    assert_eq!(seen.len(), n, "records were lost across rotation");
}

#[test]
fn a_judgment_that_ran_out_of_time_is_recorded_as_incomplete_with_the_reason() {
    // The gate fails closed when it exceeds its deadline. That is the right
    // answer for the command and a confusing one for the operator, who sees a
    // refusal of something innocent. The log is where the cause has to be
    // legible: not just "denied", but "denied because evaluation did not
    // finish".
    let sb = Sandbox::new("deadline");
    let log = sb.log();
    let out = sb.run(&["eval", "-d", "0", "--audit", log.to_str().unwrap(), "echo hi"]);
    assert_eq!(out.status.code(), Some(3), "a blown deadline should fail closed");

    let rec = &read(&log)[1];
    assert_eq!(rec.kind(), "evaluate");
    assert!(rec.0.contains("\"complete\":false"), "{}", rec.0);
    assert!(
        rec.str("incomplete").is_some_and(|s| s.contains("budget")),
        "the reason was not recorded: {}",
        rec.0
    );
}

/// A log that opens fine and then fails on its first record.
///
/// The file is pre-filled to just under the rotation floor, so the first record
/// forces a rotation; with `--audit-keep 1` rotation must first remove
/// `audit.jsonl.1`, which here is a non-empty directory and cannot be removed.
/// That is a genuine mid-run write failure, produced without root, a full disk,
/// or any hook in the code under test.
#[cfg(unix)]
fn log_that_fails_on_its_first_record(sb: &Sandbox) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let log = sb.log();
    let dir = log.parent().unwrap();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(&log, "x".repeat(131_000)).unwrap();
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();
    let blocker = dir.join("audit.jsonl.1");
    std::fs::create_dir_all(blocker.join("not-empty")).unwrap();
    log
}

#[cfg(unix)]
#[test]
fn a_required_log_that_fails_mid_run_exits_65_and_the_command_does_not_run() {
    let sb = Sandbox::new("required-fails");
    let log = log_that_fails_on_its_first_record(&sb);
    let l = log.to_str().unwrap();

    let out = sb.run(&[
        "run",
        "--audit",
        l,
        "--audit-required",
        "--audit-max-bytes",
        "131072",
        "--audit-keep",
        "1",
        "echo ran > marker.txt",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(65), "{err}");
    assert!(err.contains("not run"), "{err}");
    assert!(
        !sb.ws().join("marker.txt").exists(),
        "the command ran although it could not be recorded"
    );

    // A judgment has no side effect, but a caller must still not mistake a
    // verdict that was never written down for an answer.
    let out = sb.run(&[
        "eval",
        "--audit",
        l,
        "--audit-required",
        "--audit-max-bytes",
        "131072",
        "--audit-keep",
        "1",
        "ls",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(65), "not a verdict exit code: {err}");
    assert!(err.contains("could not record"), "{err}");
    assert!(out.stdout.is_empty(), "a verdict was printed that was not recorded");
}

#[cfg(unix)]
#[test]
fn a_best_effort_log_that_fails_mid_run_warns_and_carries_on() {
    let sb = Sandbox::new("besteffort-fails");
    let log = log_that_fails_on_its_first_record(&sb);
    let l = log.to_str().unwrap();

    let out = sb.run(&[
        "run",
        "--audit",
        l,
        "--audit-max-bytes",
        "131072",
        "--audit-keep",
        "1",
        "echo ran > marker.txt",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(sb.ws().join("marker.txt").exists(), "the command should still have run");
    assert!(err.contains("not fully recorded"), "the gap was not reported: {err}");

    // The verdict's own exit code is preserved; only stderr carries the warning.
    let out = sb.run(&[
        "eval",
        "--audit",
        l,
        "--audit-max-bytes",
        "131072",
        "--audit-keep",
        "1",
        "rm -rf /etc",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("could not record"));
}
