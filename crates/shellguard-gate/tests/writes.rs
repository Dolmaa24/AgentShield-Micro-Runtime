//! Programs that write where their arguments say, against the real programs.
//!
//! The gate learns each program's destination from a table (`src/writes.rs`),
//! and a table about a program is a claim about the program. So every line of
//! `tests/writes.txt` that writes somewhere local is judged by the gate *and*
//! run in a scratch fixture, and a directory beside the workspace is compared
//! before and after: a line said to write outside must change it, a line said
//! to stay inside must not.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use shellguard_gate::{Gate, GateConfig, Verdict, Worker};

const SPEC: &str = include_str!("../../../tests/writes.txt");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Ask,
    Truncate,
    Inside,
    System,
    Remote,
}

impl Class {
    fn parse(s: &str) -> Option<Class> {
        Some(match s {
            "ask" => Class::Ask,
            "truncate" => Class::Truncate,
            "inside" => Class::Inside,
            "system" => Class::System,
            "remote" => Class::Remote,
            _ => return None,
        })
    }
    fn runs(self) -> bool {
        matches!(self, Class::Ask | Class::Truncate | Class::Inside)
    }
    fn verdict_ok(self, v: Verdict) -> bool {
        match self {
            Class::Ask => v == Verdict::Ask,
            Class::Truncate | Class::System => v == Verdict::Deny,
            Class::Inside | Class::Remote => v <= Verdict::Confine,
        }
    }
    fn expected(self) -> &'static str {
        match self {
            Class::Ask => "ask",
            Class::Truncate | Class::System => "deny",
            Class::Inside | Class::Remote => "allow or confine",
        }
    }
}

struct Case {
    line: usize,
    class: Class,
    cmd: String,
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for (i, raw) in SPEC.lines().enumerate() {
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (c, cmd) = l.split_once('\t').unwrap_or_else(|| panic!("line {}: no tab", i + 1));
        let class = Class::parse(c).unwrap_or_else(|| panic!("line {}: bad class `{c}`", i + 1));
        out.push(Case { line: i + 1, class, cmd: cmd.trim().to_string() });
    }
    out
}

fn sh(cmd: &str, cwd: &Path) -> std::process::Output {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", cwd)
        .stdin(Stdio::null())
        .output()
        .expect("sh")
}

/// The workspace and the directory beside it, as the spec describes them.
fn build_fixture(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    let ws = root.join("ws");
    let out = root.join("out");
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(ws.join("a.txt"), "a\n").unwrap();
    std::fs::write(ws.join("moveme.txt"), "move\n").unwrap();
    std::fs::write(ws.join("inner.txt"), "old\n").unwrap();
    std::fs::write(ws.join("src/f.txt"), "f\n").unwrap();
    std::fs::write(out.join("precious.txt"), "precious\n").unwrap();
    std::fs::write(out.join("target.txt"), "old\n").unwrap();
    let diff = |name: &str| format!("--- {name}\n+++ {name}\n@@ -1 +1 @@\n-old\n+new\n");
    std::fs::write(ws.join("a.patch"), diff("target.txt")).unwrap();
    std::fs::write(ws.join("inside.patch"), diff("inner.txt")).unwrap();

    // Archives, made with the tools themselves in a staging directory.
    let stage = root.join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("member.txt"), "m\n").unwrap();
    std::fs::write(stage.join("zmember.txt"), "z\n").unwrap();
    let tar = format!("tar -cf {} member.txt", ws.join("x.tar").display());
    assert!(sh(&tar, &stage).status.success(), "could not build x.tar");
    let zip = format!("zip -q {} zmember.txt", ws.join("x.zip").display());
    assert!(sh(&zip, &stage).status.success(), "could not build x.zip");
    std::fs::remove_dir_all(&stage).unwrap();
}

/// Every path under `dir`, with its size and content, so any change shows.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(dir).unwrap().to_path_buf();
            let meta = std::fs::symlink_metadata(&p).unwrap();
            if meta.file_type().is_symlink() {
                out.insert(
                    rel,
                    std::fs::read_link(&p).unwrap().as_os_str().as_encoded_bytes().to_vec(),
                );
            } else if meta.is_dir() {
                out.insert(rel, b"<dir>".to_vec());
                stack.push(p);
            } else {
                out.insert(rel, std::fs::read(&p).unwrap_or_default());
            }
        }
    }
    out
}

fn copy_dir(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    let st = Command::new("cp").arg("-R").arg(from).arg(to).status().expect("cp");
    assert!(st.success());
}

#[test]
fn every_write_lands_where_the_gate_says_and_gets_the_agreed_verdict() {
    let root = std::env::temp_dir().join(format!("shellguard-writes-{}", std::process::id()));
    let base = root.join("base");
    let work = root.join("work");
    build_fixture(&base);
    copy_dir(&base, &work);
    let work = work.canonicalize().unwrap();
    let ws = work.join("ws");
    let out_dir = work.join("out");

    let cfg = GateConfig {
        workspace: ws.clone(),
        cwd: ws.clone(),
        home: Some(PathBuf::from("/home/agent")),
        deadline: Duration::from_secs(30),
        ..GateConfig::default()
    };
    let gate = Gate::with_default_policy(cfg);
    let mut w = Worker::new();

    let mut failures = Vec::new();
    let mut ran = 0;
    // Forms this host's program does not accept (`cp -t` is GNU's; macOS's cp
    // has no -t). The verdict is still checked; the effect cannot be.
    let mut unsupported = Vec::new();
    for c in cases() {
        let cmd = c.cmd.replace("{OUT}", &out_dir.display().to_string());
        let d = gate.evaluate(&cmd, &mut w);
        if !c.class.verdict_ok(d.verdict) {
            let rules: Vec<&str> = d.findings.iter().map(|f| f.rule_id.as_str()).collect();
            failures.push(format!(
                "  writes.txt:{} [{:?}] gate said {}, expected {}\n    {}\n    matched: {}",
                c.line,
                c.class,
                d.verdict.as_str(),
                c.class.expected(),
                c.cmd,
                if rules.is_empty() { "nothing".into() } else { rules.join(", ") }
            ));
        }
        if !c.class.runs() {
            continue;
        }

        copy_dir(&base, &work);
        let before = snapshot(&out_dir);
        let res = sh(&cmd, &ws);
        let after = snapshot(&out_dir);
        ran += 1;
        let changed = before != after;
        let should = c.class != Class::Inside;
        let stderr = String::from_utf8_lossy(&res.stderr);
        if !res.status.success()
            && ["illegal option", "unrecognized option", "invalid option"]
                .iter()
                .any(|m| stderr.contains(m))
        {
            unsupported.push(format!("writes.txt:{} {}", c.line, c.cmd));
            ran -= 1;
        } else if !res.status.success() {
            failures.push(format!(
                "  writes.txt:{} the command failed, so it proves nothing: {}\n    {}",
                c.line,
                c.cmd,
                String::from_utf8_lossy(&res.stderr).lines().next().unwrap_or("")
            ));
        } else if changed != should {
            failures.push(format!(
                "  writes.txt:{} [{:?}] the directory outside the workspace {}\n    {}",
                c.line,
                c.class,
                if changed { "CHANGED" } else { "did not change" },
                c.cmd
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&root);

    assert!(failures.is_empty(), "{} lines disagree:\n{}", failures.len(), failures.join("\n"));
    assert!(ran >= 35, "only {ran} lines were run");
    assert!(unsupported.len() <= 3, "too many forms unsupported here: {unsupported:?}");
    eprintln!("{ran} run for real; not supported by this host's programs: {unsupported:?}");
}
