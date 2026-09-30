//! `git branch` and `git tag`: the gate's verdict against what git really does.
//!
//! The policy allows a `git branch` or `git tag` only when every flag on it is one
//! that lists. That is a claim about git - that none of them can move, create or
//! delete a ref - and a claim about a program should be tested against the
//! program. Each line of `tests/git_refs.txt` is judged by the gate, then run in a
//! scratch repository, and the refs before and after are compared.
//!
//! The two halves catch different mistakes. The gate half catches a rule that is
//! too loose or too tight. The git half catches a line whose description is wrong
//! (a "mutating" command that changes nothing proves nothing), and a flag that is
//! read-only in the policy's mind and not in git's.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use shellguard_gate::{Gate, GateConfig, Verdict, Worker};

const SPEC: &str = include_str!("../../../tests/git_refs.txt");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Readonly,
    Conservative,
    Mutates,
    Destroys,
    Inert,
}

impl Class {
    fn parse(s: &str) -> Option<Class> {
        Some(match s {
            "readonly" => Class::Readonly,
            "conservative" => Class::Conservative,
            "mutates" => Class::Mutates,
            "destroys" => Class::Destroys,
            "inert" => Class::Inert,
            _ => return None,
        })
    }
    fn verdict(self) -> Verdict {
        match self {
            Class::Readonly => Verdict::Allow,
            Class::Conservative | Class::Mutates => Verdict::Confine,
            Class::Destroys | Class::Inert => Verdict::Ask,
        }
    }
    /// Whether git is expected to change a ref.
    fn changes_refs(self) -> bool {
        matches!(self, Class::Mutates | Class::Destroys)
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

fn git_available() -> bool {
    Command::new("git").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

/// A `git` (or `sh`) invocation confined to one repository and cut off from the
/// user's own configuration. `GIT_DIR` is set explicitly so that even a wrong
/// working directory could not reach any repository but the scratch one.
fn scratch(program: &str, repo: &Path) -> Command {
    let mut c = Command::new(program);
    c.current_dir(repo)
        .env("GIT_DIR", repo.join(".git"))
        .env("GIT_WORK_TREE", repo)
        .env("GIT_CEILING_DIRECTORIES", repo.parent().unwrap())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_PAGER", "cat")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_EDITOR", "true")
        .env("HOME", repo)
        .env("LC_ALL", "C")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com");
    c
}

fn git(repo: &Path, args: &[&str]) -> String {
    let out = scratch("git", repo).args(args).output().expect("git");
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// main (checked out) at the newest of three commits, `victim` at the oldest,
/// `other` in the middle, `v1` and `v2` on the first two. Everything is at a
/// different commit so that moving or deleting any ref is visible.
fn build_fixture(repo: &Path) {
    let _ = std::fs::remove_dir_all(repo);
    std::fs::create_dir_all(repo).unwrap();
    git(repo, &["-c", "init.defaultBranch=main", "init", "-q", "."]);
    for (n, extra) in [(1, "victim"), (2, "other"), (3, "")] {
        std::fs::write(repo.join("f.txt"), format!("commit {n}\n")).unwrap();
        git(repo, &["add", "f.txt"]);
        git(repo, &["commit", "-q", "-m", &format!("commit {n}")]);
        if !extra.is_empty() {
            git(repo, &["branch", extra]);
        }
        if n <= 2 {
            git(repo, &["tag", &format!("v{n}")]);
        }
    }
}

/// Every ref and what it points at, and where HEAD is.
fn snapshot(repo: &Path) -> String {
    let refs = git(repo, &["for-each-ref", "--format=%(refname) %(objectname)"]);
    let head = git(repo, &["symbolic-ref", "HEAD"]);
    format!("{refs}HEAD {head}")
}

fn copy_dir(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    let st = Command::new("cp").arg("-R").arg(from).arg(to).status().expect("cp");
    assert!(st.success(), "cp -R failed");
}

fn gate_for(work: &Path) -> Gate {
    let cfg = GateConfig {
        workspace: work.to_path_buf(),
        cwd: work.to_path_buf(),
        home: Some(PathBuf::from("/home/agent")),
        // The verdict is under test, not the latency.
        deadline: Duration::from_secs(30),
        ..GateConfig::default()
    };
    Gate::with_default_policy(cfg)
}

#[test]
fn every_branch_and_tag_command_gets_the_verdict_git_s_behaviour_earns() {
    if !git_available() {
        eprintln!("git is not installed: skipping (this test needs the real program)");
        return;
    }
    let root = std::env::temp_dir().join(format!("shellguard-git-refs-{}", std::process::id()));
    let base = root.join("base");
    let work = root.join("work");
    std::fs::create_dir_all(&root).unwrap();
    build_fixture(&base);
    // The gate resolves paths against a fixed directory, so the fixture is
    // copied to the same place for every case.
    std::fs::create_dir_all(&work).unwrap();
    let work = work.canonicalize().unwrap();
    let gate = gate_for(&work);
    let mut worker = Worker::new();

    let mut failures = Vec::new();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();

    for c in cases() {
        copy_dir(&base, &work);
        let before = snapshot(&work);

        let d = gate.evaluate(&c.cmd, &mut worker);
        if d.verdict != c.class.verdict() {
            let rules: Vec<&str> = d.findings.iter().map(|f| f.rule_id.as_str()).collect();
            failures.push(format!(
                "  git_refs.txt:{}  [{:?}] gate said {}, expected {}\n    {}\n    matched: {}",
                c.line,
                c.class,
                d.verdict.as_str(),
                c.class.verdict().as_str(),
                c.cmd,
                if rules.is_empty() { "nothing".into() } else { rules.join(", ") }
            ));
        }

        // Then the real thing, whatever the gate said.
        let out = scratch("sh", &work).arg("-c").arg(&c.cmd).output().expect("sh");
        let after = snapshot(&work);
        let changed = before != after;
        if changed != c.class.changes_refs() {
            failures.push(format!(
                "  git_refs.txt:{}  [{:?}] git {} the refs, expected it to {}\n    {}\n    exit {:?}, stderr: {}",
                c.line,
                c.class,
                if changed { "CHANGED" } else { "did not change" },
                if c.class.changes_refs() { "change them" } else { "leave them alone" },
                c.cmd,
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("")
            ));
        }
        *counts.entry(format!("{:?}", c.class)).or_default() += 1;
    }
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        failures.is_empty(),
        "{} of {} lines disagree with the ruleset or with git:\n{}",
        failures.len(),
        cases().len(),
        failures.join("\n")
    );
    // A spec that lost a class, or a harness that skipped lines, proves nothing.
    for (class, min) in
        [("Readonly", 15), ("Conservative", 5), ("Mutates", 8), ("Destroys", 15), ("Inert", 4)]
    {
        assert!(
            counts.get(class).copied().unwrap_or(0) >= min,
            "only {:?} lines of class {class}; expected at least {min}",
            counts.get(class)
        );
    }
    eprintln!("git_refs.txt: {counts:?}");
}

/// A command is judged whole, not by its first word: a read-only listing must not
/// launder what it is chained to, and wrapping a mutation must not hide it.
#[test]
fn a_listing_does_not_launder_its_neighbours_and_wrappers_do_not_hide_a_delete() {
    let work = std::env::temp_dir().join("shellguard-git-refs-verdicts/ws");
    std::fs::create_dir_all(&work).unwrap();
    let gate = gate_for(&work.canonicalize().unwrap());
    let mut w = Worker::new();
    let mut v = |cmd: &str| gate.evaluate(cmd, &mut w).verdict;

    // Allowed alone; the neighbour decides the rest.
    assert_eq!(v("git branch -a"), Verdict::Allow);
    assert_eq!(v("git branch -a; git branch -D victim"), Verdict::Ask);
    assert_eq!(v("git branch -a && git tag -d v1"), Verdict::Ask);
    assert_eq!(v("git branch -a | cat"), Verdict::Allow);
    // A redirect turns a read into a write.
    assert_eq!(v("git branch -a > out.txt"), Verdict::Confine);
    // The delete survives being wrapped.
    for wrapped in [
        "sudo git branch -D victim",
        "env GIT_PAGER=cat git branch -D victim",
        "bash -c 'git branch -D victim'",
        "timeout 5 git tag -d v1",
        "xargs git branch -D",
        "git -C . branch -D victim",
    ] {
        assert!(v(wrapped) >= Verdict::Confine, "{wrapped}");
    }
    assert_eq!(v("sudo git branch -D victim"), Verdict::Ask);
    assert_eq!(v("bash -c 'git branch -D victim'"), Verdict::Ask);
    assert_eq!(v("timeout 5 git tag -d v1"), Verdict::Ask);
    assert_eq!(v("env GIT_PAGER=cat git branch -D victim"), Verdict::Ask);
    // An unknown flag value is never assumed harmless.
    assert_eq!(v("git branch --list $FLAG"), Verdict::Confine);
    assert_eq!(v("git branch --list \"$(cat pattern.txt)\""), Verdict::Confine);
    assert_eq!(v("git branch --list *"), Verdict::Confine);
}

/// Not a ref but the same question: `--output=<file>` on the "read-only" log-style
/// commands makes git write that file. The gate must not call it `allow`, and this
/// checks that the reason for saying so is true of the git on this machine.
#[test]
fn git_output_flag_writes_a_file_so_it_is_not_read_only() {
    if !git_available() {
        eprintln!("git is not installed: skipping");
        return;
    }
    let root = std::env::temp_dir().join(format!("shellguard-git-output-{}", std::process::id()));
    let base = root.join("base");
    let work = root.join("work");
    build_fixture(&base);
    std::fs::create_dir_all(&work).unwrap();
    let work = work.canonicalize().unwrap();
    let gate = gate_for(&work);
    let mut w = Worker::new();

    let mut checked = 0;
    for cmd in [
        "git diff HEAD~1 --output=out.txt",
        "git log --output=out.txt",
        "git show --output=out.txt HEAD",
        "git shortlog -s --output=out.txt",
    ] {
        copy_dir(&base, &work);
        let verdict = gate.evaluate(cmd, &mut w).verdict;
        // `shortlog` reads its input from stdin unless it is closed.
        let out = scratch("sh", &work)
            .arg("-c")
            .arg(cmd)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("sh");
        assert!(work.join("out.txt").exists(), "`{cmd}` did not write a file: {:?}", out);
        assert_ne!(verdict, Verdict::Allow, "`{cmd}` writes a file yet the gate says allow");
        checked += 1;
    }
    assert_eq!(checked, 4);
    // The same commands without the flag stay allowed, so the rule did not just
    // get narrower across the board.
    assert_eq!(gate.evaluate("git log --oneline -5", &mut w).verdict, Verdict::Allow);
    assert_eq!(gate.evaluate("git diff --stat", &mut w).verdict, Verdict::Allow);
    let _ = std::fs::remove_dir_all(&root);
}
