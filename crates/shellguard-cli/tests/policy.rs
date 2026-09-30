//! `--policy` must mean the same thing to every subcommand.
//!
//! It once did not: `eval` honoured it and `run` silently used the built-in
//! rules, so an operator could validate a stricter policy with one and execute
//! under a weaker one with the other.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_shellguard");

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root = std::env::temp_dir()
            .join(format!("shellguard-cli-policy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ws")).unwrap();
        Sandbox { root: root.canonicalize().unwrap() }
    }
    fn ws(&self) -> PathBuf {
        self.root.join("ws")
    }
    fn policy(&self, text: &str) -> PathBuf {
        let p = self.root.join("test.policy");
        std::fs::write(&p, text).unwrap();
        p
    }
    fn run(&self, sub: &str, extra: &[&str], cmd: &str) -> std::process::Output {
        Command::new(BIN)
            .arg(sub)
            .arg("-w")
            .arg(self.ws())
            .args(extra)
            .arg(cmd)
            .env_remove("SHELLGUARD_AUDIT")
            .output()
            .unwrap()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const DENY_ECHO: &str = "version 1\ndefault confine\n\n\
rule test.no-echo deny\n  reason echo is forbidden by this policy\n  program echo\n  cap fs.read\nend\n";

#[test]
fn run_honours_a_custom_policy_exactly_as_eval_does() {
    let sb = Sandbox::new("honoured");
    let p = sb.policy(DENY_ECHO);
    let p = p.to_str().unwrap();

    let eval = sb.run("eval", &["--policy", p], "echo hi");
    assert_eq!(eval.status.code(), Some(3), "eval should deny under this policy");

    let run = sb.run("run", &["--policy", p], "echo hi");
    assert_eq!(run.status.code(), Some(3), "run must refuse what eval denies");
    // A refusal prints `DENY  echo hi`, which contains "hi"; only a line that
    // is exactly the command's output means it ran.
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.lines().any(|l| l == "hi"),
        "the command ran under a policy that forbids it:\n{stdout}"
    );
}

#[test]
fn without_a_policy_flag_run_still_uses_the_built_in_rules() {
    let sb = Sandbox::new("default");
    let run = sb.run("run", &[], "echo hi");
    assert_eq!(run.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&run.stdout).lines().any(|l| l == "hi"));
}

#[test]
fn a_bad_policy_file_stops_run_rather_than_falling_back_to_the_default() {
    let sb = Sandbox::new("bad");
    let p = sb.policy("this is not a policy\n");
    let run = sb.run("run", &["--policy", p.to_str().unwrap()], "echo hi");
    assert_ne!(run.status.code(), Some(0), "fell back to a policy nobody asked for");
    assert!(!String::from_utf8_lossy(&run.stdout).lines().any(|l| l == "hi"));
}

#[test]
fn the_execution_timeout_is_not_handed_to_the_gate_as_its_deadline() {
    // `run -d 0` is a zero-millisecond *execution* budget. Before this was
    // separated, giving `run` a custom policy would also have made it the
    // gate's deadline and failed every command closed.
    let sb = Sandbox::new("timeout");
    let p = sb.policy("version 1\ndefault confine\n\nrule t.x deny\n  reason x\n  program nonexistent-program\n  cap fs.read\nend\n");
    let out = sb.run("run", &["--policy", p.to_str().unwrap(), "-d", "0"], "echo hi");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("exceeded"), "the gate's deadline was set from -d: {err}");
}
