//! `shellguard profile` must describe the sandbox `shellguard run` uses.
//!
//! It once did not: it rebuilt the profile on its own and skipped the step that
//! makes the workspace writable for a confined command, so it printed a
//! read-only workspace for `touch newfile` while `run` created the file. A
//! profile printout that is wrong in the direction of "more restricted" is the
//! worst kind, because it is the one people believe.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_shellguard");

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let root = std::env::temp_dir()
            .join(format!("shellguard-cli-profile-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ws")).unwrap();
        Sandbox { root: root.canonicalize().unwrap() }
    }
    fn ws(&self) -> PathBuf {
        self.root.join("ws")
    }
    fn cli(&self, sub: &str, extra: &[&str], cmd: &str) -> (i32, String) {
        let out = Command::new(BIN)
            .arg(sub)
            .arg("-w")
            .arg(self.ws())
            .args(extra)
            .arg(cmd)
            .env_remove("SHELLGUARD_AUDIT")
            .output()
            .expect("run the CLI");
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        (out.status.code().unwrap_or(-1), text)
    }
    fn profile(&self, cmd: &str) -> String {
        self.cli("profile", &[], cmd).1
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The value of a `# key: value` header line.
fn header<'a>(text: &'a str, key: &str) -> &'a str {
    let prefix = format!("# {key}: ");
    text.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no `# {key}:` line in:\n{text}"))
}

#[test]
fn a_confined_command_is_shown_able_to_write_the_workspace_because_it_can() {
    let sb = Sandbox::new("confine");
    let ws = sb.ws().display().to_string();

    let shown = sb.profile("touch newfile");
    assert_eq!(header(&shown, "verdict"), "confine");
    assert!(
        header(&shown, "writable").split(", ").any(|w| w == ws),
        "the printout says the workspace is not writable:\n{shown}"
    );

    // And `run` agrees, by doing it.
    let (code, out) = sb.cli("run", &[], "touch newfile");
    assert_eq!(code, 0, "{out}");
    assert!(sb.ws().join("newfile").exists(), "run did not write, yet the profile says it may");
}

#[cfg(target_os = "macos")]
#[test]
fn the_printed_seatbelt_profile_grants_what_the_header_says() {
    let sb = Sandbox::new("sbpl");
    let shown = sb.profile("touch newfile");
    let writes = shown.split("(allow file-write*").nth(1).expect("no write block");
    let writes = &writes[..writes.find("\n)\n").expect("unterminated write block")];
    assert!(writes.contains(&format!("(subpath \"{}\")", sb.ws().display())), "{writes}");
    assert!(writes.contains("shellguard-scratch-PER-RUN"), "no per-run scratch: {writes}");
}

#[test]
fn an_allowed_read_keeps_the_workspace_read_only() {
    let sb = Sandbox::new("allow");
    let shown = sb.profile("ls");
    assert_eq!(header(&shown, "verdict"), "allow");
    assert_eq!(header(&shown, "writable"), "<per-run scratch>");
    assert_eq!(header(&shown, "network"), "none");
}

#[test]
fn network_is_shown_exactly_when_it_is_granted() {
    let sb = Sandbox::new("net");
    assert_eq!(header(&sb.profile("pip install requests"), "network"), "outbound");
    assert_eq!(header(&sb.profile("python3 build.py"), "network"), "none");
}

#[test]
fn a_denied_command_gets_no_profile_and_an_asked_one_says_so() {
    let sb = Sandbox::new("deny-ask");
    let denied = sb.profile("rm -rf /etc");
    assert_eq!(header(&denied, "verdict"), "deny");
    assert!(!denied.contains("(version 1)"), "a denied command was given a profile:\n{denied}");

    let asked = sb.profile("git push --force origin main");
    assert_eq!(header(&asked, "verdict"), "ask");
    assert!(asked.contains("--run-on-ask"), "{asked}");
}

#[test]
fn profile_honours_the_policy_run_would_use() {
    let sb = Sandbox::new("policy");
    let policy = sb.root.join("t.policy");
    std::fs::write(
        &policy,
        "version 1\ndefault confine\n\nrule t.no-touch deny\n  reason no\n  program touch\n  cap fs.write\nend\n",
    )
    .unwrap();
    let p = policy.display().to_string();
    let (_, shown) = sb.cli("profile", &["--policy", &p], "touch newfile");
    assert_eq!(header(&shown, "verdict"), "deny", "{shown}");
    let (_, ran) = sb.cli("run", &["--policy", &p], "touch newfile");
    assert!(!sb.ws().join("newfile").exists(), "run ignored the policy profile honoured: {ran}");
}
