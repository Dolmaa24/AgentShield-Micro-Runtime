//! `shellguard shell`, end to end, with a stand-in agent.
//!
//! `HOME` points at a fixture for every run, so the agent's "state" and
//! "secrets" are the fixture's and the real home directory is never involved.
#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_shellguard");

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let root = std::env::temp_dir()
            .join(format!("shellguard-cli-shell-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["ws", "home/.ssh", "outside"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("home/.ssh/key"), "PRIVATE").unwrap();
        Fixture { root: root.canonicalize().unwrap() }
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
    /// `shellguard shell [opts] -- /bin/sh -c script [extra...]`
    fn shell(&self, opts: &[&str], script: &str, extra: &[&str]) -> (i32, String, String) {
        let out = Command::new(BIN)
            .arg("shell")
            .arg("-w")
            .arg(self.p("ws"))
            .args(opts)
            .args(["--", "/bin/sh", "-c", script])
            .args(extra)
            .env("HOME", self.p("home"))
            .env("OUT", self.p("outside"))
            .output()
            .expect("run shellguard");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn the_session_writes_the_workspace_and_nothing_outside_it() {
    let fx = Fixture::new("writes");
    let (code, _, err) = fx.shell(&["-q"], "echo in > inside.txt", &[]);
    assert_eq!(code, 0, "{err}");
    assert!(fx.p("ws/inside.txt").exists());

    let (code, _, _) = fx.shell(&["-q"], "echo out > \"$OUT/new.txt\"", &[]);
    assert_ne!(code, 0, "a write outside the workspace succeeded");
    assert!(!fx.p("outside/new.txt").exists());

    let (code, _, _) = fx.shell(&["-q"], "bash -c 'touch \"$HOME/planted\"'", &[]);
    assert_ne!(code, 0);
    assert!(!fx.p("home/planted").exists());
}

#[test]
fn secrets_are_unreadable_unless_given_back() {
    let fx = Fixture::new("secrets");
    let (code, out, _) = fx.shell(&["-q"], "cat \"$HOME/.ssh/key\"", &[]);
    assert_ne!(code, 0);
    assert!(!out.contains("PRIVATE"));

    // And a place the person marks secret is, too.
    std::fs::create_dir_all(fx.p("canary")).unwrap();
    std::fs::write(fx.p("canary/token"), "CANARY").unwrap();
    let canary = fx.p("canary").display().to_string();
    let (code, out, _) = fx.shell(
        &["-q", "--secret", &canary],
        "cat \"$1\"",
        &["_", &fx.p("canary/token").display().to_string()],
    );
    assert_ne!(code, 0);
    assert!(!out.contains("CANARY"));

    let ssh = fx.p("home/.ssh").display().to_string();
    let (code, out, err) = fx.shell(&["-q", "--allow-secret", &ssh], "cat \"$HOME/.ssh/key\"", &[]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("PRIVATE"));
}

#[test]
fn the_program_gets_its_arguments_and_its_exit_status_comes_back() {
    let fx = Fixture::new("args");
    // `--dry-run` after the program is the program's, not shellguard's.
    let (code, out, err) = fx.shell(&["-q"], "echo \"$1|$2\"; exit 7", &["_", "--dry-run", "-w"]);
    assert_eq!(code, 7, "{err}");
    assert_eq!(out.trim(), "--dry-run|-w");
}

#[test]
fn the_session_gets_its_own_temp_directory_and_it_is_removed_after() {
    let fx = Fixture::new("tmp");
    let (code, out, err) =
        fx.shell(&["-q"], "echo \"$TMPDIR\"; echo t > \"$TMPDIR/x\" && echo wrote", &[]);
    assert_eq!(code, 0, "{err}");
    let mut lines = out.lines();
    let tmp = PathBuf::from(lines.next().unwrap());
    assert_eq!(lines.next(), Some("wrote"));
    assert!(tmp.file_name().unwrap().to_string_lossy().starts_with("shellguard-session-"));
    assert!(!tmp.exists(), "the session's temp directory outlived it");
}

#[test]
fn the_banner_says_what_is_confined_and_dry_run_runs_nothing() {
    let fx = Fixture::new("banner");
    let (code, _, err) = fx.shell(&[], "true", &[]);
    assert_eq!(code, 0);
    assert!(err.contains("is confined to") && err.contains("unreadable:"), "{err}");

    let (code, out, _) = fx.shell(&["--dry-run"], "touch ran", &[]);
    assert_eq!(code, 0);
    assert!(out.contains("(deny default)") && out.contains("(allow file-write*"), "{out}");
    assert!(!fx.p("ws/ran").exists(), "--dry-run ran the program");
}

#[test]
fn no_network_means_no_network() {
    let fx = Fixture::new("net");
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let connect =
        format!("python3 -c 'import socket; socket.create_connection((\"127.0.0.1\",{port}),2)'");
    let (code, _, err) = fx.shell(&["-q"], &connect, &[]);
    assert_eq!(code, 0, "the control failed: with network the connection should work\n{err}");
    let (code, _, _) = fx.shell(&["-q", "--no-network"], &connect, &[]);
    assert_ne!(code, 0, "--no-network allowed a connection");
}

#[test]
fn tls_roots_come_from_the_system_bundle_unless_the_person_chose_one() {
    let fx = Fixture::new("tls");
    let out = Command::new(BIN)
        .args(["shell", "-q", "-w"])
        .arg(fx.p("ws"))
        .args(["--", "/bin/sh", "-c", "echo \"$SSL_CERT_FILE\""])
        .env("HOME", fx.p("home"))
        .env_remove("SSL_CERT_FILE")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "/etc/ssl/cert.pem");
    let out = Command::new(BIN)
        .args(["shell", "-q", "-w"])
        .arg(fx.p("ws"))
        .args(["--", "/bin/sh", "-c", "echo \"$SSL_CERT_FILE\""])
        .env("HOME", fx.p("home"))
        .env("SSL_CERT_FILE", "/mine.pem")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "/mine.pem");
}

fn shell_with_env(
    fx: &Fixture,
    opts: &[&str],
    script: &str,
    env: &[(&str, String)],
) -> (i32, String, String) {
    let mut c = Command::new(BIN);
    c.arg("shell").arg("-w").arg(fx.p("ws")).args(opts).args(["--", "/bin/sh", "-c", script]);
    c.env("HOME", fx.p("home")).current_dir(fx.p("ws"));
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn credentials_in_the_environment_do_not_reach_the_session() {
    let fx = Fixture::new("env");
    let env = [("FAKE_SERVICE_TOKEN", "s3cret".to_string())];
    let (code, out, err) = shell_with_env(&fx, &[], "echo \"${FAKE_SERVICE_TOKEN:-gone}\"", &env);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.trim(), "gone");
    assert!(err.contains("FAKE_SERVICE_TOKEN"), "the removal was not reported:\n{err}");

    let (_, out, _) = shell_with_env(
        &fx,
        &["-q", "--keep-env", "FAKE_SERVICE_TOKEN"],
        "echo \"${FAKE_SERVICE_TOKEN:-gone}\"",
        &env,
    );
    assert_eq!(out.trim(), "s3cret");
}

#[test]
fn the_ssh_agent_is_unreachable_unless_allowed() {
    let fx = Fixture::new("ssh");
    // Relative names: the absolute path is too long for a socket address.
    let sock = fx.p("ws/agent.sock");
    let _agent = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let env = [("SSH_AUTH_SOCK", sock.display().to_string())];
    let script = "echo \"${SSH_AUTH_SOCK:-gone}\"; python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); s.connect('agent.sock')\" && echo connected";

    let (_, out, err) = shell_with_env(&fx, &["-q"], script, &env);
    assert!(out.starts_with("gone"), "SSH_AUTH_SOCK reached the session: {out}");
    assert!(!out.contains("connected"), "the session reached the SSH agent\n{out}{err}");

    let (_, out, err) = shell_with_env(&fx, &["-q", "--allow-ssh-agent"], script, &env);
    assert!(out.contains("connected"), "--allow-ssh-agent did not allow it\n{out}{err}");
    assert!(out.starts_with(&sock.display().to_string()));
}

#[test]
fn another_agents_login_and_history_kept_elsewhere_are_unreadable() {
    let fx = Fixture::new("others");
    for (f, text) in [
        ("home/.codex/auth.json", "CODEX-LOGIN"),
        ("home/.claude.json", "MCP-KEYS"),
        ("home/hist/custom", "TYPED-TOKEN"),
    ] {
        std::fs::create_dir_all(fx.p(f).parent().unwrap()).unwrap();
        std::fs::write(fx.p(f), text).unwrap();
    }
    // A stand-in named `codex`, so it gets Codex's profile.
    std::fs::create_dir_all(fx.p("bin")).unwrap();
    let codex = fx.p("bin/codex");
    std::fs::write(&codex, "#!/bin/sh\nfor f in \"$@\"; do cat \"$f\" 2>/dev/null; echo; done\n")
        .unwrap();
    std::fs::set_permissions(&codex, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let run = |opts: &[&str]| {
        let out = Command::new(BIN)
            .args(["shell", "-q", "-w"])
            .arg(fx.p("ws"))
            .args(opts)
            .arg("--")
            .arg(&codex)
            .args([".codex/auth.json", ".claude.json", "hist/custom"].map(|f| fx.p("home").join(f)))
            .env("HOME", fx.p("home"))
            .env("HISTFILE", fx.p("home/hist/custom"))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let out = run(&[]);
    assert!(out.contains("CODEX-LOGIN"), "codex could not read its own login: {out}");
    assert!(!out.contains("MCP-KEYS"), "codex read Claude's configuration: {out}");
    assert!(!out.contains("TYPED-TOKEN"), "the history HISTFILE names was readable: {out}");

    let claude_json = fx.p("home/.claude.json").display().to_string();
    let out = run(&["--allow-secret", &claude_json]);
    assert!(out.contains("MCP-KEYS"), "--allow-secret did not give it back: {out}");
    assert!(!out.contains("TYPED-TOKEN"));
}

/// `shellguard shell [opts] -- /bin/sh -c script`, with the variables that would
/// point npm or zsh somewhere else removed, so the fixture's files are the ones read.
fn shell_clean(fx: &Fixture, opts: &[&str], script: &str) -> (String, String) {
    let out = Command::new(BIN)
        .arg("shell")
        .arg("-w")
        .arg(fx.p("ws"))
        .args(opts)
        .args(["--", "/bin/sh", "-c", script])
        .env("HOME", fx.p("home"))
        .env_remove("NPM_CONFIG_USERCONFIG")
        .env_remove("npm_config_userconfig")
        .env_remove("ZDOTDIR")
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn npm_keeps_its_registries_and_not_its_credentials() {
    let fx = Fixture::new("npmrc");
    std::fs::write(
        fx.p("home/.npmrc"),
        "@corp:registry=https://npm.corp.example.test/\n//npm.corp.example.test/:_authToken=NPM-SECRET\n",
    )
    .unwrap();
    let npm =
        Command::new("/bin/sh").args(["-c", "command -v npm"]).output().unwrap().status.success();
    let script = "cat \"$HOME/.npmrc\"; echo \"copy: $(cat \"$NPM_CONFIG_USERCONFIG\")\"; \
                  command -v npm >/dev/null && echo \"npm says: $(npm config get @corp:registry)\"";

    let (out, err) = shell_clean(&fx, &[], script);
    assert!(!out.contains("NPM-SECRET"), "the credential reached the session:\n{out}");
    assert!(out.contains("copy: @corp:registry=https://npm.corp.example.test/"), "{out}\n{err}");
    if npm {
        // The point of the copy: the private scope still resolves to its own registry.
        assert!(out.contains("npm says: https://npm.corp.example.test/"), "{out}\n{err}");
    } else {
        eprintln!("npm is not installed; checked the copy, not npm reading it");
    }
    assert!(err.contains("npm:") && err.contains("without its 1 credential line"), "{err}");

    // Given back, it is the original, read as it is.
    let npmrc = fx.p("home/.npmrc").display().to_string();
    let (out, err) = shell_clean(&fx, &["--allow-secret", &npmrc], script);
    assert!(out.contains("NPM-SECRET"), "--allow-secret did not give it back:\n{out}");
    assert!(!err.contains("npm:"), "{err}");
}

#[test]
fn a_credential_written_in_a_startup_file_is_named_and_never_shown() {
    let fx = Fixture::new("startup");
    std::fs::write(
        fx.p("home/.zshrc"),
        "export FAKE_TOKEN=s3cr3t-value\nexport FETCHED_TOKEN=$(gh auth token)\nexport EDITOR=vim\n",
    )
    .unwrap();
    let (out, err) = shell_clean(&fx, &[], "true");
    let warning: Vec<&str> = err.lines().filter(|l| l.contains("warning:")).collect();
    assert_eq!(warning.len(), 1, "{err}");
    assert!(warning[0].contains("~/.zshrc sets FAKE_TOKEN in the file itself"), "{err}");
    assert!(!(out.clone() + &err).contains("s3cr3t-value"), "a value was printed:\n{err}");
    assert!(!err.contains("FETCHED_TOKEN"), "a fetched value is not in the file:\n{err}");

    let (_, err) = shell_clean(&fx, &["-q"], "true");
    assert!(err.is_empty(), "{err}");
}
