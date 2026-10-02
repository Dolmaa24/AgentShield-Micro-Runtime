//! `shellguard shell -- <agent>`: run a whole agent session confined.
//!
//! The agent — Claude Code, Codex, Gemini, or anything else — and every process
//! it starts run under one kernel profile: the workspace and the agent's own
//! state writable, secrets unreadable, the network open. Whatever permission mode
//! the agent is in, and whether or not any hook is configured, nothing outside
//! the workspace is written. See `AgentProfile` for the shape and why.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use shellguard_enforce::AgentProfile;

const USAGE: &str = "\
USAGE:
    shellguard shell [OPTIONS] [--] <program> [args...]

Runs <program> and everything it starts confined to the workspace. Everything
after <program> is passed to it unchanged.

OPTIONS:
    -w, --workspace DIR    the directory the agent works in (default: cwd)
        --write DIR        also writable (repeatable)
        --allow-secret DIR readable after all, though it holds secrets (repeatable)
        --secret DIR       also unreadable (repeatable)
        --allow-mach NAME  also reachable: a Mach service by name (repeatable)
        --keep-env NAME    keep an environment variable that looks like a
                           credential (repeatable; the agent's own are kept)
        --allow-ssh-agent  let the session use the SSH agent
        --allow-docker     let the session reach container daemons (Docker,
                           OrbStack, Colima, Podman...), which can mount /
        --no-network       no network at all (the agent cannot reach its model)
        --no-listen        no listening, even on localhost
        --dry-run          print the profile and exit
    -q, --quiet            no banner
";

#[derive(Default)]
struct ShellOpts {
    workspace: Option<PathBuf>,
    write: Vec<PathBuf>,
    allow_secret: Vec<PathBuf>,
    secret: Vec<PathBuf>,
    allow_mach: Vec<String>,
    keep_env: Vec<String>,
    allow_ssh_agent: bool,
    allow_docker: bool,
    no_network: bool,
    no_listen: bool,
    dry_run: bool,
    quiet: bool,
    program: Option<String>,
    args: Vec<String>,
}

/// shellguard's own options, up to the program; the rest is the program's.
fn parse(args: impl Iterator<Item = String>) -> Result<ShellOpts, String> {
    let mut o = ShellOpts::default();
    let mut args = args.peekable();
    while let Some(a) = args.next() {
        let mut take = |name: &str| -> Result<String, String> {
            args.next().ok_or_else(|| format!("{name} needs a value"))
        };
        match a.as_str() {
            "-w" | "--workspace" => o.workspace = Some(PathBuf::from(take("--workspace")?)),
            "--write" => o.write.push(PathBuf::from(take("--write")?)),
            "--allow-secret" => o.allow_secret.push(PathBuf::from(take("--allow-secret")?)),
            "--secret" => o.secret.push(PathBuf::from(take("--secret")?)),
            "--allow-mach" => o.allow_mach.push(take("--allow-mach")?),
            "--keep-env" => o.keep_env.push(take("--keep-env")?),
            "--allow-ssh-agent" => o.allow_ssh_agent = true,
            "--allow-docker" => o.allow_docker = true,
            "--no-network" => o.no_network = true,
            "--no-listen" => o.no_listen = true,
            "--dry-run" => o.dry_run = true,
            "-q" | "--quiet" => o.quiet = true,
            "-h" | "--help" => return Err(USAGE.to_string()),
            "--" => {
                o.program = args.next();
                o.args.extend(args.by_ref());
                break;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option `{other}`\n\n{USAGE}"));
            }
            program => {
                o.program = Some(program.to_string());
                o.args.extend(args.by_ref());
                break;
            }
        }
    }
    Ok(o)
}

/// A path for display, with the home directory shortened to `~`.
fn tilde(p: &Path, home: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".into(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
}

pub fn cmd_shell(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let o = parse(args)?;
    let program = o.program.clone().ok_or_else(|| format!("no program given\n\n{USAGE}"))?;

    let workspace = match &o.workspace {
        Some(w) => w.clone(),
        None => std::env::current_dir().map_err(|e| format!("cannot read cwd: {e}"))?,
    };
    let workspace = workspace
        .canonicalize()
        .map_err(|e| format!("cannot open workspace {}: {e}", workspace.display()))?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set, so the agent's state and the secrets cannot be located")?;

    // A temporary directory of the session's own, removed when it ends.
    let tmp = std::env::temp_dir().join(format!(
        "shellguard-session-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let mut profile = AgentProfile::for_program(&program, &workspace, &home, &tmp);
    profile.write_dirs.extend(o.write.iter().cloned());
    let given_back: Vec<PathBuf> =
        o.allow_secret.iter().map(|p| p.canonicalize().unwrap_or_else(|_| p.clone())).collect();
    // History kept somewhere other than the default, where the environment says.
    let elsewhere = [
        std::env::var_os("HISTFILE").map(PathBuf::from),
        std::env::var_os("ZDOTDIR").map(|z| PathBuf::from(z).join(".zsh_history")),
    ];
    for h in elsewhere.into_iter().flatten() {
        if !profile.secret_dirs.contains(&h) {
            profile.secret_dirs.push(h);
        }
    }
    profile.secret_dirs.retain(|s| !given_back.iter().any(|g| g == s));
    profile.secret_prefixes.retain(|s| !given_back.iter().any(|g| g == s));
    profile.secret_dirs.extend(o.secret.iter().cloned());
    profile.mach_services.extend(o.allow_mach.iter().cloned());
    let (env, removed) = session_env(&program, &o.keep_env, o.allow_ssh_agent);
    if o.allow_ssh_agent {
        profile.block_ssh_agent = false;
    } else if let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") {
        profile.blocked_sockets.push(PathBuf::from(sock));
    }
    if o.allow_docker {
        profile.blocked_socket_dirs.clear();
    } else {
        // Podman's machine socket lives under the person's own temp directory.
        profile.blocked_socket_dirs.push(std::env::temp_dir().join("podman"));
        profile.blocked_sockets.push(PathBuf::from("/var/run/docker.sock"));
        if let Some(sock) = std::env::var("DOCKER_HOST")
            .ok()
            .and_then(|h| h.strip_prefix("unix://").map(PathBuf::from))
        {
            profile.blocked_sockets.push(sock);
        }
    }
    if o.no_network {
        profile.allow_network = false;
        profile.allow_local_listen = false;
    }
    if o.no_listen {
        profile.allow_local_listen = false;
    }

    let summary = || {
        let writable: Vec<String> = profile
            .writable()
            .iter()
            .map(|p| {
                if *p == tmp.as_path() {
                    "<session temp>".to_string()
                } else if profile.write_prefixes.iter().any(|w| w == p) {
                    format!("{}*", tilde(p, &home))
                } else {
                    tilde(p, &home)
                }
            })
            .collect();
        let network = match (profile.allow_network, profile.allow_local_listen) {
            (true, true) => "outbound, and listening on localhost",
            (true, false) => "outbound",
            (false, _) => "none",
        };
        let mut text = format!(
            "shellguard: {program} is confined to {}\n  writable:   {}\n  unreadable: {} places that hold secrets (~/.ssh, ~/.aws, shell history, other agents' logins, ...)\n  frozen:     {}\n  network:    {network}\n  ssh agent:  {}\n  containers: {}\n",
            tilde(&workspace, &home),
            writable.join(", "),
            profile.unreadable_count(),
            profile.frozen_dirs.iter().map(|d| tilde(d, &home)).collect::<Vec<_>>().join(", "),
            if profile.block_ssh_agent { "blocked" } else { "allowed" },
            if profile.blocked_socket_dirs.is_empty() { "daemons reachable" } else { "daemons blocked" },
        );
        if !removed.is_empty() {
            text.push_str(&format!(
                "  env:        removed {} that look like credentials: {}\n",
                removed.len(),
                removed.join(", ")
            ));
        }
        text
    };

    #[cfg(not(target_os = "macos"))]
    {
        // The launch and its hints are macOS's; see the error below.
        let _ = (&summary, &o.args, &env, login_hint, sandbox_hint);
        Err("`shell` needs the macOS backend. On Linux it is not built yet: Landlock grants \
             access and cannot take it back, so a home directory cannot be readable while the \
             secrets in it are not, and that is the shape this mode is."
            .to_string())
    }

    #[cfg(target_os = "macos")]
    {
        if o.dry_run {
            print!("{}", summary());
            println!();
            print!(
                "{}",
                shellguard_enforce::macos::agent_sbpl(&profile).map_err(|e| e.to_string())?
            );
            return Ok(ExitCode::SUCCESS);
        }
        std::fs::create_dir_all(&tmp)
            .map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
        let argv = shellguard_enforce::macos::agent_command(&profile, &program, &o.args)
            .map_err(|e| e.to_string())?;
        if !o.quiet {
            eprint!("{}", summary());
            if let Some(hint) = login_hint(&program, &env) {
                eprintln!("{hint}");
            }
            if let Some(hint) = sandbox_hint(&program, &o.args) {
                eprintln!("{hint}");
            }
        }
        let status = run_foreground(&argv, &workspace, &tmp, &env);
        let _ = std::fs::remove_dir_all(&tmp);
        let status = status?;
        Ok(exit_code(status))
    }
}

/// The environment the session starts with: this one, less every variable whose
/// name says it holds a credential — except the agent's own and any the person
/// keeps — and less `SSH_AUTH_SOCK` unless the SSH agent is allowed. Returns it,
/// and the names removed.
///
/// A secret in the environment is readable by every command the agent runs, so
/// sealing the files that hold secrets and leaving them in variables would be
/// sealing one door of two.
fn session_env(
    program: &str,
    keep: &[String],
    allow_ssh_agent: bool,
) -> (Vec<(OsString, OsString)>, Vec<String>) {
    let own = shellguard_enforce::agent_credentials(program);
    let mut env = Vec::new();
    let mut removed = Vec::new();
    for (k, v) in std::env::vars_os() {
        let name = k.to_string_lossy().into_owned();
        let kept = own.contains(&name.as_str()) || keep.contains(&name);
        let drop = (name == "SSH_AUTH_SOCK" && !allow_ssh_agent)
            || (shellguard_enforce::looks_like_credential(&name) && !kept);
        if drop {
            removed.push(name);
        } else {
            env.push((k, v));
        }
    }
    removed.sort();
    (env, removed)
}

/// What to tell someone starting an agent that will find no login.
///
/// Claude Code keeps its login in the Keychain, and a session cannot reach the
/// Keychain — by decision, so that nothing in it can read or change the items
/// there. It authenticates from the environment instead.
fn login_hint(program: &str, env: &[(OsString, OsString)]) -> Option<&'static str> {
    let has = |n: &str| env.iter().any(|(k, _)| k == n);
    let base = Path::new(program).file_name().and_then(|n| n.to_str()).unwrap_or(program);
    match base {
        "claude"
            if !has("CLAUDE_CODE_OAUTH_TOKEN")
                && !has("ANTHROPIC_API_KEY")
                && !has("ANTHROPIC_AUTH_TOKEN") =>
        {
            Some(
                "  login:      Claude Code keeps its login in the Keychain, which a session cannot\n\
                 \x20             reach. Run `claude setup-token` once, outside, and set\n\
                 \x20             CLAUDE_CODE_OAUTH_TOKEN in the terminal that starts the session,\n\
                 \x20             not in a startup file: other sessions can read those.",
            )
        }
        _ => None,
    }
}

/// What to tell someone starting an agent whose own sandbox will not work here.
///
/// Codex runs the commands it starts under Seatbelt, and macOS refuses a sandbox
/// inside a sandbox (measured: `codex sandbox -- echo` works outside a session and
/// fails with `sandbox_apply: Operation not permitted` inside one). The session
/// is the sandbox, so Codex's own has to be off.
fn sandbox_hint(program: &str, args: &[String]) -> Option<&'static str> {
    let base = Path::new(program).file_name().and_then(|n| n.to_str()).unwrap_or(program);
    let off = args.iter().any(|a| {
        a.contains("danger-full-access") || a == "--dangerously-bypass-approvals-and-sandbox"
    });
    (base == "codex" && !off).then_some(
        "  sandbox:    Codex sandboxes its commands with Seatbelt, which macOS will not run\n\
         \x20             inside this session. Start it with `--sandbox danger-full-access`:\n\
         \x20             the session is the sandbox.",
    )
}

/// The root certificates macOS ships as a file.
#[cfg(target_os = "macos")]
const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/cert.pem";

#[cfg(target_os = "macos")]
fn run_foreground(
    argv: &[String],
    workspace: &Path,
    tmp: &Path,
    env: &[(OsString, OsString)],
) -> Result<std::process::ExitStatus, String> {
    use std::os::raw::c_int;
    extern "C" {
        fn signal(sig: c_int, handler: usize) -> usize;
    }
    const SIGINT: c_int = 2;
    const SIGQUIT: c_int = 3;
    const SIG_IGN: usize = 1;

    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(workspace)
        .env_clear()
        .envs(env.iter().cloned())
        .env("TMPDIR", tmp);
    // TLS roots from the system's bundle file rather than the Keychain, which
    // the session cannot read. Measured: Codex loads its roots through the
    // Keychain, and without this every request failed after the TCP connect;
    // with it, the sandboxed run got the same answer from the server as an
    // unsandboxed one. A bundle the person set is left alone.
    if std::env::var_os("SSL_CERT_FILE").is_none() && Path::new(SYSTEM_CA_BUNDLE).exists() {
        cmd.env("SSL_CERT_FILE", SYSTEM_CA_BUNDLE);
    }
    let mut child = cmd.spawn().map_err(|e| format!("cannot start {}: {e}", argv[0]))?;
    // Ctrl-C goes to the agent, which decides what it means. This process only
    // waits, and must not die and hand the terminal back with the agent still
    // running. Set *after* spawning: an ignored signal is inherited across
    // exec, and an agent that ignored Ctrl-C would be worse.
    // SAFETY: `signal` with SIG_IGN installs no handler code; it is sound to
    // call from any thread.
    unsafe {
        signal(SIGINT, SIG_IGN);
        signal(SIGQUIT, SIG_IGN);
    }
    child.wait().map_err(|e| format!("waiting for the session: {e}"))
}

#[cfg(target_os = "macos")]
fn exit_code(status: std::process::ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(c), _) => ExitCode::from(c.clamp(0, 255) as u8),
        (None, Some(s)) => ExitCode::from((128 + s).clamp(0, 255) as u8),
        _ => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> ShellOpts {
        parse(args.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn everything_after_the_program_belongs_to_it() {
        let o = p(&["-w", "/w", "claude", "--model", "x", "-p", "hi", "--dry-run"]);
        assert_eq!(o.program.as_deref(), Some("claude"));
        assert_eq!(o.args, ["--model", "x", "-p", "hi", "--dry-run"]);
        assert!(!o.dry_run, "an agent flag was taken for shellguard's");
        let o = p(&["--no-network", "--", "-weird-program", "--x"]);
        assert_eq!(o.program.as_deref(), Some("-weird-program"));
        assert_eq!(o.args, ["--x"]);
        assert!(o.no_network);
    }

    #[test]
    fn the_session_environment_drops_credentials_but_keeps_the_agents_own() {
        // Set in this test process only; `session_env` reads the environment.
        std::env::set_var("SHELLGUARD_TEST_GITHUB_TOKEN", "x");
        std::env::set_var("SHELLGUARD_TEST_DB_PASSWORD", "x");
        std::env::set_var("SHELLGUARD_TEST_KEPT_SECRET", "x");
        std::env::set_var("CLAUDE_CODE_OAUTH_TOKEN", "x");
        std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");
        let keep = vec!["SHELLGUARD_TEST_KEPT_SECRET".to_string()];
        let (env, removed) = session_env("claude", &keep, false);
        let names: Vec<String> =
            env.iter().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
        for gone in ["SHELLGUARD_TEST_GITHUB_TOKEN", "SHELLGUARD_TEST_DB_PASSWORD", "SSH_AUTH_SOCK"]
        {
            assert!(!names.iter().any(|n| n == gone), "{gone} survived");
            assert!(removed.iter().any(|n| n == gone), "{gone} not reported");
        }
        assert!(
            names.iter().any(|n| n == "CLAUDE_CODE_OAUTH_TOKEN"),
            "the agent's own token was removed"
        );
        assert!(names.iter().any(|n| n == "SHELLGUARD_TEST_KEPT_SECRET"));
        assert!(names.iter().any(|n| n == "PATH"));
        // For another program the Claude token is just a credential.
        let (_, removed) = session_env("bash", &[], true);
        assert!(removed.iter().any(|n| n == "CLAUDE_CODE_OAUTH_TOKEN"));
        assert!(!removed.iter().any(|n| n == "SSH_AUTH_SOCK"), "--allow-ssh-agent removed it");
        // A login hint only when Claude would find no login.
        assert!(login_hint("claude", &env).is_none());
        assert!(login_hint("claude", &[]).is_some());
        assert!(login_hint("codex", &[]).is_none());
        assert!(sandbox_hint("codex", &[]).is_some());
        assert!(sandbox_hint("codex", &["--sandbox".into(), "danger-full-access".into()]).is_none());
        assert!(sandbox_hint("claude", &[]).is_none());
    }

    #[test]
    fn unknown_options_before_the_program_are_errors() {
        assert!(parse(["--nope".to_string(), "claude".to_string()].into_iter()).is_err());
    }
}
