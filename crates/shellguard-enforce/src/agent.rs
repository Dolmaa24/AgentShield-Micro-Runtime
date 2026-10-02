//! Confinement for a whole agent session: the agent and everything it starts.
//!
//! [`Profile`](crate::Profile) is for one command whose purpose the gate has
//! read. An agent session is the opposite case: one long-lived process that will
//! run commands nobody has seen yet, read code and toolchains anywhere, edit
//! files with its own tools rather than through a shell, and talk to its model
//! over the network. So the shape is different, and stated here:
//!
//! - **reads are open, except where secrets are kept.** An agent that cannot read
//!   a toolchain or a dotfile cannot do its job, and a list of what it *may* read
//!   would be either useless or endless. A list of what it may not — keys,
//!   cloud credentials, browser profiles, the Keychain files — is short.
//! - **writes are closed, except the workspace and the agent's own state.**
//!   This is the property the wrapper exists for: nothing outside the workspace
//!   is deleted or changed, whatever mode the agent runs in.
//! - **outbound network is open**, because the agent needs it, and every command
//!   the agent runs inherits it. On macOS a sandboxed process cannot narrow the
//!   profile for its children (measured: any stricter `sandbox_apply` inside one
//!   is refused), so per-command network isolation is not available inside a
//!   session. That is the price of this shape, and it is why it is a choice.

use std::path::{Path, PathBuf};

/// What a whole agent session may do.
#[derive(Clone, Debug)]
pub struct AgentProfile {
    /// The directory the agent works in, and may change.
    pub workspace: PathBuf,
    /// Writable subtrees besides the workspace: the agent's state, a private
    /// temporary directory.
    pub write_dirs: Vec<PathBuf>,
    /// Writable files, together with anything whose path begins the same way:
    /// `~/.claude.json` and the temporary copy written beside it before a rename.
    pub write_prefixes: Vec<PathBuf>,
    /// Subtrees whose contents cannot be read, although reads are otherwise open.
    /// Their existence can still be seen: denying `stat` breaks tools that only
    /// look.
    pub secret_dirs: Vec<PathBuf>,
    /// Files whose contents cannot be read, together with anything whose path
    /// begins the same way: another agent's `~/.claude.json` and the backups
    /// written beside it.
    pub secret_prefixes: Vec<PathBuf>,
    /// Subtrees of the workspace that stay read-only. `.git/hooks` by default: a
    /// hook planted there runs, unconfined, the next time the *person* commits.
    pub frozen_dirs: Vec<PathBuf>,
    /// Outbound connections. The agent needs this to reach its model.
    pub allow_network: bool,
    /// Listening on the loopback interface, for the dev servers agents start.
    pub allow_local_listen: bool,
    /// Mach services the session may look up, by name.
    pub mach_services: Vec<String>,
    /// Refuse connections to the SSH agent. With `~/.ssh` unreadable, the agent
    /// socket is still a way to *use* the keys — to push anywhere the person can,
    /// or log in to their servers. Blocks the launchd-provided socket by pattern;
    /// any other agent socket goes in `blocked_sockets`.
    pub block_ssh_agent: bool,
    /// Unix sockets nothing in the session may connect to: the socket
    /// `SSH_AUTH_SOCK` names, when it is not launchd's.
    pub blocked_sockets: Vec<PathBuf>,
    /// Directories no socket under which may be connected to. By default, where
    /// container runtimes keep their daemon's socket: a daemon that will run
    /// `docker run -v /:/host` for any client is a way out of every rule here,
    /// and connecting to a socket is not a write the profile can see.
    pub blocked_socket_dirs: Vec<PathBuf>,
}

/// Where container runtimes put the socket of the daemon that runs containers,
/// relative to the home directory: Docker Desktop, OrbStack, Colima, Lima,
/// Rancher Desktop, Podman.
pub const CONTAINER_SOCKET_DIRS: &[&str] =
    &[".docker/run", ".orbstack/run", ".colima", ".lima", ".rd", ".local/share/containers"];

/// Where secrets live, relative to the home directory. Readable nowhere in a
/// session unless the person asks for one back.
pub const SECRET_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".azure",
    ".kube",
    ".docker",
    ".password-store",
    ".config/gh",
    ".config/gcloud",
    ".config/op",
    ".config/rclone",
    ".config/hub",
    ".local/share/keyrings",
    ".terraform.d",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Safari",
    "Library/Messages",
    "Library/Mail",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge",
    "Library/Group Containers/2BUA8C4S2C.com.1password",
    // GitHub Copilot's login, which no agent here needs.
    ".config/github-copilot",
    // Terminal's per-window shell history.
    ".zsh_sessions",
];

/// Single files that hold credentials, relative to the home directory.
///
/// Shell and REPL history among them: a token typed or pasted on a command line
/// stays there, and no agent needs to read what the person typed before.
pub const SECRET_FILES: &[&str] = &[
    ".netrc",
    ".git-credentials",
    ".pypirc",
    ".vault-token",
    ".cargo/credentials.toml",
    ".zsh_history",
    ".bash_history",
    ".local/share/fish/fish_history",
    ".python_history",
    ".node_repl_history",
    ".irb_history",
    ".psql_history",
    ".mysql_history",
    ".sqlite_history",
    ".rediscli_history",
];

/// The agents whose state [`AgentProfile::for_program`] knows.
pub const KNOWN_AGENTS: &[&str] = &["claude", "codex", "gemini"];

/// What a known agent writes outside the workspace, relative to the home
/// directory: (directories, file prefixes).
fn agent_state(program: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match program {
        // `.local/state/claude` holds the lock Claude Code takes on its own
        // version; refused, it was the first write the kernel logged.
        "claude" => (&[".claude", ".local/state/claude"], &[".claude.json"]),
        "codex" => (&[".codex"], &[]),
        "gemini" => (&[".gemini"], &[]),
        _ => (&[], &[]),
    }
}

/// Environment variables that carry a known agent's own credentials, kept when
/// the rest of the credential-looking environment is removed.
pub fn agent_credentials(program: &str) -> &'static [&'static str] {
    let base = Path::new(program).file_name().and_then(|n| n.to_str()).unwrap_or(program);
    match base {
        "claude" => &["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"],
        "codex" => &["OPENAI_API_KEY", "CODEX_API_KEY"],
        "gemini" => &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        _ => &[],
    }
}

/// Whether an environment variable's name says it holds a credential.
///
/// Matched on the name only — the value is never looked at — and broadly,
/// because a credential left in the environment is readable by every command the
/// agent runs. A name kept wrongly is a leak; a name removed wrongly is a
/// `--keep-env` away.
pub fn looks_like_credential(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "APIKEY",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "CREDENTIAL",
    ]
    .iter()
    .any(|w| n.contains(w))
}

impl AgentProfile {
    /// The profile for running `program` in `workspace`, for a person whose home
    /// is `home`, with `tmp` as the session's private temporary directory.
    ///
    /// Known agents (`claude`, `codex`, `gemini`) also get their own state
    /// directories. Anything else gets the workspace and `tmp` and nothing more.
    ///
    /// Every *other* known agent's state is unreadable: it holds that agent's
    /// login (`~/.codex/auth.json`), and its configuration can hold more
    /// (`~/.claude.json` keeps the environment of each MCP server, API keys
    /// included).
    pub fn for_program(program: &str, workspace: &Path, home: &Path, tmp: &Path) -> AgentProfile {
        let base = Path::new(program).file_name().and_then(|n| n.to_str()).unwrap_or(program);
        let (dirs, prefixes) = agent_state(base);
        let mut write_dirs: Vec<PathBuf> = dirs.iter().map(|d| home.join(d)).collect();
        write_dirs.push(tmp.to_path_buf());
        let mut secret_dirs: Vec<PathBuf> = SECRET_DIRS.iter().map(|d| home.join(d)).collect();
        secret_dirs.extend(SECRET_FILES.iter().map(|f| home.join(f)));
        let mut secret_prefixes = Vec::new();
        for other in KNOWN_AGENTS.iter().filter(|a| **a != base) {
            let (dirs, prefixes) = agent_state(other);
            secret_dirs.extend(dirs.iter().map(|d| home.join(d)));
            secret_prefixes.extend(prefixes.iter().map(|p| home.join(p)));
        }
        AgentProfile {
            workspace: workspace.to_path_buf(),
            write_dirs,
            write_prefixes: prefixes.iter().map(|p| home.join(p)).collect(),
            secret_dirs,
            secret_prefixes,
            frozen_dirs: vec![workspace.join(".git/hooks")],
            allow_network: true,
            allow_local_listen: true,
            mach_services: Vec::new(),
            block_ssh_agent: true,
            blocked_sockets: Vec::new(),
            blocked_socket_dirs: CONTAINER_SOCKET_DIRS.iter().map(|d| home.join(d)).collect(),
        }
    }

    /// How many places the session cannot read, for a summary a person can read.
    pub fn unreadable_count(&self) -> usize {
        self.secret_dirs.len() + self.secret_prefixes.len()
    }

    /// Every path the session may write, for a summary a person can read.
    pub fn writable(&self) -> Vec<&Path> {
        let mut v: Vec<&Path> = vec![self.workspace.as_path()];
        v.extend(self.write_dirs.iter().map(PathBuf::as_path));
        v.extend(self.write_prefixes.iter().map(PathBuf::as_path));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_agent_gets_its_state_and_nothing_else_outside_the_workspace() {
        let p = AgentProfile::for_program(
            "/Users/me/.local/bin/claude",
            Path::new("/w"),
            Path::new("/Users/me"),
            Path::new("/t"),
        );
        assert_eq!(
            p.write_dirs,
            [
                PathBuf::from("/Users/me/.claude"),
                PathBuf::from("/Users/me/.local/state/claude"),
                PathBuf::from("/t")
            ]
        );
        assert_eq!(p.write_prefixes, [PathBuf::from("/Users/me/.claude.json")]);
        assert!(p.secret_dirs.contains(&PathBuf::from("/Users/me/.ssh")));
        assert!(p.secret_dirs.contains(&PathBuf::from("/Users/me/.netrc")));
        assert_eq!(p.frozen_dirs, [PathBuf::from("/w/.git/hooks")]);

        let other =
            AgentProfile::for_program("bash", Path::new("/w"), Path::new("/h"), Path::new("/t"));
        assert_eq!(other.write_dirs, [PathBuf::from("/t")]);
        assert!(other.write_prefixes.is_empty());
    }

    #[test]
    fn other_agents_logins_and_the_persons_history_are_unreadable() {
        let home = Path::new("/h");
        let profile =
            |agent| AgentProfile::for_program(agent, Path::new("/w"), home, Path::new("/t"));
        let codex = profile("/opt/bin/codex");
        for d in [".claude", ".local/state/claude", ".gemini"] {
            assert!(codex.secret_dirs.contains(&home.join(d)), "{d}");
        }
        assert_eq!(codex.secret_prefixes, [home.join(".claude.json")]);
        assert!(!codex.secret_dirs.contains(&home.join(".codex")));

        let claude = profile("claude");
        assert!(claude.secret_dirs.contains(&home.join(".codex")));
        assert!(claude.secret_dirs.contains(&home.join(".gemini")));
        assert!(claude.secret_prefixes.is_empty());

        // Anything that is not one of them reads none of them.
        let bash = profile("bash");
        for d in [".claude", ".codex", ".gemini"] {
            assert!(bash.secret_dirs.contains(&home.join(d)), "{d}");
        }
        assert_eq!(bash.secret_prefixes, [home.join(".claude.json")]);

        for p in [codex, claude, bash] {
            for h in [".zsh_history", ".bash_history", ".zsh_sessions", ".python_history"] {
                assert!(p.secret_dirs.contains(&home.join(h)), "{h}");
            }
        }
    }

    #[test]
    fn credential_names_are_recognised_and_ordinary_ones_are_not() {
        for n in [
            "GITHUB_TOKEN",
            "gh_token",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "NPM_TOKEN",
            "OPENAI_API_KEY",
            "DB_PASSWORD",
            "STRIPE_APIKEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ] {
            assert!(looks_like_credential(n), "{n}");
        }
        for n in ["PATH", "HOME", "GIT_AUTHOR_NAME", "SSH_AUTH_SOCK", "LANG", "EDITOR", "TERM"] {
            assert!(!looks_like_credential(n), "{n}");
        }
        assert!(agent_credentials("/x/claude").contains(&"CLAUDE_CODE_OAUTH_TOKEN"));
        assert!(agent_credentials("bash").is_empty());
    }

    #[test]
    fn no_secret_overlaps_the_agents_own_state() {
        // If one did, the agent could not read its own state, or the state
        // directory would hand out a secret. Compared by path component, as the
        // sandbox compares, and by string prefix for the prefix rules.
        let home = Path::new("/h");
        for agent in KNOWN_AGENTS {
            let p = AgentProfile::for_program(agent, Path::new("/w"), home, Path::new("/t"));
            let secret = p.secret_dirs.iter().chain(&p.secret_prefixes);
            for s in secret {
                for own in p.write_dirs.iter().chain(&p.write_prefixes) {
                    let (s_text, own_text) = (s.to_string_lossy(), own.to_string_lossy());
                    assert!(
                        !s.starts_with(own)
                            && !own.starts_with(s)
                            && !s_text.starts_with(&*own_text)
                            && !own_text.starts_with(&*s_text),
                        "{agent}: secret {s:?} overlaps its own state {own:?}"
                    );
                }
            }
        }
    }
}
