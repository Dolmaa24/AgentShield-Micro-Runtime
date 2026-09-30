//! Gate configuration.

use std::path::PathBuf;
use std::time::Duration;

use shellguard_parse::Limits;
use shellguard_policy::Verdict;

/// Everything the gate needs to know about the world it is judging commands in.
#[derive(Clone, Debug)]
pub struct GateConfig {
    /// The directory the agent is allowed to treat as its own. Paths resolving
    /// outside it are what most rules key on.
    pub workspace: PathBuf,
    /// The shell's working directory, used to resolve relative paths.
    pub cwd: PathBuf,
    /// Used to expand a leading `~`.
    pub home: Option<PathBuf>,
    /// `$PATH`, in order, used to resolve program names.
    pub path: Vec<PathBuf>,

    /// The evaluation budget. Exceeding it is a decision, not a hang.
    pub deadline: Duration,
    /// Parser resource limits.
    pub limits: Limits,
    /// How many layers of wrapper (`sudo env timeout ...`) to peel.
    pub max_unwrap_depth: u8,

    /// Verdict when evaluation runs out of time.
    ///
    /// [`Verdict::Deny`] by default. The alternative is a gate whose bypass is
    /// "make evaluation slow", which an agent emitting adversarial input can
    /// arrange and which would leave no trace beyond a latency blip.
    pub on_timeout: Verdict,
    /// Verdict when the command does not parse.
    ///
    /// Also [`Verdict::Deny`]. Input that a shell would accept and this parser
    /// rejects is precisely the interesting case, and it is not the case to be
    /// lenient about.
    pub on_parse_error: Verdict,
}

impl Default for GateConfig {
    fn default() -> Self {
        GateConfig {
            workspace: PathBuf::from("."),
            cwd: PathBuf::from("."),
            home: None,
            path: default_path(),
            deadline: crate::gate::DEFAULT_DEADLINE,
            limits: Limits::default(),
            max_unwrap_depth: 4,
            on_timeout: Verdict::Deny,
            on_parse_error: Verdict::Deny,
        }
    }
}

impl GateConfig {
    /// Build a config from the current process environment, with `workspace` as
    /// the agent's writable root.
    pub fn from_env(workspace: impl Into<PathBuf>) -> Self {
        let workspace = workspace.into();
        let cwd = std::env::current_dir().unwrap_or_else(|_| workspace.clone());
        GateConfig {
            workspace,
            cwd,
            home: std::env::var_os("HOME").map(PathBuf::from),
            path: std::env::var_os("PATH")
                .map(|p| std::env::split_paths(&p).collect())
                .unwrap_or_else(default_path),
            ..Default::default()
        }
    }

    pub fn with_deadline(mut self, d: Duration) -> Self {
        self.deadline = d;
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = cwd.into();
        self
    }

    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    pub fn with_path(mut self, path: Vec<PathBuf>) -> Self {
        self.path = path;
        self
    }
}

/// A conservative `$PATH` for when the environment does not provide one.
///
/// Note this is not used to *run* anything — the gate never executes. It only
/// decides which binary a name would resolve to, and an empty `$PATH` would
/// make every program unresolvable and therefore unjudgeable.
fn default_path() -> Vec<PathBuf> {
    ["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/opt/homebrew/bin"]
        .iter()
        .map(PathBuf::from)
        .collect()
}
