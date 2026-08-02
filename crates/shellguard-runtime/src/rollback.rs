//! Checkpoint and rollback.
//!
//! # What `git stash create` actually does
//!
//! It writes a commit object recording the current worktree and index and
//! prints its SHA. It does **not** move `refs/stash`, does not touch the
//! worktree, and does not race a command that is still running — which is what
//! makes it usable as a snapshot primitive, unlike `git stash push`.
//!
//! It also does **not capture untracked files**, and that gap is the whole
//! reason this module is more than three lines. An agent that creates a file
//! and gets rolled back would leave it behind; worse, an agent that *deletes*
//! an untracked file loses it permanently, because nothing ever recorded it.
//! So untracked files are hashed into the object database separately and
//! restored by hand.
//!
//! # What a checkpoint does not cover
//!
//! Files outside the workspace, and files inside it that `.gitignore` excludes
//! — `node_modules`, build output, `.env`. This is a deliberate boundary:
//! capturing an ignored tree can mean copying gigabytes, and the workspace is
//! the only thing the gate lets a command write anyway. Protected files
//! (§ [`RollbackPolicy::protected`]) close the gap for the specific paths that
//! matter, by digest rather than by content.
//!
//! On Linux an overlayfs upper layer is the complete answer and is cheaper than
//! all of this; see [`crate::overlay`].
//!
//! # Rollback is itself destructive
//!
//! It overwrites files and can delete them. Every path it touches is checked to
//! resolve inside the canonicalised workspace first, and a checkpoint taken
//! against a different workspace is refused rather than applied.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use crate::sha256;

#[derive(Debug)]
pub enum RollbackError {
    NotARepository(PathBuf),
    Git {
        args: String,
        status: Option<i32>,
        stderr: String,
    },
    Io(std::io::Error),
    /// The checkpoint was taken somewhere else. Applying it would write into a
    /// tree it never described.
    WorkspaceMismatch {
        expected: PathBuf,
        actual: PathBuf,
    },
    /// A path in the checkpoint resolves outside the workspace.
    EscapesWorkspace(PathBuf),
}

impl std::fmt::Display for RollbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RollbackError::NotARepository(p) => {
                write!(f, "{} is not a git repository", p.display())
            }
            RollbackError::Git { args, status, stderr } => {
                write!(f, "git {args} failed ({status:?}): {}", stderr.trim())
            }
            RollbackError::Io(e) => write!(f, "{e}"),
            RollbackError::WorkspaceMismatch { expected, actual } => write!(
                f,
                "checkpoint was taken in {} but the workspace is {}",
                expected.display(),
                actual.display()
            ),
            RollbackError::EscapesWorkspace(p) => {
                write!(f, "{} resolves outside the workspace", p.display())
            }
        }
    }
}

impl std::error::Error for RollbackError {}

impl From<std::io::Error> for RollbackError {
    fn from(e: std::io::Error) -> Self {
        RollbackError::Io(e)
    }
}

type Result<T> = std::result::Result<T, RollbackError>;

/// An untracked file, recorded by content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Untracked {
    pub path: PathBuf,
    /// Blob SHA in the repository's object database.
    pub blob: String,
    /// Unix mode, so an executable script comes back executable.
    pub mode: u32,
}

/// A protected file's digest at checkpoint time. `None` means it did not exist,
/// which is itself a state worth restoring to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedDigest {
    pub path: PathBuf,
    pub digest: Option<[u8; 32]>,
}

/// A point in time the workspace can be returned to.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub workspace: PathBuf,
    pub taken_at: SystemTime,
    /// `HEAD` at checkpoint time, absent in a repository with no commits.
    pub head: Option<String>,
    /// The `git stash create` commit, absent when the tree was clean.
    pub stash: Option<String>,
    pub untracked: Vec<Untracked>,
    pub protected: Vec<ProtectedDigest>,
    /// How long taking it cost, so the overhead is visible rather than assumed.
    pub took: Duration,
}

impl Checkpoint {
    /// Whether there was anything to restore.
    pub fn is_empty(&self) -> bool {
        self.stash.is_none() && self.untracked.is_empty()
    }

    pub fn summary(&self) -> String {
        format!(
            "checkpoint: head {}, {} stash, {} untracked, {} protected ({:?})",
            self.head.as_deref().map(|h| &h[..7.min(h.len())]).unwrap_or("none"),
            if self.stash.is_some() { "1" } else { "0" },
            self.untracked.len(),
            self.protected.len(),
            self.took
        )
    }
}

/// When to roll back automatically.
#[derive(Clone, Debug)]
pub struct RollbackPolicy {
    /// The command exited non-zero.
    pub on_nonzero_exit: bool,
    /// A health check failed.
    pub on_health_failure: bool,
    /// A protected file changed, whatever the exit status.
    pub on_protected_change: bool,
    /// Paths that must not change, relative to the workspace or absolute.
    pub protected: Vec<PathBuf>,
    /// Delete untracked files that appeared after the checkpoint.
    ///
    /// Off by default. Rolling back a *failed* command is one thing; deleting
    /// a file the agent created is another, and the file may be the only
    /// record of what it was trying to do. Callers that want a truly pristine
    /// tree opt in.
    pub remove_new_untracked: bool,
}

impl Default for RollbackPolicy {
    fn default() -> Self {
        RollbackPolicy {
            on_nonzero_exit: false,
            on_health_failure: true,
            on_protected_change: true,
            protected: Vec::new(),
            remove_new_untracked: false,
        }
    }
}

/// A condition checked after the command runs.
#[derive(Clone, Debug)]
pub enum HealthCheck {
    /// A command that must exit zero. Run in the workspace.
    Command { argv: Vec<String>, timeout: Duration },
    /// No protected file changed.
    ProtectedUnchanged,
    /// `HEAD` did not move.
    HeadUnchanged,
    /// The workspace still contains this path.
    Exists(PathBuf),
}

impl HealthCheck {
    pub fn describe(&self) -> String {
        match self {
            HealthCheck::Command { argv, .. } => format!("`{}`", argv.join(" ")),
            HealthCheck::ProtectedUnchanged => "protected files unchanged".into(),
            HealthCheck::HeadUnchanged => "HEAD unchanged".into(),
            HealthCheck::Exists(p) => format!("{} exists", p.display()),
        }
    }
}

/// How the command itself ended.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecOutcome {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

impl ExecOutcome {
    pub fn ok(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthReport {
    pub failures: Vec<String>,
}

impl HealthReport {
    pub fn healthy(&self) -> bool {
        self.failures.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct RollbackReport {
    pub restored_tracked: bool,
    pub head_reset: bool,
    pub untracked_restored: Vec<PathBuf>,
    pub untracked_removed: Vec<PathBuf>,
    pub took: Duration,
}

/// The whole story of one guarded execution.
#[derive(Clone, Debug)]
pub struct GuardOutcome {
    pub checkpoint: Checkpoint,
    pub exec: ExecOutcome,
    pub health: HealthReport,
    pub changed_protected: Vec<PathBuf>,
    /// Why a rollback happened. Empty means none did.
    pub rollback_reasons: Vec<String>,
    pub rollback: Option<RollbackReport>,
}

impl GuardOutcome {
    pub fn rolled_back(&self) -> bool {
        self.rollback.is_some()
    }
}

/// Takes checkpoints and restores them.
#[derive(Debug)]
pub struct StateManager {
    workspace: PathBuf,
    policy: RollbackPolicy,
    is_repo: bool,
}

impl StateManager {
    /// Open a workspace. Succeeds whether or not it is a git repository; the
    /// non-repo case degrades to protected-file digests only, which is worth
    /// having and is better than refusing to run.
    pub fn open(workspace: impl AsRef<Path>, policy: RollbackPolicy) -> Result<Self> {
        let workspace = workspace.as_ref().canonicalize().map_err(RollbackError::Io)?;
        let is_repo = git_in(&workspace, &["rev-parse", "--is-inside-work-tree"])
            .map(|o| String::from_utf8_lossy(&o).trim() == "true")
            .unwrap_or(false);
        Ok(StateManager { workspace, policy, is_repo })
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn is_repo(&self) -> bool {
        self.is_repo
    }

    pub fn policy(&self) -> &RollbackPolicy {
        &self.policy
    }

    fn git(&self, args: &[&str]) -> Result<Vec<u8>> {
        git_in(&self.workspace, args)
    }

    // ------------------------------------------------------------ checkpoint

    pub fn checkpoint(&self) -> Result<Checkpoint> {
        let t0 = Instant::now();
        let mut head = None;
        let mut stash = None;
        let mut untracked = Vec::new();

        if self.is_repo {
            // A repository with no commits has no HEAD, and `stash create`
            // cannot work there either. Not an error: a fresh `git init` is a
            // legitimate state for an agent to be working in.
            head = self
                .git(&["rev-parse", "HEAD"])
                .ok()
                .map(|o| String::from_utf8_lossy(&o).trim().to_string())
                .filter(|s| !s.is_empty());

            if head.is_some() {
                let out = self.git(&["stash", "create"])?;
                let sha = String::from_utf8_lossy(&out).trim().to_string();
                // Empty output means the tree was clean, which is a valid
                // snapshot: there is simply nothing to restore.
                if !sha.is_empty() {
                    stash = Some(sha);
                }
                untracked = self.capture_untracked()?;
            }
        }

        let protected = self.digest_protected();

        Ok(Checkpoint {
            workspace: self.workspace.clone(),
            taken_at: SystemTime::now(),
            head,
            stash,
            untracked,
            protected,
            took: t0.elapsed(),
        })
    }

    /// Hash every untracked, non-ignored file into the object database.
    ///
    /// Using git's own store rather than a side directory means the blobs are
    /// garbage-collected with everything else and need no separate lifecycle.
    fn capture_untracked(&self) -> Result<Vec<Untracked>> {
        let out = self.git(&["ls-files", "--others", "--exclude-standard", "-z"])?;
        let mut files = Vec::new();

        for name in out.split(|b| *b == 0) {
            if name.is_empty() {
                continue;
            }
            let rel = PathBuf::from(String::from_utf8_lossy(name).into_owned());
            let abs = self.workspace.join(&rel);

            // Symlinks are recorded as-is rather than followed: following one
            // would copy the target's content and restore it as a regular
            // file, quietly replacing a link with a copy.
            let meta = match std::fs::symlink_metadata(&abs) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !meta.is_file() {
                continue;
            }

            let blob = self.git(&["hash-object", "-w", "--", &abs.to_string_lossy()])?;
            let blob = String::from_utf8_lossy(&blob).trim().to_string();
            if blob.is_empty() {
                continue;
            }

            let mode = mode_of(&meta);
            files.push(Untracked { path: rel, blob, mode });
        }

        Ok(files)
    }

    fn digest_protected(&self) -> Vec<ProtectedDigest> {
        self.policy
            .protected
            .iter()
            .map(|p| {
                let abs = if p.is_absolute() { p.clone() } else { self.workspace.join(p) };
                ProtectedDigest { path: p.clone(), digest: sha256::hash_file(&abs).ok() }
            })
            .collect()
    }

    /// Protected paths whose content differs from the checkpoint.
    pub fn changed_protected(&self, cp: &Checkpoint) -> Vec<PathBuf> {
        let mut changed = Vec::new();
        for p in &cp.protected {
            let abs =
                if p.path.is_absolute() { p.path.clone() } else { self.workspace.join(&p.path) };
            let now = sha256::hash_file(&abs).ok();
            if now != p.digest {
                changed.push(p.path.clone());
            }
        }
        changed
    }

    // --------------------------------------------------------------- health

    pub fn run_health(&self, cp: &Checkpoint, checks: &[HealthCheck]) -> HealthReport {
        let mut failures = Vec::new();

        for c in checks {
            let ok = match c {
                HealthCheck::Command { argv, timeout } => self.run_health_command(argv, *timeout),
                HealthCheck::ProtectedUnchanged => self.changed_protected(cp).is_empty(),
                HealthCheck::HeadUnchanged => {
                    let now = self
                        .git(&["rev-parse", "HEAD"])
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o).trim().to_string())
                        .filter(|s| !s.is_empty());
                    now == cp.head
                }
                HealthCheck::Exists(p) => {
                    let abs = if p.is_absolute() { p.clone() } else { self.workspace.join(p) };
                    abs.exists()
                }
            };
            if !ok {
                failures.push(c.describe());
            }
        }

        HealthReport { failures }
    }

    fn run_health_command(&self, argv: &[String], timeout: Duration) -> bool {
        let Some((program, args)) = argv.split_first() else { return false };
        let child = Command::new(program)
            .args(args)
            .current_dir(&self.workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        let Ok(mut child) = child else { return false };
        match wait_timeout(&mut child, timeout) {
            Some(status) => status.success(),
            None => {
                // A health check that hangs has failed. Kill it, or it outlives
                // the thing it was checking.
                let _ = child.kill();
                let _ = child.wait();
                false
            }
        }
    }

    // ------------------------------------------------------------- rollback

    /// Decide, then act. The single entry point a caller needs.
    pub fn finish(
        &self,
        cp: Checkpoint,
        exec: ExecOutcome,
        checks: &[HealthCheck],
    ) -> Result<GuardOutcome> {
        let health = self.run_health(&cp, checks);
        let changed_protected = self.changed_protected(&cp);

        let mut reasons = Vec::new();
        if self.policy.on_nonzero_exit && !exec.ok() {
            reasons.push(match exec.exit_code {
                _ if exec.timed_out => "the command timed out".to_string(),
                Some(c) => format!("the command exited {c}"),
                None => "the command was killed by a signal".to_string(),
            });
        }
        if self.policy.on_health_failure && !health.healthy() {
            reasons.push(format!("health check failed: {}", health.failures.join(", ")));
        }
        if self.policy.on_protected_change && !changed_protected.is_empty() {
            let names: Vec<String> =
                changed_protected.iter().map(|p| p.display().to_string()).collect();
            reasons.push(format!("protected files changed: {}", names.join(", ")));
        }

        let rollback = if reasons.is_empty() { None } else { Some(self.rollback(&cp)?) };

        Ok(GuardOutcome {
            checkpoint: cp,
            exec,
            health,
            changed_protected,
            rollback_reasons: reasons,
            rollback,
        })
    }

    /// Restore the workspace to a checkpoint.
    pub fn rollback(&self, cp: &Checkpoint) -> Result<RollbackReport> {
        if cp.workspace != self.workspace {
            return Err(RollbackError::WorkspaceMismatch {
                expected: cp.workspace.clone(),
                actual: self.workspace.clone(),
            });
        }

        let t0 = Instant::now();
        let mut report = RollbackReport::default();

        if !self.is_repo {
            report.took = t0.elapsed();
            return Ok(report);
        }

        // Move HEAD back first. `--soft` leaves the index and worktree alone so
        // the tree restore below is the only thing that touches files; doing it
        // the other way round would undo that restore.
        if let Some(head) = &cp.head {
            let now = self
                .git(&["rev-parse", "HEAD"])
                .ok()
                .map(|o| String::from_utf8_lossy(&o).trim().to_string());
            if now.as_deref() != Some(head.as_str()) {
                self.git(&["reset", "--soft", head])?;
                report.head_reset = true;
            }
        }

        match &cp.stash {
            Some(stash) => {
                // The stash commit's own tree is the worktree state at
                // checkpoint time. `read-tree -u --reset` restores index and
                // worktree together and removes tracked files that were not
                // there — untracked files are not in the index, so they are
                // left for the explicit handling below.
                let tree = format!("{stash}^{{tree}}");
                self.git(&["read-tree", "-u", "--reset", &tree])?;
                report.restored_tracked = true;
            }
            None => {
                // The tree was clean at checkpoint time, so restoring means
                // discarding everything since.
                if let Some(head) = &cp.head {
                    let tree = format!("{head}^{{tree}}");
                    self.git(&["read-tree", "-u", "--reset", &tree])?;
                    report.restored_tracked = true;
                }
            }
        }

        self.restore_untracked(cp, &mut report)?;

        report.took = t0.elapsed();
        Ok(report)
    }

    fn restore_untracked(&self, cp: &Checkpoint, report: &mut RollbackReport) -> Result<()> {
        let recorded: BTreeMap<&Path, &Untracked> =
            cp.untracked.iter().map(|u| (u.path.as_path(), u)).collect();

        // Put back what was there, including anything the command deleted.
        for u in &cp.untracked {
            let abs = self.safe_join(&u.path)?;
            let content = self.git(&["cat-file", "blob", &u.blob])?;

            let needs_write = match std::fs::read(&abs) {
                Ok(existing) => existing != content,
                Err(_) => true,
            };
            if needs_write {
                if let Some(parent) = abs.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&abs, &content)?;
                set_mode(&abs, u.mode);
                report.untracked_restored.push(u.path.clone());
            }
        }

        if !self.policy.remove_new_untracked {
            return Ok(());
        }

        // Remove what appeared since. Scoped to files git currently reports as
        // untracked and non-ignored, so build output and `node_modules` are
        // never candidates.
        let out = self.git(&["ls-files", "--others", "--exclude-standard", "-z"])?;
        for name in out.split(|b| *b == 0) {
            if name.is_empty() {
                continue;
            }
            let rel = PathBuf::from(String::from_utf8_lossy(name).into_owned());
            if recorded.contains_key(rel.as_path()) {
                continue;
            }
            let abs = self.safe_join(&rel)?;
            // symlink_metadata, so a symlink is removed rather than followed.
            if std::fs::symlink_metadata(&abs).is_ok() {
                std::fs::remove_file(&abs)?;
                report.untracked_removed.push(rel);
            }
        }

        Ok(())
    }

    /// Join a checkpoint-relative path to the workspace, refusing anything that
    /// escapes it.
    ///
    /// The paths here come from a checkpoint taken before an untrusted command
    /// ran, but the *filesystem* did not: a `..` component or a symlinked
    /// parent directory created by that command could otherwise redirect a
    /// write outside the workspace, turning rollback into the exploit.
    fn safe_join(&self, rel: &Path) -> Result<PathBuf> {
        let joined = self.workspace.join(rel);
        let normalized = normalize(&joined);
        if !normalized.starts_with(&self.workspace) {
            return Err(RollbackError::EscapesWorkspace(rel.to_path_buf()));
        }
        // Resolve the deepest existing ancestor, so a symlinked parent is
        // caught rather than normalised away.
        let mut probe = normalized.as_path();
        loop {
            if let Ok(real) = probe.canonicalize() {
                if !real.starts_with(&self.workspace) {
                    return Err(RollbackError::EscapesWorkspace(rel.to_path_buf()));
                }
                break;
            }
            match probe.parent() {
                Some(p) if p.starts_with(&self.workspace) => probe = p,
                _ => break,
            }
        }
        Ok(normalized)
    }
}

fn git_in(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git").args(args).current_dir(dir).stdin(Stdio::null()).output()?;
    if !out.status.success() {
        return Err(RollbackError::Git {
            args: args.join(" "),
            status: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(out.stdout)
}

fn mode_of(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.mode()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0o644
    }
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

/// Resolve `.` and `..` textually.
fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Wait for a child with a timeout, without pulling in a dependency.
///
/// Polls rather than using a signal or a thread. The granularity is a
/// millisecond, which is irrelevant against a health check measured in tenths
/// of a second and keeps the code to something one can read in a sitting.
fn wait_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Repo {
        dir: PathBuf,
    }

    impl Repo {
        fn new(name: &str) -> Repo {
            let dir = std::env::temp_dir().join(format!("shellguard-rollback-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let r = Repo { dir: dir.canonicalize().unwrap() };
            r.git(&["init", "-q", "-b", "main", "."]);
            r.git(&["config", "user.email", "t@example.com"]);
            r.git(&["config", "user.name", "test"]);
            r
        }

        fn git(&self, args: &[&str]) -> String {
            let out = Command::new("git").args(args).current_dir(&self.dir).output().unwrap();
            assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn write(&self, rel: &str, content: &str) {
            let p = self.dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, content).unwrap();
        }

        fn read(&self, rel: &str) -> Option<String> {
            std::fs::read_to_string(self.dir.join(rel)).ok()
        }

        fn exists(&self, rel: &str) -> bool {
            self.dir.join(rel).exists()
        }

        fn commit_initial(&self) {
            self.write("tracked.txt", "original\n");
            self.write("keep.txt", "keep\n");
            self.git(&["add", "-A"]);
            self.git(&["commit", "-qm", "init"]);
        }

        fn manager(&self, policy: RollbackPolicy) -> StateManager {
            StateManager::open(&self.dir, policy).unwrap()
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    // ------------------------------------------------------- checkpointing

    #[test]
    fn taking_a_checkpoint_does_not_disturb_the_worktree() {
        // The property that makes `stash create` usable at all.
        let r = Repo::new("nondisturb");
        r.commit_initial();
        r.write("tracked.txt", "modified\n");
        r.write("new.txt", "brand new\n");

        let before = r.git(&["status", "--porcelain"]);
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();
        let after = r.git(&["status", "--porcelain"]);

        assert_eq!(before, after, "checkpointing changed the working tree");
        assert_eq!(r.read("tracked.txt").as_deref(), Some("modified\n"));
        assert!(cp.stash.is_some());
        // And it must not have created a stash entry the user would see.
        assert!(Command::new("git")
            .args(["rev-parse", "--verify", "refs/stash"])
            .current_dir(&r.dir)
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true));
    }

    #[test]
    fn untracked_files_are_captured_because_stash_create_omits_them() {
        let r = Repo::new("untracked-capture");
        r.commit_initial();
        r.write("new.txt", "brand new\n");
        r.write("nested/deep.txt", "deep\n");

        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        let names: Vec<String> =
            cp.untracked.iter().map(|u| u.path.display().to_string()).collect();
        assert!(names.contains(&"new.txt".to_string()), "{names:?}");
        assert!(names.contains(&"nested/deep.txt".to_string()), "{names:?}");
    }

    #[test]
    fn ignored_files_are_not_captured() {
        let r = Repo::new("ignored");
        r.commit_initial();
        r.write(".gitignore", "build/\n");
        r.write("build/artifact.bin", "huge\n");
        r.git(&["add", ".gitignore"]);
        r.git(&["commit", "-qm", "ignore"]);

        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();
        assert!(
            !cp.untracked.iter().any(|u| u.path.starts_with("build")),
            "ignored output should not be checkpointed"
        );
    }

    #[test]
    fn a_repository_with_no_commits_checkpoints_without_erroring() {
        let r = Repo::new("no-commits");
        r.write("scratch.txt", "x\n");
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();
        assert!(cp.head.is_none());
        assert!(cp.stash.is_none());
    }

    #[test]
    fn a_non_repository_degrades_to_digests_only() {
        let dir = std::env::temp_dir().join("shellguard-rollback-norepo");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("secret.conf"), "v1").unwrap();

        let policy =
            RollbackPolicy { protected: vec![PathBuf::from("secret.conf")], ..Default::default() };
        let sm = StateManager::open(&dir, policy).unwrap();
        assert!(!sm.is_repo());

        let cp = sm.checkpoint().unwrap();
        assert_eq!(cp.protected.len(), 1);
        assert!(cp.protected[0].digest.is_some());
        assert!(sm.changed_protected(&cp).is_empty());

        std::fs::write(dir.join("secret.conf"), "v2").unwrap();
        assert_eq!(sm.changed_protected(&cp), vec![PathBuf::from("secret.conf")]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------ rollback

    #[test]
    fn rollback_restores_a_modified_tracked_file() {
        let r = Repo::new("restore-modified");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        r.write("tracked.txt", "vandalised\n");
        sm.rollback(&cp).unwrap();

        assert_eq!(r.read("tracked.txt").as_deref(), Some("original\n"));
    }

    #[test]
    fn rollback_restores_a_deleted_tracked_file() {
        let r = Repo::new("restore-deleted");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        std::fs::remove_file(r.dir.join("keep.txt")).unwrap();
        assert!(!r.exists("keep.txt"));

        sm.rollback(&cp).unwrap();
        assert_eq!(r.read("keep.txt").as_deref(), Some("keep\n"));
    }

    #[test]
    fn rollback_restores_a_deleted_untracked_file() {
        // The case `git stash create` alone loses forever.
        let r = Repo::new("restore-deleted-untracked");
        r.commit_initial();
        r.write("notes.md", "hours of work\n");

        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        std::fs::remove_file(r.dir.join("notes.md")).unwrap();
        let report = sm.rollback(&cp).unwrap();

        assert_eq!(r.read("notes.md").as_deref(), Some("hours of work\n"));
        assert_eq!(report.untracked_restored, vec![PathBuf::from("notes.md")]);
    }

    #[test]
    fn rollback_restores_a_modified_untracked_file() {
        let r = Repo::new("restore-modified-untracked");
        r.commit_initial();
        r.write("notes.md", "v1\n");
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        r.write("notes.md", "clobbered\n");
        sm.rollback(&cp).unwrap();
        assert_eq!(r.read("notes.md").as_deref(), Some("v1\n"));
    }

    #[test]
    fn an_executable_untracked_file_comes_back_executable() {
        let r = Repo::new("exec-mode");
        r.commit_initial();
        r.write("run.sh", "#!/bin/sh\necho hi\n");
        set_mode(&r.dir.join("run.sh"), 0o755);

        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();
        std::fs::remove_file(r.dir.join("run.sh")).unwrap();
        sm.rollback(&cp).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(r.dir.join("run.sh")).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "lost the executable bit");
        }
    }

    #[test]
    fn rollback_undoes_a_commit() {
        let r = Repo::new("undo-commit");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();
        let head_before = r.git(&["rev-parse", "HEAD"]);

        r.write("tracked.txt", "committed change\n");
        r.git(&["add", "-A"]);
        r.git(&["commit", "-qm", "agent commit"]);
        assert_ne!(r.git(&["rev-parse", "HEAD"]), head_before);

        let report = sm.rollback(&cp).unwrap();
        assert!(report.head_reset);
        assert_eq!(r.git(&["rev-parse", "HEAD"]), head_before);
        assert_eq!(r.read("tracked.txt").as_deref(), Some("original\n"));
    }

    #[test]
    fn new_untracked_files_survive_by_default() {
        // Deleting an agent's new file is a bigger decision than undoing a
        // failed command, so it is opt-in.
        let r = Repo::new("keep-new");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        r.write("agent-output.txt", "possibly valuable\n");
        sm.rollback(&cp).unwrap();
        assert!(r.exists("agent-output.txt"));
    }

    #[test]
    fn new_untracked_files_are_removed_when_asked() {
        let r = Repo::new("remove-new");
        r.commit_initial();
        let policy = RollbackPolicy { remove_new_untracked: true, ..Default::default() };
        let sm = r.manager(policy);
        let cp = sm.checkpoint().unwrap();

        r.write("agent-output.txt", "junk\n");
        let report = sm.rollback(&cp).unwrap();

        assert!(!r.exists("agent-output.txt"));
        assert_eq!(report.untracked_removed, vec![PathBuf::from("agent-output.txt")]);
    }

    #[test]
    fn removing_new_files_does_not_touch_ignored_ones() {
        // Wiping `node_modules` on every failed command would be its own kind
        // of damage.
        let r = Repo::new("remove-new-ignored");
        r.commit_initial();
        r.write(".gitignore", "build/\n");
        r.git(&["add", ".gitignore"]);
        r.git(&["commit", "-qm", "ignore"]);

        let policy = RollbackPolicy { remove_new_untracked: true, ..Default::default() };
        let sm = r.manager(policy);
        let cp = sm.checkpoint().unwrap();

        r.write("build/expensive.o", "an hour of compilation\n");
        sm.rollback(&cp).unwrap();
        assert!(r.exists("build/expensive.o"), "ignored build output was deleted");
    }

    #[test]
    fn a_checkpoint_from_another_workspace_is_refused() {
        let a = Repo::new("ws-a");
        let b = Repo::new("ws-b");
        a.commit_initial();
        b.commit_initial();

        let cp = a.manager(RollbackPolicy::default()).checkpoint().unwrap();
        let err = b.manager(RollbackPolicy::default()).rollback(&cp).unwrap_err();
        assert!(matches!(err, RollbackError::WorkspaceMismatch { .. }), "{err}");
    }

    #[test]
    fn a_path_escaping_the_workspace_is_refused() {
        let r = Repo::new("escape");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        assert!(matches!(
            sm.safe_join(Path::new("../../etc/passwd")),
            Err(RollbackError::EscapesWorkspace(_))
        ));
        assert!(sm.safe_join(Path::new("src/main.rs")).is_ok());
    }

    #[test]
    fn a_symlinked_parent_cannot_redirect_a_restore() {
        // A command could create `link -> /tmp/elsewhere` and a checkpoint
        // entry under it would otherwise write outside the workspace.
        let r = Repo::new("symlink-escape");
        r.commit_initial();
        let outside = std::env::temp_dir().join("shellguard-rollback-outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, r.dir.join("link")).unwrap();

        let sm = r.manager(RollbackPolicy::default());
        assert!(matches!(
            sm.safe_join(Path::new("link/evil.txt")),
            Err(RollbackError::EscapesWorkspace(_))
        ));
        let _ = std::fs::remove_dir_all(&outside);
    }

    // -------------------------------------------------- health and policy

    #[test]
    fn a_failing_health_check_triggers_rollback() {
        let r = Repo::new("health-fail");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        r.write("tracked.txt", "broken\n");

        let checks =
            [HealthCheck::Command { argv: vec!["false".into()], timeout: Duration::from_secs(5) }];
        let out =
            sm.finish(cp, ExecOutcome { exit_code: Some(0), timed_out: false }, &checks).unwrap();

        assert!(out.rolled_back());
        assert!(!out.health.healthy());
        assert_eq!(r.read("tracked.txt").as_deref(), Some("original\n"));
    }

    #[test]
    fn a_passing_health_check_keeps_the_work() {
        let r = Repo::new("health-pass");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        r.write("tracked.txt", "deliberate change\n");

        let checks =
            [HealthCheck::Command { argv: vec!["true".into()], timeout: Duration::from_secs(5) }];
        let out =
            sm.finish(cp, ExecOutcome { exit_code: Some(0), timed_out: false }, &checks).unwrap();

        assert!(!out.rolled_back());
        assert_eq!(r.read("tracked.txt").as_deref(), Some("deliberate change\n"));
    }

    #[test]
    fn a_hanging_health_check_fails_rather_than_hanging() {
        let r = Repo::new("health-hang");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        let checks = [HealthCheck::Command {
            argv: vec!["sleep".into(), "30".into()],
            timeout: Duration::from_millis(150),
        }];
        let t = Instant::now();
        let report = sm.run_health(&cp, &checks);
        assert!(t.elapsed() < Duration::from_secs(5), "took {:?}", t.elapsed());
        assert!(!report.healthy());
    }

    #[test]
    fn a_protected_file_change_triggers_rollback() {
        let r = Repo::new("protected");
        r.commit_initial();
        let policy =
            RollbackPolicy { protected: vec![PathBuf::from("keep.txt")], ..Default::default() };
        let sm = r.manager(policy);
        let cp = sm.checkpoint().unwrap();

        r.write("keep.txt", "tampered\n");
        let out = sm.finish(cp, ExecOutcome { exit_code: Some(0), timed_out: false }, &[]).unwrap();

        assert!(out.rolled_back());
        assert_eq!(out.changed_protected, vec![PathBuf::from("keep.txt")]);
        assert_eq!(r.read("keep.txt").as_deref(), Some("keep\n"));
    }

    #[test]
    fn a_nonzero_exit_rolls_back_only_when_the_policy_says_so() {
        let r = Repo::new("exit-policy");
        r.commit_initial();

        // Default: a failing command does not by itself discard its work.
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();
        r.write("tracked.txt", "partial progress\n");
        let out = sm.finish(cp, ExecOutcome { exit_code: Some(1), timed_out: false }, &[]).unwrap();
        assert!(!out.rolled_back());
        assert_eq!(r.read("tracked.txt").as_deref(), Some("partial progress\n"));

        // Opted in, it does.
        let sm = r.manager(RollbackPolicy { on_nonzero_exit: true, ..Default::default() });
        let cp = sm.checkpoint().unwrap();
        r.write("tracked.txt", "more partial progress\n");
        let out = sm.finish(cp, ExecOutcome { exit_code: Some(1), timed_out: false }, &[]).unwrap();
        assert!(out.rolled_back());
        assert_eq!(r.read("tracked.txt").as_deref(), Some("partial progress\n"));
    }

    #[test]
    fn head_unchanged_check_notices_a_commit() {
        let r = Repo::new("head-check");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        assert!(sm.run_health(&cp, &[HealthCheck::HeadUnchanged]).healthy());

        r.write("tracked.txt", "x\n");
        r.git(&["add", "-A"]);
        r.git(&["commit", "-qm", "moved"]);
        assert!(!sm.run_health(&cp, &[HealthCheck::HeadUnchanged]).healthy());
    }

    #[test]
    fn rollback_is_idempotent() {
        let r = Repo::new("idempotent");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();

        r.write("tracked.txt", "changed\n");
        sm.rollback(&cp).unwrap();
        let first = r.read("tracked.txt");
        sm.rollback(&cp).unwrap();
        assert_eq!(r.read("tracked.txt"), first);
        assert_eq!(first.as_deref(), Some("original\n"));
    }

    #[test]
    fn checkpoint_records_how_long_it_took() {
        let r = Repo::new("timing");
        r.commit_initial();
        let sm = r.manager(RollbackPolicy::default());
        let cp = sm.checkpoint().unwrap();
        assert!(cp.took > Duration::ZERO);
        assert!(cp.summary().contains("checkpoint:"));
    }
}
