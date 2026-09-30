//! Program and path resolution, with the caching that keeps it off the
//! latency budget.
//!
//! # What resolution is for, and what it is not
//!
//! Rules key on program identity, and a program name is not an identity:
//! `./rm`, `/bin/rm` and `rm` share a basename and nothing else, and a `$PATH`
//! the agent controls decides which one `rm` means. Resolving turns the name
//! into a path before any rule looks at it.
//!
//! Path classification answers a different question — is this argument inside
//! the workspace — and answers it *lexically*, after canonicalising the longest
//! existing ancestor. That handles a symlinked parent directory but it does not
//! handle a symlink created between this decision and the command running, and
//! nothing at this layer can. Time-of-check to time-of-use is not a bug to fix
//! in the gate; it is the reason the gate is not the security boundary. The
//! kernel enforcement layer is, and it evaluates the path at the moment of the
//! syscall. See DESIGN.md § 3.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::config::GateConfig;

/// What resolution concluded about a path argument.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathClass {
    pub absolute: bool,
    /// The path resolves outside the workspace.
    pub outside: bool,
}

/// Caches for the two things in the decision path that touch the filesystem.
///
/// Bounded and cleared wholesale when full. A proper LRU would keep a better
/// working set, but the access pattern here is a small set of programs hit over
/// and over, so hit rate is high and eviction is rare; the extra bookkeeping
/// would cost more than it saves.
#[derive(Debug)]
pub struct PathCache {
    exec: HashMap<String, Option<PathBuf>>,
    canon: HashMap<PathBuf, PathBuf>,
    cap: usize,
    hits: u64,
    misses: u64,
    /// Where every evaluation starts: the configured working directory, as the
    /// one-element set the collector begins from, and whether it is inside the
    /// workspace. The same for every evaluation until the configuration changes,
    /// and asked by every one of them.
    start: Option<Start>,
    /// The last directory a relative path was resolved from, and where it
    /// really is. Almost always the configured working directory.
    base: Option<(PathBuf, PathBuf)>,
}

#[derive(Debug)]
struct Start {
    cwd: PathBuf,
    workspace: PathBuf,
    dirs: Arc<[PathBuf]>,
    inside: bool,
}

impl Default for PathCache {
    fn default() -> Self {
        PathCache::with_capacity(1024)
    }
}

impl PathCache {
    pub fn with_capacity(cap: usize) -> Self {
        PathCache {
            exec: HashMap::new(),
            canon: HashMap::new(),
            cap,
            hits: 0,
            misses: 0,
            start: None,
            base: None,
        }
    }

    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    pub fn clear(&mut self) {
        self.exec.clear();
        self.canon.clear();
        self.start = None;
        self.base = None;
    }

    /// The directory set an evaluation starts from, and whether it lies inside
    /// the workspace. Worked out once per configuration, not once per command.
    pub(crate) fn start(&mut self, cfg: &GateConfig) -> (Arc<[PathBuf]>, bool) {
        if let Some(s) = &self.start {
            if s.cwd == cfg.cwd && s.workspace == cfg.workspace {
                return (s.dirs.clone(), s.inside);
            }
        }
        let inside = !self.classify_in(".", &cfg.cwd, cfg).outside;
        let dirs: Arc<[PathBuf]> = Arc::from(vec![cfg.cwd.clone()]);
        self.start = Some(Start {
            cwd: cfg.cwd.clone(),
            workspace: cfg.workspace.clone(),
            dirs: dirs.clone(),
            inside,
        });
        (dirs, inside)
    }

    /// Where `cwd` really is, remembered for the next path from the same place.
    fn physical_base(&mut self, cwd: &Path) -> PathBuf {
        if let Some((logical, physical)) = &self.base {
            if logical == cwd {
                return physical.clone();
            }
        }
        let physical = self.resolve_existing_ancestor(cwd);
        self.base = Some((cwd.to_path_buf(), physical.clone()));
        physical
    }

    /// Resolve a program name to an absolute path.
    ///
    /// A name containing `/` is a path and is resolved against the working
    /// directory. Anything else is searched for on `$PATH`.
    pub fn resolve_exec(&mut self, name: &str, cfg: &GateConfig) -> Option<PathBuf> {
        let cwd = cfg.cwd.clone();
        self.resolve_exec_in(name, Some(&cwd), cfg)
    }

    /// [`resolve_exec`](Self::resolve_exec) with the shell standing in `cwd`, or
    /// somewhere unknown (`None`), which leaves a relative path unresolvable.
    pub fn resolve_exec_in(
        &mut self,
        name: &str,
        cwd: Option<&Path>,
        cfg: &GateConfig,
    ) -> Option<PathBuf> {
        if name.is_empty() {
            return None;
        }
        // A name with a `/` is a path, cached by where it points: after a `cd`,
        // the same `./build.sh` is a different program.
        let path = if name.contains('/') {
            let p = expand_tilde(name, cfg);
            Some(if p.is_absolute() {
                p
            } else {
                let base = self.resolve_existing_ancestor(cwd?);
                base.join(p)
            })
        } else {
            None
        };
        let key = match &path {
            Some(p) => p.to_string_lossy().into_owned(),
            None => name.to_string(),
        };
        if let Some(cached) = self.exec.get(&key) {
            self.hits += 1;
            return cached.clone();
        }
        self.misses += 1;

        let found = match &path {
            Some(p) => is_executable_file(p).then(|| lexical_normalize(p)),
            None => cfg.path.iter().find_map(|dir| {
                let cand = dir.join(name);
                is_executable_file(&cand).then(|| lexical_normalize(&cand))
            }),
        };

        if self.exec.len() >= self.cap {
            self.exec.clear();
        }
        self.exec.insert(key, found.clone());
        found
    }

    /// Classify a path argument relative to the workspace.
    pub fn classify(&mut self, raw: &str, cfg: &GateConfig) -> PathClass {
        let cwd = cfg.cwd.clone();
        self.classify_in(raw, &cwd, cfg)
    }

    /// [`classify`](Self::classify) with the shell standing in `cwd`.
    ///
    /// A relative path is joined to where `cwd` *really* is, not to how it is
    /// spelled: after `cd link` (a symlink to `/elsewhere`), the kernel resolves
    /// `../x` to `/x`, while the text `link/../x` reads as `./x`.
    pub fn classify_in(&mut self, raw: &str, cwd: &Path, cfg: &GateConfig) -> PathClass {
        if raw.is_empty() {
            return PathClass::default();
        }
        let expanded = expand_tilde(raw, cfg);
        let absolute = expanded.is_absolute();
        let resolved = if dotdot_after_name(&expanded) {
            // `link/../x`: textually `./x`, but the kernel resolves `link` first,
            // so `..` is the parent of wherever `link` points. Walked a component
            // at a time; only paths shaped like this pay for it.
            self.physical(Some(cwd), &expanded)
        } else {
            let joined = if absolute {
                expanded
            } else {
                let base = self.physical_base(cwd);
                base.join(expanded)
            };
            self.resolve_existing_ancestor(&joined)
        };
        let workspace = self.resolve_existing_ancestor(&cfg.workspace);
        PathClass { absolute, outside: !resolved.starts_with(&workspace) }
    }

    /// Where `chdir(path)` from `base` really lands: each component resolved
    /// through its symlinks before the next `..` is applied, as the kernel does.
    /// Past the first component that does not exist, the rest is applied
    /// textually. Each step goes through the same cache as every other lookup,
    /// so a `cd` the gate has seen before costs no system call.
    pub(crate) fn physical(&mut self, base: Option<&Path>, path: &Path) -> PathBuf {
        let mut cur = match base {
            Some(b) if !path.is_absolute() => self.physical_base(b),
            _ => PathBuf::from("/"),
        };
        for c in path.components() {
            match c {
                Component::RootDir => cur = PathBuf::from("/"),
                Component::Prefix(_) | Component::CurDir => {}
                // `cur` is always a real location, so its parent is the real
                // parent.
                Component::ParentDir => {
                    cur.pop();
                }
                Component::Normal(n) => {
                    cur.push(n);
                    cur = self.resolve_existing_ancestor(&cur);
                }
            }
        }
        cur
    }

    /// Canonicalise the longest existing prefix of a path, then reattach the
    /// rest lexically.
    ///
    /// Full `canonicalize` fails on paths that do not exist yet, which is most
    /// of what a command is about to create. Pure lexical normalisation misses
    /// a symlinked parent. Doing both catches the case that matters — a
    /// workspace subdirectory symlinked out to `/etc` — at the cost of one
    /// cached syscall per directory.
    pub(crate) fn resolve_existing_ancestor(&mut self, path: &Path) -> PathBuf {
        let normalized = lexical_normalize(path);
        let mut prefix = normalized.as_path();
        let mut tail: Vec<&std::ffi::OsStr> = Vec::new();

        loop {
            if let Some(c) = self.canon.get(prefix) {
                let mut out = c.clone();
                for part in tail.iter().rev() {
                    out.push(part);
                }
                self.hits += 1;
                return out;
            }
            if prefix.exists() {
                break;
            }
            match (prefix.parent(), prefix.file_name()) {
                (Some(parent), Some(name)) => {
                    tail.push(name);
                    prefix = parent;
                }
                _ => return normalized,
            }
        }

        self.misses += 1;
        let canonical = prefix.canonicalize().unwrap_or_else(|_| prefix.to_path_buf());
        if self.canon.len() >= self.cap {
            self.canon.clear();
        }
        self.canon.insert(prefix.to_path_buf(), canonical.clone());

        let mut out = canonical;
        for part in tail.iter().rev() {
            out.push(part);
        }
        out
    }
}

fn expand_tilde(raw: &str, cfg: &GateConfig) -> PathBuf {
    if raw == "~" {
        if let Some(h) = &cfg.home {
            return h.clone();
        }
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(h) = &cfg.home {
            return h.join(rest);
        }
    }
    PathBuf::from(raw)
}

/// A `..` that follows a name, where reading it textually and reading it the
/// way the kernel does can disagree. A leading `..` cannot: it is applied to a
/// directory that has already been resolved.
fn dotdot_after_name(p: &Path) -> bool {
    let mut named = false;
    for c in p.components() {
        match c {
            Component::Normal(_) => named = true,
            Component::ParentDir if named => return true,
            _ => {}
        }
    }
    false
}

/// Resolve `.` and `..` textually, without touching the filesystem.
pub fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                // Popping past the root leaves the root, matching how the
                // kernel treats `/..`.
                if !out.pop() && out.as_os_str().is_empty() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Whether an argument looks like it names a filesystem path.
///
/// Deliberately syntactic and cheap. The alternative — stat every argument to
/// see if it exists — would put a syscall on every token of every command, and
/// would still be wrong for paths the command is about to create.
pub fn looks_like_path(s: &str) -> bool {
    if s.is_empty() || s.starts_with('-') {
        return false;
    }
    s.contains('/') || s.starts_with('~') || s == "." || s == ".."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_normalization() {
        assert_eq!(lexical_normalize(Path::new("/a/./b")), PathBuf::from("/a/b"));
        assert_eq!(lexical_normalize(Path::new("/a/b/../c")), PathBuf::from("/a/c"));
        assert_eq!(lexical_normalize(Path::new("/a/b/../..")), PathBuf::from("/"));
        // Escaping past the root stays at the root.
        assert_eq!(lexical_normalize(Path::new("/../../etc")), PathBuf::from("/etc"));
        assert_eq!(lexical_normalize(Path::new("a/b/../c")), PathBuf::from("a/c"));
    }

    #[test]
    fn path_shapes() {
        assert!(looks_like_path("/etc/passwd"));
        assert!(looks_like_path("./build"));
        assert!(looks_like_path("~/x"));
        assert!(looks_like_path(".."));
        assert!(!looks_like_path("-rf"));
        assert!(!looks_like_path("--force"));
        assert!(!looks_like_path(""));
        // A bare name is not treated as a path; it cannot escape the workspace
        // without a separator, so nothing is lost by skipping the check.
        assert!(!looks_like_path("build"));
    }

    #[test]
    fn dotdot_escapes_the_workspace() {
        let tmp = std::env::temp_dir().join("shellguard-resolve-test/ws");
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = GateConfig {
            workspace: tmp.clone(),
            cwd: tmp.clone(),
            home: Some(PathBuf::from("/home/agent")),
            ..Default::default()
        };
        let mut c = PathCache::default();
        assert!(!c.classify("src/main.rs", &cfg).outside);
        assert!(!c.classify("./src/../src", &cfg).outside);
        assert!(c.classify("../secrets", &cfg).outside);
        assert!(c.classify("/etc/passwd", &cfg).outside);
        assert!(c.classify("src/../../escape", &cfg).outside);
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("shellguard-resolve-test"));
    }

    #[test]
    fn tilde_expands_to_the_configured_home() {
        let cfg = GateConfig {
            workspace: PathBuf::from("/ws"),
            cwd: PathBuf::from("/ws"),
            home: Some(PathBuf::from("/home/agent")),
            ..Default::default()
        };
        let mut c = PathCache::default();
        assert!(c.classify("~/.ssh/id_rsa", &cfg).outside);
        assert!(c.classify("~", &cfg).outside);
    }

    #[test]
    fn a_symlinked_ancestor_is_followed() {
        let root = std::env::temp_dir().join("shellguard-symlink-test");
        let _ = std::fs::remove_dir_all(&root);
        let ws = root.join("ws");
        let outside = root.join("outside");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        // A directory inside the workspace pointing out of it. Lexical
        // normalisation alone would call this inside.
        std::os::unix::fs::symlink(&outside, ws.join("link")).unwrap();

        let cfg = GateConfig { workspace: ws.clone(), cwd: ws.clone(), ..Default::default() };
        let mut c = PathCache::default();
        assert!(
            c.classify("link/secret", &cfg).outside,
            "a symlinked ancestor must be resolved, not normalised away"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn program_resolution_uses_path_and_caches() {
        let cfg = GateConfig {
            path: vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")],
            ..Default::default()
        };
        let mut c = PathCache::default();
        let first = c.resolve_exec("sh", &cfg);
        assert!(first.is_some(), "sh should resolve on any unix");
        assert_eq!(c.hit_rate(), 0.0);
        let second = c.resolve_exec("sh", &cfg);
        assert_eq!(first, second);
        assert!(c.hit_rate() > 0.0, "the second lookup must come from cache");

        // A name that is not on PATH resolves to nothing, and that is cached
        // too — the negative result is the expensive one to recompute.
        assert_eq!(c.resolve_exec("definitely-not-a-real-program-xyz", &cfg), None);
        assert_eq!(c.resolve_exec("definitely-not-a-real-program-xyz", &cfg), None);
    }

    #[test]
    fn a_slash_in_the_name_bypasses_path_search() {
        let cfg = GateConfig { cwd: PathBuf::from("/"), ..Default::default() };
        let mut c = PathCache::default();
        assert!(c.resolve_exec("/bin/sh", &cfg).is_some());
        // Not executable, so it does not resolve even though it exists.
        assert_eq!(c.resolve_exec("/etc/hosts", &cfg), None);
    }
}
