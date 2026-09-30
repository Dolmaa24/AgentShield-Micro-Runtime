//! Following `cd`: the directories each command may run in.
//!
//! # Why
//!
//! Every rule about where a path points — "recursive delete outside the
//! workspace" — is only as good as the directory a relative path is resolved
//! against. Resolving against one fixed directory judged `cd / && rm -rf *`
//! exactly like `rm -rf .`: a `confine` for a command that deletes the machine.
//!
//! # The model
//!
//! The gate does not run the shell, so it cannot know which directory the shell
//! is in. It knows a *set*: every directory the shell could be in at that point,
//! or [`Cwd::Unknown`] when it cannot bound it. A path argument is outside the
//! workspace if it resolves outside from *any* directory in the set, and
//! unresolved if the set is unknown — the same answer `rm -rf $DIR` already gets.
//! The property the tests hold this to, against real `sh`, `bash`, `zsh` and
//! `dash`: the directory a command really runs in is always in its set.
//!
//! Two sets are carried through the syntax tree, for "the last thing succeeded"
//! and "it failed", because that is what `&&`, `||` and `if` choose between:
//! after `cd /tmp && x`, `x` runs only in `/tmp`; after `cd /tmp || x` only where
//! the shell already was; after `cd /tmp; x`, in either. `OLDPWD` (`cd -`) and the
//! `pushd` stack are tracked the same way.
//!
//! # What was measured, and shaped this
//!
//! * `cd` is *logical*: `cd link && cd ..` returns to where it started. The
//!   kernel resolves a relative path *physically*: after `cd link`, `rm ../x`
//!   removes a sibling of the link's *target*. So the set holds the directory as
//!   `cd` spells it, and a path argument is resolved from its physical location.
//!   `cd -P`, `set -P` and `chdir(2)` are physical; where the two readings of a
//!   `cd` are different directories, both go in the set.
//! * With `CDPATH` exported, `cd src` goes to `$CDPATH/src` *before* `./src`.
//! * The last stage of a pipeline runs in the current shell in `zsh`, not in
//!   `bash` or `dash`, so `echo | cd /` may or may not move.
//! * `alias go=cd` on one line makes `go /` a `cd` on the next, even in `sh -c`;
//!   `trap 'cd /' DEBUG` runs a `cd` before every later command; `c=cd; $c /`
//!   is a `cd`; a function that calls `cd` moves its caller; `declare "HO"ME=/`
//!   changes where a bare `cd` goes, after quote removal. None of these can be
//!   followed statically, so each makes the directory unknown from there on.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use shellguard_parse::{Node, Simple, Word, WordPart};

use crate::normalize::Collector;
use crate::resolve::lexical_normalize;

/// Beyond this many candidate directories the set is given up as unknown.
/// Each `cd a || cd b || ...` adds one; only an input built to grow it gets here.
const MAX_DIRS: usize = 8;

/// The directories the shell may be in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cwd {
    /// One of these, spelled as `cd` would leave `$PWD`. Never empty.
    Known(Arc<[PathBuf]>),
    /// Anywhere.
    Unknown,
}

impl Default for Cwd {
    /// Unknown: the conservative answer, for a command nobody placed.
    fn default() -> Self {
        Cwd::Unknown
    }
}

impl Cwd {
    pub fn at(p: impl Into<PathBuf>) -> Cwd {
        Cwd::Known(Arc::from(vec![p.into()]))
    }

    /// The directories, if they are known.
    pub fn known(&self) -> Option<&[PathBuf]> {
        match self {
            Cwd::Known(d) => Some(d),
            Cwd::Unknown => None,
        }
    }

    /// Either this or that.
    pub fn union(&self, other: &Cwd) -> Cwd {
        match (self, other) {
            (Cwd::Known(a), Cwd::Known(b)) => {
                if b.iter().all(|p| a.contains(p)) {
                    return self.clone();
                }
                let mut v = a.to_vec();
                for p in b.iter() {
                    if !v.contains(p) {
                        v.push(p.clone());
                    }
                }
                if v.len() > MAX_DIRS {
                    Cwd::Unknown
                } else {
                    Cwd::Known(Arc::from(v))
                }
            }
            _ => Cwd::Unknown,
        }
    }

    /// The same set: by identity first, which is the usual case, since the state
    /// is passed along by cloning the `Arc`.
    pub fn same(&self, other: &Cwd) -> bool {
        match (self, other) {
            (Cwd::Known(a), Cwd::Known(b)) => Arc::ptr_eq(a, b) || a == b,
            (Cwd::Unknown, Cwd::Unknown) => true,
            _ => false,
        }
    }

    /// The empty set, as the start of a union. Never escapes this module.
    fn none() -> Cwd {
        Cwd::Known(Arc::from(Vec::new()))
    }
}

/// The part of the shell's state that decides where relative paths point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirState {
    /// Where the shell may be.
    pub pwd: Cwd,
    /// Where `cd -` would go.
    pub oldpwd: Cwd,
    /// The `pushd` stack, top last; `None` when its depth is not known.
    pub stack: Option<Vec<Cwd>>,
}

impl DirState {
    /// A shell that has just started in `cwd`. `OLDPWD` is unknown: it may be
    /// inherited, and `cd -` without it fails in some shells and not others.
    pub fn at(cwd: impl Into<PathBuf>) -> DirState {
        DirState { pwd: Cwd::at(cwd), oldpwd: Cwd::Unknown, stack: Some(Vec::new()) }
    }

    pub fn unknown() -> DirState {
        DirState { pwd: Cwd::Unknown, oldpwd: Cwd::Unknown, stack: None }
    }

    pub fn union(&self, other: &DirState) -> DirState {
        let stack = match (&self.stack, &other.stack) {
            (Some(a), Some(b)) if a.len() == b.len() => {
                Some(a.iter().zip(b).map(|(x, y)| x.union(y)).collect())
            }
            _ => None,
        };
        DirState {
            pwd: self.pwd.union(&other.pwd),
            oldpwd: self.oldpwd.union(&other.oldpwd),
            stack,
        }
    }

    /// After a successful `cd` to `pwd`: the shell sets `OLDPWD` to where it was.
    fn moved_to(&self, pwd: Cwd) -> DirState {
        DirState { pwd, oldpwd: self.pwd.clone(), stack: self.stack.clone() }
    }
}

/// What the gate has learned, reading the source in order, about things `cd`
/// consults. Every flag is sticky: once set it stays set for the rest of the
/// source, which over-approximates and is the point.
#[derive(Clone, Debug, Default)]
pub struct DirContext {
    /// `HOME` may have been changed, so `cd` and `cd ~` go somewhere unknown.
    home_unknown: bool,
    /// `CDPATH` may have been set, so `cd name` may go anywhere.
    cdpath_unknown: bool,
    /// `OLDPWD` may have been set, so `cd -` may go anywhere.
    oldpwd_unknown: bool,
    /// `DIRSTACK` may have been changed, so `popd` may go anywhere.
    stack_unknown: bool,
    /// An alias, trap, `eval` or `source` has been seen: any later command may
    /// be a `cd`, or be preceded by one.
    untrusted: bool,
    /// Functions defined so far, and whether calling one may change directory.
    functions: Vec<(String, bool)>,
    /// Somewhere in this source the directory may change, so a function body
    /// (which runs wherever it is later called from) is judged as run anywhere.
    source_changes_dirs: bool,
}

/// Builtins that change the directory or the stack.
const DIR_BUILTINS: &[&str] = &["cd", "chdir", "pushd", "popd", "dirs"];

/// Builtins after which nothing about the directory can be known.
const UNTRUSTED: &[&str] = &["eval", "source", ".", "alias", "trap", "shopt", "enable"];

/// Builtins whose arguments name variables they set.
const ASSIGNS_BY_ARGUMENT: &[&str] = &[
    "export",
    "readonly",
    "declare",
    "typeset",
    "local",
    "unset",
    "read",
    "printf",
    "getopts",
    "mapfile",
    "readarray",
    "let",
];

impl DirContext {
    /// A context for a source the shell is about to read.
    ///
    /// The text scan catches what the syntax tree does not show as an
    /// assignment: `${CDPATH:=/}`, `(( HOME = 1 ))`. The rare names are flagged
    /// on any mention; `HOME` is read constantly, so only where it looks written.
    pub(crate) fn for_source(src: &str) -> DirContext {
        let mut c = DirContext::default();
        c.scan(src);
        c
    }

    /// A context for a child shell (`bash -c '...'`), which starts from what the
    /// parent knew — including functions, which `export -f` hands down.
    pub(crate) fn for_child(&self, src: &str) -> DirContext {
        let mut c = DirContext { source_changes_dirs: false, ..self.clone() };
        c.scan(src);
        c
    }

    fn scan(&mut self, src: &str) {
        self.cdpath_unknown |= src.contains("CDPATH");
        self.oldpwd_unknown |= src.contains("OLDPWD");
        self.stack_unknown |= src.contains("DIRSTACK");
        self.home_unknown |= src.match_indices("HOME").any(|(i, _)| {
            let rest = src[i + 4..].trim_start();
            rest.starts_with('=')
                || rest.starts_with(":=")
                || rest.starts_with("+=")
                || rest.starts_with('[')
        });
    }

    fn note_name(&mut self, name: &str) {
        match name {
            "HOME" => self.home_unknown = true,
            "CDPATH" => self.cdpath_unknown = true,
            "OLDPWD" => self.oldpwd_unknown = true,
            "DIRSTACK" => self.stack_unknown = true,
            _ => {}
        }
    }

    fn note_every_name(&mut self) {
        for n in ["HOME", "CDPATH", "OLDPWD", "DIRSTACK"] {
            self.note_name(n);
        }
    }

    pub(crate) fn note_loop_variable(&mut self, var: &str) {
        self.note_name(var);
    }

    pub(crate) fn untrusted(&self) -> bool {
        self.untrusted
    }

    pub(crate) fn source_changes_dirs(&self) -> bool {
        self.source_changes_dirs
    }

    pub(crate) fn set_source_changes_dirs(&mut self, v: bool) {
        self.source_changes_dirs = v;
    }

    pub(crate) fn define_function(&mut self, name: &str, changes_dirs: bool) {
        self.functions.push((name.to_string(), changes_dirs));
    }

    fn function(&self, name: &str) -> Option<bool> {
        self.functions.iter().rev().find(|(n, _)| n == name).map(|&(_, c)| c)
    }
}

/// A word's literal value, borrowed when it is a single literal run — which
/// almost every program name is — so asking costs no allocation.
fn text(w: &Word) -> Option<Cow<'_, str>> {
    match w.parts.as_slice() {
        [WordPart::Literal(s)] => Some(Cow::Borrowed(s)),
        _ => w.literal().map(Cow::Owned),
    }
}

/// Where the program word is once `builtin` and `command` are peeled off, and
/// whether `command` was one of them. `None` means the command only prints
/// (`command -v cd`) and runs nothing.
fn peel(words: &[Word]) -> Option<(usize, bool)> {
    let mut i = 0;
    let mut via_command = false;
    loop {
        match words.get(i).and_then(text).as_deref() {
            Some("builtin") => i += 1,
            Some("command") => {
                via_command = true;
                i += 1;
                while let Some(l) = words.get(i).and_then(text) {
                    if l == "--" {
                        i += 1;
                        break;
                    }
                    if !l.starts_with('-') || l.len() < 2 {
                        break;
                    }
                    if l.contains('v') || l.contains('V') {
                        return None;
                    }
                    i += 1;
                }
            }
            _ => return Some((i, via_command)),
        }
    }
}

/// How a `cd` reads `..`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The default: textually, against `$PWD`. The physical reading is added too
    /// when it is a different directory, since `set -P` may be in effect.
    Logical,
    /// `cd -P`, `chdir(2)`: against the real directory.
    Physical,
}

/// `cd`'s options and operands.
fn cd_operands(args: &[Word]) -> (Mode, &[Word]) {
    let mut mode = Mode::Logical;
    let mut i = 0;
    while let Some(l) = args.get(i).and_then(Word::literal) {
        if l == "--" {
            i += 1;
            break;
        }
        if l.len() < 2 || !l.starts_with('-') || !l[1..].chars().all(|c| "LPe@".contains(c)) {
            break;
        }
        if let Some(last) = l.rfind(['L', 'P']) {
            mode = if &l[last..=last] == "P" { Mode::Physical } else { Mode::Logical };
        }
        i += 1;
    }
    (mode, &args[i..])
}

/// A `cd` operand: its text, and whether it began with an unquoted `~`.
struct Target {
    text: String,
    tilde: bool,
}

impl Target {
    fn of(w: &Word) -> Option<Target> {
        Some(Target {
            text: w.literal()?,
            tilde: matches!(w.parts.first(), Some(WordPart::Tilde(_))),
        })
    }
    fn home() -> Target {
        Target { text: "~".into(), tilde: true }
    }
}

impl Collector<'_> {
    /// Where the shell may be after `s` runs, if it succeeds and if it fails.
    ///
    /// `entry` is where it was. Everything that is not a directory change
    /// returns it unchanged in both.
    pub(crate) fn dir_effect(&mut self, s: &Simple, entry: &DirState) -> (DirState, DirState) {
        for a in &s.assignments {
            self.dctx.note_name(&a.name);
        }
        let neutral = || (entry.clone(), entry.clone());
        let Some((start, via_command)) = peel(&s.words) else { return neutral() };
        let Some(word) = s.words.get(start) else { return neutral() };
        let Some(program) = text(word) else {
            // `$c /` with `c=cd` is a `cd`, and so is a glob that matches a file
            // named `cd`.
            return (DirState::unknown(), DirState::unknown());
        };
        let args = &s.words[start + 1..];

        if UNTRUSTED.contains(&&*program) {
            self.dctx.untrusted = true;
            return (DirState::unknown(), DirState::unknown());
        }
        // A function shadows the builtin it is named after.
        if let Some(changes) = self.dctx.function(&program) {
            return if changes { (DirState::unknown(), DirState::unknown()) } else { neutral() };
        }
        if ASSIGNS_BY_ARGUMENT.contains(&&*program) {
            for a in args {
                match a.literal() {
                    Some(l) => {
                        let name = l.split(['=', '[', '+']).next().unwrap_or("");
                        self.dctx.note_name(name);
                    }
                    None => self.dctx.note_every_name(),
                }
            }
            return neutral();
        }

        let ok = match &*program {
            "cd" | "chdir" => self.cd(args, entry),
            "pushd" => self.pushd(args, entry),
            "popd" => self.popd(args, entry),
            "dirs" => {
                let clears = args.iter().any(|a| a.literal().as_deref() == Some("-c"));
                if clears {
                    DirState { stack: Some(Vec::new()), ..entry.clone() }
                } else {
                    entry.clone()
                }
            }
            _ => return neutral(),
        };
        // `command cd` is the builtin in bash and dash, but an external program
        // in zsh, which moves nothing.
        let ok = if via_command { ok.union(entry) } else { ok };
        // A failed `cd` does not move.
        (ok, entry.clone())
    }

    /// Whether running `s` may change the directory or the stack.
    ///
    /// Must be true for everything `dir_effect` does not return unchanged: loops
    /// and function bodies rely on it to know when one pass is not the whole
    /// story.
    fn simple_may_change_dirs(&self, s: &Simple) -> bool {
        let Some((start, _)) = peel(&s.words) else { return false };
        let Some(word) = s.words.get(start) else { return false };
        let Some(program) = text(word) else { return true };
        UNTRUSTED.contains(&&*program)
            || DIR_BUILTINS.contains(&&*program)
            || self.dctx.function(&program).unwrap_or(false)
    }

    /// Whether running `node` may change the directory the shell is in.
    pub(crate) fn may_change_dirs(&self, node: &Node) -> bool {
        match node {
            Node::Empty | Node::Arith { .. } | Node::Cond { .. } => false,
            // A child shell's `cd` does not come back.
            Node::Subshell { .. } => false,
            Node::Simple(s) => self.simple_may_change_dirs(s),
            Node::Pipeline { commands, .. } => commands.iter().any(|c| self.may_change_dirs(c)),
            Node::List { items, .. } => items.iter().any(|it| self.may_change_dirs(&it.node)),
            Node::Group { body, .. } | Node::For { body, .. } => self.may_change_dirs(body),
            Node::Loop { cond, body, .. } => {
                self.may_change_dirs(cond) || self.may_change_dirs(body)
            }
            Node::If { cond, then, otherwise, .. } => {
                self.may_change_dirs(cond)
                    || self.may_change_dirs(then)
                    || otherwise.as_deref().is_some_and(|o| self.may_change_dirs(o))
            }
            Node::Case { arms, .. } => arms.iter().any(|a| self.may_change_dirs(&a.body)),
            // Defining a function moves nothing, but a call to one defined here
            // may, and the walk has no other way to see its body.
            Node::Function { body, .. } => self.may_change_dirs(body),
        }
    }

    fn cd(&mut self, args: &[Word], entry: &DirState) -> DirState {
        let (mode, operands) = cd_operands(args);
        let target = match operands {
            [] => self.target_dirs(&entry.pwd, &Target::home(), mode, true),
            [w] if w.literal().as_deref() == Some("-") => {
                if self.dctx.oldpwd_unknown {
                    Cwd::Unknown
                } else {
                    entry.oldpwd.clone()
                }
            }
            [w] => match Target::of(w) {
                Some(t) => self.target_dirs(&entry.pwd, &t, mode, true),
                None => Cwd::Unknown,
            },
            // bash ignores the extras; zsh reads `cd old new` as "replace old with
            // new in $PWD".
            _ => Cwd::Unknown,
        };
        entry.moved_to(target)
    }

    fn pushd(&mut self, args: &[Word], entry: &DirState) -> DirState {
        let first = args.first().and_then(Word::literal);
        let plain = match first.as_deref() {
            Some("--") => &args[1..],
            _ => args,
        };
        match plain {
            // `pushd` with no directory rotates the stack; `-n`, `+N`, `-N`
            // likewise. Not followed.
            [w] if !w.literal().is_some_and(|l| l.starts_with(['-', '+'])) => {
                let target = match Target::of(w) {
                    Some(t) => self.target_dirs(&entry.pwd, &t, Mode::Logical, true),
                    None => Cwd::Unknown,
                };
                let stack = if self.dctx.stack_unknown {
                    None
                } else {
                    entry.stack.clone().map(|mut s| {
                        s.push(entry.pwd.clone());
                        s
                    })
                };
                DirState { stack, ..entry.moved_to(target) }
            }
            _ => DirState::unknown(),
        }
    }

    fn popd(&mut self, args: &[Word], entry: &DirState) -> DirState {
        if !args.is_empty() || self.dctx.stack_unknown {
            return DirState::unknown();
        }
        match &entry.stack {
            Some(s) if !s.is_empty() => {
                let mut s = s.clone();
                let top = s.pop().unwrap_or_default();
                DirState { stack: Some(s), ..entry.moved_to(top) }
            }
            // An empty stack: `popd` fails, and nothing moves.
            Some(_) => entry.clone(),
            None => DirState::unknown(),
        }
    }

    /// Every directory `cd <target>` may lead to from anywhere in `from`.
    fn target_dirs(&mut self, from: &Cwd, t: &Target, mode: Mode, use_cdpath: bool) -> Cwd {
        let path = if t.tilde {
            let rest = &t.text[1..];
            let (user, tail) = rest.split_once('/').unwrap_or((rest, ""));
            if !user.is_empty() || self.dctx.home_unknown {
                return Cwd::Unknown;
            }
            match &self.cfg.home {
                Some(h) => h.join(tail),
                None => return Cwd::Unknown,
            }
        } else {
            PathBuf::from(&t.text)
        };
        if path.is_absolute() {
            return self.dirs_for(None, &path, mode);
        }

        let Some(bases) = from.known() else { return Cwd::Unknown };
        // POSIX: CDPATH is not searched for an operand starting with `.` or `..`.
        let searched = use_cdpath
            && !(t.text == "."
                || t.text == ".."
                || t.text.starts_with("./")
                || t.text.starts_with("../"));
        if searched && self.dctx.cdpath_unknown {
            return Cwd::Unknown;
        }
        let cdpath: Vec<PathBuf> = if searched { self.cfg.cdpath.clone() } else { Vec::new() };
        let mut out = Cwd::none();
        for base in bases.iter() {
            for entry in &cdpath {
                // An empty CDPATH entry means the current directory.
                let b = if entry.as_os_str().is_empty() { base.clone() } else { base.join(entry) };
                out = out.union(&self.dirs_for(Some(&b), &path, mode));
            }
            // Tried last, and tried even when CDPATH has no empty entry.
            out = out.union(&self.dirs_for(Some(base), &path, mode));
        }
        out
    }

    /// The directory `path` names from `base`, read the way `mode` says.
    fn dirs_for(&mut self, base: Option<&Path>, path: &Path, mode: Mode) -> Cwd {
        let physical = self.cache.physical(base, path);
        if mode == Mode::Physical {
            return Cwd::at(physical);
        }
        let logical = match base {
            Some(b) => lexical_normalize(&b.join(path)),
            None => lexical_normalize(path),
        };
        if self.cache.resolve_existing_ancestor(&logical) == physical {
            Cwd::at(logical)
        } else {
            // A symlink followed by `..`: `cd` and the kernel disagree about which
            // directory this is, and `set -P` decides which one `cd` means.
            Cwd::Known(Arc::from(vec![logical, physical]))
        }
    }

    /// The directory a wrapper's `chdir(2)` goes to: `env -C dir`, `sudo -D dir`.
    pub(crate) fn chdir_target(&mut self, from: &Cwd, text: &str) -> Cwd {
        let t = Target { text: text.to_string(), tilde: false };
        self.target_dirs(from, &t, Mode::Physical, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(ps: &[&str]) -> Cwd {
        Cwd::Known(Arc::from(ps.iter().map(PathBuf::from).collect::<Vec<_>>()))
    }

    #[test]
    fn union_is_a_set_and_unknown_absorbs() {
        let a = known(&["/a"]);
        let b = known(&["/b"]);
        assert_eq!(a.union(&b), known(&["/a", "/b"]));
        assert_eq!(a.union(&a), a);
        assert_eq!(a.union(&Cwd::Unknown), Cwd::Unknown);
        assert_eq!(Cwd::Unknown.union(&a), Cwd::Unknown);
        assert_eq!(Cwd::none().union(&a), a);
    }

    #[test]
    fn too_many_candidates_is_unknown() {
        let mut c = Cwd::at("/0");
        for i in 1..MAX_DIRS {
            c = c.union(&Cwd::at(format!("/{i}")));
        }
        assert!(matches!(c, Cwd::Known(_)));
        assert_eq!(c.union(&Cwd::at("/one-more")), Cwd::Unknown);
    }

    #[test]
    fn stacks_of_different_depth_do_not_union() {
        let a = DirState::at("/a");
        let mut b = DirState::at("/b");
        b.stack = Some(vec![Cwd::at("/x")]);
        assert_eq!(a.union(&b).stack, None);
        assert_eq!(a.union(&a).stack, Some(Vec::new()));
    }

    #[test]
    fn home_is_flagged_only_where_it_looks_written() {
        for (src, flagged) in [
            ("cd $HOME/x", false),
            ("echo \"${HOME}\"", false),
            ("echo ${HOME:-/}", false),
            ("HOME=/ cd", true),
            ("export HOME=/", true),
            (": ${HOME:=/}", true),
            (": ${HOME=/}", true),
            ("(( HOME = 1 ))", true),
            ("HOME+=x", true),
            ("HOME[0]=/", true),
        ] {
            assert_eq!(DirContext::for_source(src).home_unknown, flagged, "{src}");
        }
        assert!(DirContext::for_source(": ${CDPATH:=/}").cdpath_unknown);
        assert!(DirContext::for_source("echo $OLDPWD").oldpwd_unknown);
        assert!(!DirContext::for_source("cd /tmp").cdpath_unknown);
    }
}

#[cfg(all(test, unix))]
mod against_real_shells {
    //! The model, checked against the shells it models.
    //!
    //! Each script marks points with `P1`, `P2`... The gate is asked where the
    //! shell may be at each; then the script is run by every shell here, with
    //! each mark replaced by a line that records `pwd -P`. The property: every
    //! directory a shell really was in is one the gate considered, or the gate
    //! said it did not know. A shell that disagrees with the model is a failure
    //! with the script, the shell and the directory in the message.

    use super::*;
    use crate::config::GateConfig;
    use crate::normalize::{Cmd, Collector, Ctx};
    use crate::resolve::PathCache;
    use shellguard_parse::{parse, Limits};
    use std::collections::BTreeMap;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// `{WS}`, `{OUT}` and `{R}` are replaced by the fixture's paths.
    const SCRIPTS: &[&str] = &[
        "P1",
        "cd src && P1",
        "cd src; P1",
        "cd nonexistent 2>/dev/null || P1",
        "cd nonexistent 2>/dev/null; P1",
        "cd nonexistent 2>/dev/null && P1 || P2",
        "cd /; P1",
        "cd ..; P1",
        "cd ../out && P1",
        "cd . && P1",
        "cd ./src && P1",
        "cd '' 2>/dev/null; P1",
        "cd src/deep && cd ../.. && P1",
        "cd {OUT} && cd ../ws && P1",
        // Symlinks: `cd` is logical, the kernel physical.
        "cd link && P1",
        "cd link && cd .. && P1",
        "cd link/.. && P1",
        "cd -P link/.. && P1",
        "cd link; cd -P ..; P1",
        "set -P 2>/dev/null; cd link/.. && P1",
        "cd link/src 2>/dev/null && cd ../.. && P1",
        // HOME, OLDPWD.
        "cd; P1",
        "cd ~ && P1",
        "cd ~/.. && P1",
        "cd - >/dev/null 2>&1; P1",
        "cd src && cd - >/dev/null && P1",
        "cd src; cd /; cd - >/dev/null; P1",
        "OLDPWD=/; cd - >/dev/null 2>&1; P1",
        "HOME=/; cd; P1",
        "HOME=/ cd; P1",
        "declare \"HO\"ME=/ 2>/dev/null; cd; P1",
        "read HOME 2>/dev/null <<EOF\n/\nEOF\ncd; P1",
        // CDPATH.
        "export CDPATH={OUT}; cd src >/dev/null; P1",
        "CDPATH={OUT} cd src >/dev/null; P1",
        ": ${CDPATH:={OUT}}; cd src >/dev/null; P1",
        // Child shells, groups, substitutions, pipelines, jobs.
        "(cd /; P1); P2",
        "{ cd /; P1; }; P2",
        "x=$(cd /; P1); P2",
        "echo \"$(cd /)\" >/dev/null; P1",
        "echo | cd /; P1",
        "cd / | cat; P1",
        "cd / & wait; P1",
        "cd / && P1 &\nwait; P2",
        "cd src & P1; wait",
        "! cd /; P1",
        "! cd /nonexistent 2>/dev/null && P1",
        "time cd / 2>/dev/null; P1",
        "exec 3>&1; cd src; P1",
        // Lists.
        "true && cd src || cd /; P1",
        "false && cd src || cd /; P1",
        "cd src && false || P1",
        "cd /nonexistent 2>/dev/null || cd src && P1",
        "cd src\ncd deep\nP1",
        "cd src; (cd /); P1",
        "cd src && { cd deep; P1; }; P2",
        "cd src deep 2>/dev/null; P1",
        // Conditionals and loops.
        "if cd src; then P1; else P2; fi; P3",
        "if cd nonexistent 2>/dev/null; then P1; else P2; fi; P3",
        "if cd src; then cd /; fi; P1",
        // `&&` after the `if`, not `;`: `;` merges the two outcomes and would
        // hide which branch the success came from.
        "if cd nonexistent 2>/dev/null; then P1; fi && P2",
        "if cd nonexistent 2>/dev/null; then :; else cd src; fi && P1",
        "if cd src; then false; fi || P1",
        "while cd src; do P1; break; done; P2",
        "for d in src deep; do cd $d; P1; done; P2",
        "for d in a b; do P1; done",
        "until cd src; do :; done; P1",
        "case x in x) cd src;; esac; P1",
        "case x in y) cd /;; x) P1;; esac",
        // Functions, and things that cannot be followed.
        "f() { cd /; }; f; P1",
        "f() { P1; }; cd src; f",
        "cd() { :; }; cd /; P1",
        "cd() { builtin cd /; }; cd src; P1",
        "c=cd; $c /; P1",
        "alias go=cd\ngo /\nP1",
        "trap 'cd /' DEBUG 2>/dev/null\nP1",
        // A later `cd` to a known place does not make an alias or a trap go away.
        "alias go=cd\ncd {WS}/src && go / && P1",
        "trap 'cd /' DEBUG 2>/dev/null\ncd {WS}/src && P1",
        "eval 'cd /'; P1",
        // Builtins by another name, and the directory stack.
        "command cd /; P1",
        "command cd / && P1",
        "builtin cd / 2>/dev/null; P1",
        "command -v cd >/dev/null; P1",
        "pushd / >/dev/null 2>&1 && P1",
        "pushd {WS}/src >/dev/null 2>&1; popd >/dev/null 2>&1; P1",
        "pushd / >/dev/null 2>&1; pushd {OUT} >/dev/null 2>&1; popd >/dev/null 2>&1; P1",
        "popd >/dev/null 2>&1; P1",
        "dirs -c 2>/dev/null; pushd / >/dev/null 2>&1; popd >/dev/null 2>&1; P1",
        // Wrappers that change directory, and shells within shells.
        "env -C / sh -c 'P1'",
        "env -C src sh -c 'P1'",
        "sh -c 'cd /; P1'; P2",
        "sh -c 'cd / && P1'",
        "cd src && sh -c 'cd ..; P1'",
        r"find src -maxdepth 0 -execdir sh -c 'P1' \;",
    ];

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        /// One per test: tests run in parallel, and a shared fixture was deleted
        /// by whichever test finished first, under the others.
        fn new(name: &str) -> Fixture {
            let root =
                std::env::temp_dir().join(format!("shellguard-cwd-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let root = root.canonicalize().unwrap();
            for d in ["ws/src/deep", "out/src", "home", "log"] {
                std::fs::create_dir_all(root.join(d)).unwrap();
            }
            let _ = std::os::unix::fs::symlink(root.join("out"), root.join("ws/link"));
            Fixture { root }
        }
        fn ws(&self) -> PathBuf {
            self.root.join("ws")
        }
        fn fill(&self, script: &str) -> String {
            let r = self.root.display().to_string();
            script
                .replace("{WS}", &format!("{r}/ws"))
                .replace("{OUT}", &format!("{r}/out"))
                .replace("{R}", &r)
        }
        fn cfg(&self) -> GateConfig {
            GateConfig {
                workspace: self.ws(),
                cwd: self.ws(),
                home: Some(self.root.join("home")),
                ..Default::default()
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Mark numbers in a script, in order.
    fn marks(script: &str) -> Vec<u32> {
        let b = script.as_bytes();
        let mut out = Vec::new();
        for i in 0..b.len() {
            if b[i] == b'P' && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
                out.push((b[i + 1] - b'0') as u32);
            }
        }
        out
    }

    /// Where the gate thinks the shell may be at each mark.
    fn gate_view(fx: &Fixture, script: &str) -> BTreeMap<u32, Cwd> {
        let mut src = script.to_string();
        for n in marks(script) {
            src = src.replace(&format!("P{n}"), &format!("probe_mark_{n}"));
        }
        let cfg = fx.cfg();
        let ast = parse(&src).unwrap_or_else(|e| panic!("{script:?} does not parse: {e}"));
        let mut cache = PathCache::default();
        let mut c = Collector::new(&cfg, &mut cache, &src, Limits::default(), 4);
        let mut cmds: Vec<Cmd> = Vec::new();
        c.collect_root(&ast, Ctx::default(), &mut cmds);
        let mut out: BTreeMap<u32, Cwd> = BTreeMap::new();
        for cmd in &cmds {
            let Some(p) = cmd.program.as_deref() else { continue };
            if let Some(n) = p.strip_prefix("probe_mark_") {
                let n: u32 = n.parse().unwrap();
                let merged = match out.get(&n) {
                    Some(prev) => prev.union(&cmd.dirs),
                    None => cmd.dirs.clone(),
                };
                out.insert(n, merged);
            }
        }
        out
    }

    /// Where `shell` really was at each mark it reached, as `pwd -P` saw it.
    fn shell_view(fx: &Fixture, shell: &str, script: &str) -> Vec<(u32, PathBuf)> {
        let log = fx.root.join("log/marks");
        let _ = std::fs::remove_file(&log);
        let mut src = script.to_string();
        for n in marks(script) {
            src = src.replace(&format!("P{n}"), &format!("echo {n} \"$(pwd -P)\" >> \"$LOG\""));
        }
        let mut child = Command::new(shell)
            .arg("-c")
            .arg(&src)
            .current_dir(fx.ws())
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", fx.root.join("home"))
            .env("LOG", &log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("{shell}: {e}"));
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if start.elapsed() < Duration::from_secs(10) => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{shell} did not finish {script:?}");
                }
            }
        }
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        text.lines()
            .filter_map(|l| l.split_once(' '))
            .map(|(n, d)| (n.parse().unwrap(), PathBuf::from(d)))
            .collect()
    }

    /// With `CDPATH` in the environment, `cd src` goes to `$CDPATH/src` before
    /// `./src`. The gate reads it from its configuration.
    #[test]
    fn cdpath_from_the_environment_is_followed() {
        let fx = Fixture::new("exact");
        let script = "cd src >/dev/null && P1";
        let cfg = GateConfig { cdpath: vec![fx.root.join("out")], ..fx.cfg() };
        let src = script.replace("P1", "probe_mark_1");
        let ast = parse(&src).unwrap();
        let mut cache = PathCache::default();
        let mut c = Collector::new(&cfg, &mut cache, &src, Limits::default(), 4);
        let mut cmds: Vec<Cmd> = Vec::new();
        c.collect_root(&ast, Ctx::default(), &mut cmds);
        let dirs = cmds
            .iter()
            .find(|c| c.program.as_deref() == Some("probe_mark_1"))
            .map(|c| c.dirs.clone())
            .unwrap();
        let want = Cwd::Known(Arc::from(vec![fx.root.join("out/src"), fx.root.join("ws/src")]));
        assert_eq!(dirs, want);

        // And the shell agrees that it can be the first of those.
        let log = fx.root.join("log/marks");
        let _ = std::fs::remove_file(&log);
        let st = Command::new("/bin/sh")
            .arg("-c")
            .arg(script.replace("P1", "pwd -P > \"$LOG\""))
            .current_dir(fx.ws())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("CDPATH", fx.root.join("out"))
            .env("LOG", &log)
            .status()
            .unwrap();
        assert!(st.success());
        let actual = PathBuf::from(std::fs::read_to_string(&log).unwrap().trim());
        assert_eq!(actual, fx.root.join("out/src"));
    }

    /// After `cd link`, and in `link/../x`, `..` is the parent of where the link
    /// *points*, which is how the kernel resolves it and how the gate must.
    #[test]
    fn a_dotdot_through_a_symlink_is_resolved_where_the_kernel_resolves_it() {
        let fx = Fixture::new("cdpath");
        std::fs::write(fx.root.join("victim"), "precious").unwrap();
        // The kernel's view, first: both of these name a file outside ws.
        assert_eq!(std::fs::read_to_string(fx.ws().join("link/../victim")).unwrap(), "precious");

        let cfg = fx.cfg();
        for src in
            ["rm -rf link/../victim", "cd link && rm -rf ../victim", "rm -rf link/../out/../victim"]
        {
            let ast = parse(src).unwrap();
            let mut cache = PathCache::default();
            let mut c = Collector::new(&cfg, &mut cache, src, Limits::default(), 4);
            let mut cmds: Vec<Cmd> = Vec::new();
            c.collect_root(&ast, Ctx::default(), &mut cmds);
            let rm = cmds.iter().find(|c| c.program.as_deref() == Some("rm")).unwrap();
            let target = rm.args.last().unwrap();
            assert!(target.outside_workspace, "{src}: judged inside the workspace: {target:?}");
        }
        // And a `..` that stays inside stays inside.
        for src in ["rm -rf src/../src", "cd src && rm -rf ../src/deep", "rm -rf src/deep/.."] {
            let ast = parse(src).unwrap();
            let mut cache = PathCache::default();
            let mut c = Collector::new(&cfg, &mut cache, src, Limits::default(), 4);
            let mut cmds: Vec<Cmd> = Vec::new();
            c.collect_root(&ast, Ctx::default(), &mut cmds);
            let rm = cmds.iter().find(|c| c.program.as_deref() == Some("rm")).unwrap();
            assert!(!rm.args.last().unwrap().outside_workspace, "{src}: judged outside");
        }
    }

    fn shells() -> Vec<&'static str> {
        ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/usr/bin/dash"]
            .into_iter()
            .filter(|s| Path::new(s).exists())
            .collect()
    }

    /// Soundness allows answering "anywhere" to everything. This pins the
    /// answer for what agents actually write, so a change that makes the model
    /// lazier — and turns `cd src && rm -rf build` into a question — fails here.
    #[test]
    fn common_constructs_get_exactly_the_directories_they_can_reach() {
        let fx = Fixture::new("symlink");
        let r = fx.root.clone();
        let at = |names: &[&str]| -> Cwd {
            Cwd::Known(Arc::from(names.iter().map(|n| r.join(n)).collect::<Vec<_>>()))
        };
        let cases: &[(&str, u32, Option<&[&str]>)] = &[
            ("P1", 1, Some(&["ws"])),
            ("cd src && P1", 1, Some(&["ws/src"])),
            ("cd src || P1", 1, Some(&["ws"])),
            ("cd src; P1", 1, Some(&["ws/src", "ws"])),
            ("cd src && cd deep && P1", 1, Some(&["ws/src/deep"])),
            ("cd src/deep && cd ../.. && P1", 1, Some(&["ws"])),
            ("(cd /); P1", 1, Some(&["ws"])),
            ("x=$(cd /); P1", 1, Some(&["ws"])),
            ("{ cd src; }; P1", 1, Some(&["ws/src", "ws"])),
            ("cd / & P1", 1, Some(&["ws"])),
            ("if cd src; then P1; else P2; fi", 1, Some(&["ws/src"])),
            ("if cd src; then P1; else P2; fi", 2, Some(&["ws"])),
            ("if cd nowhere; then :; else cd src; fi && P1", 1, Some(&["ws/nowhere", "ws/src"])),
            ("cd src && cd - && P1", 1, Some(&["ws"])),
            ("pushd src && popd && P1", 1, Some(&["ws"])),
            ("pushd src && P1", 1, Some(&["ws/src"])),
            ("cd link && P1", 1, Some(&["ws/link"])),
            ("cd ../out && P1", 1, Some(&["out"])),
            // `cd` and the kernel disagree about `link/..`; both are kept.
            ("cd link/.. && P1", 1, Some(&["ws", ""])),
            ("cd -P link/.. && P1", 1, Some(&[""])),
            ("cd && P1", 1, Some(&["home"])),
            ("for d in a b; do P1; done", 1, Some(&["ws"])),
            ("f() { :; }; f; P1", 1, Some(&["ws"])),
            ("cd() { :; }; cd /; P1", 1, Some(&["ws"])),
            ("env -C src sh -c 'P1'", 1, Some(&["ws/src"])),
            // Not followed, by design.
            ("cd $X && P1", 1, None),
            ("f() { cd /; }; f; P1", 1, None),
            ("for d in a b; do cd $d; done; P1", 1, None),
            ("alias go=cd; P1", 1, None),
            ("eval x; P1", 1, None),
            ("c=cd; $c /; P1", 1, None),
            // OLDPWD is not known at the start: `cd -` may fail and stay, or go
            // anywhere, so after the `;` it is anywhere.
            ("cd -; P1", 1, None),
        ];
        let mut wrong = Vec::new();
        for (script, n, want) in cases {
            let view = gate_view(&fx, script);
            let got = view.get(n).cloned().unwrap_or_default();
            let want = match want {
                Some(names) => at(names),
                None => Cwd::Unknown,
            };
            if got != want {
                wrong.push(format!("  {script:?} P{n}: got {got:?}, want {want:?}"));
            }
        }
        assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
    }

    #[test]
    fn every_directory_a_real_shell_was_in_is_one_the_gate_considered() {
        let fx = Fixture::new("shells");
        let shells = shells();
        assert!(!shells.is_empty(), "no shell to test against");

        let mut wrong = Vec::new();
        let mut reached = 0usize;
        let mut known = 0usize;
        let mut never_reached = Vec::new();

        for raw in SCRIPTS {
            let script = fx.fill(raw);
            let view = gate_view(&fx, &script);
            for n in marks(&script) {
                assert!(view.contains_key(&n), "{raw:?}: the gate never saw P{n}");
            }
            let mut any = false;
            for shell in &shells {
                for (n, actual) in shell_view(&fx, shell, &script) {
                    any = true;
                    reached += 1;
                    match &view[&n] {
                        Cwd::Unknown => {}
                        Cwd::Known(dirs) => {
                            known += 1;
                            let considered: Vec<PathBuf> =
                                dirs.iter().filter_map(|d| d.canonicalize().ok()).collect();
                            if !considered.contains(&actual) {
                                wrong.push(format!(
                                    "  {raw:?} under {shell}: P{n} ran in {} but the gate considered only {:?}",
                                    actual.display(),
                                    dirs
                                ));
                            }
                        }
                    }
                }
            }
            if !any {
                never_reached.push(*raw);
            }
        }

        assert!(
            wrong.is_empty(),
            "{} marks ran somewhere the gate did not consider:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
        // A script whose marks no shell reached tests nothing.
        assert!(never_reached.is_empty(), "no shell reached a mark in: {never_reached:?}");
        // Unknown is always sound, so a model that said it for everything would
        // pass the check above. Most marks must have been placed.
        assert!(
            known * 10 >= reached * 7,
            "only {known} of {reached} marks had a known set of directories"
        );
        eprintln!("{reached} marks reached across {} shells; {known} placed", shells.len());
    }
}
