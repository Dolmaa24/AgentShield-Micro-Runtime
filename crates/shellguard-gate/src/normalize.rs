//! Turning a syntax tree into the facts rules ask about.
//!
//! This is the only place that both understands syntax and touches the
//! filesystem. Everything upstream is pure parsing; everything downstream is
//! pure matching. Concentrating the impure part here is what makes the ruleset
//! testable without a fixture directory, and it keeps every syscall the
//! decision path makes in one file where the caching can be reasoned about.

use shellguard_parse::{
    basename, parse_with_limits, Limits, ListOp, Node, Opacity, RedirTarget, Simple, Span, Taint,
    Word, WordPart,
};

use std::path::PathBuf;

use crate::config::GateConfig;
use crate::cwd::{Cwd, DirContext, DirState};
use crate::resolve::{looks_like_path, PathCache};
use crate::unwrap::{unwrap_wrapper, Chdir, Unwrapped};

/// One argument, resolved.
#[derive(Clone, Debug, Default)]
pub struct Arg {
    pub literal: Option<String>,
    pub prefix: String,
    pub taint: Taint,
    pub looks_like_path: bool,
    pub absolute: bool,
    pub outside_workspace: bool,
    /// Names a path, but taint made it impossible to say where it points.
    pub unresolved_path: bool,
    /// Where it really is, from each directory the shell may be in. Only worked
    /// out for write destinations.
    pub resolved: Vec<String>,
}

/// One command, resolved and normalised.
#[derive(Clone, Debug, Default)]
pub struct Cmd {
    /// Basename of the program, after resolution.
    pub program: Option<String>,
    /// Absolute path the program resolved to, if it resolved at all.
    pub resolved: Option<String>,
    pub args: Vec<Arg>,
    pub write_targets: Vec<Arg>,
    /// Paths the program writes because its arguments name them. See
    /// [`crate::writes`].
    pub writes: Vec<Arg>,
    pub assignments: Vec<String>,
    pub short_flags: String,
    pub subcommand: Option<String>,
    pub arg_taint: Taint,
    pub opacity: Opacity,
    pub has_write_redirect: bool,
    pub has_truncating_redirect: bool,
    pub write_redirect_outside: bool,
    pub upstream: Vec<String>,
    pub downstream: Vec<String>,
    pub span: Span,
    pub text: String,
    pub nested: bool,
    pub wrap_depth: u8,
    /// Recovered by unwrapping a wrapper, so it does not appear as written.
    pub synthetic: bool,
    /// Which wrapper it was recovered from — `find -exec`, `sh -c`, `sudo`.
    /// Without this a report says "denied: rm" about a command whose text
    /// contains no `rm`, and the reader has to reverse-engineer why.
    pub via: Option<&'static str>,
    /// This command exists to run another one (`timeout 5 ls`, `sudo`, `find
    /// -exec`, `bash -c`), and the command it runs was collected separately.
    ///
    /// Such a node is judged through what it wraps, so it is not asked "did a
    /// rule speak for you?" — `timeout` alone matching nothing says nothing about
    /// `timeout 5 rm -rf /`, and a default verdict on the wrapper would make every
    /// wrapped `ls` a `confine`.
    pub wrapper: bool,
    /// The directories this command may run in, which relative paths in it were
    /// resolved against. See [`crate::cwd`].
    pub dirs: Cwd,
}

impl Cmd {
    /// Whether this command causes something to run.
    ///
    /// A bare `FOO=bar` executes nothing. A command whose program cannot be
    /// named (`$CMD args`) does execute something — it just cannot be known
    /// which — and must not be mistaken for the harmless case.
    pub fn executes(&self) -> bool {
        self.program.is_some() || self.opacity != Opacity::Transparent
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Ctx {
    pub nested: bool,
    pub wrap_depth: u8,
}

pub struct Collector<'a> {
    pub cfg: &'a GateConfig,
    pub cache: &'a mut PathCache,
    pub src: &'a str,
    /// When set, collected commands report this span instead of their own.
    ///
    /// Commands recovered from inside a `bash -c '...'` string have spans that
    /// index into that string. Reported against the original command text they
    /// would point at nonsense, so they are all attributed to the `-c` payload
    /// that produced them. The excerpt still comes from the inner source, so a
    /// finding reads as the command it is about.
    pub span_override: Option<Span>,
    pub limits: Limits,
    pub max_unwrap_depth: u8,
    /// Set when a wrapper chain was deeper than the limit, or a recovered shell
    /// payload failed to parse. Either way something was not judged, and the
    /// caller needs to know rather than see a clean verdict.
    pub unwrap_truncated: bool,
    /// Where the shell may be standing. On entry to [`collect`](Self::collect),
    /// where the node starts; on return, where it may be if the node succeeded.
    pub dirs: DirState,
    /// On return from [`collect`](Self::collect): where the shell may be if the
    /// node failed. `&&`, `||` and `if` choose between the two.
    pub dirs_if_failed: DirState,
    /// What has been learned so far about things `cd` consults.
    pub dctx: DirContext,
    /// Whether every directory in `dirs.pwd` is inside the workspace, for the
    /// `pwd` it was worked out for. Asked once per command, and almost always
    /// about the same set.
    pwd_inside: Option<(Cwd, bool)>,
}

impl<'a> Collector<'a> {
    /// A collector for `src`, standing where the configuration says the shell is.
    pub fn new(
        cfg: &'a GateConfig,
        cache: &'a mut PathCache,
        src: &'a str,
        limits: Limits,
        max_unwrap_depth: u8,
    ) -> Self {
        let (start, inside) = cache.start(cfg);
        let dirs = DirState { pwd: Cwd::Known(start), ..DirState::unknown() };
        let dirs = DirState { stack: Some(Vec::new()), ..dirs };
        Collector {
            cfg,
            cache,
            src,
            span_override: None,
            limits,
            max_unwrap_depth,
            unwrap_truncated: false,
            dirs_if_failed: dirs.clone(),
            pwd_inside: Some((dirs.pwd.clone(), inside)),
            dirs,
            dctx: DirContext::for_source(src),
        }
    }

    /// Collect a whole source: the entry point, where [`collect`](Self::collect)
    /// is for its parts.
    pub fn collect_root(&mut self, node: &Node, ctx: Ctx, out: &mut Vec<Cmd>) {
        let changes = self.may_change_dirs(node);
        self.dctx.set_source_changes_dirs(changes);
        self.collect(node, ctx, out);
    }

    /// Record that `node` leaves the directory as it found it, whatever its status.
    fn unchanged(&mut self, entry: DirState) {
        self.dirs_if_failed = entry.clone();
        self.dirs = entry;
    }

    /// Collect `node` starting from `entry`, and return where it leaves the
    /// shell: (if it succeeded, if it failed).
    fn collect_from(
        &mut self,
        node: &Node,
        entry: DirState,
        ctx: Ctx,
        out: &mut Vec<Cmd>,
    ) -> (DirState, DirState) {
        self.dirs = entry;
        self.collect(node, ctx, out);
        (self.dirs.clone(), self.dirs_if_failed.clone())
    }

    /// Collect the substitutions inside `w`. They run in child shells, before
    /// the command they belong to, so whatever they `cd` to does not last.
    fn collect_subs_in_place(&mut self, w: &Word, ctx: Ctx, out: &mut Vec<Cmd>) {
        let has_subs = w
            .parts
            .iter()
            .any(|p| matches!(p, WordPart::CommandSub { .. } | WordPart::ProcSub { .. }));
        if !has_subs {
            return;
        }
        let entry = self.dirs.clone();
        self.collect_word_subs(w, ctx, out);
        self.dirs = entry;
    }

    pub fn collect(&mut self, node: &Node, ctx: Ctx, out: &mut Vec<Cmd>) {
        match node {
            Node::Empty | Node::Arith { .. } => {
                let entry = self.dirs.clone();
                self.unchanged(entry);
            }

            Node::Simple(s) => {
                // After an alias or a trap, any command may be a `cd` or be
                // preceded by one.
                if self.dctx.untrusted() {
                    self.dirs = DirState::unknown();
                }
                let entry = self.dirs.clone();
                let cmd = self.simple_to_cmd(s, ctx);
                let at = out.len();
                out.push(cmd);
                out[at].wrapper = self.collect_unwrapped(s, ctx, out);
                // Substitutions inside words are commands in their own right.
                for w in &s.words {
                    self.collect_subs_in_place(w, ctx, out);
                }
                for a in &s.assignments {
                    self.collect_subs_in_place(&a.value, ctx, out);
                }
                for r in &s.redirects {
                    if let RedirTarget::Word(w) = &r.target {
                        self.collect_subs_in_place(w, ctx, out);
                    }
                }
                let (ok, failed) = self.dir_effect(s, &entry);
                self.dirs = ok;
                self.dirs_if_failed = failed;
            }

            Node::Pipeline { commands, negated, .. } => {
                let inner = Ctx { nested: ctx.nested, ..ctx };
                let entry = self.dirs.clone();
                let mut last = (entry.clone(), entry.clone());
                let mut stages: Vec<(usize, usize)> = Vec::with_capacity(commands.len());
                for c in commands {
                    let start = out.len();
                    last = self.collect_from(c, entry.clone(), inner, out);
                    stages.push((start, out.len()));
                }
                if commands.len() == 1 {
                    // `! cmd`: the same shell, the status inverted.
                    let (ok, failed) = last;
                    let (ok, failed) = if *negated { (failed, ok) } else { (ok, failed) };
                    self.dirs = ok;
                    self.dirs_if_failed = failed;
                } else {
                    // Every stage but the last runs in a child shell. The last
                    // does in bash and dash and does not in zsh, and with
                    // `pipefail` either outcome can go with either status.
                    let merged = entry.union(&last.0).union(&last.1);
                    self.unchanged(merged);
                }
                // Link adjacent stages by their head command. `curl x | sh`
                // must be visible as "curl feeds sh" from both sides, because a
                // rule can reasonably be written from either end.
                for pair in stages.windows(2) {
                    let (a_start, a_end) = pair[0];
                    let (b_start, b_end) = pair[1];
                    if a_start >= a_end || b_start >= b_end {
                        continue;
                    }
                    let producer = out[a_start].program.clone();
                    let consumer = out[b_start].program.clone();
                    if let Some(p) = consumer {
                        out[a_start].downstream.push(p);
                    }
                    if let Some(p) = producer {
                        out[b_start].upstream.push(p);
                    }
                }
            }

            Node::List { items, .. } => {
                // `a && b` runs `b` only where `a` succeeded, `a || b` only where
                // it failed, `a; b` in either; `a & b` runs `a` in a child shell.
                // `chain_entry` is where the current and-or chain began, and
                // `chain_passed` every state the chain has been through.
                let mut chain_entry = self.dirs.clone();
                let mut state = (chain_entry.clone(), chain_entry.clone());
                let mut chain_passed = chain_entry.clone();
                let mut chain_len = 0usize;
                let mut prev: Option<ListOp> = None;
                for it in items {
                    let input = match prev {
                        Some(ListOp::And) => state.0.clone(),
                        Some(ListOp::Or) => state.1.clone(),
                        _ => chain_entry.clone(),
                    };
                    let (ok, failed) = self.collect_from(&it.node, input, ctx, out);
                    chain_passed = chain_passed.union(&ok).union(&failed);
                    chain_len += 1;
                    state = match prev {
                        // Skipped when an earlier link failed, so failure also
                        // leaves the shell where that link did.
                        Some(ListOp::And) => (ok, state.1.union(&failed)),
                        Some(ListOp::Or) => (state.0.union(&ok), failed),
                        _ => (ok, failed),
                    };
                    match it.op {
                        ListOp::Seq => chain_entry = state.0.union(&state.1),
                        ListOp::Background => {
                            // A lone `cd / &` moves nothing, in every shell. But
                            // zsh 5.9 runs the first command of `cd / && x &` in
                            // this shell and only the rest in the background —
                            // found by the real-shell test — so a longer chain may
                            // leave this shell anywhere it went.
                            // The parser keeps `a && b` as one item holding an
                            // inner list, so "lone" means one item that is not one.
                            let lone = chain_len == 1 && !matches!(it.node, Node::List { .. });
                            let after =
                                if lone { chain_entry.clone() } else { chain_passed.clone() };
                            state = (after.clone(), after.clone());
                            chain_entry = after;
                        }
                        ListOp::And | ListOp::Or => {}
                    }
                    if matches!(it.op, ListOp::Seq | ListOp::Background) {
                        chain_passed = chain_entry.clone();
                        chain_len = 0;
                    }
                    prev = Some(it.op);
                }
                self.dirs = state.0;
                self.dirs_if_failed = state.1;
            }

            Node::Subshell { body, redirects, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                let entry = self.dirs.clone();
                for r in redirects {
                    if let RedirTarget::Word(w) = &r.target {
                        self.collect_subs_in_place(w, inner, out);
                    }
                }
                self.collect(body, inner, out);
                // Whatever the child shell did, the parent is where it was.
                self.unchanged(entry);
            }

            Node::Group { body, redirects, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                for r in redirects {
                    if let RedirTarget::Word(w) = &r.target {
                        self.collect_subs_in_place(w, inner, out);
                    }
                }
                // `{ ...; }` runs in this shell, so its `cd` lasts.
                self.collect(body, inner, out);
            }

            Node::If { cond, then, otherwise, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                let entry = self.dirs.clone();
                let (c_ok, c_failed) = self.collect_from(cond, entry, inner, out);
                let (t_ok, t_failed) = self.collect_from(then, c_ok, inner, out);
                let (e_ok, e_failed) = match otherwise {
                    Some(o) => self.collect_from(o, c_failed, inner, out),
                    // No `else`: a false condition is a successful `if`.
                    None => (c_failed.clone(), t_failed.clone()),
                };
                self.dirs = t_ok.union(&e_ok);
                self.dirs_if_failed = t_failed.union(&e_failed);
            }

            Node::For { var, words, body, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                for w in words {
                    self.collect_subs_in_place(w, inner, out);
                }
                self.dctx.note_loop_variable(var);
                self.collect_loop(&[body], inner, out);
            }

            Node::Loop { cond, body, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                self.collect_loop(&[cond, body], inner, out);
            }

            Node::Case { word, arms, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                self.collect_subs_in_place(word, inner, out);
                let entry = self.dirs.clone();
                // An arm can fall through into the next (`;&`), which the tree
                // does not record, so each arm may start where any earlier one
                // ended. No arm matching is a success where the shell already was.
                let mut reach = entry.clone();
                let mut failed_any: Option<DirState> = None;
                for arm in arms {
                    for p in &arm.patterns {
                        self.collect_subs_in_place(p, inner, out);
                    }
                    let (ok, failed) = self.collect_from(&arm.body, reach.clone(), inner, out);
                    reach = reach.union(&ok).union(&failed);
                    failed_any = Some(match failed_any {
                        Some(f) => f.union(&failed),
                        None => failed,
                    });
                }
                self.dirs = reach;
                self.dirs_if_failed = failed_any.unwrap_or(entry);
            }

            Node::Function { name, body, .. } => {
                // A function body is judged where it is defined. Deferring to
                // the call site would mean never judging it, since the call may
                // be in a later command the gate never sees as one unit.
                //
                // It runs wherever it is later called from, so if anything in this
                // source can change directory, it is judged as run anywhere.
                let changes = self.may_change_dirs(body);
                let entry = self.dirs.clone();
                let body_entry = if self.dctx.source_changes_dirs() {
                    DirState::unknown()
                } else {
                    entry.clone()
                };
                self.collect_from(body, body_entry, Ctx { nested: true, ..ctx }, out);
                self.dctx.define_function(name, changes);
                // Defining a function runs nothing.
                self.unchanged(entry);
            }

            Node::Cond { words, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                for w in words {
                    self.collect_subs_in_place(w, inner, out);
                }
                let entry = self.dirs.clone();
                self.unchanged(entry);
            }
        }
    }

    /// A `for` or `while` loop: `parts` run in order, repeatedly.
    ///
    /// If nothing in it can change directory, one pass describes every pass. If
    /// something can, the second pass starts where the first ended, and so on,
    /// so the loop is judged — and left — as anywhere. Collecting twice to be
    /// more precise would double the work for every nested loop.
    fn collect_loop(&mut self, parts: &[&Node], ctx: Ctx, out: &mut Vec<Cmd>) {
        let entry = self.dirs.clone();
        let moves = parts.iter().any(|p| self.may_change_dirs(p));
        let start = if moves { DirState::unknown() } else { entry.clone() };
        for p in parts {
            self.collect_from(p, start.clone(), ctx, out);
        }
        self.unchanged(if moves { DirState::unknown() } else { entry });
    }

    /// Recover and judge whatever a wrapper is hiding.
    ///
    /// Recursion is bounded and the bound is reported, because `sudo env nice
    /// timeout 5 sh -c '...'` is a real shape and so is a chain built purely to
    /// exhaust the limit.
    ///
    /// Returns whether `s` is a wrapper at all, so the caller can mark it.
    fn collect_unwrapped(&mut self, s: &Simple, ctx: Ctx, out: &mut Vec<Cmd>) -> bool {
        let unwrapped = unwrap_wrapper(s);
        if unwrapped.is_empty() {
            return false;
        }
        if ctx.wrap_depth >= self.max_unwrap_depth {
            self.unwrap_truncated = true;
            return true;
        }
        let inner = Ctx { nested: ctx.nested, wrap_depth: ctx.wrap_depth + 1 };

        for u in unwrapped {
            let via = u.via();
            let entry = self.dirs.clone();
            match u {
                Unwrapped::Argv { words, chdir, .. } => {
                    // `env -C dir cmd` runs `cmd` in `dir`, and only `cmd`.
                    match chdir {
                        Chdir::Stay => {}
                        Chdir::To(dir) => {
                            let pwd = self.chdir_target(&entry.pwd, &dir);
                            self.dirs = DirState { pwd, ..entry.clone() };
                        }
                        Chdir::Unknown => {
                            self.dirs = DirState { pwd: Cwd::Unknown, ..entry.clone() }
                        }
                    }
                    let span =
                        words.iter().map(|w| w.span).reduce(|a, b| a.to(b)).unwrap_or(s.span);
                    let synthetic = Simple {
                        assignments: Vec::new(),
                        words: words.to_vec(),
                        redirects: Vec::new(),
                        span,
                    };
                    let mut cmd = self.simple_to_cmd(&synthetic, inner);
                    cmd.synthetic = true;
                    cmd.via = Some(via);
                    let at = out.len();
                    out.push(cmd);
                    out[at].wrapper = self.collect_unwrapped(&synthetic, inner, out);
                    for w in &synthetic.words {
                        self.collect_subs_in_place(w, inner, out);
                    }
                    // The wrapped program is a child process: nothing it does to
                    // its directory reaches this shell.
                    self.dirs = entry;
                }
                Unwrapped::ShellText { text, span, .. } => {
                    let Ok(ast) = parse_with_limits(&text, self.limits) else {
                        // A payload that does not parse is one that was not
                        // judged. Silence here would be the whole bypass.
                        self.unwrap_truncated = true;
                        continue;
                    };
                    let mut sub = Collector {
                        span_override: Some(self.span_override.unwrap_or(span)),
                        dirs: entry.clone(),
                        dirs_if_failed: entry.clone(),
                        dctx: self.dctx.for_child(&text),
                        ..Collector::new(
                            self.cfg,
                            &mut *self.cache,
                            &text,
                            self.limits,
                            self.max_unwrap_depth,
                        )
                    };
                    let start = out.len();
                    // A child shell: it starts where this one is, and its `cd`
                    // does not come back.
                    sub.collect_root(&ast, inner, out);
                    let truncated = sub.unwrap_truncated;
                    self.unwrap_truncated |= truncated;
                    for c in &mut out[start..] {
                        c.synthetic = true;
                        c.via.get_or_insert(via);
                    }
                }
            }
        }
        true
    }

    fn collect_word_subs(&mut self, w: &Word, ctx: Ctx, out: &mut Vec<Cmd>) {
        let inner = Ctx { nested: true, ..ctx };
        for part in &w.parts {
            match part {
                WordPart::CommandSub { node, .. } | WordPart::ProcSub { node, .. } => {
                    self.collect(node, inner, out)
                }
                _ => {}
            }
        }
    }

    pub fn simple_to_cmd(&mut self, s: &Simple, ctx: Ctx) -> Cmd {
        let mut cmd = Cmd {
            nested: ctx.nested,
            wrap_depth: ctx.wrap_depth,
            opacity: s.opacity(),
            arg_taint: s.arg_taint(),
            ..Default::default()
        };

        cmd.span = self.span_override.unwrap_or(s.span);
        cmd.text = s.span.slice(self.src).to_string();
        cmd.dirs = self.dirs.pwd.clone();

        if let Some(name) = s.program() {
            cmd.program = Some(basename(&name).to_string());
            // A relative program path is found from where the shell is; with
            // more than one candidate, the most recent `cd` target is the guess.
            // Only the name's identity rides on it — rules see the basename
            // either way.
            let here = self.dirs.pwd.known().and_then(|d| d.first()).map(PathBuf::as_path);
            if let Some(p) = self.cache.resolve_exec_in(&name, here, self.cfg) {
                // Resolution can change the basename: `python` is very often a
                // symlink to `python3`, and a rule naming one should see the
                // other. The resolved name wins where they differ.
                if let Some(b) = p.file_name().and_then(|f| f.to_str()) {
                    cmd.program = Some(b.to_string());
                }
                cmd.resolved = Some(p.to_string_lossy().into_owned());
            }
        }

        for a in &s.assignments {
            cmd.assignments.push(a.name.clone());
        }

        let bare_names_are_paths = !self.pwd_is_inside();
        let globals = global_value_options(cmd.program.as_deref().unwrap_or(""));
        let mut is_value = false;
        for w in s.args() {
            let arg = self.word_to_arg(w, bare_names_are_paths);
            if is_value {
                // The value of a global option — the `dir` in `git -C dir` — is
                // neither the subcommand nor a flag.
                is_value = false;
            } else if let Some(lit) = &arg.literal {
                if cmd.subcommand.is_none() && globals.contains(&lit.as_str()) {
                    is_value = true;
                } else if is_short_flag_bundle(lit) {
                    cmd.short_flags.push_str(&lit[1..]);
                } else if cmd.subcommand.is_none() && !lit.starts_with('-') {
                    cmd.subcommand = Some(lit.clone());
                }
            }
            cmd.args.push(arg);
        }

        for d in crate::writes::destinations(cmd.program.as_deref().unwrap_or(""), &cmd.args) {
            let w = self.write_destination(&d, &cmd.args);
            cmd.writes.push(w);
        }

        for r in &s.redirects {
            if !r.op.writes() {
                continue;
            }
            cmd.has_write_redirect = true;
            cmd.has_truncating_redirect |= r.op.truncates();
            if let RedirTarget::Word(w) = &r.target {
                let t = self.word_to_arg(w, bare_names_are_paths);
                if t.outside_workspace {
                    cmd.write_redirect_outside = true;
                }
                cmd.write_targets.push(t);
            }
        }

        cmd
    }

    /// A program's write destination, placed. Always classified as a path,
    /// whatever it looks like: `cp x build` writes `build`, a bare name.
    fn write_destination(&mut self, d: &crate::writes::Dest, args: &[Arg]) -> Arg {
        use crate::writes::Dest;
        let text = match d {
            Dest::Arg(i) => match &args[*i].literal {
                Some(l) => l.clone(),
                // `cp x "$OUT"`: where it goes is not known, and is not guessed.
                None => return args[*i].clone(),
            },
            Dest::Text(t) => t.clone(),
            Dest::Here => ".".to_string(),
        };
        let placed = self.classify_here(&text);
        let resolved = self.resolve_here(&text);
        Arg {
            prefix: text.clone(),
            literal: Some(text),
            looks_like_path: true,
            absolute: placed.absolute,
            outside_workspace: placed.outside,
            unresolved_path: placed.unresolved,
            resolved,
            ..Default::default()
        }
    }

    /// `raw` as an absolute path spelled the way the shell would name it, from
    /// each directory the shell may be in: joined and `..`-collapsed, symlinks
    /// left alone. What `cd / && tar -x` needs — `.` from `/` is `/` — without
    /// following `/home` on macOS into `/System/Volumes/Data/home`, which is the
    /// writable data volume and not the system.
    fn resolve_here(&mut self, raw: &str) -> Vec<String> {
        let expanded = match (raw.strip_prefix('~'), &self.cfg.home) {
            (Some(""), Some(h)) => h.clone(),
            (Some(rest), Some(h)) if rest.starts_with('/') => h.join(&rest[1..]),
            _ => PathBuf::from(raw),
        };
        let mut out: Vec<String> = Vec::new();
        let mut add = |p: PathBuf| {
            let s = crate::resolve::lexical_normalize(&p).to_string_lossy().into_owned();
            if !out.contains(&s) {
                out.push(s);
            }
        };
        if expanded.is_absolute() {
            add(expanded);
        } else if let Cwd::Known(dirs) = &self.dirs.pwd {
            for d in dirs.iter() {
                add(d.join(&expanded));
            }
        }
        out
    }

    /// Whether every directory the shell may be in is inside the workspace.
    fn pwd_is_inside(&mut self) -> bool {
        if let Some((pwd, inside)) = &self.pwd_inside {
            if pwd.same(&self.dirs.pwd) {
                return *inside;
            }
        }
        let inside = match &self.dirs.pwd {
            Cwd::Unknown => false,
            Cwd::Known(dirs) => {
                dirs.iter().all(|d| !self.cache.classify_in(".", d, self.cfg).outside)
            }
        };
        self.pwd_inside = Some((self.dirs.pwd.clone(), inside));
        inside
    }

    /// Where a path argument points, from every directory the shell may be in.
    fn classify_here(&mut self, raw: &str) -> Placed {
        let rooted = raw.starts_with('/') || raw.starts_with('~');
        match &self.dirs.pwd {
            Cwd::Known(dirs) => {
                let mut placed = Placed::default();
                for d in dirs.iter() {
                    let c = self.cache.classify_in(raw, d, self.cfg);
                    placed.absolute = c.absolute;
                    placed.outside |= c.outside;
                    if rooted {
                        break;
                    }
                }
                placed
            }
            Cwd::Unknown if rooted => {
                let cwd = self.cfg.cwd.clone();
                let c = self.cache.classify_in(raw, &cwd, self.cfg);
                Placed { absolute: c.absolute, outside: c.outside, unresolved: false }
            }
            // Relative to somewhere unknown: the same answer `$DIR/x` gets.
            Cwd::Unknown => Placed { absolute: false, outside: false, unresolved: true },
        }
    }

    /// `bare_names_are_paths`: the shell may be outside the workspace, so a name
    /// with no `/` in it — `build`, `*` — is a path somewhere that matters.
    /// Inside the workspace it cannot point out of it, and is not worth a lookup.
    pub fn word_to_arg(&mut self, w: &Word, bare_names_are_paths: bool) -> Arg {
        let literal = w.literal();
        let prefix = w.literal_prefix();
        let taint = w.taint();

        let probe = literal.as_deref().unwrap_or(&prefix);
        let is_path = looks_like_path(probe)
            || (bare_names_are_paths && !probe.starts_with('-') && taint < Taint::Variable);

        let mut arg = Arg {
            prefix,
            taint,
            looks_like_path: is_path,
            literal: literal.clone(),
            ..Default::default()
        };

        match (&literal, is_path) {
            (Some(lit), true) => {
                let placed = self.classify_here(lit);
                arg.absolute = placed.absolute;
                arg.outside_workspace = placed.outside;
                arg.unresolved_path = placed.unresolved;
            }
            (None, _) if taint >= Taint::Variable => {
                // A tainted argument that looks like a path, or that could
                // become one, is reported as unresolved rather than guessed at.
                // Treating `$TARGET` as inside the workspace because its
                // literal prefix is empty would be the most dangerous possible
                // default.
                arg.looks_like_path = is_path || arg.prefix.is_empty();
                arg.unresolved_path = arg.looks_like_path;
            }
            (None, true) => {
                // Static but glob-expanded, e.g. `build/*`. The prefix is
                // enough to place it; a bare `*` is the directory itself.
                let at = if arg.prefix.is_empty() { "." } else { arg.prefix.as_str() };
                let placed = self.classify_here(at);
                arg.absolute = placed.absolute;
                arg.outside_workspace = placed.outside;
                arg.unresolved_path = placed.unresolved;
            }
            _ => {}
        }

        arg
    }
}

/// Options a program takes before its subcommand that consume the next word.
///
/// Without this the subcommand is the option's *value*: `git -C dir reset
/// --hard` had the subcommand `dir`, so every rule about `reset`, `clean`,
/// `push --force` or `config core.pager` looked straight past it — and so did
/// `git -c x=y`. Only programs whose rules key on a subcommand need an entry,
/// and only options that take a separate word; `--opt=value` is one word.
fn global_value_options(program: &str) -> &'static [&'static str] {
    match program {
        "git" => &[
            "-C",
            "-c",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--super-prefix",
            "--config-env",
            "--attr-source",
        ],
        "npm" => &["--prefix", "-w", "--workspace"],
        "yarn" => &["--cwd"],
        "pnpm" => &["-C", "--dir", "-F", "--filter"],
        "go" => &["-C"],
        "cargo" => &["-C", "-Z", "--config", "--color"],
        _ => &[],
    }
}

/// Where a path argument lands, from the directories the shell may be in.
#[derive(Clone, Copy, Debug, Default)]
struct Placed {
    absolute: bool,
    /// Outside the workspace from at least one of them.
    outside: bool,
    /// Relative to a directory that is not known.
    unresolved: bool,
}

/// `-rf` is a bundle of short flags; `--force` and `-` are not.
fn is_short_flag_bundle(s: &str) -> bool {
    s.len() >= 2
        && s.starts_with('-')
        && !s.starts_with("--")
        && s[1..].bytes().all(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellguard_parse::parse;
    use std::path::PathBuf;

    fn collect_all(src: &str, cfg: &GateConfig) -> Vec<Cmd> {
        let ast = parse(src).unwrap();
        let mut cache = PathCache::default();
        let mut c = Collector::new(cfg, &mut cache, src, Limits::default(), 4);
        let mut out = Vec::new();
        c.collect_root(&ast, Ctx::default(), &mut out);
        out
    }

    fn cfg() -> GateConfig {
        GateConfig {
            workspace: PathBuf::from("/ws"),
            cwd: PathBuf::from("/ws"),
            home: Some(PathBuf::from("/home/agent")),
            ..Default::default()
        }
    }

    #[test]
    fn short_flag_bundles_are_decomposed() {
        let cmds = collect_all("rm -rf build", &cfg());
        assert_eq!(cmds[0].short_flags, "rf");
        assert_eq!(cmds[0].subcommand.as_deref(), Some("build"));
    }

    #[test]
    fn long_flags_are_not_short_flags() {
        let cmds = collect_all("rm --recursive --force build", &cfg());
        assert_eq!(cmds[0].short_flags, "");
    }

    #[test]
    fn a_global_option_s_value_is_not_the_subcommand() {
        for (src, sub) in [
            ("git -C /elsewhere reset --hard", "reset"),
            ("git -c core.pager=less log", "log"),
            ("git --git-dir .git --work-tree . clean -fdx", "clean"),
            ("git --config-env core.pager=P log", "log"),
            ("git --git-dir=.git status", "status"),
            ("npm --prefix /opt install x", "install"),
            ("go -C sub build", "build"),
        ] {
            let cmds = collect_all(src, &cfg());
            assert_eq!(cmds[0].subcommand.as_deref(), Some(sub), "{src}");
        }
        // `-C` before the subcommand is git's directory, not `branch -C`.
        let cmds = collect_all("git -C sub branch -a", &cfg());
        assert_eq!(cmds[0].short_flags, "a");
        // After the subcommand, the same word is the subcommand's own flag.
        let cmds = collect_all("git branch -C a b", &cfg());
        assert_eq!(cmds[0].short_flags, "C");
    }

    #[test]
    fn subcommand_is_the_first_non_flag() {
        // This used to assert `x=y` — the value of git's `-c` — as the
        // subcommand, which is how `git -c x=y reset --hard` slipped past every
        // rule about `reset`. For a program with no known global options the
        // first non-flag literal is still the subcommand.
        let cmds = collect_all("git -c x=y reset --hard", &cfg());
        assert_eq!(cmds[0].subcommand.as_deref(), Some("reset"));
        let cmds = collect_all("tool -c x=y reset", &cfg());
        assert_eq!(cmds[0].subcommand.as_deref(), Some("x=y"));
        let cmds = collect_all("git reset --hard", &cfg());
        assert_eq!(cmds[0].subcommand.as_deref(), Some("reset"));
    }

    #[test]
    fn paths_are_classified_against_the_workspace() {
        let cmds = collect_all("rm -rf /etc/passwd", &cfg());
        assert!(cmds[0].args[1].outside_workspace);
        assert!(cmds[0].args[1].absolute);

        let cmds = collect_all("rm -rf ./src", &cfg());
        assert!(!cmds[0].args[1].outside_workspace);
    }

    #[test]
    fn a_tainted_path_is_unresolved_not_assumed_safe() {
        let cmds = collect_all("rm -rf $TARGET", &cfg());
        let arg = &cmds[0].args[1];
        assert!(arg.unresolved_path, "a tainted target must not be assumed inside the workspace");
        assert!(!arg.outside_workspace);
        assert_eq!(arg.taint, Taint::Variable);
    }

    #[test]
    fn redirect_targets_are_write_targets_not_arguments() {
        let cmds = collect_all("echo hi > /etc/hosts", &cfg());
        let c = &cmds[0];
        assert!(c.has_write_redirect);
        assert!(c.write_redirect_outside);
        assert_eq!(c.write_targets.len(), 1);
        // The path must not appear in argv; `echo` never sees it.
        assert!(c.args.iter().all(|a| a.literal.as_deref() != Some("/etc/hosts")));
    }

    #[test]
    fn reads_are_not_write_targets() {
        let cmds = collect_all("cat < /etc/hosts", &cfg());
        assert!(!cmds[0].has_write_redirect);
        assert!(cmds[0].write_targets.is_empty());
    }

    #[test]
    fn pipeline_neighbours_are_linked_both_ways() {
        let cmds = collect_all("curl http://x | sh", &cfg());
        assert_eq!(cmds[0].downstream, vec!["sh".to_string()]);
        assert_eq!(cmds[1].upstream, vec!["curl".to_string()]);
    }

    #[test]
    fn substitutions_are_collected_and_marked_nested() {
        let cmds = collect_all("echo $(rm -rf /)", &cfg());
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[1].program.as_deref(), Some("rm"));
        assert!(cmds[1].nested);
        assert!(!cmds[0].nested);
    }

    #[test]
    fn commands_in_branches_and_loops_are_collected() {
        let cmds = collect_all("if x; then rm -rf /; fi", &cfg());
        assert!(cmds.iter().any(|c| c.program.as_deref() == Some("rm")));
        let cmds = collect_all("for f in a; do rm $f; done", &cfg());
        assert!(cmds.iter().any(|c| c.program.as_deref() == Some("rm")));
    }

    #[test]
    fn function_bodies_are_judged_at_definition() {
        let cmds = collect_all("cleanup() { rm -rf /; }", &cfg());
        assert!(cmds.iter().any(|c| c.program.as_deref() == Some("rm")));
    }

    #[test]
    fn assignments_are_recorded_by_name() {
        let cmds = collect_all("LD_PRELOAD=/tmp/x.so ls", &cfg());
        assert_eq!(cmds[0].assignments, vec!["LD_PRELOAD".to_string()]);
        assert_eq!(cmds[0].program.as_deref(), Some("ls"));
    }

    #[test]
    fn excerpt_text_comes_from_the_original_source() {
        let cmds = collect_all("echo one && rm -rf two", &cfg());
        assert_eq!(cmds[1].text.trim(), "rm -rf two");
    }

    #[test]
    fn opacity_is_carried_through() {
        let cmds = collect_all("$CMD -rf /", &cfg());
        assert_eq!(cmds[0].opacity, Opacity::Indirect);
        let cmds = collect_all("$(get) -rf /", &cfg());
        assert_eq!(cmds[0].opacity, Opacity::Opaque);
    }
}
