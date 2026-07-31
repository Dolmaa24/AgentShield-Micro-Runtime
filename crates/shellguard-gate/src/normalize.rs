//! Turning a syntax tree into the facts rules ask about.
//!
//! This is the only place that both understands syntax and touches the
//! filesystem. Everything upstream is pure parsing; everything downstream is
//! pure matching. Concentrating the impure part here is what makes the ruleset
//! testable without a fixture directory, and it keeps every syscall the
//! decision path makes in one file where the caching can be reasoned about.

use shellguard_parse::{
    basename, parse_with_limits, Limits, Node, Opacity, RedirTarget, Simple, Span, Taint, Word,
    WordPart,
};

use crate::config::GateConfig;
use crate::resolve::{looks_like_path, PathCache};
use crate::unwrap::{unwrap_wrapper, Unwrapped};

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
}

impl<'a> Collector<'a> {
    pub fn collect(&mut self, node: &Node, ctx: Ctx, out: &mut Vec<Cmd>) {
        match node {
            Node::Empty | Node::Arith { .. } => {}

            Node::Simple(s) => {
                let cmd = self.simple_to_cmd(s, ctx);
                out.push(cmd);
                self.collect_unwrapped(s, ctx, out);
                // Substitutions inside words are commands in their own right.
                for w in &s.words {
                    self.collect_word_subs(w, ctx, out);
                }
                for a in &s.assignments {
                    self.collect_word_subs(&a.value, ctx, out);
                }
                for r in &s.redirects {
                    if let RedirTarget::Word(w) = &r.target {
                        self.collect_word_subs(w, ctx, out);
                    }
                }
            }

            Node::Pipeline { commands, .. } => {
                let inner = Ctx { nested: ctx.nested, ..ctx };
                let mut stages: Vec<(usize, usize)> = Vec::with_capacity(commands.len());
                for c in commands {
                    let start = out.len();
                    self.collect(c, inner, out);
                    stages.push((start, out.len()));
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
                for it in items {
                    self.collect(&it.node, ctx, out);
                }
            }

            Node::Subshell { body, redirects, .. } | Node::Group { body, redirects, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                self.collect(body, inner, out);
                for r in redirects {
                    if let RedirTarget::Word(w) = &r.target {
                        self.collect_word_subs(w, inner, out);
                    }
                }
            }

            Node::If { cond, then, otherwise, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                self.collect(cond, inner, out);
                self.collect(then, inner, out);
                if let Some(o) = otherwise {
                    self.collect(o, inner, out);
                }
            }

            Node::For { words, body, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                for w in words {
                    self.collect_word_subs(w, inner, out);
                }
                self.collect(body, inner, out);
            }

            Node::Loop { cond, body, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                self.collect(cond, inner, out);
                self.collect(body, inner, out);
            }

            Node::Case { word, arms, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                self.collect_word_subs(word, inner, out);
                for arm in arms {
                    for p in &arm.patterns {
                        self.collect_word_subs(p, inner, out);
                    }
                    self.collect(&arm.body, inner, out);
                }
            }

            Node::Function { body, .. } => {
                // A function body is judged where it is defined. Deferring to
                // the call site would mean never judging it, since the call may
                // be in a later command the gate never sees as one unit.
                self.collect(body, Ctx { nested: true, ..ctx }, out);
            }

            Node::Cond { words, .. } => {
                let inner = Ctx { nested: true, ..ctx };
                for w in words {
                    self.collect_word_subs(w, inner, out);
                }
            }
        }
    }

    /// Recover and judge whatever a wrapper is hiding.
    ///
    /// Recursion is bounded and the bound is reported, because `sudo env nice
    /// timeout 5 sh -c '...'` is a real shape and so is a chain built purely to
    /// exhaust the limit.
    fn collect_unwrapped(&mut self, s: &Simple, ctx: Ctx, out: &mut Vec<Cmd>) {
        let unwrapped = unwrap_wrapper(s);
        if unwrapped.is_empty() {
            return;
        }
        if ctx.wrap_depth >= self.max_unwrap_depth {
            self.unwrap_truncated = true;
            return;
        }
        let inner = Ctx { nested: ctx.nested, wrap_depth: ctx.wrap_depth + 1 };

        for u in unwrapped {
            let via = u.via();
            match u {
                Unwrapped::Argv { words, .. } => {
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
                    out.push(cmd);
                    self.collect_unwrapped(&synthetic, inner, out);
                    for w in &synthetic.words {
                        self.collect_word_subs(w, inner, out);
                    }
                }
                Unwrapped::ShellText { text, span, .. } => {
                    let Ok(ast) = parse_with_limits(&text, self.limits) else {
                        // A payload that does not parse is one that was not
                        // judged. Silence here would be the whole bypass.
                        self.unwrap_truncated = true;
                        continue;
                    };
                    let mut sub = Collector {
                        cfg: self.cfg,
                        cache: &mut *self.cache,
                        src: &text,
                        span_override: Some(self.span_override.unwrap_or(span)),
                        limits: self.limits,
                        max_unwrap_depth: self.max_unwrap_depth,
                        unwrap_truncated: false,
                    };
                    let start = out.len();
                    sub.collect(&ast, inner, out);
                    let truncated = sub.unwrap_truncated;
                    self.unwrap_truncated |= truncated;
                    for c in &mut out[start..] {
                        c.synthetic = true;
                        c.via.get_or_insert(via);
                    }
                }
            }
        }
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

        if let Some(name) = s.program() {
            cmd.program = Some(basename(&name).to_string());
            if let Some(p) = self.cache.resolve_exec(&name, self.cfg) {
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

        for w in s.args() {
            let arg = self.word_to_arg(w);
            if let Some(lit) = &arg.literal {
                if is_short_flag_bundle(lit) {
                    cmd.short_flags.push_str(&lit[1..]);
                } else if cmd.subcommand.is_none() && !lit.starts_with('-') {
                    cmd.subcommand = Some(lit.clone());
                }
            }
            cmd.args.push(arg);
        }

        for r in &s.redirects {
            if !r.op.writes() {
                continue;
            }
            cmd.has_write_redirect = true;
            cmd.has_truncating_redirect |= r.op.truncates();
            if let RedirTarget::Word(w) = &r.target {
                let t = self.word_to_arg(w);
                if t.outside_workspace {
                    cmd.write_redirect_outside = true;
                }
                cmd.write_targets.push(t);
            }
        }

        cmd
    }

    pub fn word_to_arg(&mut self, w: &Word) -> Arg {
        let literal = w.literal();
        let prefix = w.literal_prefix();
        let taint = w.taint();

        let probe = literal.as_deref().unwrap_or(&prefix);
        let is_path = looks_like_path(probe);

        let mut arg = Arg {
            prefix,
            taint,
            looks_like_path: is_path,
            literal: literal.clone(),
            ..Default::default()
        };

        match (&literal, is_path) {
            (Some(lit), true) => {
                let class = self.cache.classify(lit, self.cfg);
                arg.absolute = class.absolute;
                arg.outside_workspace = class.outside;
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
                // enough to place it.
                let class = self.cache.classify(&arg.prefix, self.cfg);
                arg.absolute = class.absolute;
                arg.outside_workspace = class.outside;
            }
            _ => {}
        }

        arg
    }
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
        let mut c = Collector {
            cfg,
            cache: &mut cache,
            src,
            span_override: None,
            limits: Limits::default(),
            max_unwrap_depth: 4,
            unwrap_truncated: false,
        };
        let mut out = Vec::new();
        c.collect(&ast, Ctx::default(), &mut out);
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
    fn subcommand_is_the_first_non_flag() {
        let cmds = collect_all("git -c x=y reset --hard", &cfg());
        // `-c` is a short-flag bundle, `x=y` is the first non-flag literal.
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
