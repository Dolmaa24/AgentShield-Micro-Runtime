//! What a policy says, and what it says it about.

use shellguard_parse::{Opacity, Taint};

/// What the gate should do with a command.
///
/// Ordered by severity, so combining verdicts is a maximum. A command that
/// matches one `Allow` rule and one `Deny` rule is denied; there is no rule
/// precedence to reason about and no way for an over-broad allow to
/// accidentally outrank a specific deny. Policies that need an exception carve
/// it out with a predicate on the deny rule, where it is visible.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub enum Verdict {
    /// Run it directly. Reserved for commands with no interesting effects.
    #[default]
    Allow,
    /// Run it, but only inside the sandbox with the profile the rule implies.
    /// This is the expected verdict for most real work.
    Confine,
    /// Stop and put it to a human.
    Ask,
    /// Refuse.
    Deny,
}

impl Verdict {
    pub fn join(self, other: Verdict) -> Verdict {
        if self >= other {
            self
        } else {
            other
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Confine => "confine",
            Verdict::Ask => "ask",
            Verdict::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<Verdict> {
        Some(match s {
            "allow" => Verdict::Allow,
            "confine" => Verdict::Confine,
            "ask" => Verdict::Ask,
            "deny" => Verdict::Deny,
            _ => return None,
        })
    }
}

/// A class of effect a command is asking for.
///
/// Capabilities are what the decision is *reported* in terms of, and what the
/// enforcement layer is configured from: a command granted only `FsRead` gets a
/// sandbox profile with no write paths at all. Without them the gate can say
/// "denied by rule 47" but cannot answer "what would this have done", which is
/// the question a human reviewing an escalation actually has.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Capability {
    FsRead,
    FsWrite,
    FsDelete,
    NetConnect,
    NetListen,
    ProcSpawn,
    ProcSignal,
    /// `sudo`, `su`, `doas`, setuid manipulation.
    PrivEsc,
    /// Writing to a block or character device.
    DeviceWrite,
    KernelModule,
    /// The command runs shell text computed at runtime.
    ShellEscape,
    /// Package managers execute arbitrary install hooks by design.
    PackageInstall,
    /// Operations that destroy version-control history.
    VcsHistoryRewrite,
    /// Reads of credential material.
    CredentialAccess,
    /// Attempts to reach outside a container or sandbox.
    SandboxEscape,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::FsRead => "fs.read",
            Capability::FsWrite => "fs.write",
            Capability::FsDelete => "fs.delete",
            Capability::NetConnect => "net.connect",
            Capability::NetListen => "net.listen",
            Capability::ProcSpawn => "proc.spawn",
            Capability::ProcSignal => "proc.signal",
            Capability::PrivEsc => "priv.esc",
            Capability::DeviceWrite => "device.write",
            Capability::KernelModule => "kernel.module",
            Capability::ShellEscape => "shell.escape",
            Capability::PackageInstall => "pkg.install",
            Capability::VcsHistoryRewrite => "vcs.rewrite",
            Capability::CredentialAccess => "cred.access",
            Capability::SandboxEscape => "sandbox.escape",
        }
    }

    pub fn parse(s: &str) -> Option<Capability> {
        Some(match s {
            "fs.read" => Capability::FsRead,
            "fs.write" => Capability::FsWrite,
            "fs.delete" => Capability::FsDelete,
            "net.connect" => Capability::NetConnect,
            "net.listen" => Capability::NetListen,
            "proc.spawn" => Capability::ProcSpawn,
            "proc.signal" => Capability::ProcSignal,
            "priv.esc" => Capability::PrivEsc,
            "device.write" => Capability::DeviceWrite,
            "kernel.module" => Capability::KernelModule,
            "shell.escape" => Capability::ShellEscape,
            "pkg.install" => Capability::PackageInstall,
            "vcs.rewrite" => Capability::VcsHistoryRewrite,
            "cred.access" => Capability::CredentialAccess,
            "sandbox.escape" => Capability::SandboxEscape,
            _ => return None,
        })
    }
}

/// One argument, reduced to the properties rules ask about.
///
/// The gate fills this in; the policy layer never touches the filesystem or the
/// syntax tree itself. Keeping that split means rule evaluation is pure and
/// therefore trivially testable, and it keeps the expensive work (path
/// resolution) in one place where it can be cached.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArgFacts<'a> {
    /// The full value, if the argument is fully literal.
    pub literal: Option<&'a str>,
    /// The leading literal run, which exists even when `literal` does not.
    pub prefix: &'a str,
    pub taint: Taint,
    pub looks_like_path: bool,
    pub absolute: bool,
    /// The argument resolves to somewhere outside the declared workspace.
    /// `false` when the argument is too tainted to resolve — see
    /// `unresolved_path`, which is the honest signal for that case.
    pub outside_workspace: bool,
    /// The argument names a path but taint prevented resolving it.
    pub unresolved_path: bool,
}

impl<'a> ArgFacts<'a> {
    /// The best available text for substring matching.
    pub fn text(&self) -> &'a str {
        self.literal.unwrap_or(self.prefix)
    }

    /// The argument is certainly a flag: it begins with `-` and is not the bare
    /// `-` that means standard input. Decided from the leading literal run, so
    /// `--sort=$X` is a flag even though its value is not known.
    fn is_flag(&self) -> bool {
        match self.literal {
            Some(l) => l.starts_with('-') && l != "-",
            None => self.prefix.starts_with('-'),
        }
    }

    /// The argument starts with something the shell expands (`$X`, `*`, `$(...)`),
    /// so nothing is known about its first character and it may become a flag —
    /// `git branch --list $X` with `X=-D` is a deletion.
    fn may_become_a_flag(&self) -> bool {
        self.literal.is_none() && self.prefix.is_empty()
    }

    /// Whether this argument is acceptable to `flags-within`.
    fn flag_is_within(&self, allowed: &[String]) -> bool {
        if self.may_become_a_flag() {
            return false;
        }
        if !self.is_flag() {
            // A positional argument. Whether one is welcome is `no-positional`'s
            // question, not this predicate's.
            return true;
        }
        let text = self.text();
        if let Some(long) = text.strip_prefix("--") {
            // `--name` or `--name=value`. Without an `=` a tainted argument's name
            // may continue past what is known (`--$X`), so it is refused. The
            // bare `--` (end of options) has an empty name and is refused too.
            let name = match long.split_once('=') {
                Some((name, _)) => name,
                None if self.literal.is_some() => long,
                None => return false,
            };
            !name.is_empty() && allowed.iter().any(|a| a.strip_prefix("--") == Some(name))
        } else {
            // A bundle of short flags: every one must be allowed. `text` starts
            // with the one-byte `-`, so slicing at 1 is on a boundary.
            let bundle = &text[1..];
            self.literal.is_some()
                && !bundle.is_empty()
                && bundle.chars().all(|c| allowed.iter().any(|a| short_flag_entry(a) == Some(c)))
        }
    }
}

/// The character of a `-x` entry in a `flags-within` list, if it is one.
fn short_flag_entry(entry: &str) -> Option<char> {
    let mut cs = entry.chars();
    match (cs.next(), cs.next(), cs.next()) {
        (Some('-'), Some(c), None) if c != '-' => Some(c),
        _ => None,
    }
}

/// A command, reduced to the properties rules ask about.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommandFacts<'a> {
    /// Basename of the resolved program.
    pub program: Option<&'a str>,
    /// Absolute path the program resolved to, when it could be resolved.
    pub program_path: Option<&'a str>,
    /// First non-flag argument: the `reset` in `git reset --hard`.
    pub subcommand: Option<&'a str>,
    pub args: &'a [ArgFacts<'a>],
    /// Paths the shell itself will create or truncate on this command's behalf.
    ///
    /// Kept apart from `args` because they are not arguments — `cmd > /etc/x`
    /// writes `/etc/x` without `cmd` ever seeing the name. A ruleset that only
    /// inspects argv is blind to exactly this, so redirection targets get their
    /// own facts and their own predicates rather than being quietly folded in.
    pub write_targets: &'a [ArgFacts<'a>],
    /// Names of `NAME=value` assignments attached to the command.
    pub assignments: &'a [&'a str],
    /// Short flags with bundles decomposed, so `-rf` contributes `r` and `f`.
    pub short_flags: &'a str,
    pub arg_taint: Taint,
    pub opacity: Opacity,
    pub has_write_redirect: bool,
    /// At least one redirection *truncates* rather than appends.
    ///
    /// Worth distinguishing: `> file` destroys what was there and `>> file`
    /// does not, and a rule that denies both under a reason that says
    /// "truncates" is lying to whoever reads the refusal.
    pub has_truncating_redirect: bool,
    pub write_redirect_outside_workspace: bool,
    /// Programs this command's output feeds.
    pub downstream: &'a [&'a str],
    /// Programs feeding this command's input.
    pub upstream: &'a [&'a str],
    /// The command's own source text.
    pub text: &'a str,
    /// The command sits inside `$(...)`, a loop, a branch or a function body.
    pub nested: bool,
    /// How many wrapper layers were unwrapped to reach it (`sudo env timeout`).
    pub wrap_depth: u8,
}

/// A predicate over a command. Predicates within a rule are conjoined; a list
/// of values inside one predicate is a disjunction.
///
/// The two-level structure is the whole ergonomics story: `arg-prefix -rf -fr`
/// reads as "any of these", and stacking directives reads as "and". Rules that
/// need real boolean structure use `Any`/`Not`, but almost none do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pred {
    /// Always true. For rules selected purely by program.
    Always,
    /// Some argument is exactly one of these.
    ArgEq(Vec<String>),
    /// Some argument's literal prefix begins with one of these.
    ArgPrefix(Vec<String>),
    /// Some argument contains one of these.
    ArgContains(Vec<String>),
    /// Some argument contains one of these, ignoring ASCII case.
    ///
    /// For names the program itself reads without regard to case: git config
    /// keys are case-insensitive, so `git config CORE.PAGER x` sets `core.pager`,
    /// and a case-sensitive rule about `core.pager` never sees it. Values are
    /// compared lowercased; write them in lower case.
    ArgContainsNoCase(Vec<String>),
    /// Some argument ends with one of these.
    ArgSuffix(Vec<String>),
    /// The command text contains one of these. Indexed by the prefilter.
    TextContains(Vec<String>),
    /// One of these short flags is set, bundles included.
    ShortFlag(Vec<char>),
    /// The first non-flag argument is one of these.
    Subcommand(Vec<String>),
    /// The argument at this index (0 = first argument) is one of these.
    ArgAt(usize, Vec<String>),
    /// The final argument is one of these. Most commands put their operand
    /// last, which is the difference between `kill -1 4242` (a signal number)
    /// and `kill -9 -1` (every process the user owns).
    ArgLast(Vec<String>),
    TaintAtLeast(Taint),
    OpacityAtLeast(Opacity),
    /// The command has a redirection that creates or truncates a file.
    WriteRedirect,
    /// At least one redirection truncates an existing file.
    TruncatingRedirect,
    /// A write redirection targets somewhere outside the workspace.
    WriteRedirectOutside,
    /// Some write-redirection target begins with one of these.
    WriteTargetPrefix(Vec<String>),
    /// The command carries an assignment with one of these names.
    Assigns(Vec<String>),
    /// Some path argument resolves outside the workspace.
    PathOutsideWorkspace,
    /// Some path argument could not be resolved because it is tainted.
    UnresolvedPath,
    /// Some argument is an absolute path.
    AbsolutePathArg,
    /// Output feeds one of these programs.
    PipesInto(Vec<String>),
    /// Input comes from one of these programs.
    PipedFrom(Vec<String>),
    /// The command was reached by unwrapping at least this many wrappers.
    WrapDepthAtLeast(u8),
    /// No argument is positional except the subcommand itself: everything given
    /// is a flag. `git branch -a` has none; `git branch feature` has one. Only
    /// meaningful alongside `subcommand`, which is what it makes room for.
    ///
    /// An argument that starts with an expansion counts as positional, because
    /// nothing is known about it — the conservative reading for a predicate whose
    /// job is to say "there is nothing here that could name a target".
    NoPositional,
    /// Every argument that is, or could become, a flag is one of these.
    ///
    /// Entries are `--name` (matches `--name` and `--name=value`) or `-x` (a
    /// single short flag, matched inside bundles: `-vv` needs `-v`). It is an
    /// *allowlist*, which is the point: `git branch` has a dozen flags that
    /// delete, move, copy or overwrite, and git accepts unambiguous prefixes of
    /// long options (`--del` deletes), so a list of what is bad is a list of what
    /// was thought of. A flag not named here, an abbreviation, the `--`
    /// terminator, and any argument that begins with an expansion all fail it.
    FlagsWithin(Vec<String>),
    Not(Box<Pred>),
    Any(Vec<Pred>),
}

impl Pred {
    pub fn matches(&self, f: &CommandFacts<'_>) -> bool {
        match self {
            Pred::Always => true,
            Pred::ArgEq(vs) => f.args.iter().any(|a| match a.literal {
                Some(l) => vs.iter().any(|v| v == l),
                None => false,
            }),
            Pred::ArgPrefix(vs) => {
                f.args.iter().any(|a| vs.iter().any(|v| a.prefix.starts_with(v.as_str())))
            }
            Pred::ArgContains(vs) => {
                f.args.iter().any(|a| vs.iter().any(|v| a.text().contains(v.as_str())))
            }
            Pred::ArgContainsNoCase(vs) => f.args.iter().any(|a| {
                let text = a.text().to_ascii_lowercase();
                vs.iter().any(|v| text.contains(v.as_str()))
            }),
            Pred::ArgSuffix(vs) => f.args.iter().any(|a| match a.literal {
                Some(l) => vs.iter().any(|v| l.ends_with(v.as_str())),
                None => false,
            }),
            Pred::TextContains(vs) => vs.iter().any(|v| f.text.contains(v.as_str())),
            Pred::ShortFlag(cs) => cs.iter().any(|c| f.short_flags.contains(*c)),
            Pred::Subcommand(vs) => match f.subcommand {
                Some(s) => vs.iter().any(|v| v == s),
                None => false,
            },
            Pred::ArgAt(i, vs) => match f.args.get(*i).and_then(|a| a.literal) {
                Some(l) => vs.iter().any(|v| v == l),
                None => false,
            },
            Pred::ArgLast(vs) => match f.args.last().and_then(|a| a.literal) {
                Some(l) => vs.iter().any(|v| v == l),
                None => false,
            },
            Pred::TaintAtLeast(t) => f.arg_taint >= *t,
            Pred::OpacityAtLeast(o) => f.opacity >= *o,
            Pred::WriteRedirect => f.has_write_redirect,
            Pred::TruncatingRedirect => f.has_truncating_redirect,
            Pred::WriteRedirectOutside => f.write_redirect_outside_workspace,
            Pred::WriteTargetPrefix(vs) => {
                f.write_targets.iter().any(|t| vs.iter().any(|v| t.prefix.starts_with(v.as_str())))
            }
            Pred::Assigns(vs) => f.assignments.iter().any(|a| vs.iter().any(|v| v == a)),
            Pred::PathOutsideWorkspace => f.args.iter().any(|a| a.outside_workspace),
            Pred::UnresolvedPath => f.args.iter().any(|a| a.unresolved_path),
            Pred::AbsolutePathArg => f.args.iter().any(|a| a.absolute),
            Pred::PipesInto(vs) => f.downstream.iter().any(|d| vs.iter().any(|v| v == d)),
            Pred::PipedFrom(vs) => f.upstream.iter().any(|u| vs.iter().any(|v| v == u)),
            Pred::WrapDepthAtLeast(n) => f.wrap_depth >= *n,
            Pred::NoPositional => {
                let positional = f.args.iter().filter(|a| !a.is_flag()).count();
                positional <= usize::from(f.subcommand.is_some())
            }
            Pred::FlagsWithin(allowed) => f.args.iter().all(|a| a.flag_is_within(allowed)),
            Pred::Not(inner) => !inner.matches(f),
            Pred::Any(preds) => preds.iter().any(|p| p.matches(f)),
        }
    }

    /// Literal needles this predicate implies, for the prefilter.
    ///
    /// Only sound for predicates where a match *requires* the needle to occur
    /// in the command text. `Not` contributes nothing, because a negated
    /// predicate matches precisely when its needle is absent — indexing it
    /// would drop the rule from consideration exactly when it should fire.
    /// Nor does `ArgContainsNoCase`: the prefilter matches exact bytes, and
    /// `CORE.PAGER` does not contain `core.pager`.
    fn needles(&self, out: &mut Vec<String>) {
        match self {
            Pred::TextContains(vs)
            | Pred::ArgEq(vs)
            | Pred::ArgContains(vs)
            | Pred::ArgSuffix(vs)
            | Pred::ArgPrefix(vs) => out.extend(vs.iter().cloned()),
            Pred::Subcommand(vs) | Pred::ArgAt(_, vs) | Pred::ArgLast(vs) => {
                out.extend(vs.iter().cloned())
            }
            Pred::WriteTargetPrefix(vs) | Pred::Assigns(vs) => out.extend(vs.iter().cloned()),
            // A disjunction only prefilters if every branch contributes, since
            // an unindexed branch could match on its own.
            Pred::Any(preds) => {
                let mut all = Vec::new();
                for p in preds {
                    let before = all.len();
                    p.needles(&mut all);
                    if all.len() == before {
                        return;
                    }
                }
                out.extend(all);
            }
            _ => {}
        }
    }
}

/// A single policy rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub verdict: Verdict,
    pub reason: String,
    /// Program basenames this rule applies to. Empty means any program, which
    /// puts the rule on the prefilter path instead of the hash-bucket path.
    pub programs: Vec<String>,
    /// Conjoined predicates.
    pub preds: Vec<Pred>,
    pub caps: Vec<Capability>,
}

impl Rule {
    pub fn matches(&self, f: &CommandFacts<'_>) -> bool {
        if !self.programs.is_empty() {
            match f.program {
                Some(p) => {
                    if !self.programs.iter().any(|x| x == p) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        self.preds.iter().all(|p| p.matches(f))
    }

    /// Needles for the prefilter, or `None` if this rule cannot be prefiltered
    /// and must always be evaluated.
    pub(crate) fn prefilter_needles(&self) -> Option<Vec<String>> {
        let mut out = Vec::new();
        for p in &self.preds {
            p.needles(&mut out);
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

/// A rule that fired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleHit {
    pub rule_id: String,
    pub verdict: Verdict,
    pub reason: String,
    pub caps: Vec<Capability>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(program: &'a str, args: &'a [ArgFacts<'a>], flags: &'a str) -> CommandFacts<'a> {
        CommandFacts {
            program: Some(program),
            args,
            short_flags: flags,
            text: "",
            ..Default::default()
        }
    }

    fn arg(lit: &str) -> ArgFacts<'_> {
        ArgFacts { literal: Some(lit), prefix: lit, ..Default::default() }
    }

    #[test]
    fn verdicts_join_to_the_most_severe() {
        assert_eq!(Verdict::Allow.join(Verdict::Deny), Verdict::Deny);
        assert_eq!(Verdict::Deny.join(Verdict::Allow), Verdict::Deny);
        assert_eq!(Verdict::Confine.join(Verdict::Ask), Verdict::Ask);
        assert!(Verdict::Allow < Verdict::Confine);
    }

    #[test]
    fn short_flag_matching_sees_bundles() {
        let args = [arg("-rf"), arg("/tmp/x")];
        let f = facts("rm", &args, "rf");
        assert!(Pred::ShortFlag(vec!['r']).matches(&f));
        assert!(Pred::ShortFlag(vec!['f']).matches(&f));
        assert!(!Pred::ShortFlag(vec!['z']).matches(&f));
    }

    #[test]
    fn prefix_matching_works_on_tainted_arguments() {
        // `--output=$X` has no literal but still has a usable prefix.
        let args = [ArgFacts {
            literal: None,
            prefix: "--output=",
            taint: Taint::Variable,
            ..Default::default()
        }];
        let f = facts("tar", &args, "");
        assert!(Pred::ArgPrefix(vec!["--output".into()]).matches(&f));
        assert!(!Pred::ArgEq(vec!["--output=x".into()]).matches(&f));
    }

    #[test]
    fn subcommand_and_positional() {
        let args = [arg("reset"), arg("--hard")];
        let f = CommandFacts { subcommand: Some("reset"), ..facts("git", &args, "") };
        assert!(Pred::Subcommand(vec!["reset".into()]).matches(&f));
        assert!(Pred::ArgAt(0, vec!["reset".into()]).matches(&f));
        assert!(!Pred::ArgAt(1, vec!["reset".into()]).matches(&f));
    }

    /// An argument whose value is not known, with the literal run it starts with.
    fn unknown(prefix: &str) -> ArgFacts<'_> {
        ArgFacts { literal: None, prefix, taint: Taint::Variable, ..Default::default() }
    }

    fn allowed(flags: &[&str]) -> Pred {
        Pred::FlagsWithin(flags.iter().map(|s| s.to_string()).collect())
    }

    /// `git <sub> <args>`, judged by `p`.
    fn git_matches(p: &Pred, sub: &str, rest: &[ArgFacts<'_>]) -> bool {
        let mut args = vec![arg(sub)];
        args.extend_from_slice(rest);
        let f = CommandFacts { subcommand: Some(sub), ..facts("git", &args, "") };
        p.matches(&f)
    }

    #[test]
    fn no_positional_allows_only_the_subcommand() {
        let p = Pred::NoPositional;
        assert!(git_matches(&p, "branch", &[]));
        assert!(git_matches(&p, "branch", &[arg("-a")]));
        assert!(git_matches(&p, "branch", &[arg("--sort=-committerdate")]));
        assert!(!git_matches(&p, "branch", &[arg("feature")]));
        assert!(!git_matches(&p, "branch", &[arg("-a"), arg("feature")]));
        // The bare `-` is standard input, a positional.
        assert!(!git_matches(&p, "branch", &[arg("-")]));
        // Nothing is known about an argument that starts with an expansion.
        assert!(!git_matches(&p, "branch", &[unknown("")]));
        // But a flag whose *value* is unknown is still a flag.
        assert!(git_matches(&p, "branch", &[unknown("--format=")]));
        // Without a subcommand there is nothing to make room for.
        let args = [arg("-a")];
        assert!(p.matches(&facts("ls", &args, "a")));
        let args = [arg("dir")];
        assert!(!p.matches(&facts("ls", &args, "")));
    }

    #[test]
    fn flags_within_is_an_allowlist_of_exact_names() {
        let p = allowed(&["--list", "--sort", "-a", "-v"]);
        // Allowed, alone and bundled, with or without an attached value.
        assert!(git_matches(&p, "branch", &[]));
        assert!(git_matches(&p, "branch", &[arg("--list")]));
        assert!(git_matches(&p, "branch", &[arg("--sort=-committerdate")]));
        assert!(git_matches(&p, "branch", &[arg("-a")]));
        assert!(git_matches(&p, "branch", &[arg("-av")]));
        assert!(git_matches(&p, "branch", &[arg("-vv")]));
        assert!(git_matches(&p, "branch", &[arg("-a"), arg("-v"), arg("--list")]));
        // A positional is not this predicate's business.
        assert!(git_matches(&p, "branch", &[arg("--list"), arg("feat*")]));
        assert!(git_matches(&p, "branch", &[arg("-")]));
    }

    #[test]
    fn flags_within_refuses_everything_not_named() {
        let p = allowed(&["--list", "--sort", "-a", "-v"]);
        for bad in [
            "-D",       // not listed
            "-aD",      // one bad flag spoils a bundle
            "-Dv",      // ... wherever it sits
            "--delete", // not listed
            "--del",    // git accepts unambiguous abbreviations of long options
            "--lis",    // ... including of the ones that *are* listed
            "--listx",  // a longer name is a different flag
            "--",       // end of options: what follows is not judged
            "-n5",      // a digit is not a listed flag
            "-a=1",     // '=' is not a flag character
        ] {
            assert!(!git_matches(&p, "branch", &[arg(bad)]), "`{bad}` should not be within");
            assert!(
                !git_matches(&p, "branch", &[arg("--list"), arg(bad)]),
                "`{bad}` after an allowed flag should not be within"
            );
        }
    }

    #[test]
    fn flags_within_refuses_what_may_become_a_flag() {
        let p = allowed(&["--list", "--sort", "-a"]);
        // `git branch --list $X` with X=-D deletes a branch; `*` may likewise
        // expand to a file named `-D`. Both are an argument with no known start.
        assert!(!git_matches(&p, "branch", &[arg("--list"), unknown("")]));
        // A dash followed by an expansion is a flag of unknown spelling.
        assert!(!git_matches(&p, "branch", &[unknown("-")]));
        assert!(!git_matches(&p, "branch", &[unknown("-a")]));
        // The name of a long flag that is cut off by an expansion is unknown.
        assert!(!git_matches(&p, "branch", &[unknown("--list")]));
        assert!(!git_matches(&p, "branch", &[unknown("--")]));
        // A positional that *starts* with known text cannot become a flag.
        assert!(git_matches(&p, "branch", &[arg("--list"), unknown("feat")]));
        // A known flag with an unknown value is fine: the name is what matters.
        assert!(git_matches(&p, "branch", &[unknown("--sort=")]));
        assert!(!git_matches(&p, "branch", &[unknown("--delete=")]));
    }

    #[test]
    fn a_flags_within_entry_is_read_as_a_short_flag_only_if_it_is_one() {
        assert_eq!(short_flag_entry("-a"), Some('a'));
        assert_eq!(short_flag_entry("-9"), Some('9'));
        assert_eq!(short_flag_entry("--"), None);
        assert_eq!(short_flag_entry("--a"), None);
        assert_eq!(short_flag_entry("-"), None);
        assert_eq!(short_flag_entry("-ab"), None);
        assert_eq!(short_flag_entry("a"), None);
        // ... so a long name can never be mistaken for a short flag.
        let p = allowed(&["--list"]);
        assert!(!git_matches(&p, "branch", &[arg("-l")]));
    }

    #[test]
    fn nocase_matching_ignores_case_and_the_prefilter_does_not_index_it() {
        let args = [arg("CORE.PAGER"), arg("less")];
        let f = CommandFacts { subcommand: Some("config"), ..facts("git", &args, "") };
        assert!(Pred::ArgContainsNoCase(vec!["core.pager".into()]).matches(&f));
        assert!(!Pred::ArgContains(vec!["core.pager".into()]).matches(&f));
        assert!(!Pred::ArgContainsNoCase(vec!["core.editor".into()]).matches(&f));
        let mut out = Vec::new();
        Pred::ArgContainsNoCase(vec!["core.pager".into()]).needles(&mut out);
        assert!(out.is_empty(), "a case-insensitive predicate must not become a byte needle");
    }

    #[test]
    fn not_and_any_compose() {
        let args = [arg("-rf"), arg("build")];
        let f = facts("rm", &args, "rf");
        let p = Pred::Not(Box::new(Pred::ArgEq(vec!["/".into()])));
        assert!(p.matches(&f));
        let p = Pred::Any(vec![Pred::ArgEq(vec!["/".into()]), Pred::ArgEq(vec!["build".into()])]);
        assert!(p.matches(&f));
    }

    #[test]
    fn rule_requires_all_predicates() {
        let rule = Rule {
            id: "t".into(),
            verdict: Verdict::Deny,
            reason: String::new(),
            programs: vec!["rm".into()],
            preds: vec![Pred::ShortFlag(vec!['r']), Pred::ArgEq(vec!["/".into()])],
            caps: vec![],
        };
        let args = [arg("-rf"), arg("/")];
        assert!(rule.matches(&facts("rm", &args, "rf")));
        let args = [arg("-rf"), arg("build")];
        assert!(!rule.matches(&facts("rm", &args, "rf")));
        // Wrong program, same arguments.
        let args = [arg("-rf"), arg("/")];
        assert!(!rule.matches(&facts("rmdir", &args, "rf")));
    }

    #[test]
    fn negated_predicates_are_not_indexed() {
        // Indexing a `Not` needle would skip the rule exactly when it applies.
        let p = Pred::Not(Box::new(Pred::ArgEq(vec!["safe".into()])));
        let mut out = Vec::new();
        p.needles(&mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn disjunction_indexes_only_when_every_branch_does() {
        let mut out = Vec::new();
        Pred::Any(vec![Pred::ArgEq(vec!["a".into()]), Pred::ArgEq(vec!["b".into()])])
            .needles(&mut out);
        assert_eq!(out, vec!["a".to_string(), "b".to_string()]);

        // One branch has no needle, so the whole disjunction is unindexable.
        let mut out = Vec::new();
        Pred::Any(vec![Pred::ArgEq(vec!["a".into()]), Pred::WriteRedirect]).needles(&mut out);
        assert!(out.is_empty());
    }
}
