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
