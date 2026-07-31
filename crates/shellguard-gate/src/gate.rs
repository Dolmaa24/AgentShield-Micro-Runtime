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

use std::time::{Duration, Instant};

use shellguard_parse::parse_with_limits;
use shellguard_policy::{
    ArgFacts, Capability, CommandFacts, CompiledPolicy, RuleHit, Scratch, Verdict,
};

use crate::config::GateConfig;
use crate::decision::{CommandSummary, Decision, Finding, Incomplete};
use crate::normalize::{Cmd, Collector, Ctx};
use crate::resolve::PathCache;

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
    policy: CompiledPolicy,
    config: GateConfig,
}

impl Gate {
    pub fn new(policy: CompiledPolicy, config: GateConfig) -> Self {
        Gate { policy, config }
    }

    /// A gate carrying the built-in ruleset.
    pub fn with_default_policy(config: GateConfig) -> Self {
        Gate::new(shellguard_policy::default_policy(), config)
    }

    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    pub fn policy(&self) -> &CompiledPolicy {
        &self.policy
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
                };
            }
        };

        // Taken out of the worker so the collector can borrow the cache while
        // the loop below borrows the scratch buffers. Returned at the end, so
        // the allocation is reused across evaluations.
        let mut cmds = std::mem::take(&mut w.cmds);
        let mut collector = Collector {
            cfg: &self.config,
            cache: &mut w.cache,
            src,
            span_override: None,
            limits: self.config.limits,
            max_unwrap_depth: self.config.max_unwrap_depth,
            unwrap_truncated: false,
        };
        collector.collect(&ast, Ctx::default(), &mut cmds);
        let unwrap_truncated = collector.unwrap_truncated;

        let mut verdict = Verdict::Allow;
        let mut findings: Vec<Finding> = Vec::new();
        let mut capabilities: Vec<Capability> = Vec::new();
        let mut commands: Vec<CommandSummary> = Vec::new();
        let mut matched_any = false;
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
            let assignments: Vec<&str> = cmd.assignments.iter().map(String::as_str).collect();
            let downstream: Vec<&str> = cmd.downstream.iter().map(String::as_str).collect();
            let upstream: Vec<&str> = cmd.upstream.iter().map(String::as_str).collect();

            let facts = CommandFacts {
                program: cmd.program.as_deref(),
                program_path: cmd.resolved.as_deref(),
                subcommand: cmd.subcommand.as_deref(),
                args: &args,
                write_targets: &targets,
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
            self.policy.evaluate(&facts, &mut w.scratch, &mut w.hits);

            if !w.hits.is_empty() {
                matched_any = true;
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

        // No rule had anything to say. That is not evidence of safety, so the
        // policy's declared default applies rather than an implicit allow.
        if !matched_any {
            verdict = verdict.join(self.policy.default_verdict());
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

        Decision { verdict, findings, capabilities, commands, incomplete, elapsed: start.elapsed() }
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
    }
}

/// The gate's evaluation budget, exposed for callers that want to report it.
pub const DEFAULT_DEADLINE: Duration = Duration::from_millis(10);
