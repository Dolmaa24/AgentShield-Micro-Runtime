//! Rule compilation and evaluation.
//!
//! A policy is compiled once at load and evaluated once per command. All the
//! work that can be moved to load time is: building the program index, choosing
//! which rules can be prefiltered, and constructing the automaton.
//!
//! Evaluation narrows candidates in two steps. Rules that name a program are
//! found by hashing the resolved basename, so `git status` never looks at a
//! single `rm` rule. Rules that apply to any program are narrowed by the
//! Aho-Corasick prefilter, so a rule about `/etc/shadow` costs nothing on a
//! command that does not mention it. What survives both is usually a handful of
//! rules, and only those get their predicates run.

use std::collections::HashMap;

use crate::ac::{AhoCorasick, BitSet};
use crate::model::{CommandFacts, Rule, RuleHit, Verdict};

/// A policy before compilation.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub version: u32,
    /// The verdict for a command that matches no rule at all.
    ///
    /// Defaults to [`Verdict::Confine`], not [`Verdict::Allow`]. "No rule
    /// matched" means the ruleset had nothing to say, which is not the same as
    /// the command being safe — and for an agent-authored command it is the
    /// common case rather than the exception. Running it inside the sandbox
    /// costs a warm-namespace entry; running it directly costs whatever it
    /// turns out to have done.
    pub default_verdict: Verdict,
    pub rules: Vec<Rule>,
}

impl Policy {
    pub fn compile(self) -> CompiledPolicy {
        let mut by_program: HashMap<String, Vec<u32>> = HashMap::new();
        let mut always: Vec<u32> = Vec::new();
        let mut patterns: Vec<String> = Vec::new();
        let mut pattern_rules: Vec<Vec<u32>> = Vec::new();
        let mut pattern_index: HashMap<String, usize> = HashMap::new();

        for (i, rule) in self.rules.iter().enumerate() {
            let id = i as u32;
            if !rule.programs.is_empty() {
                for p in &rule.programs {
                    by_program.entry(p.clone()).or_default().push(id);
                }
                continue;
            }
            // Program-agnostic. Index it if every match implies a literal.
            match rule.prefilter_needles() {
                Some(needles) => {
                    for n in needles {
                        let pi = *pattern_index.entry(n.clone()).or_insert_with(|| {
                            patterns.push(n);
                            pattern_rules.push(Vec::new());
                            patterns.len() - 1
                        });
                        pattern_rules[pi].push(id);
                    }
                }
                None => always.push(id),
            }
        }

        let ac = AhoCorasick::new(&patterns);
        let npatterns = patterns.len();

        CompiledPolicy {
            rules: self.rules,
            default_verdict: self.default_verdict,
            by_program,
            always,
            ac,
            pattern_rules,
            npatterns,
        }
    }
}

/// Reusable buffers, so evaluation does not allocate.
///
/// One of these lives per gate worker. Handing the caller an explicit scratch
/// rather than hiding a thread-local keeps the allocation behaviour visible,
/// which matters when the whole point is a latency bound.
#[derive(Debug, Default)]
pub struct Scratch {
    matched_patterns: BitSet,
    seen_rules: BitSet,
    candidates: Vec<u32>,
}

impl Scratch {
    pub fn new() -> Self {
        Scratch::default()
    }
}

#[derive(Debug)]
pub struct CompiledPolicy {
    rules: Vec<Rule>,
    default_verdict: Verdict,
    by_program: HashMap<String, Vec<u32>>,
    /// Program-agnostic rules that cannot be prefiltered.
    always: Vec<u32>,
    ac: AhoCorasick,
    pattern_rules: Vec<Vec<u32>>,
    npatterns: usize,
}

impl CompiledPolicy {
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn default_verdict(&self) -> Verdict {
        self.default_verdict
    }

    /// Number of rules that must be evaluated for every command regardless of
    /// content. Worth keeping small and worth being able to see.
    pub fn unindexed_rule_count(&self) -> usize {
        self.always.len()
    }

    pub fn prefilter_pattern_count(&self) -> usize {
        self.npatterns
    }

    /// Evaluate every rule that could apply, appending hits to `hits`.
    pub fn evaluate(
        &self,
        facts: &CommandFacts<'_>,
        scratch: &mut Scratch,
        hits: &mut Vec<RuleHit>,
    ) {
        scratch.candidates.clear();
        scratch.seen_rules.resize(self.rules.len());
        scratch.seen_rules.clear();

        let push = |cands: &mut Vec<u32>, seen: &mut BitSet, id: u32| {
            if !seen.contains(id as usize) {
                seen.insert(id as usize);
                cands.push(id);
            }
        };

        if let Some(p) = facts.program {
            if let Some(ids) = self.by_program.get(p) {
                for &id in ids {
                    push(&mut scratch.candidates, &mut scratch.seen_rules, id);
                }
            }
        }
        for &id in &self.always {
            push(&mut scratch.candidates, &mut scratch.seen_rules, id);
        }

        if !self.ac.is_empty() {
            scratch.matched_patterns.resize(self.npatterns);
            scratch.matched_patterns.clear();
            self.ac.scan_into(facts.text.as_bytes(), &mut scratch.matched_patterns);
            for pi in scratch.matched_patterns.iter() {
                for &id in &self.pattern_rules[pi] {
                    push(&mut scratch.candidates, &mut scratch.seen_rules, id);
                }
            }
        }

        // Evaluate in declaration order so explanations read the way the policy
        // file reads.
        scratch.candidates.sort_unstable();
        for &id in &scratch.candidates {
            let rule = &self.rules[id as usize];
            if rule.matches(facts) {
                hits.push(RuleHit {
                    rule_id: rule.id.clone(),
                    verdict: rule.verdict,
                    reason: rule.reason.clone(),
                    caps: rule.caps.clone(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ArgFacts, Capability, Pred};

    fn rule(id: &str, programs: &[&str], preds: Vec<Pred>, verdict: Verdict) -> Rule {
        Rule {
            id: id.into(),
            verdict,
            reason: format!("reason for {id}"),
            programs: programs.iter().map(|s| s.to_string()).collect(),
            preds,
            caps: vec![Capability::FsDelete],
        }
    }

    fn eval(p: &CompiledPolicy, f: &CommandFacts<'_>) -> Vec<String> {
        let mut s = Scratch::new();
        let mut hits = Vec::new();
        p.evaluate(f, &mut s, &mut hits);
        hits.into_iter().map(|h| h.rule_id).collect()
    }

    #[test]
    fn program_bucketing_skips_unrelated_rules() {
        let p = Policy {
            version: 1,
            default_verdict: Verdict::Confine,
            rules: vec![
                rule("rm.any", &["rm"], vec![Pred::Always], Verdict::Deny),
                rule("git.any", &["git"], vec![Pred::Always], Verdict::Allow),
            ],
        }
        .compile();

        let f = CommandFacts { program: Some("rm"), text: "rm -rf x", ..Default::default() };
        assert_eq!(eval(&p, &f), vec!["rm.any"]);
        let f = CommandFacts { program: Some("git"), text: "git status", ..Default::default() };
        assert_eq!(eval(&p, &f), vec!["git.any"]);
        let f = CommandFacts { program: Some("ls"), text: "ls", ..Default::default() };
        assert!(eval(&p, &f).is_empty());
    }

    #[test]
    fn prefilter_narrows_program_agnostic_rules() {
        let p = Policy {
            version: 1,
            default_verdict: Verdict::Confine,
            rules: vec![
                rule(
                    "shadow",
                    &[],
                    vec![Pred::TextContains(vec!["/etc/shadow".into()])],
                    Verdict::Deny,
                ),
                rule("ssh", &[], vec![Pred::TextContains(vec!["/.ssh/".into()])], Verdict::Ask),
            ],
        }
        .compile();
        assert_eq!(p.prefilter_pattern_count(), 2);
        assert_eq!(p.unindexed_rule_count(), 0);

        let f =
            CommandFacts { program: Some("cat"), text: "cat /etc/shadow", ..Default::default() };
        assert_eq!(eval(&p, &f), vec!["shadow"]);
        let f = CommandFacts { program: Some("cat"), text: "cat README", ..Default::default() };
        assert!(eval(&p, &f).is_empty());
    }

    #[test]
    fn unindexable_rules_are_always_evaluated() {
        // `WriteRedirect` implies no literal, so it cannot be prefiltered and
        // must not be silently dropped.
        let p = Policy {
            version: 1,
            default_verdict: Verdict::Confine,
            rules: vec![rule("redir", &[], vec![Pred::WriteRedirect], Verdict::Ask)],
        }
        .compile();
        assert_eq!(p.unindexed_rule_count(), 1);

        let f = CommandFacts {
            program: Some("echo"),
            has_write_redirect: true,
            text: "echo hi > f",
            ..Default::default()
        };
        assert_eq!(eval(&p, &f), vec!["redir"]);
    }

    #[test]
    fn a_rule_matching_by_both_paths_fires_once() {
        let p = Policy {
            version: 1,
            default_verdict: Verdict::Confine,
            rules: vec![rule(
                "dup",
                &[],
                vec![Pred::TextContains(vec!["rm".into(), "rf".into()])],
                Verdict::Deny,
            )],
        }
        .compile();
        // Both needles are present; the rule must appear once, not twice.
        let f = CommandFacts { program: Some("rm"), text: "rm -rf /", ..Default::default() };
        assert_eq!(eval(&p, &f), vec!["dup"]);
    }

    #[test]
    fn evaluation_is_in_declaration_order() {
        let p = Policy {
            version: 1,
            default_verdict: Verdict::Confine,
            rules: vec![
                rule("first", &["rm"], vec![Pred::Always], Verdict::Confine),
                rule("second", &["rm"], vec![Pred::Always], Verdict::Deny),
            ],
        }
        .compile();
        let f = CommandFacts { program: Some("rm"), text: "rm x", ..Default::default() };
        assert_eq!(eval(&p, &f), vec!["first", "second"]);
    }

    #[test]
    fn scratch_is_reusable_across_evaluations() {
        let p = Policy {
            version: 1,
            default_verdict: Verdict::Confine,
            rules: vec![rule("rm.any", &["rm"], vec![Pred::Always], Verdict::Deny)],
        }
        .compile();
        let mut s = Scratch::new();
        for _ in 0..3 {
            let mut hits = Vec::new();
            let f = CommandFacts { program: Some("rm"), text: "rm x", ..Default::default() };
            p.evaluate(&f, &mut s, &mut hits);
            assert_eq!(hits.len(), 1);
            let mut hits = Vec::new();
            let f = CommandFacts { program: Some("ls"), text: "ls", ..Default::default() };
            p.evaluate(&f, &mut s, &mut hits);
            assert!(hits.is_empty());
        }
    }

    #[test]
    fn arg_predicates_reach_the_facts() {
        let p = Policy {
            version: 1,
            default_verdict: Verdict::Confine,
            rules: vec![rule(
                "rm.root",
                &["rm"],
                vec![Pred::ShortFlag(vec!['r']), Pred::ArgEq(vec!["/".into()])],
                Verdict::Deny,
            )],
        }
        .compile();
        let args = [ArgFacts { literal: Some("/"), prefix: "/", ..Default::default() }];
        let f = CommandFacts {
            program: Some("rm"),
            args: &args,
            short_flags: "rf",
            text: "rm -rf /",
            ..Default::default()
        };
        assert_eq!(eval(&p, &f), vec!["rm.root"]);
    }
}
