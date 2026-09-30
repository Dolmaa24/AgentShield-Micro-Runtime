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
        let fingerprint = fingerprint_of(self.default_verdict, &self.rules);

        CompiledPolicy {
            rules: self.rules,
            default_verdict: self.default_verdict,
            fingerprint,
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
    fingerprint: u64,
    by_program: HashMap<String, Vec<u32>>,
    /// Program-agnostic rules that cannot be prefiltered.
    always: Vec<u32>,
    ac: AhoCorasick,
    pattern_rules: Vec<Vec<u32>>,
    npatterns: usize,
}

/// FNV-1a over a canonical rendering of the policy's meaning.
///
/// An identifier, not a defence: it exists so that a decision can say *which*
/// ruleset made it. That matters once rules can change under a running process
/// — without it, the record of a refusal cannot be tied to the rules that
/// refused. It is deterministic across processes for the same rules, differs
/// when any rule or the default changes, and is **not** stable across releases
/// of this crate (it hashes the derived `Debug` form). Use the SHA-256 of the
/// policy *text* when a stable, collision-resistant identity is needed.
fn fingerprint_of(default_verdict: Verdict, rules: &[Rule]) -> u64 {
    let canonical = format!("{default_verdict:?}|{rules:?}");
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in canonical.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// What changed between two policies, and whether any of it lowers protection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDiff {
    /// Rule ids present only in the new policy.
    pub added: Vec<String>,
    /// Rule ids present only in the old policy.
    pub removed: Vec<String>,
    /// Rule ids in both whose definition differs.
    pub changed: Vec<String>,
    pub default_before: Verdict,
    pub default_after: Verdict,
    /// Why this change may lower protection, one line each. Empty means none of
    /// the *detectable* kinds of weakening are present.
    pub weakened: Vec<String>,
}

impl PolicyDiff {
    /// Nothing differs.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
            && self.default_before == self.default_after
    }

    /// Whether a detectable kind of weakening is present.
    ///
    /// A tripwire, not a proof. It flags removing a rule that restricted
    /// something, lowering a rule's or the default's verdict, and adding a rule
    /// more permissive than the default (a matching `allow` rule replaces the
    /// default rather than joining it). It **cannot** see that a rule's
    /// predicates were loosened while its verdict stayed put — those rules are
    /// listed in [`changed`](Self::changed) for a human to read.
    pub fn weakens(&self) -> bool {
        !self.weakened.is_empty()
    }
}

impl CompiledPolicy {
    /// The rules, in file order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// An identifier for this policy's content. See [`fingerprint_of`].
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// What replacing `self` with `next` would change.
    pub fn diff(&self, next: &CompiledPolicy) -> PolicyDiff {
        let old: HashMap<&str, &Rule> = self.rules.iter().map(|r| (r.id.as_str(), r)).collect();
        let new: HashMap<&str, &Rule> = next.rules.iter().map(|r| (r.id.as_str(), r)).collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        let mut weakened = Vec::new();

        // Iterate the rule vectors rather than the maps so output order is the
        // file order, not the hasher's.
        for r in &next.rules {
            match old.get(r.id.as_str()) {
                None => {
                    added.push(r.id.clone());
                    if r.verdict < next.default_verdict {
                        weakened.push(format!(
                            "added rule `{}` allows what the default ({}) would not",
                            r.id,
                            next.default_verdict.as_str()
                        ));
                    }
                }
                Some(o) if *o != r => {
                    changed.push(r.id.clone());
                    if r.verdict < o.verdict {
                        weakened.push(format!(
                            "rule `{}` lowered from {} to {}",
                            r.id,
                            o.verdict.as_str(),
                            r.verdict.as_str()
                        ));
                    }
                }
                Some(_) => {}
            }
        }
        for r in &self.rules {
            if !new.contains_key(r.id.as_str()) {
                removed.push(r.id.clone());
                if r.verdict > Verdict::Allow {
                    weakened.push(format!("removed {} rule `{}`", r.verdict.as_str(), r.id));
                }
            }
        }
        if next.default_verdict < self.default_verdict {
            weakened.push(format!(
                "default verdict lowered from {} to {}",
                self.default_verdict.as_str(),
                next.default_verdict.as_str()
            ));
        }

        PolicyDiff {
            added,
            removed,
            changed,
            default_before: self.default_verdict,
            default_after: next.default_verdict,
            weakened,
        }
    }

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

#[cfg(test)]
mod reload_tests {
    use super::*;
    use crate::{parse_policy, DEFAULT_POLICY_TEXT};

    fn pol(src: &str) -> CompiledPolicy {
        parse_policy(src).unwrap_or_else(|e| panic!("{e}\n{src}")).compile()
    }

    const BASE: &str = "\
version 1
default confine

rule net.block deny
  reason no network tools
  program curl wget
  cap net.connect
end

rule vcs.push ask
  reason pushing needs a human
  program git
  subcommand push
  cap net.connect
end

rule read.safe allow
  reason read-only
  program ls cat
  cap fs.read
end
";

    // ------------------------------------------------------------ fingerprint

    #[test]
    fn the_same_policy_has_the_same_fingerprint_every_time() {
        assert_eq!(pol(BASE).fingerprint(), pol(BASE).fingerprint());
    }

    #[test]
    fn comments_and_blank_lines_do_not_change_what_a_policy_is() {
        let noisy = format!(
            "# a header comment\n\n{}\n\n# trailing\n",
            BASE.replace("end\n", "end  # done\n")
        );
        assert_eq!(pol(BASE).fingerprint(), pol(&noisy).fingerprint());
    }

    #[test]
    fn changing_anything_that_matters_changes_the_fingerprint() {
        let base = pol(BASE).fingerprint();
        for (what, changed) in [
            ("a reason", BASE.replace("no network tools", "no network")),
            ("a verdict", BASE.replace("rule net.block deny", "rule net.block ask")),
            ("a program", BASE.replace("curl wget", "curl")),
            ("the default", BASE.replace("default confine", "default ask")),
            ("a capability", BASE.replace("cap fs.read", "cap fs.write")),
            ("a predicate", BASE.replace("subcommand push", "subcommand pull")),
        ] {
            assert_ne!(
                pol(&changed).fingerprint(),
                base,
                "changing {what} left the fingerprint alone"
            );
        }
    }

    // ------------------------------------------------------------------- diff

    #[test]
    fn identical_policies_have_an_empty_diff() {
        let d = pol(BASE).diff(&pol(BASE));
        assert!(d.is_empty() && !d.weakens(), "{d:?}");
    }

    #[test]
    fn added_removed_and_changed_rules_are_listed_in_file_order() {
        let next = BASE
            .replace("no network tools", "no network tools at all") // changed
            .replace("rule vcs.push ask", "rule vcs.push-x ask") // removed + added
            + "\nrule z.new ask\n  reason new\n  program zzz\n  cap fs.read\nend\n";
        let d = pol(BASE).diff(&pol(&next));
        assert_eq!(d.added, ["vcs.push-x", "z.new"]);
        assert_eq!(d.removed, ["vcs.push"]);
        assert_eq!(d.changed, ["net.block"]);
        assert!(!d.is_empty());
    }

    #[test]
    fn a_changed_default_is_reported() {
        let d = pol(BASE).diff(&pol(&BASE.replace("default confine", "default ask")));
        assert_eq!((d.default_before, d.default_after), (Verdict::Confine, Verdict::Ask));
        assert!(!d.is_empty());
        assert!(!d.weakens(), "raising the default is not a weakening");
    }

    // -------------------------------------------------------------- weakening

    fn weakens(next: &str) -> bool {
        pol(BASE).diff(&pol(next)).weakens()
    }

    #[test]
    fn removing_a_restrictive_rule_is_a_weakening() {
        // Every removal of a deny or an ask.
        assert!(weakens(&BASE.replace(
            "rule net.block deny\n  reason no network tools\n  program curl wget\n  cap net.connect\nend\n",
            ""
        )));
        assert!(weakens(&BASE.replace(
            "rule vcs.push ask\n  reason pushing needs a human\n  program git\n  subcommand push\n  cap net.connect\nend\n",
            ""
        )));
    }

    #[test]
    fn removing_an_allow_rule_tightens_and_is_not_a_weakening() {
        let without_allow = BASE.replace(
            "rule read.safe allow\n  reason read-only\n  program ls cat\n  cap fs.read\nend\n",
            "",
        );
        let d = pol(BASE).diff(&pol(&without_allow));
        assert_eq!(d.removed, ["read.safe"]);
        assert!(!d.weakens(), "{d:?}");
    }

    #[test]
    fn lowering_a_rules_verdict_is_a_weakening_and_raising_it_is_not() {
        assert!(weakens(&BASE.replace("rule net.block deny", "rule net.block ask")));
        assert!(!weakens(&BASE.replace("rule vcs.push ask", "rule vcs.push deny")));
    }

    #[test]
    fn lowering_the_default_is_a_weakening() {
        assert!(weakens(&BASE.replace("default confine", "default allow")));
        assert!(!weakens(&BASE.replace("default confine", "default deny")));
    }

    #[test]
    fn adding_a_rule_more_permissive_than_the_default_is_a_weakening() {
        // A matching `allow` rule replaces the default rather than joining it,
        // so this really does lower scrutiny for `wc`.
        let with_allow = format!(
            "{BASE}\nrule read.wc allow\n  reason counts\n  program wc\n  cap fs.read\nend\n"
        );
        let d = pol(BASE).diff(&pol(&with_allow));
        assert!(d.weakens(), "{d:?}");
        assert!(d.weakened[0].contains("read.wc"), "{:?}", d.weakened);

        let with_deny = format!(
            "{BASE}\nrule x.deny deny\n  reason no\n  program nc\n  cap net.connect\nend\n"
        );
        assert!(!pol(BASE).diff(&pol(&with_deny)).weakens());
    }

    #[test]
    fn a_loosened_predicate_with_the_same_verdict_is_listed_but_not_flagged() {
        // The documented blind spot: this genuinely could weaken the rule, and
        // the diff cannot tell. It must at least be visible as `changed`.
        let next = BASE.replace("subcommand push", "subcommand nonexistent");
        let d = pol(BASE).diff(&pol(&next));
        assert_eq!(d.changed, ["vcs.push"]);
        assert!(!d.weakens(), "if this starts flagging, update the docs on what weakens() sees");
    }

    // ------------------------------------------------- truncation, on the real file

    #[test]
    fn a_truncated_copy_of_the_real_policy_is_never_silently_weaker() {
        // A half-written save is a prefix of the file. Cut the built-in policy
        // at every line: a cut inside a rule must fail to parse, and a cut
        // between rules parses as a *smaller* policy — which must be flagged
        // whenever it dropped anything that restricted a command.
        let full = pol(DEFAULT_POLICY_TEXT);
        let lines: Vec<&str> = DEFAULT_POLICY_TEXT.lines().collect();
        let (mut rejected, mut parsed_and_flagged) = (0, 0);

        for cut in 1..lines.len() {
            let prefix = lines[..cut].join("\n");
            match parse_policy(&prefix) {
                Err(_) => rejected += 1,
                Ok(p) => {
                    let smaller = p.compile();
                    let d = full.diff(&smaller);
                    let dropped_something_restrictive = d.removed.iter().any(|id| {
                        full.rules().iter().any(|r| &r.id == id && r.verdict > Verdict::Allow)
                    });
                    if dropped_something_restrictive {
                        assert!(
                            d.weakens(),
                            "a truncation at line {cut} dropped rules without being flagged: {:?}",
                            d.removed
                        );
                        parsed_and_flagged += 1;
                    }
                }
            }
        }
        assert!(
            rejected > 0,
            "no cut point was rejected; the test proves nothing about mid-rule cuts"
        );
        assert!(
            parsed_and_flagged > 0,
            "no cut point parsed; the test proves nothing about rule-boundary cuts"
        );
    }

    // ------------------------------------------------------- duplicate ids

    #[test]
    fn a_duplicate_rule_id_is_rejected_and_points_at_both_definitions() {
        let dup = format!(
            "{BASE}\nrule net.block deny\n  reason again\n  program nc\n  cap net.connect\nend\n"
        );
        let e = parse_policy(&dup).unwrap_err();
        assert!(e.message.contains("duplicate rule id `net.block`"), "{e}");
        assert!(e.message.contains("first defined on line 4"), "{e}");
        assert!(e.line > 4);
    }

    #[test]
    fn the_same_rule_pasted_twice_is_caught() {
        // The actual mistake: a block appended to a policy file twice.
        let block = "rule dup.x deny\n  reason x\n  program nc\n  cap net.connect\nend\n";
        let e = parse_policy(&format!("{BASE}\n{block}\n{block}")).unwrap_err();
        assert!(e.message.contains("duplicate rule id `dup.x`"), "{e}");
    }
}
