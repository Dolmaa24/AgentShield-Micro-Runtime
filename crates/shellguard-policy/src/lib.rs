//! Policy: what a command is allowed to do, and how that question gets asked
//! fast enough to ask on every command.
//!
//! This crate is deliberately pure. It never touches the filesystem, never
//! resolves a path, never looks at a syntax tree. It takes [`CommandFacts`] —
//! a command already reduced to the properties rules ask about — and returns
//! the rules that fired. All the expensive and platform-dependent work of
//! producing those facts belongs to `shellguard-gate`.
//!
//! The split is what makes the ruleset testable. A rule about `rm -rf` outside
//! the workspace can be exercised with a struct literal, with no temporary
//! directory, no `$PATH`, and no dependence on what happens to be installed on
//! the machine running the tests.

mod ac;
mod compile;
mod model;
mod text;

pub use ac::{AhoCorasick, BitSet};
pub use compile::{CompiledPolicy, Policy, Scratch};
pub use model::{ArgFacts, Capability, CommandFacts, Pred, Rule, RuleHit, Verdict};
pub use text::{parse_policy, PolicyError};

/// The built-in ruleset, embedded at compile time.
///
/// It is written in the same format users write, and parsed by the same parser.
/// A default policy expressed as Rust structs would drift from the format it
/// documents, and would let the built-in rules use expressive power the file
/// format does not have.
pub const DEFAULT_POLICY_TEXT: &str = include_str!("../../../policies/default.policy");

/// Parse and compile the built-in ruleset.
///
/// Panics if the embedded policy is malformed, which a test in this crate makes
/// a build-time failure rather than a runtime one.
pub fn default_policy() -> CompiledPolicy {
    parse_policy(DEFAULT_POLICY_TEXT)
        .expect("the built-in policy is checked by a test in this crate")
        .compile()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_built_in_policy_parses() {
        let p = parse_policy(DEFAULT_POLICY_TEXT).unwrap_or_else(|e| {
            panic!("policies/default.policy is malformed: {e}");
        });
        assert_eq!(p.version, 1);
        assert!(p.rules.len() > 30, "expected a substantial ruleset, got {}", p.rules.len());
    }

    #[test]
    fn the_default_verdict_is_not_allow() {
        // If this ever becomes `allow`, every command the ruleset has nothing
        // to say about runs unconfined. That is the single highest-impact line
        // in the file, so it gets its own test.
        let p = parse_policy(DEFAULT_POLICY_TEXT).unwrap();
        assert_ne!(p.default_verdict, Verdict::Allow);
    }

    #[test]
    fn rule_ids_are_unique() {
        let p = parse_policy(DEFAULT_POLICY_TEXT).unwrap();
        let mut seen = HashSet::new();
        for r in &p.rules {
            assert!(seen.insert(r.id.clone()), "duplicate rule id `{}`", r.id);
        }
    }

    #[test]
    fn every_rule_declares_a_capability() {
        // A rule with no capability can produce a verdict nobody can explain in
        // terms of effects, which is how escalations become unreviewable.
        let p = parse_policy(DEFAULT_POLICY_TEXT).unwrap();
        for r in &p.rules {
            assert!(!r.caps.is_empty(), "rule `{}` declares no capability", r.id);
        }
    }

    #[test]
    fn every_rule_id_is_namespaced() {
        let p = parse_policy(DEFAULT_POLICY_TEXT).unwrap();
        for r in &p.rules {
            assert!(r.id.contains('.'), "rule id `{}` is not namespaced", r.id);
        }
    }

    #[test]
    fn the_built_in_policy_compiles_and_indexes() {
        let c = default_policy();
        assert!(c.rule_count() > 30);
        assert!(c.prefilter_pattern_count() > 0, "no rules were indexed");
        // Some rules genuinely cannot be indexed; the point is that most are.
        assert!(
            c.unindexed_rule_count() * 4 < c.rule_count(),
            "{} of {} rules must be evaluated on every command",
            c.unindexed_rule_count(),
            c.rule_count()
        );
    }
}
