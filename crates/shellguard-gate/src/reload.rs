//! Replacing the ruleset of a gate that is already running.
//!
//! # Why this needs care
//!
//! A gate's policy used to be a constant for the life of the process: changing
//! a rule meant a restart, which is friction but also a checkpoint. Removing the
//! friction is the point of reloading; removing the checkpoint is a risk, and
//! the design here is about keeping the first without losing the second.
//!
//! **Evaluations never see half a policy.** The policy sits behind an
//! `Arc` that is swapped whole. An evaluation takes one snapshot at its start
//! and uses it throughout, so a command is judged entirely by the old rules or
//! entirely by the new ones, never by a mixture — and one already in flight
//! finishes against the rules it started with.
//!
//! **A bad file never replaces a good policy.** Text is parsed and compiled in
//! full before anything is touched. Any error leaves the previous policy in
//! force and is returned to the caller; there is no path on which a failed
//! reload falls back to something more permissive.
//!
//! **A file that parses can still be worse.** A half-written save is a prefix
//! of the file, and a prefix cut between two rules is a valid, smaller policy.
//! So a reload is compared with what it replaces, and one that *lowers
//! protection* is refused unless the caller says, in so many words, that
//! weakening is intended ([`ReloadMode::AllowWeakening`]). That check is a
//! tripwire and not a proof — see [`shellguard_policy::PolicyDiff::weakens`]
//! for what it can and cannot see.
//!
//! **Reload is explicit.** There is no file watcher. A watcher reacts to a save
//! in progress, which is the failure this is trying to avoid, and it makes
//! "who changed the rules" a question about the filesystem instead of about a
//! call. The caller supplies the *text*, not a path, so an embedding application
//! can put its own review in front of it, and there is no gap between checking a
//! file and reading it.

use std::sync::Arc;

use shellguard_policy::{parse_policy, CompiledPolicy, PolicyDiff, PolicyError};

use crate::decision::json_str;
use crate::gate::Gate;

/// Whether a reload that lowers protection is acceptable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReloadMode {
    /// Refuse a change that removes a restriction, lowers a verdict, or adds a
    /// rule more permissive than the default. The safe default.
    #[default]
    Strict,
    /// Accept it. For the operator who meant to loosen the policy; the report
    /// still says exactly what was loosened.
    AllowWeakening,
}

/// What a successful reload did.
#[derive(Clone, Debug)]
pub struct ReloadReport {
    /// Fingerprint of the policy that was replaced.
    pub before: u64,
    /// Fingerprint of the policy now in force.
    pub after: u64,
    /// Rules in the policy now in force.
    pub rules: usize,
    pub diff: PolicyDiff,
}

impl ReloadReport {
    /// Whether the policy in force is different from before.
    pub fn changed(&self) -> bool {
        self.before != self.after || !self.diff.is_empty()
    }

    pub fn to_json(&self) -> String {
        fn list(s: &mut String, key: &str, items: &[String]) {
            s.push_str(",\"");
            s.push_str(key);
            s.push_str("\":[");
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                json_str(s, x);
            }
            s.push(']');
        }

        let mut s = String::with_capacity(256);
        s.push_str(&format!(
            "{{\"before\":\"{:016x}\",\"after\":\"{:016x}\",\"changed\":{},\"rules\":{}",
            self.before,
            self.after,
            self.changed(),
            self.rules
        ));
        list(&mut s, "added", &self.diff.added);
        list(&mut s, "removed", &self.diff.removed);
        list(&mut s, "modified", &self.diff.changed);
        s.push_str(",\"default_before\":");
        json_str(&mut s, self.diff.default_before.as_str());
        s.push_str(",\"default_after\":");
        json_str(&mut s, self.diff.default_after.as_str());
        list(&mut s, "weakened", &self.diff.weakened);
        s.push('}');
        s
    }
}

/// Why a reload did not happen. In every case the previous policy is still in
/// force.
#[derive(Clone, Debug)]
pub enum ReloadError {
    /// The text is not a valid policy.
    Invalid(PolicyError),
    /// It is valid, but it lowers protection and [`ReloadMode::Strict`] was in
    /// effect.
    Weakens(PolicyDiff),
}

impl ReloadError {
    /// The diff that was refused, if the refusal was for weakening.
    pub fn diff(&self) -> Option<&PolicyDiff> {
        match self {
            ReloadError::Weakens(d) => Some(d),
            ReloadError::Invalid(_) => None,
        }
    }
}

impl std::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReloadError::Invalid(e) => write!(
                f,
                "policy rejected, previous policy still in force: line {}: {}",
                e.line, e.message
            ),
            ReloadError::Weakens(d) => write!(
                f,
                "policy rejected because it would lower protection, previous policy still in \
                 force: {} (reload with weakening allowed if this is intended)",
                d.weakened.join("; ")
            ),
        }
    }
}

impl std::error::Error for ReloadError {}

impl Gate {
    /// Parse `text` as a policy and, if it is acceptable, put it in force.
    pub fn reload_text(&self, text: &str, mode: ReloadMode) -> Result<ReloadReport, ReloadError> {
        let next = parse_policy(text).map_err(ReloadError::Invalid)?.compile();
        self.reload(next, mode)
    }

    /// Put an already-compiled policy in force.
    ///
    /// The comparison and the swap happen under one write lock, so two
    /// concurrent reloads are each judged against the policy they actually
    /// replace rather than against a stale copy.
    pub fn reload(
        &self,
        next: CompiledPolicy,
        mode: ReloadMode,
    ) -> Result<ReloadReport, ReloadError> {
        let mut slot = self.policy.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let diff = slot.diff(&next);
        if diff.weakens() && mode == ReloadMode::Strict {
            return Err(ReloadError::Weakens(diff));
        }

        let before = slot.fingerprint();
        let after = next.fingerprint();
        let rules = next.rule_count();
        // Structural equality decides whether there is anything to swap, not
        // the 64-bit fingerprint: a collision must never be able to make a
        // different policy be skipped as "unchanged".
        if before != after || !diff.is_empty() {
            *slot = Arc::new(next);
        }
        Ok(ReloadReport { before, after, rules, diff })
    }
}
