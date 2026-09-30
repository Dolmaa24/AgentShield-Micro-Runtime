//! Replacing a running gate's policy.
//!
//! What these hold the design to: an evaluation is judged by one whole policy,
//! a bad reload never displaces a good policy, and a worker that has been
//! evaluating keeps working across a reload that changes the ruleset's size.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use shellguard_gate::{Gate, GateConfig, ReloadError, ReloadMode, Verdict, Worker};
use shellguard_policy::parse_policy;

fn gate(policy: &str) -> Gate {
    let ws = std::env::temp_dir();
    let mut cfg = GateConfig::from_env(&ws);
    cfg.cwd = ws;
    // Generous: these tests are about which policy judged, not about latency,
    // and a busy CI host must not turn a slow evaluation into a spurious deny.
    cfg.deadline = std::time::Duration::from_secs(5);
    Gate::new(parse_policy(policy).unwrap().compile(), cfg)
}

fn verdict(g: &Gate, cmd: &str) -> Verdict {
    g.evaluate(cmd, &mut Worker::new()).verdict
}

/// Denies `echo`; confines everything else.
const DENY_ECHO: &str = "\
version 1
default confine

rule t.no-echo deny
  reason echo is forbidden
  program echo
  cap fs.read
end
";

/// The same policy without that rule.
const OPEN: &str = "version 1\ndefault confine\n";

#[test]
fn a_reload_changes_the_verdict_of_the_next_command() {
    let g = gate(OPEN);
    assert_eq!(verdict(&g, "echo hi"), Verdict::Confine);
    let before = g.policy_fingerprint();

    let report = g.reload_text(DENY_ECHO, ReloadMode::Strict).unwrap();

    assert_eq!(verdict(&g, "echo hi"), Verdict::Deny);
    assert!(report.changed());
    assert_eq!(report.before, before);
    assert_eq!(report.after, g.policy_fingerprint());
    assert_ne!(report.before, report.after);
    assert_eq!(report.diff.added, ["t.no-echo"]);
    assert_eq!(report.rules, 1);
}

#[test]
fn decisions_say_which_policy_made_them() {
    let g = gate(OPEN);
    let d1 = g.evaluate("echo hi", &mut Worker::new());
    g.reload_text(DENY_ECHO, ReloadMode::Strict).unwrap();
    let d2 = g.evaluate("echo hi", &mut Worker::new());

    assert_eq!(d1.policy_fingerprint, parse_policy(OPEN).unwrap().compile().fingerprint());
    assert_eq!(d2.policy_fingerprint, parse_policy(DENY_ECHO).unwrap().compile().fingerprint());
    assert_ne!(d1.policy_fingerprint, d2.policy_fingerprint);
    assert!(d2
        .to_json("echo hi")
        .contains(&format!("\"policy\":\"{:016x}\"", d2.policy_fingerprint)));
}

#[test]
fn a_bad_policy_never_displaces_the_one_in_force() {
    let g = gate(DENY_ECHO);
    let fp = g.policy_fingerprint();

    let bad = [
        ("empty", ""),
        ("garbage", "this is not a policy\n"),
        ("no version", "default confine\n"),
        ("unterminated rule", "version 1\nrule x deny\n  reason r\n  program echo\n"),
        ("unknown verdict", "version 1\nrule x maybe\n  reason r\n  program echo\nend\n"),
        ("unknown capability", "version 1\nrule x deny\n  reason r\n  program echo\n  cap nope\nend\n"),
        (
            "duplicate id",
            "version 1\nrule x deny\n  reason r\n  program a\nend\nrule x deny\n  reason r\n  program b\nend\n",
        ),
        ("binary noise", "\u{0}\u{1}\u{2}\u{7f}"),
    ];
    for (what, text) in bad {
        let err = g.reload_text(text, ReloadMode::AllowWeakening).unwrap_err();
        assert!(matches!(err, ReloadError::Invalid(_)), "{what}: {err}");
        assert!(err.to_string().contains("previous policy still in force"), "{what}: {err}");
        assert_eq!(g.policy_fingerprint(), fp, "{what}: the policy in force changed");
        assert_eq!(verdict(&g, "echo hi"), Verdict::Deny, "{what}: behaviour changed");
    }
}

#[test]
fn even_when_weakening_is_allowed_a_malformed_policy_is_refused() {
    // `AllowWeakening` is permission to loosen, not permission to be invalid.
    let g = gate(DENY_ECHO);
    assert!(g.reload_text("version 1\nrule x deny\n", ReloadMode::AllowWeakening).is_err());
    assert_eq!(verdict(&g, "echo hi"), Verdict::Deny);
}

#[test]
fn a_reload_that_lowers_protection_is_refused_unless_it_says_so() {
    let g = gate(DENY_ECHO);
    let fp = g.policy_fingerprint();

    let err = g.reload_text(OPEN, ReloadMode::Strict).unwrap_err();
    let ReloadError::Weakens(diff) = &err else { panic!("wrong error: {err}") };
    assert_eq!(diff.removed, ["t.no-echo"]);
    assert!(diff.weakened[0].contains("t.no-echo"), "{:?}", diff.weakened);
    assert!(err.to_string().contains("previous policy still in force"));
    assert_eq!(g.policy_fingerprint(), fp);
    assert_eq!(verdict(&g, "echo hi"), Verdict::Deny);

    // The default mode is the strict one.
    assert!(g.reload_text(OPEN, ReloadMode::default()).is_err());

    // Said out loud, it goes through — and the report says what was loosened.
    let report = g.reload_text(OPEN, ReloadMode::AllowWeakening).unwrap();
    assert!(report.diff.weakens());
    assert_eq!(verdict(&g, "echo hi"), Verdict::Confine);
}

#[test]
fn strengthening_is_never_refused() {
    let g = gate(OPEN);
    assert!(g.reload_text(DENY_ECHO, ReloadMode::Strict).is_ok());
}

#[test]
fn strictness_is_judged_against_what_is_in_force_not_what_was_first_loaded() {
    let g = gate(OPEN);
    g.reload_text(DENY_ECHO, ReloadMode::Strict).unwrap(); // stronger than OPEN
                                                           // Going back to OPEN is now a weakening, even though OPEN is where we began.
    assert!(matches!(g.reload_text(OPEN, ReloadMode::Strict), Err(ReloadError::Weakens(_))));
}

#[test]
fn reloading_the_same_policy_changes_nothing() {
    let g = gate(DENY_ECHO);
    let fp = g.policy_fingerprint();
    let snapshot = g.policy();

    let report = g.reload_text(DENY_ECHO, ReloadMode::Strict).unwrap();

    assert!(!report.changed());
    assert!(report.diff.is_empty());
    assert_eq!(g.policy_fingerprint(), fp);
    assert!(Arc::ptr_eq(&snapshot, &g.policy()), "an identical reload swapped the policy anyway");
}

#[test]
fn a_reload_that_only_reorders_rules_is_still_applied() {
    // Same rules, different order: no diff, different fingerprint, and finding
    // order differs — so it must take effect rather than be skipped as a no-op.
    let a = "version 1\ndefault confine\n\
             rule a deny\n  reason a\n  program aa\n  cap fs.read\nend\n\
             rule b deny\n  reason b\n  program bb\n  cap fs.read\nend\n";
    let b = "version 1\ndefault confine\n\
             rule b deny\n  reason b\n  program bb\n  cap fs.read\nend\n\
             rule a deny\n  reason a\n  program aa\n  cap fs.read\nend\n";
    let g = gate(a);
    let report = g.reload_text(b, ReloadMode::Strict).unwrap();
    assert!(report.diff.is_empty());
    assert!(report.changed(), "a reorder was treated as a no-op");
    assert_eq!(g.policy().rules()[0].id, "b");
}

#[test]
fn a_snapshot_taken_before_a_reload_is_unaffected_by_it() {
    let g = gate(OPEN);
    let old = g.policy();
    g.reload_text(DENY_ECHO, ReloadMode::Strict).unwrap();
    assert_eq!(old.rule_count(), 0, "a held snapshot changed underneath its holder");
    assert_eq!(g.policy().rule_count(), 1);
}

#[test]
fn a_worker_keeps_working_across_reloads_that_change_the_size_of_the_ruleset() {
    // The worker's scratch buffers are sized to the policy. They must follow it
    // in both directions, not just grow.
    let big = shellguard_policy::DEFAULT_POLICY_TEXT;
    let g = gate(OPEN);
    let mut w = Worker::new();

    let v = |g: &Gate, w: &mut Worker, c: &str| g.evaluate(c, w).verdict;

    assert_eq!(v(&g, &mut w, "rm -rf /etc"), Verdict::Confine);
    g.reload_text(big, ReloadMode::AllowWeakening).unwrap(); // OPEN -> ~50 rules
    assert_eq!(v(&g, &mut w, "rm -rf /etc"), Verdict::Deny);
    g.reload_text(DENY_ECHO, ReloadMode::AllowWeakening).unwrap(); // ~50 -> 1
    assert_eq!(v(&g, &mut w, "echo hi"), Verdict::Deny);
    assert_eq!(v(&g, &mut w, "rm -rf /etc"), Verdict::Confine);
    g.reload_text(big, ReloadMode::AllowWeakening).unwrap(); // 1 -> ~50 again
    assert_eq!(v(&g, &mut w, "rm -rf /etc"), Verdict::Deny);
}

#[test]
fn every_evaluation_is_judged_by_one_whole_policy_while_reloads_race_it() {
    // A denies `echo`; B does not. Evaluators hammer `echo` while another
    // thread flips A <-> B. A decision that names A's fingerprint must carry
    // A's verdict, and B's must carry B's: a mixture would show as a
    // fingerprint/verdict pair that matches neither.
    let g = Arc::new(gate(DENY_ECHO));
    let fp_a = parse_policy(DENY_ECHO).unwrap().compile().fingerprint();
    let fp_b = parse_policy(OPEN).unwrap().compile().fingerprint();

    let stop = Arc::new(AtomicBool::new(false));
    let saw_a = Arc::new(AtomicUsize::new(0));
    let saw_b = Arc::new(AtomicUsize::new(0));

    let evaluators: Vec<_> = (0..4)
        .map(|_| {
            let (g, stop, saw_a, saw_b) = (g.clone(), stop.clone(), saw_a.clone(), saw_b.clone());
            std::thread::spawn(move || {
                let mut w = Worker::new();
                while !stop.load(Ordering::Relaxed) {
                    let d = g.evaluate("echo hi", &mut w);
                    if d.policy_fingerprint == fp_a {
                        assert_eq!(
                            d.verdict,
                            Verdict::Deny,
                            "policy A's fingerprint with B's verdict"
                        );
                        saw_a.fetch_add(1, Ordering::Relaxed);
                    } else if d.policy_fingerprint == fp_b {
                        assert_eq!(
                            d.verdict,
                            Verdict::Confine,
                            "policy B's fingerprint with A's verdict"
                        );
                        saw_b.fetch_add(1, Ordering::Relaxed);
                    } else {
                        panic!("a decision named a policy that was never installed");
                    }
                }
            })
        })
        .collect();

    for i in 0..3000 {
        let text = if i % 2 == 0 { OPEN } else { DENY_ECHO };
        g.reload_text(text, ReloadMode::AllowWeakening).unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    for e in evaluators {
        e.join().expect("an evaluator panicked");
    }

    assert!(
        saw_a.load(Ordering::Relaxed) > 0 && saw_b.load(Ordering::Relaxed) > 0,
        "the test never observed both policies, so it raced nothing"
    );
}

#[test]
fn concurrent_reloads_are_serialised_and_leave_one_of_the_candidates() {
    let g = Arc::new(gate(OPEN));
    let candidates: Vec<String> = (0..8)
        .map(|i| {
            format!(
                "version 1\ndefault confine\nrule c{i} deny\n  reason c{i}\n  program prog{i}\n  cap fs.read\nend\n"
            )
        })
        .collect();
    let allowed: Vec<u64> =
        candidates.iter().map(|t| parse_policy(t).unwrap().compile().fingerprint()).collect();

    let handles: Vec<_> = candidates
        .into_iter()
        .map(|t| {
            let g = g.clone();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    // Each is a change relative to whatever is in force; some
                    // are refused as weakening, which is fine — the point is
                    // that nothing deadlocks or corrupts.
                    let _ = g.reload_text(&t, ReloadMode::AllowWeakening);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert!(
        allowed.contains(&g.policy_fingerprint()),
        "the policy in force is none of those installed"
    );
}
