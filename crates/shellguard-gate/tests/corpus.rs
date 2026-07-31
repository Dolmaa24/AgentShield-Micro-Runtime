//! The corpus and the latency budget, as tests.
//!
//! Both live here rather than only in the CLI so that `cargo test` checks
//! them. A specification that is only verified when someone remembers to run a
//! separate tool is a specification that drifts.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use shellguard_gate::{Gate, GateConfig, Verdict, Worker};

const CORPUS: &str = include_str!("../../../tests/corpus.txt");

/// A scratch workspace, so `./src` is inside it and `/etc` is not.
fn workspace() -> PathBuf {
    let ws = std::env::temp_dir().join("shellguard-corpus-test/ws");
    std::fs::create_dir_all(ws.join("src")).expect("create scratch workspace");
    ws
}

fn gate() -> Gate {
    let ws = workspace();
    let cfg = GateConfig {
        workspace: ws.clone(),
        cwd: ws,
        home: Some(PathBuf::from("/home/agent")),
        // Generous, so a loaded CI machine does not turn a latency blip into a
        // verdict change. The budget itself is asserted separately below.
        deadline: Duration::from_secs(30),
        ..GateConfig::default()
    };
    Gate::with_default_policy(cfg)
}

fn cases() -> Vec<(usize, Verdict, String)> {
    let mut out = Vec::new();
    for (i, raw) in CORPUS.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (v, cmd) = line.split_once(char::is_whitespace).expect("verdict then command");
        let verdict = Verdict::parse(v).unwrap_or_else(|| panic!("line {}: bad verdict {v}", i + 1));
        out.push((i + 1, verdict, cmd.trim().to_string()));
    }
    out
}

#[test]
fn the_corpus_matches_the_ruleset() {
    let gate = gate();
    let mut worker = Worker::new();
    let mut failures = Vec::new();

    for (line, expected, command) in cases() {
        let d = gate.evaluate(&command, &mut worker);
        if d.verdict != expected {
            let rules: Vec<&str> = d.findings.iter().map(|f| f.rule_id.as_str()).collect();
            failures.push(format!(
                "  corpus.txt:{line}  expected {}, got {}\n    {command}\n    matched: {}",
                expected.as_str(),
                d.verdict.as_str(),
                if rules.is_empty() { "nothing".to_string() } else { rules.join(", ") }
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} corpus cases disagree with the ruleset.\n\
         Each one is either a policy regression or an expectation that needs \
         updating — decide which, do not just edit the corpus.\n\n{}",
        failures.len(),
        cases().len(),
        failures.join("\n")
    );
}

#[test]
fn the_corpus_covers_every_verdict() {
    // A corpus that has drifted into being all-deny stops testing calibration,
    // which is most of what the ruleset gets wrong.
    let cases = cases();
    for v in [Verdict::Allow, Verdict::Confine, Verdict::Ask, Verdict::Deny] {
        let n = cases.iter().filter(|(_, e, _)| *e == v).count();
        assert!(n >= 10, "only {n} cases expect {}", v.as_str());
    }
}

/// Inputs built to be as expensive as the parser's limits permit.
fn adversarial() -> Vec<(&'static str, String)> {
    vec![
        ("9k arguments", format!("echo {}", "arg ".repeat(9000))),
        (
            "depth-30 nesting with a 4 KiB payload",
            format!("echo {}id {}{}", "$(".repeat(30), "x".repeat(4000), ")".repeat(30)),
        ),
        ("3k sibling substitutions", format!("echo {}", "$(id) ".repeat(3000))),
        ("2k-stage pipeline", (0..2000).map(|_| "grep x").collect::<Vec<_>>().join(" | ")),
        (
            "1k quote-confusing substitutions",
            format!("echo {}", r#""$(a ")" b)" "#.repeat(1000)),
        ),
        ("800 nested parameter defaults", format!("echo {}", "${X:-$(id)} ".repeat(800))),
        ("over the byte cap", format!("echo {}", "a".repeat(200_000))),
    ]
}

#[test]
fn adversarial_input_does_not_blow_up_super_linearly() {
    // Deliberately an order of magnitude above the 10 ms budget. This is a
    // guard against an algorithmic regression — an accidental quadratic in the
    // scanner — not a benchmark, and a tight bound here would flake on a
    // loaded machine while telling us nothing extra. Measured worst case at
    // the time of writing is about 2 ms; see `shellguard bench`.
    const CEILING: Duration = Duration::from_millis(100);

    let gate = gate();
    let mut worker = Worker::new();

    for (name, src) in adversarial() {
        // Warm, so the first sample is not measuring cold caches.
        let _ = gate.evaluate(&src, &mut worker);
        let t = Instant::now();
        let d = gate.evaluate(&src, &mut worker);
        let elapsed = t.elapsed();
        assert!(
            elapsed < CEILING,
            "{name} took {elapsed:?}, over the {CEILING:?} regression ceiling"
        );
        // Whatever it decides, it must decide something.
        let _ = d.verdict;
    }
}

#[test]
fn a_blown_deadline_never_allows() {
    // The property that makes the budget safe rather than merely usually fast:
    // running out of time is a decision, and the decision is not "allow".
    let ws = workspace();
    let cfg = GateConfig {
        workspace: ws.clone(),
        cwd: ws,
        deadline: Duration::from_nanos(1),
        ..GateConfig::default()
    };
    let gate = Gate::with_default_policy(cfg);
    let mut worker = Worker::new();

    for (_, _, command) in cases().into_iter().take(40) {
        let d = gate.evaluate(&command, &mut worker);
        assert_ne!(
            d.verdict,
            Verdict::Allow,
            "an impossible deadline allowed {command:?}"
        );
    }
}
