//! The latency harness.
//!
//! # Why percentiles and not a mean
//!
//! The claim this project makes is a *budget*: evaluation completes within
//! 10 ms. A mean cannot support that claim — a mean of 200 µs is consistent
//! with one command in a thousand taking 50 ms, and that one command is the
//! one that matters, because it is the one an adversarial input produces on
//! purpose. What a budget needs is a tail: p99, p999 and the worst case.
//!
//! This is also why the harness is a hundred lines of `Instant::now` rather
//! than a statistics framework. Criterion is built to detect small differences
//! in a mean between two revisions, which is a different and largely opposite
//! problem: it discards outliers as noise, and here the outliers are the
//! measurement.

use std::time::{Duration, Instant};

use shellguard_gate::{Gate, Worker};

pub struct Samples {
    nanos: Vec<u64>,
}

impl Samples {
    pub fn new() -> Self {
        Samples { nanos: Vec::new() }
    }

    pub fn push(&mut self, d: Duration) {
        self.nanos.push(d.as_nanos() as u64);
    }

    pub fn sorted(mut self) -> SortedSamples {
        self.nanos.sort_unstable();
        SortedSamples { nanos: self.nanos }
    }
}

pub struct SortedSamples {
    nanos: Vec<u64>,
}

impl SortedSamples {
    /// Nearest-rank percentile. No interpolation: a real observed measurement
    /// is more defensible than an average of two, and at these sample counts
    /// the difference is noise anyway.
    pub fn pct(&self, p: f64) -> Duration {
        if self.nanos.is_empty() {
            return Duration::ZERO;
        }
        let rank = ((p / 100.0) * self.nanos.len() as f64).ceil() as usize;
        let idx = rank.saturating_sub(1).min(self.nanos.len() - 1);
        Duration::from_nanos(self.nanos[idx])
    }

    pub fn max(&self) -> Duration {
        Duration::from_nanos(self.nanos.last().copied().unwrap_or(0))
    }

    pub fn mean(&self) -> Duration {
        if self.nanos.is_empty() {
            return Duration::ZERO;
        }
        let sum: u128 = self.nanos.iter().map(|n| *n as u128).sum();
        Duration::from_nanos((sum / self.nanos.len() as u128) as u64)
    }

    pub fn len(&self) -> usize {
        self.nanos.len()
    }

    /// Share of samples at or under a budget.
    pub fn within(&self, budget: Duration) -> f64 {
        let limit = budget.as_nanos() as u64;
        let n = self.nanos.partition_point(|x| *x <= limit);
        n as f64 / self.nanos.len().max(1) as f64
    }
}

pub fn fmt(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 1_000 {
        format!("{ns} ns")
    } else if ns < 1_000_000 {
        format!("{:.1} µs", ns as f64 / 1_000.0)
    } else {
        format!("{:.2} ms", ns as f64 / 1_000_000.0)
    }
}

/// Inputs built to cost as much as possible while staying inside the parser's
/// resource limits.
///
/// The steady-state corpus measures what an agent normally emits. These
/// measure what an agent emits when it is trying to get past the gate, and
/// they are the numbers the latency claim actually rests on — an attacker
/// picks the input, so the honest budget is the worst case reachable under the
/// limits, not the median of ordinary work.
///
/// Each one targets a different super-linear risk: re-parsing inner text once
/// per nesting level, rescanning for a matching delimiter from every opening
/// one, and quoted delimiters that defeat a naive scan.
pub fn adversarial_inputs() -> Vec<(&'static str, String)> {
    let mut v = Vec::new();

    v.push(("9k arguments, near the byte cap", format!("echo {}", "arg ".repeat(9000))));

    // Nesting re-parses the innermost payload once per level.
    v.push((
        "depth-30 nesting with a 4 KiB payload",
        format!("echo {}id {}{}", "$(".repeat(30), "x".repeat(4000), ")".repeat(30)),
    ));

    // Each `$(` triggers a forward scan for its match.
    v.push(("3k sibling substitutions", format!("echo {}", "$(id) ".repeat(3000))));

    v.push(("2k-stage pipeline", (0..2000).map(|_| "grep x").collect::<Vec<_>>().join(" | ")));

    // Quoted delimiters inside substitutions: the scan cannot stop at the
    // first `)` it sees, so it must track quote state the whole way.
    v.push((
        "1k quote-confusing substitutions",
        format!("echo {}", r#""$(a ")" b)" "#.repeat(1000)),
    ));

    // Deeply nested parameter expansions with defaults, each of which is
    // rescanned for embedded substitutions.
    v.push(("800 nested parameter defaults", format!("echo {}", "${X:-$(id)} ".repeat(800))));

    v.push((
        "500 here-strings",
        (0..500).map(|i| format!("cat <<<w{i}")).collect::<Vec<_>>().join("\n"),
    ));

    // Must be rejected on sight rather than parsed.
    v.push(("over the byte cap, must be rejected", format!("echo {}", "a".repeat(200_000))));

    v
}

pub struct AdversarialResult {
    pub name: &'static str,
    pub bytes: usize,
    pub p99: Duration,
    pub max: Duration,
    pub verdict: &'static str,
}

pub fn run_adversarial(gate: &Gate, iterations: usize) -> Vec<AdversarialResult> {
    let mut worker = Worker::new();
    let mut out = Vec::new();

    for (name, src) in adversarial_inputs() {
        // Warm once so the first sample is not measuring cold caches.
        std::hint::black_box(gate.evaluate(&src, &mut worker));

        let mut s = Samples::new();
        let mut verdict = "";
        for _ in 0..iterations {
            let t = Instant::now();
            let d = gate.evaluate(&src, &mut worker);
            s.push(t.elapsed());
            verdict = match d.verdict {
                shellguard_policy::Verdict::Allow => "allow",
                shellguard_policy::Verdict::Confine => "confine",
                shellguard_policy::Verdict::Ask => "ask",
                shellguard_policy::Verdict::Deny => "deny",
            };
            std::hint::black_box(&d);
        }
        let s = s.sorted();
        out.push(AdversarialResult {
            name,
            bytes: src.len(),
            p99: s.pct(99.0),
            max: s.max(),
            verdict,
        });
    }
    out
}

/// Per-command timing, for finding what is actually slow.
pub struct CommandTiming {
    pub command: String,
    pub p99: Duration,
    pub max: Duration,
}

pub struct Report {
    pub overall: SortedSamples,
    pub parse_only: SortedSamples,
    pub slowest: Vec<CommandTiming>,
    pub commands: usize,
    pub iterations: usize,
    pub cache_hit_rate: f64,
}

pub fn run(gate: &Gate, commands: &[String], iterations: usize) -> Report {
    let mut worker = Worker::new();

    // Warm the caches and let the CPU settle. Without this the first few
    // hundred samples measure `$PATH` resolution and page faults, which is a
    // real cost but a startup one, and mixing it into the steady-state tail
    // would overstate the number that matters.
    for _ in 0..3 {
        for c in commands {
            std::hint::black_box(gate.evaluate(c, &mut worker));
        }
    }

    let mut overall = Samples::new();
    let mut per_command: Vec<Samples> = (0..commands.len()).map(|_| Samples::new()).collect();

    for _ in 0..iterations {
        for (i, c) in commands.iter().enumerate() {
            let t = Instant::now();
            let d = gate.evaluate(c, &mut worker);
            let elapsed = t.elapsed();
            std::hint::black_box(&d);
            overall.push(elapsed);
            per_command[i].push(elapsed);
        }
    }

    // Parsing alone, to show how the budget divides between reading the
    // command and judging it.
    let mut parse_only = Samples::new();
    for _ in 0..iterations {
        for c in commands {
            let t = Instant::now();
            let r = shellguard_parse::parse(c);
            let elapsed = t.elapsed();
            std::hint::black_box(&r);
            parse_only.push(elapsed);
        }
    }

    let mut slowest: Vec<CommandTiming> = per_command
        .into_iter()
        .zip(commands.iter())
        .map(|(s, c)| {
            let s = s.sorted();
            CommandTiming { command: c.clone(), p99: s.pct(99.0), max: s.max() }
        })
        .collect();
    slowest.sort_by_key(|t| std::cmp::Reverse(t.p99));
    slowest.truncate(8);

    Report {
        overall: overall.sorted(),
        parse_only: parse_only.sorted(),
        slowest,
        commands: commands.len(),
        iterations,
        cache_hit_rate: worker.cache_hit_rate(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples(v: &[u64]) -> SortedSamples {
        let mut s = Samples::new();
        for n in v {
            s.push(Duration::from_nanos(*n));
        }
        s.sorted()
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let s = samples(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(s.pct(50.0), Duration::from_nanos(5));
        assert_eq!(s.pct(90.0), Duration::from_nanos(9));
        assert_eq!(s.pct(100.0), Duration::from_nanos(10));
        assert_eq!(s.max(), Duration::from_nanos(10));
    }

    #[test]
    fn percentiles_of_an_empty_set_are_zero_not_a_panic() {
        let s = samples(&[]);
        assert_eq!(s.pct(99.0), Duration::ZERO);
        assert_eq!(s.max(), Duration::ZERO);
        assert_eq!(s.mean(), Duration::ZERO);
    }

    #[test]
    fn a_single_slow_sample_shows_in_the_tail_but_not_the_mean() {
        // The reason this harness reports percentiles at all.
        let mut v = vec![100u64; 999];
        v.push(50_000_000);
        let s = samples(&v);
        assert!(s.mean() < Duration::from_micros(100), "mean hides it: {:?}", s.mean());
        assert_eq!(s.max(), Duration::from_millis(50));
        assert!(s.pct(100.0) > Duration::from_millis(1));
    }

    #[test]
    fn within_budget_counts_correctly() {
        let s = samples(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 100]);
        assert_eq!(s.within(Duration::from_nanos(9)), 0.9);
        assert_eq!(s.within(Duration::from_nanos(100)), 1.0);
        assert_eq!(s.within(Duration::from_nanos(0)), 0.0);
    }

    #[test]
    fn formatting_picks_a_readable_unit() {
        assert_eq!(fmt(Duration::from_nanos(500)), "500 ns");
        assert_eq!(fmt(Duration::from_nanos(1_500)), "1.5 µs");
        assert_eq!(fmt(Duration::from_millis(2)), "2.00 ms");
    }
}
