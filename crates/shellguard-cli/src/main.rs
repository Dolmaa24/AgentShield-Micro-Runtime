//! `shellguard` — evaluate, verify and measure.

mod bench;
mod corpus;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use shellguard_enforce::Profile;
use shellguard_gate::{Decision, Gate, GateConfig, Worker};
use shellguard_policy::Verdict;

const USAGE: &str = "\
shellguard — decide whether an agent's shell command should run

USAGE:
    shellguard eval    [OPTIONS] <command>     judge one command
    shellguard run     [OPTIONS] <command>     judge it, run it, roll back on failure
    shellguard profile [OPTIONS] <command>     show the sandbox profile it would get
    shellguard corpus  [OPTIONS] [FILE]        check the ruleset against expectations
    shellguard bench   [OPTIONS] [FILE]        measure evaluation latency
    shellguard rules                           list the loaded ruleset

OPTIONS:
    -w, --workspace DIR    the directory the agent may write to (default: cwd)
    -C, --cwd DIR          resolve relative paths against this (default: the workspace)
    -p, --policy FILE      a policy file (default: the built-in ruleset)
    -d, --deadline MS      evaluation budget in milliseconds (default: 10)
    -n, --iterations N     bench iterations over the corpus (default: 200)
        --json             machine-readable output (eval and run)
        --protect PATH     a file that must not change (repeatable; run only)
        --rollback-on-failure  revert if the command exits non-zero (run only)
        --run-on-ask       run commands the gate escalates (run only)
        --audit FILE       append every judgment and execution to FILE as JSON
                           lines, secrets redacted (also: $SHELLGUARD_AUDIT)
        --audit-verbose    also record stdout and stderr, redacted (run only)
        --audit-required   refuse to run, or answer, if the record cannot be
                           written (default: warn and carry on)
        --audit-max-bytes N  rotate the log at N bytes (default 8 MiB, min 128 KiB)
        --audit-keep N     rotated files to keep (default 5; 0 keeps none)
    -h, --help             this text
    -V, --version          version and backend

EXIT STATUS:
    0  allow      2  ask        64  usage error
    1  confine    3  deny       65  internal error
";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("shellguard: {e}");
            ExitCode::from(64)
        }
    }
}

#[derive(Default)]
struct Opts {
    workspace: Option<PathBuf>,
    cwd: Option<PathBuf>,
    policy: Option<PathBuf>,
    deadline_ms: Option<u64>,
    iterations: Option<usize>,
    json: bool,
    protect: Vec<PathBuf>,
    rollback_on_failure: bool,
    run_on_ask: bool,
    audit: Option<PathBuf>,
    audit_verbose: bool,
    audit_required: bool,
    audit_max_bytes: Option<u64>,
    audit_keep: Option<usize>,
    rest: Vec<String>,
}

fn run() -> Result<ExitCode, String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print!("{USAGE}");
        return Ok(ExitCode::from(64));
    };

    if matches!(command.as_str(), "-h" | "--help" | "help") {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    if matches!(command.as_str(), "-V" | "--version" | "version") {
        println!(
            "shellguard {} ({} backend on {})",
            env!("CARGO_PKG_VERSION"),
            shellguard_enforce::backend(),
            std::env::consts::OS
        );
        return Ok(ExitCode::SUCCESS);
    }

    let opts = parse_opts(args)?;

    match command.as_str() {
        "eval" => cmd_eval(&opts),
        "run" => cmd_run(&opts),
        "profile" => cmd_profile(&opts),
        "corpus" => cmd_corpus(&opts),
        "bench" => cmd_bench(&opts),
        "rules" => cmd_rules(&opts),
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

fn parse_opts(args: impl Iterator<Item = String>) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut args = args.peekable();
    while let Some(a) = args.next() {
        let mut take = |name: &str| -> Result<String, String> {
            args.next().ok_or_else(|| format!("{name} needs a value"))
        };
        match a.as_str() {
            "-w" | "--workspace" => o.workspace = Some(PathBuf::from(take("--workspace")?)),
            "-C" | "--cwd" => o.cwd = Some(PathBuf::from(take("--cwd")?)),
            "-p" | "--policy" => o.policy = Some(PathBuf::from(take("--policy")?)),
            "-d" | "--deadline" => {
                let v = take("--deadline")?;
                o.deadline_ms = Some(v.parse().map_err(|_| format!("bad deadline `{v}`"))?);
            }
            "-n" | "--iterations" => {
                let v = take("--iterations")?;
                o.iterations = Some(v.parse().map_err(|_| format!("bad count `{v}`"))?);
            }
            "--json" => o.json = true,
            "--protect" => o.protect.push(PathBuf::from(take("--protect")?)),
            "--rollback-on-failure" => o.rollback_on_failure = true,
            "--run-on-ask" => o.run_on_ask = true,
            "--audit" => o.audit = Some(PathBuf::from(take("--audit")?)),
            "--audit-verbose" => o.audit_verbose = true,
            "--audit-required" => o.audit_required = true,
            "--audit-max-bytes" => {
                let v = take("--audit-max-bytes")?;
                o.audit_max_bytes = Some(v.parse().map_err(|_| format!("bad size `{v}`"))?);
            }
            "--audit-keep" => {
                let v = take("--audit-keep")?;
                o.audit_keep = Some(v.parse().map_err(|_| format!("bad count `{v}`"))?);
            }
            "--" => {
                o.rest.extend(args.by_ref());
                break;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option `{other}`"));
            }
            other => o.rest.push(other.to_string()),
        }
    }
    Ok(o)
}

/// Open the audit log if one was asked for, by flag or by `$SHELLGUARD_AUDIT`.
///
/// A log that was asked for and cannot be opened is an error, not a warning:
/// the caller believes they are being recorded. The flag wins over the
/// environment, so a one-off invocation can redirect it.
fn open_audit(o: &Opts) -> Result<Option<shellguard_runtime::audit::AuditLog>, String> {
    use shellguard_runtime::audit::{AuditConfig, AuditLog};

    let path = o.audit.clone().or_else(|| {
        std::env::var_os("SHELLGUARD_AUDIT").filter(|v| !v.is_empty()).map(PathBuf::from)
    });
    let Some(path) = path else {
        if o.audit_verbose
            || o.audit_required
            || o.audit_max_bytes.is_some()
            || o.audit_keep.is_some()
        {
            return Err("the --audit-* options need --audit FILE (or $SHELLGUARD_AUDIT)".into());
        }
        return Ok(None);
    };
    let mut cfg =
        AuditConfig::new(&path).source("cli").verbose(o.audit_verbose).required(o.audit_required);
    if o.audit_max_bytes.is_some() || o.audit_keep.is_some() {
        let (bytes, keep) =
            (o.audit_max_bytes.unwrap_or(cfg.max_bytes), o.audit_keep.unwrap_or(cfg.keep));
        cfg = cfg.rotate_at(bytes, keep);
    }
    AuditLog::open(cfg)
        .map(Some)
        .map_err(|e| format!("cannot open audit log {}: {e}", path.display()))
}

fn build_gate(o: &Opts) -> Result<Gate, String> {
    let workspace = match &o.workspace {
        Some(w) => w.clone(),
        None => std::env::current_dir().map_err(|e| format!("cannot read cwd: {e}"))?,
    };
    let mut cfg = GateConfig::from_env(&workspace);
    // The working directory defaults to the workspace, not to wherever the
    // caller happens to be standing. An agent runs its commands inside its
    // workspace, so resolving `./build` against the caller's shell would make
    // ordinary relative paths look like escapes — a confusing denial, and the
    // kind that teaches people to stop trusting the tool.
    cfg.cwd = o.cwd.clone().unwrap_or(workspace);
    if let Some(ms) = o.deadline_ms {
        cfg.deadline = Duration::from_millis(ms);
    }
    match &o.policy {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
            let policy = shellguard_policy::parse_policy(&text)
                .map_err(|e| format!("{}: {e}", p.display()))?;
            Ok(Gate::new(policy.compile(), cfg))
        }
        None => Ok(Gate::with_default_policy(cfg)),
    }
}

/// The command text, joined from the remaining arguments.
///
/// Joining with spaces rather than requiring one quoted argument, because an
/// agent harness building an argv is more likely to pass words than a shell
/// string, and silently judging only the first word would be the worst
/// possible failure mode for this tool.
fn command_text(o: &Opts) -> Result<String, String> {
    if o.rest.is_empty() {
        return Err("no command given".into());
    }
    Ok(o.rest.join(" "))
}

fn exit_for(v: Verdict) -> ExitCode {
    ExitCode::from(match v {
        Verdict::Allow => 0,
        Verdict::Confine => 1,
        Verdict::Ask => 2,
        Verdict::Deny => 3,
    })
}

// ------------------------------------------------------------------- eval

fn cmd_eval(o: &Opts) -> Result<ExitCode, String> {
    let gate = build_gate(o)?;
    let audit = open_audit(o)?;
    let src = command_text(o)?;
    let mut worker = Worker::new();
    let d = gate.evaluate(&src, &mut worker);

    // Recorded before the answer is printed, so that with `--audit-required`
    // a caller never receives a verdict that was not written down.
    if let Some(log) = &audit {
        let workspace = match &o.workspace {
            Some(w) => w.clone(),
            None => std::env::current_dir().map_err(|e| format!("cannot read cwd: {e}"))?,
        };
        if let Err(e) = log.evaluated(&src, &d, &workspace) {
            eprintln!("shellguard: audit: could not record this judgment: {e}");
            if log.required() {
                // Not a verdict exit code: a caller must not mistake this for
                // an allow, a confine, an ask or a deny.
                return Ok(ExitCode::from(65));
            }
        }
    }

    if o.json {
        print_json(&src, &d);
    } else {
        print_human(&src, &d);
    }
    Ok(exit_for(d.verdict))
}

struct Style {
    on: bool,
}

impl Style {
    fn new() -> Self {
        Style { on: std::io::stdout().is_terminal() }
    }
    fn verdict(&self, v: Verdict) -> String {
        if !self.on {
            return v.as_str().to_uppercase();
        }
        let code = match v {
            Verdict::Allow => "32",
            Verdict::Confine => "36",
            Verdict::Ask => "33",
            Verdict::Deny => "31",
        };
        format!("\x1b[1;{code}m{}\x1b[0m", v.as_str().to_uppercase())
    }
    /// For a message that is neither a verdict nor incidental — a rollback
    /// happened and the reader needs to notice.
    fn warn(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[1;33m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn dim(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[2m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

fn print_human(src: &str, d: &Decision) {
    let st = Style::new();
    println!("{}  {}", st.verdict(d.verdict), src);
    println!("{}", st.dim(&format!("  evaluated in {}", bench::fmt(d.elapsed))));

    if let Some(inc) = &d.incomplete {
        println!("  ! {inc}");
    }

    if d.findings.is_empty() && d.incomplete.is_none() {
        println!("  no rule matched; the policy default applies");
    }

    for f in &d.findings {
        let via = match (&f.program, f.via) {
            (Some(p), Some(v)) => format!(" [{p} via {v}]"),
            (Some(p), None) => format!(" [{p}]"),
            _ => String::new(),
        };
        println!("  {} {}{}", st.verdict(f.verdict), f.rule_id, via);
        println!("      {}", f.reason);
        if !f.excerpt.trim().is_empty() && f.excerpt.trim() != src.trim() {
            println!("{}", st.dim(&format!("      → {}", f.excerpt.trim())));
        }
    }

    if !d.capabilities.is_empty() {
        let caps: Vec<&str> = d.capabilities.iter().map(|c| c.as_str()).collect();
        println!("  capabilities: {}", caps.join(", "));
    }
}

fn print_json(src: &str, d: &Decision) {
    println!("{}", d.to_json(src));
}

// -------------------------------------------------------------------- run

fn cmd_run(o: &Opts) -> Result<ExitCode, String> {
    use shellguard_runtime::{Engine, RollbackPolicy};

    let src = command_text(o)?;
    let workspace = match &o.workspace {
        Some(w) => w.clone(),
        None => std::env::current_dir().map_err(|e| format!("cannot read cwd: {e}"))?,
    };

    let mut engine = Engine::new(&workspace)
        .map_err(|e| format!("cannot open {}: {e}", workspace.display()))?
        .run_on_ask(o.run_on_ask);
    if let Some(log) = open_audit(o)? {
        engine = engine.with_audit(log);
    }
    if let Some(ms) = o.deadline_ms {
        engine = engine.with_timeout(Duration::from_millis(ms));
    }
    if o.rollback_on_failure || !o.protect.is_empty() {
        engine = engine.with_rollback_policy(RollbackPolicy {
            protected: o.protect.clone(),
            on_nonzero_exit: o.rollback_on_failure,
            ..Default::default()
        });
    }

    let run = match engine.execute_with_rollback(&src) {
        Ok(r) => r,
        // Stopped on purpose, before the command started, because it could not
        // be recorded. Distinct from a failure of the command or of the tool.
        Err(e @ shellguard_runtime::RuntimeError::Audit(_)) => {
            eprintln!("shellguard: {e}");
            return Ok(ExitCode::from(65));
        }
        Err(e) => return Err(e.to_string()),
    };
    if let Some(why) = &run.audit_error {
        eprintln!("shellguard: audit: this run was not fully recorded: {why}");
    }

    if o.json {
        println!("{}", run.to_json());
        return Ok(exit_for(run.decision.verdict));
    }

    let st = Style::new();
    if !run.ran() {
        // Nothing ran, so the decision *is* the output.
        print_human(&src, &run.decision);
        return Ok(exit_for(run.decision.verdict));
    }

    let exec = run.exec.as_ref().expect("ran implies an execution");
    print!("{}", String::from_utf8_lossy(&exec.stdout));
    eprint!("{}", String::from_utf8_lossy(&exec.stderr));

    if let Some(g) = &run.guard {
        if g.rolled_back() {
            eprintln!(
                "{}",
                st.warn(&format!("workspace reverted: {}", g.rollback_reasons.join("; ")))
            );
        }
    }
    eprintln!(
        "{}",
        st.dim(&format!(
            "  {} in {} ({} runtime, exit {})",
            run.decision.verdict.as_str(),
            bench::fmt(exec.run),
            engine.runtime_name(),
            exec.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
        ))
    );

    // The command's own exit status, so `shellguard run` composes in a script
    // the way the command it wrapped would have.
    Ok(match exec.exit_code {
        Some(c) if (0..=125).contains(&c) => ExitCode::from(c as u8),
        _ => ExitCode::from(126),
    })
}

// ---------------------------------------------------------------- profile

fn cmd_profile(o: &Opts) -> Result<ExitCode, String> {
    let gate = build_gate(o)?;
    let src = command_text(o)?;
    let mut worker = Worker::new();
    let d = gate.evaluate(&src, &mut worker);

    println!("# verdict: {}", d.verdict.as_str());
    if d.verdict == Verdict::Deny {
        println!("# denied — no profile would be built, the command does not run");
        return Ok(exit_for(d.verdict));
    }

    let profile = Profile::from_capabilities(gate.config().workspace.clone(), &d.capabilities);
    println!("# backend: {}", shellguard_enforce::backend());
    println!();

    #[cfg(target_os = "macos")]
    {
        match shellguard_enforce::macos::profile_sbpl(&profile) {
            Ok(sbpl) => println!("{sbpl}"),
            Err(e) => return Err(e.to_string()),
        }
    }
    #[cfg(target_os = "linux")]
    {
        use shellguard_enforce::linux;
        let p = profile.canonicalized();
        println!("# landlock: read-only");
        println!("#   {}", p.workspace.display());
        for r in &p.read_paths {
            println!("#   {}", r.display());
        }
        println!("# landlock: writable");
        for w in p.writable() {
            println!("#   {}", w.display());
        }
        println!("# seccomp: denied syscalls ({})", linux::seccomp::DENIED.len());
        for s in linux::seccomp::DENIED {
            println!("#   {s}");
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = profile;
        println!("# no confinement backend on this platform");
    }

    Ok(exit_for(d.verdict))
}

// ----------------------------------------------------------------- corpus

fn default_corpus() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/corpus.txt"))
}

fn cmd_corpus(o: &Opts) -> Result<ExitCode, String> {
    let path = o.rest.first().map(PathBuf::from).unwrap_or_else(default_corpus);
    let cases = corpus::load(&path)?;

    // The corpus assumes a workspace that is a scratch directory: `./src` is
    // inside it and `/etc` is not. Using the caller's cwd would make results
    // depend on where they happened to run it from.
    let ws = std::env::temp_dir().join("shellguard-corpus-workspace");
    std::fs::create_dir_all(ws.join("src")).map_err(|e| e.to_string())?;
    let workspace = o.workspace.clone().unwrap_or(ws);

    let mut cfg = GateConfig::from_env(&workspace);
    cfg.cwd = workspace.clone();
    if let Some(ms) = o.deadline_ms {
        cfg.deadline = Duration::from_millis(ms);
    }
    let gate = match &o.policy {
        Some(p) => {
            let text = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
            Gate::new(
                shellguard_policy::parse_policy(&text).map_err(|e| e.to_string())?.compile(),
                cfg,
            )
        }
        None => Gate::with_default_policy(cfg),
    };

    let out = corpus::run(&gate, &cases);
    let st = Style::new();

    for m in &out.mismatches {
        println!(
            "{}:{}  expected {}, got {}",
            path.display(),
            m.line,
            st.verdict(m.expected),
            st.verdict(m.actual)
        );
        println!("    {}", m.command);
        if !m.rules.is_empty() {
            println!("{}", st.dim(&format!("    matched: {}", m.rules.join(", "))));
        }
    }

    let total = cases.len();
    println!();
    println!(
        "{} of {} cases match  (allow {}, confine {}, ask {}, deny {})",
        out.passed,
        total,
        out.by_verdict[Verdict::Allow as usize],
        out.by_verdict[Verdict::Confine as usize],
        out.by_verdict[Verdict::Ask as usize],
        out.by_verdict[Verdict::Deny as usize],
    );

    Ok(if out.mismatches.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

// ------------------------------------------------------------------ bench

fn cmd_bench(o: &Opts) -> Result<ExitCode, String> {
    let path = o.rest.first().map(PathBuf::from).unwrap_or_else(default_corpus);
    let cases = corpus::load(&path)?;
    let commands: Vec<String> = cases.iter().map(|c| c.command.clone()).collect();

    let ws = std::env::temp_dir().join("shellguard-corpus-workspace");
    std::fs::create_dir_all(ws.join("src")).map_err(|e| e.to_string())?;
    let mut cfg = GateConfig::from_env(o.workspace.clone().unwrap_or(ws.clone()));
    cfg.cwd = o.workspace.clone().unwrap_or(ws);
    // The deadline must not fire during measurement, or the harness measures
    // the deadline rather than the work.
    cfg.deadline = Duration::from_secs(60);
    let gate = Gate::with_default_policy(cfg);

    let iterations = o.iterations.unwrap_or(200);
    eprintln!("measuring {} commands x {} iterations ...", commands.len(), iterations);
    let r = bench::run(&gate, &commands, iterations);

    let budget = Duration::from_millis(10);
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "\nshellguard evaluation latency");
    let _ = writeln!(
        out,
        "  {} samples ({} commands x {} iterations), cache hit rate {:.1}%",
        r.overall.len(),
        r.commands,
        r.iterations,
        r.cache_hit_rate * 100.0
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "  {:<10} {:>12} {:>12}", "", "full gate", "parse only");
    for (label, p) in [("p50", 50.0), ("p90", 90.0), ("p99", 99.0), ("p99.9", 99.9), ("max", 100.0)]
    {
        let _ = writeln!(
            out,
            "  {:<10} {:>12} {:>12}",
            label,
            bench::fmt(r.overall.pct(p)),
            bench::fmt(r.parse_only.pct(p))
        );
    }
    let _ = writeln!(
        out,
        "  {:<10} {:>12} {:>12}",
        "mean",
        bench::fmt(r.overall.mean()),
        bench::fmt(r.parse_only.mean())
    );

    let within = r.overall.within(budget);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {:.4}% of evaluations within the {} budget",
        within * 100.0,
        bench::fmt(budget)
    );

    let _ = writeln!(out, "\n  slowest commands       p99        max");
    for t in &r.slowest {
        let c = if t.command.chars().count() > 48 {
            let s: String = t.command.chars().take(47).collect();
            format!("{s}…")
        } else {
            t.command.clone()
        };
        let _ = writeln!(out, "    {:>9}  {:>9}  {}", bench::fmt(t.p99), bench::fmt(t.max), c);
    }

    // The steady-state numbers above describe ordinary work. These describe
    // what an input built to be expensive costs, and that is the number the
    // budget claim actually rests on.
    let adv = bench::run_adversarial(&gate, 30.max(iterations / 10));
    let _ = writeln!(out, "\n  adversarial inputs, at the parser's resource limits:");
    let _ =
        writeln!(out, "    {:>9}  {:>9}  {:>8}  {:>7}  input", "p99", "max", "bytes", "verdict");
    let mut adv_max = Duration::ZERO;
    for a in &adv {
        adv_max = adv_max.max(a.max);
        let _ = writeln!(
            out,
            "    {:>9}  {:>9}  {:>8}  {:>7}  {}",
            bench::fmt(a.p99),
            bench::fmt(a.max),
            a.bytes,
            a.verdict,
            a.name
        );
    }
    let _ = writeln!(
        out,
        "\n  worst case overall: {} ({:.0}x headroom against the {} budget)",
        bench::fmt(adv_max),
        budget.as_nanos() as f64 / adv_max.as_nanos().max(1) as f64,
        bench::fmt(budget)
    );

    let worst = r.overall.max().max(adv_max);
    Ok(if worst <= budget {
        ExitCode::SUCCESS
    } else {
        // Exceeding the budget in a measurement run is a finding, not a crash:
        // the deadline still makes it safe at runtime, but the claim on the tin
        // no longer holds and CI should say so.
        eprintln!("\nworst case {} exceeded the {} budget", bench::fmt(worst), bench::fmt(budget));
        ExitCode::FAILURE
    })
}

// ------------------------------------------------------------------ rules

fn cmd_rules(o: &Opts) -> Result<ExitCode, String> {
    let gate = build_gate(o)?;
    let p = gate.policy();
    println!("{} rules, default verdict {}", p.rule_count(), p.default_verdict().as_str());
    println!(
        "{} prefilter patterns, {} rules evaluated on every command",
        p.prefilter_pattern_count(),
        p.unindexed_rule_count()
    );
    Ok(ExitCode::SUCCESS)
}
