//! What the gate returns.

use std::time::Duration;

use shellguard_parse::Span;
use shellguard_policy::{Capability, Verdict};

/// Escape a string as a JSON string literal.
///
/// Control characters are escaped rather than passed through: this output
/// carries attacker-influenced command text, and a raw newline or terminal
/// escape sequence in a log line is how a refusal gets made to look like an
/// approval in whatever reads it next.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Why the gate decided what it decided.
///
/// Every finding carries a span and an excerpt. That is not presentation
/// polish: an operator who cannot see *which part* of a 300-character command
/// tripped a rule cannot tell a true positive from a false one, and a gate
/// whose refusals cannot be checked is a gate that gets bypassed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub verdict: Verdict,
    pub reason: String,
    /// The program this finding is about, after wrapper unwrapping — so a
    /// finding on `sudo timeout 5 rm -rf /` names `rm`, not `sudo`.
    pub program: Option<String>,
    pub span: Span,
    /// The command text the span covers.
    pub excerpt: String,
    /// How many wrappers were peeled off to reach this command.
    pub wrap_depth: u8,
    /// The wrapper this command was recovered from, if any. A finding about
    /// `rm` on a command whose text says `find` is confusing without it.
    pub via: Option<&'static str>,
    pub caps: Vec<Capability>,
}

/// Why the gate could not complete a full evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incomplete {
    /// The command did not parse. Not a benign condition: unparseable input is
    /// what a successful evasion attempt looks like from in here.
    Parse(String),
    /// Evaluation ran past its deadline.
    Deadline { budget: Duration, elapsed: Duration },
    /// A wrapper chain or nested shell string was deeper than the unwrap limit.
    UnwrapDepth,
}

impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Incomplete::Parse(e) => write!(f, "command did not parse: {e}"),
            Incomplete::Deadline { budget, elapsed } => {
                write!(f, "evaluation exceeded its {budget:?} budget after {elapsed:?}")
            }
            Incomplete::UnwrapDepth => write!(f, "wrapper nesting exceeded the unwrap limit"),
        }
    }
}

/// One command the gate saw, after resolution and unwrapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSummary {
    pub program: Option<String>,
    pub resolved_path: Option<String>,
    pub span: Span,
    pub wrap_depth: u8,
    /// The command was reached by unwrapping a wrapper, so it does not appear
    /// as written in the original text.
    pub synthetic: bool,
}

/// The gate's answer.
#[derive(Clone, Debug)]
pub struct Decision {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    /// Union of capabilities across every rule that fired.
    pub capabilities: Vec<Capability>,
    pub commands: Vec<CommandSummary>,
    /// Set when evaluation could not be completed. A decision with this set is
    /// never [`Verdict::Allow`].
    pub incomplete: Option<Incomplete>,
    pub elapsed: Duration,
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        self.verdict == Verdict::Allow
    }

    pub fn is_denied(&self) -> bool {
        self.verdict == Verdict::Deny
    }

    /// Serialise to JSON.
    ///
    /// Hand-written because the whole workspace carries no dependencies, and
    /// because the shape of this output is a published interface that agent
    /// harnesses parse — it should change when someone decides to change it,
    /// not when a derive macro's defaults do.
    pub fn to_json(&self, command: &str) -> String {
        let mut s = String::with_capacity(256 + self.findings.len() * 160);
        s.push_str("{\"command\":");
        json_str(&mut s, command);
        s.push_str(",\"verdict\":");
        json_str(&mut s, self.verdict.as_str());
        s.push_str(&format!(",\"elapsed_ns\":{}", self.elapsed.as_nanos()));
        s.push_str(&format!(",\"complete\":{}", self.incomplete.is_none()));
        if let Some(i) = &self.incomplete {
            s.push_str(",\"incomplete\":");
            json_str(&mut s, &i.to_string());
        }

        s.push_str(",\"capabilities\":[");
        for (i, c) in self.capabilities.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            json_str(&mut s, c.as_str());
        }
        s.push(']');

        s.push_str(",\"findings\":[");
        for (i, f) in self.findings.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"rule\":");
            json_str(&mut s, &f.rule_id);
            s.push_str(",\"verdict\":");
            json_str(&mut s, f.verdict.as_str());
            s.push_str(",\"reason\":");
            json_str(&mut s, &f.reason);
            s.push_str(",\"excerpt\":");
            json_str(&mut s, f.excerpt.trim());
            if let Some(p) = &f.program {
                s.push_str(",\"program\":");
                json_str(&mut s, p);
            }
            if let Some(v) = f.via {
                s.push_str(",\"via\":");
                json_str(&mut s, v);
            }
            s.push_str(&format!(",\"span\":[{},{}]", f.span.start, f.span.end));
            s.push_str(",\"capabilities\":[");
            for (j, c) in f.caps.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                json_str(&mut s, c.as_str());
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        s
    }

    /// A one-line summary suitable for a log record.
    pub fn summary(&self) -> String {
        let mut s = String::new();
        s.push_str(self.verdict.as_str());
        if let Some(inc) = &self.incomplete {
            s.push_str(" (");
            s.push_str(&inc.to_string());
            s.push(')');
        }
        if let Some(f) = self.findings.first() {
            s.push_str(": ");
            s.push_str(&f.rule_id);
            s.push_str(" — ");
            s.push_str(&f.reason);
            if let (Some(p), Some(via)) = (&f.program, f.via) {
                s.push_str(&format!(" [{p} via {via}]"));
            }
            if self.findings.len() > 1 {
                s.push_str(&format!(" (+{} more)", self.findings.len() - 1));
            }
        }
        s
    }
}
