//! Running the command corpus and reporting where the ruleset disagrees with
//! it.
//!
//! The corpus is the specification, kept separately from the ruleset that
//! implements it. When a policy edit moves an entry, someone has to decide
//! whether that is a fix or a regression — which is exactly the decision that
//! gets skipped when the only record of intent is the rules themselves.

use std::path::Path;

use shellguard_gate::{Gate, Worker};
use shellguard_policy::Verdict;

#[derive(Clone, Debug)]
pub struct Case {
    pub expected: Verdict,
    pub command: String,
    pub line: usize,
}

pub fn load(path: &Path) -> Result<Vec<Case>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse(&text)
}

pub fn parse(text: &str) -> Result<Vec<Case>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (verdict, command) = trimmed
            .split_once(char::is_whitespace)
            .ok_or_else(|| format!("line {line}: expected `<verdict> <command>`"))?;
        let expected = Verdict::parse(verdict)
            .ok_or_else(|| format!("line {line}: unknown verdict `{verdict}`"))?;
        let command = command.trim().to_string();
        if command.is_empty() {
            return Err(format!("line {line}: no command"));
        }
        out.push(Case { expected, command, line });
    }
    Ok(out)
}

#[derive(Debug)]
pub struct Mismatch {
    pub line: usize,
    pub command: String,
    pub expected: Verdict,
    pub actual: Verdict,
    pub rules: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub passed: usize,
    pub mismatches: Vec<Mismatch>,
    /// Counts per expected verdict, so a corpus that has drifted into being
    /// all-deny is visible.
    pub by_verdict: [usize; 4],
}

pub fn run(gate: &Gate, cases: &[Case]) -> Outcome {
    let mut worker = Worker::new();
    let mut out = Outcome::default();

    for case in cases {
        out.by_verdict[case.expected as usize] += 1;
        let d = gate.evaluate(&case.command, &mut worker);
        if d.verdict == case.expected {
            out.passed += 1;
        } else {
            out.mismatches.push(Mismatch {
                line: case.line,
                command: case.command.clone(),
                expected: case.expected,
                actual: d.verdict,
                rules: d.findings.iter().map(|f| f.rule_id.clone()).collect(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_verdict_and_command() {
        let cases = parse("deny\trm -rf /\nallow  git status\n").unwrap();
        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0].expected, Verdict::Deny);
        assert_eq!(cases[0].command, "rm -rf /");
        assert_eq!(cases[1].expected, Verdict::Allow);
        assert_eq!(cases[1].command, "git status");
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let cases = parse("# a comment\n\n   \ndeny rm -rf /\n").unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].line, 4);
    }

    #[test]
    fn commands_keep_their_own_hashes() {
        // A `#` in a command is part of the command, not a comment.
        let cases = parse("confine git commit -m \"fix #42\"\n").unwrap();
        assert!(cases[0].command.contains("#42"));
    }

    #[test]
    fn rejects_a_bad_verdict_with_a_line_number() {
        let err = parse("deny rm -rf /\nmaybe git status\n").unwrap_err();
        assert!(err.contains("line 2"), "{err}");
        assert!(err.contains("maybe"), "{err}");
    }

    #[test]
    fn rejects_a_verdict_with_no_command() {
        assert!(parse("deny\n").is_err());
        assert!(parse("deny   \n").is_err());
    }
}
