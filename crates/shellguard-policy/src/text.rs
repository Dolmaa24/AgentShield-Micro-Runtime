//! The policy file format.
//!
//! Line-oriented and hand-parsed, for two reasons. The first is that a security
//! boundary should not gain a YAML parser — and its transitive dependencies —
//! purely to read its own configuration. The second is that policy files are
//! read by people during incidents, and a format with one directive per line
//! and no significant punctuation is one that a reviewer can be sure they have
//! understood.
//!
//! ```text
//! version 1
//! default confine
//!
//! rule destructive.rm-recursive-absolute deny
//!   reason recursive delete of an absolute path outside the workspace
//!   program rm
//!   short-flag r
//!   path-outside-workspace
//!   cap fs.delete
//! end
//! ```
//!
//! Directives inside a rule are conjoined; multiple values on one directive are
//! alternatives. `any` / `end-any` gives a disjunction and `not` negates a
//! single directive, but a ruleset that needs much of either is usually a
//! ruleset that wants to be two rules.

use shellguard_parse::{Opacity, Taint};

use crate::compile::Policy;
use crate::model::{Capability, Pred, Rule, Verdict};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for PolicyError {}

pub fn parse_policy(src: &str) -> Result<Policy, PolicyError> {
    let mut policy = Policy { version: 0, default_verdict: Verdict::Confine, rules: Vec::new() };
    let mut current: Option<Rule> = None;
    let mut current_line = 0usize;
    let mut any_block: Option<Vec<Pred>> = None;
    // Where each rule id was first defined. Two rules with one id make every
    // finding ambiguous and every diff wrong, and they are exactly what a
    // copy-paste produces; a live reload has no unit test to catch them.
    let mut defined_at: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for (i, raw) in src.lines().enumerate() {
        let line = i + 1;
        let err = |m: String| PolicyError { line, message: m };

        let trimmed = strip_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens = tokenize(trimmed).map_err(&err)?;
        let (head, args) = tokens.split_first().expect("non-empty after trim");
        let head = head.as_str();

        // ------------------------------------------------------ any / end-any
        if head == "any" {
            if current.is_none() {
                return Err(err("`any` outside a rule".into()));
            }
            if any_block.is_some() {
                return Err(err("nested `any` blocks are not supported".into()));
            }
            any_block = Some(Vec::new());
            continue;
        }
        if head == "end-any" {
            let preds = any_block.take().ok_or_else(|| err("`end-any` without `any`".into()))?;
            if preds.is_empty() {
                return Err(err("empty `any` block".into()));
            }
            current.as_mut().expect("checked when the block opened").preds.push(Pred::Any(preds));
            continue;
        }

        // ------------------------------------------------------------- rule
        if head == "rule" {
            if current.is_some() {
                return Err(err("`rule` inside a rule; missing `end`".into()));
            }
            let id = args.first().ok_or_else(|| err("`rule` needs an id".into()))?.clone();
            if let Some(first) = defined_at.get(&id) {
                return Err(err(format!(
                    "duplicate rule id `{id}` (first defined on line {first})"
                )));
            }
            defined_at.insert(id.clone(), line);
            current_line = line;
            let verdict_tok =
                args.get(1).ok_or_else(|| err(format!("rule `{id}` needs a verdict")))?;
            let verdict = Verdict::parse(verdict_tok)
                .ok_or_else(|| err(format!("unknown verdict `{verdict_tok}`")))?;
            if args.len() > 2 {
                return Err(err("`rule` takes an id and a verdict only".into()));
            }
            current = Some(Rule {
                id,
                verdict,
                reason: String::new(),
                programs: Vec::new(),
                preds: Vec::new(),
                caps: Vec::new(),
            });
            continue;
        }

        if head == "end" {
            if any_block.is_some() {
                return Err(err("`end` inside an `any` block; expected `end-any`".into()));
            }
            let rule = current.take().ok_or_else(|| err("`end` without `rule`".into()))?;
            if rule.reason.is_empty() {
                return Err(err(format!("rule `{}` (line {current_line}) has no reason", rule.id)));
            }
            if rule.programs.is_empty() && rule.preds.is_empty() {
                // A rule with no program and no predicate matches everything,
                // which is never what anyone meant to write.
                return Err(err(format!("rule `{}` matches every command", rule.id)));
            }
            policy.rules.push(rule);
            continue;
        }

        // --------------------------------------------------------- top level
        if current.is_none() {
            match head {
                "version" => {
                    let v = args.first().ok_or_else(|| err("`version` needs a number".into()))?;
                    policy.version = v.parse().map_err(|_| err(format!("bad version `{v}`")))?;
                }
                "default" => {
                    let v = args.first().ok_or_else(|| err("`default` needs a verdict".into()))?;
                    policy.default_verdict =
                        Verdict::parse(v).ok_or_else(|| err(format!("unknown verdict `{v}`")))?;
                }
                other => return Err(err(format!("unknown directive `{other}`"))),
            }
            continue;
        }

        // --------------------------------------------------- inside a rule
        let rule = current.as_mut().expect("checked above");

        match head {
            "reason" => {
                if any_block.is_some() {
                    return Err(err("`reason` cannot appear inside `any`".into()));
                }
                rule.reason = args.join(" ");
                if rule.reason.is_empty() {
                    return Err(err("`reason` needs text".into()));
                }
            }
            "program" => {
                if any_block.is_some() {
                    return Err(err("`program` cannot appear inside `any`".into()));
                }
                if args.is_empty() {
                    return Err(err("`program` needs at least one name".into()));
                }
                rule.programs.extend(args.iter().cloned());
            }
            "cap" => {
                if any_block.is_some() {
                    return Err(err("`cap` cannot appear inside `any`".into()));
                }
                if args.is_empty() {
                    return Err(err("`cap` needs at least one capability".into()));
                }
                for a in args {
                    let c = Capability::parse(a)
                        .ok_or_else(|| err(format!("unknown capability `{a}`")))?;
                    rule.caps.push(c);
                }
            }
            "not" => {
                let (inner_head, inner_args) =
                    args.split_first().ok_or_else(|| err("`not` needs a directive".into()))?;
                let p = predicate(inner_head, inner_args).map_err(&err)?;
                let p = Pred::Not(Box::new(p));
                match &mut any_block {
                    Some(b) => b.push(p),
                    None => rule.preds.push(p),
                }
            }
            _ => {
                let p = predicate(head, args).map_err(&err)?;
                match &mut any_block {
                    Some(b) => b.push(p),
                    None => rule.preds.push(p),
                }
            }
        }
    }

    if any_block.is_some() {
        return Err(PolicyError {
            line: src.lines().count(),
            message: "unterminated `any` block".into(),
        });
    }
    if let Some(r) = current {
        return Err(PolicyError {
            line: src.lines().count(),
            message: format!("unterminated rule `{}`", r.id),
        });
    }
    if policy.version == 0 {
        return Err(PolicyError { line: 1, message: "policy has no `version`".into() });
    }

    Ok(policy)
}

fn predicate(head: &str, args: &[String]) -> Result<Pred, String> {
    let need = |what: &str| -> Result<(), String> {
        if args.is_empty() {
            Err(format!("`{head}` needs {what}"))
        } else {
            Ok(())
        }
    };
    let none = |p: Pred| -> Result<Pred, String> {
        if args.is_empty() {
            Ok(p)
        } else {
            Err(format!("`{head}` takes no arguments"))
        }
    };
    let vals = || args.to_vec();

    Ok(match head {
        "always" => none(Pred::Always)?,
        "arg-eq" => {
            need("at least one value")?;
            Pred::ArgEq(vals())
        }
        "arg-prefix" => {
            need("at least one value")?;
            Pred::ArgPrefix(vals())
        }
        "arg-contains" => {
            need("at least one value")?;
            Pred::ArgContains(vals())
        }
        "arg-contains-nocase" => {
            need("at least one value")?;
            // Stored lowercased, so a value written `core.sshCommand` still
            // matches — the reader should not have to know to lowercase it.
            Pred::ArgContainsNoCase(args.iter().map(|a| a.to_ascii_lowercase()).collect())
        }
        "arg-suffix" => {
            need("at least one value")?;
            Pred::ArgSuffix(vals())
        }
        "text-contains" => {
            need("at least one value")?;
            Pred::TextContains(vals())
        }
        "subcommand" => {
            need("at least one value")?;
            Pred::Subcommand(vals())
        }
        "arg-at" => {
            let idx = args.first().ok_or_else(|| "`arg-at` needs an index".to_string())?;
            let idx: usize =
                idx.parse().map_err(|_| format!("`arg-at` index `{idx}` is not a number"))?;
            let rest = &args[1..];
            if rest.is_empty() {
                return Err("`arg-at` needs at least one value".into());
            }
            Pred::ArgAt(idx, rest.to_vec())
        }
        "arg-last" => {
            need("at least one value")?;
            Pred::ArgLast(vals())
        }
        "short-flag" => {
            need("at least one flag character")?;
            let chars: Vec<char> = args.iter().flat_map(|a| a.chars()).collect();
            Pred::ShortFlag(chars)
        }
        "taint-at-least" => {
            let v = args.first().ok_or_else(|| "`taint-at-least` needs a level".to_string())?;
            Pred::TaintAtLeast(match v.as_str() {
                "static" => Taint::Static,
                "glob" => Taint::Glob,
                "variable" => Taint::Variable,
                "dynamic" => Taint::Dynamic,
                other => return Err(format!("unknown taint level `{other}`")),
            })
        }
        "opacity-at-least" => {
            let v = args.first().ok_or_else(|| "`opacity-at-least` needs a level".to_string())?;
            Pred::OpacityAtLeast(match v.as_str() {
                "transparent" => Opacity::Transparent,
                "indirect" => Opacity::Indirect,
                "opaque" => Opacity::Opaque,
                other => return Err(format!("unknown opacity level `{other}`")),
            })
        }
        "write-redirect" => none(Pred::WriteRedirect)?,
        "truncating-redirect" => none(Pred::TruncatingRedirect)?,
        "write-redirect-outside" => none(Pred::WriteRedirectOutside)?,
        "write-target-prefix" => {
            need("at least one prefix")?;
            Pred::WriteTargetPrefix(vals())
        }
        "assigns" => {
            need("at least one variable name")?;
            Pred::Assigns(vals())
        }
        "path-outside-workspace" => none(Pred::PathOutsideWorkspace)?,
        "writes-outside" => none(Pred::WritesOutside)?,
        "writes-under" => {
            need("at least one directory")?;
            for a in args {
                if !a.starts_with('/') || !a.ends_with('/') {
                    return Err(format!(
                        "`writes-under` entry `{a}` must be an absolute directory ending in `/`"
                    ));
                }
            }
            Pred::WritesUnder(vals())
        }
        "unresolved-path" => none(Pred::UnresolvedPath)?,
        "absolute-path-arg" => none(Pred::AbsolutePathArg)?,
        "pipes-into" => {
            need("at least one program")?;
            Pred::PipesInto(vals())
        }
        "piped-from" => {
            need("at least one program")?;
            Pred::PipedFrom(vals())
        }
        "wrap-depth-at-least" => {
            let v =
                args.first().ok_or_else(|| "`wrap-depth-at-least` needs a number".to_string())?;
            Pred::WrapDepthAtLeast(v.parse().map_err(|_| format!("bad depth `{v}`"))?)
        }
        "no-positional" => none(Pred::NoPositional)?,
        "flags-within" => {
            need("at least one flag")?;
            // Each entry is checked because a wrong one does not fail loudly: an
            // entry that can never match just makes the rule quietly narrower,
            // and `-vv` (which reads as a flag) would never match anything.
            for a in args {
                let long = a.strip_prefix("--").is_some_and(|n| !n.is_empty() && !n.contains('='));
                let short = a.len() == 2 && a.starts_with('-') && !a.starts_with("--");
                if !long && !short {
                    return Err(format!(
                        "`flags-within` entry `{a}` must be `--name` or a single `-x` \
                         (a bundle like `-vv` is matched flag by flag)"
                    ));
                }
            }
            Pred::FlagsWithin(vals())
        }
        other => return Err(format!("unknown directive `{other}`")),
    })
}

/// Strip a trailing `#` comment, but not one inside a quoted value.
fn strip_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let mut in_quote = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'"' => in_quote = !in_quote,
            b'#' if !in_quote => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

/// Split on whitespace, honouring double quotes so values can contain spaces.
fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut has_token = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(n) => {
                    cur.push(n);
                    has_token = true;
                }
                None => return Err("trailing backslash".into()),
            },
            '"' => {
                in_quote = !in_quote;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quote => {
                if has_token {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if in_quote {
        return Err("unterminated quote".into());
    }
    if has_token {
        out.push(cur);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "version 1\ndefault confine\n";

    fn parse_ok(src: &str) -> Policy {
        parse_policy(src).unwrap_or_else(|e| panic!("{e}"))
    }

    fn parse_err(src: &str) -> String {
        parse_policy(src).unwrap_err().message
    }

    #[test]
    fn minimal_policy() {
        let p = parse_ok(MINIMAL);
        assert_eq!(p.version, 1);
        assert_eq!(p.default_verdict, Verdict::Confine);
        assert!(p.rules.is_empty());
    }

    #[test]
    fn a_full_rule() {
        let src = format!(
            "{MINIMAL}
rule destructive.rm deny
  reason recursive delete outside the workspace
  program rm
  short-flag rf
  path-outside-workspace
  cap fs.delete
end
"
        );
        let p = parse_ok(&src);
        assert_eq!(p.rules.len(), 1);
        let r = &p.rules[0];
        assert_eq!(r.id, "destructive.rm");
        assert_eq!(r.verdict, Verdict::Deny);
        assert_eq!(r.reason, "recursive delete outside the workspace");
        assert_eq!(r.programs, vec!["rm"]);
        assert_eq!(r.caps, vec![Capability::FsDelete]);
        assert_eq!(r.preds.len(), 2);
        assert!(matches!(r.preds[0], Pred::ShortFlag(_)));
    }

    #[test]
    fn no_positional_and_flags_within_parse() {
        let src = format!(
            "{MINIMAL}
rule t allow
  reason t
  program git
  subcommand branch
  flags-within --list --sort -a -v
  no-positional
end
"
        );
        let p = parse_ok(&src);
        assert_eq!(
            p.rules[0].preds[1],
            Pred::FlagsWithin(vec!["--list".into(), "--sort".into(), "-a".into(), "-v".into()])
        );
        assert_eq!(p.rules[0].preds[2], Pred::NoPositional);
    }

    #[test]
    fn a_flags_within_entry_that_could_never_match_is_refused_at_load() {
        // A dead entry does not fail; it makes the rule quietly narrower, so the
        // mistakes are refused where they are made.
        for bad in ["-vv", "list", "-", "--", "--sort=x", "--"] {
            let src = format!(
                "{MINIMAL}\nrule t allow\n  reason t\n  program git\n  flags-within {bad}\nend\n"
            );
            let e = parse_err(&src);
            assert!(e.contains("flags-within") && e.contains(bad), "`{bad}`: {e}");
        }
        let e = parse_err(&format!(
            "{MINIMAL}\nrule t allow\n  reason t\n  program git\n  flags-within\nend\n"
        ));
        assert!(e.contains("needs at least one flag"), "{e}");
        let e = parse_err(&format!(
            "{MINIMAL}\nrule t allow\n  reason t\n  program git\n  no-positional x\nend\n"
        ));
        assert!(e.contains("takes no arguments"), "{e}");
    }

    #[test]
    fn writes_under_takes_absolute_directories_only() {
        let ok = format!("{MINIMAL}\nrule t deny\n  reason t\n  writes-under /etc/ /usr/\nend\n");
        assert_eq!(
            parse_ok(&ok).rules[0].preds[0],
            Pred::WritesUnder(vec!["/etc/".into(), "/usr/".into()])
        );
        // Without the trailing `/`, `/etc` would also match `/etcetera`.
        for bad in ["/etc", "etc/", "~/x/"] {
            let src = format!("{MINIMAL}\nrule t deny\n  reason t\n  writes-under {bad}\nend\n");
            let e = parse_err(&src);
            assert!(e.contains("writes-under") && e.contains(bad), "`{bad}`: {e}");
        }
        let e =
            parse_err(&format!("{MINIMAL}\nrule t deny\n  reason t\n  writes-outside x\nend\n"));
        assert!(e.contains("takes no arguments"), "{e}");
    }

    #[test]
    fn quoted_values_keep_spaces() {
        let src = format!(
            "{MINIMAL}
rule t ask
  reason t
  arg-eq \"two words\"
end
"
        );
        let p = parse_ok(&src);
        let Pred::ArgEq(v) = &p.rules[0].preds[0] else { panic!() };
        assert_eq!(v, &vec!["two words".to_string()]);
    }

    #[test]
    fn comments_are_stripped_except_inside_quotes() {
        let src = format!(
            "{MINIMAL}
# a comment
rule t ask
  reason t     # trailing comment
  arg-eq \"has # inside\"
end
"
        );
        let p = parse_ok(&src);
        assert_eq!(p.rules[0].reason, "t");
        let Pred::ArgEq(v) = &p.rules[0].preds[0] else { panic!() };
        assert_eq!(v, &vec!["has # inside".to_string()]);
    }

    #[test]
    fn any_block_becomes_a_disjunction() {
        let src = format!(
            "{MINIMAL}
rule t deny
  reason t
  program rm
  any
    arg-eq /
    arg-eq /usr
  end-any
end
"
        );
        let p = parse_ok(&src);
        let Pred::Any(preds) = &p.rules[0].preds[0] else { panic!("expected Any") };
        assert_eq!(preds.len(), 2);
    }

    #[test]
    fn not_negates_a_directive() {
        let src = format!(
            "{MINIMAL}
rule t deny
  reason t
  program rm
  not path-outside-workspace
end
"
        );
        let p = parse_ok(&src);
        assert!(matches!(p.rules[0].preds[0], Pred::Not(_)));
    }

    // ------------------------------------------------- rejecting bad policy

    #[test]
    fn a_rule_that_matches_everything_is_rejected() {
        // The most dangerous typo in a policy file is one that widens a rule.
        let src = format!("{MINIMAL}\nrule t deny\n  reason t\nend\n");
        assert!(parse_err(&src).contains("matches every command"));
    }

    #[test]
    fn a_rule_without_a_reason_is_rejected() {
        let src = format!("{MINIMAL}\nrule t deny\n  program rm\nend\n");
        assert!(parse_err(&src).contains("no reason"));
    }

    #[test]
    fn missing_version_is_rejected() {
        assert!(parse_err("default confine\n").contains("no `version`"));
    }

    #[test]
    fn unterminated_rule_is_rejected() {
        let src = format!("{MINIMAL}\nrule t deny\n  reason t\n  program rm\n");
        assert!(parse_err(&src).contains("unterminated rule"));
    }

    #[test]
    fn unterminated_any_is_rejected() {
        let src =
            format!("{MINIMAL}\nrule t deny\n  reason t\n  program rm\n  any\n    arg-eq /\nend\n");
        assert!(parse_err(&src).contains("expected `end-any`"));
    }

    #[test]
    fn unknown_directive_is_rejected() {
        let src = format!("{MINIMAL}\nrule t deny\n  reason t\n  program rm\n  frobnicate\nend\n");
        assert!(parse_err(&src).contains("unknown directive"));
    }

    #[test]
    fn unknown_verdict_and_capability_are_rejected() {
        let src = format!("{MINIMAL}\nrule t maybe\n  reason t\nend\n");
        assert!(parse_err(&src).contains("unknown verdict"));
        let src =
            format!("{MINIMAL}\nrule t deny\n  reason t\n  program rm\n  cap fs.teleport\nend\n");
        assert!(parse_err(&src).contains("unknown capability"));
    }

    #[test]
    fn directives_needing_values_reject_empty() {
        let src = format!("{MINIMAL}\nrule t deny\n  reason t\n  program rm\n  arg-eq\nend\n");
        assert!(parse_err(&src).contains("at least one value"));
    }

    #[test]
    fn flag_directives_reject_stray_arguments() {
        // `write-redirect /etc` is almost certainly a misunderstanding of the
        // directive, so it is an error rather than a silently ignored argument.
        let src = format!(
            "{MINIMAL}\nrule t deny\n  reason t\n  program rm\n  write-redirect /etc\nend\n"
        );
        assert!(parse_err(&src).contains("takes no arguments"));
    }

    #[test]
    fn errors_carry_line_numbers() {
        // MINIMAL is two lines and ends in a newline, so the blank separator is
        // line 3 and `frobnicate` lands on line 7.
        let src = format!("{MINIMAL}\nrule t deny\n  reason t\n  program rm\n  frobnicate\nend\n");
        assert_eq!(parse_policy(&src).unwrap_err().line, 7);
    }

    #[test]
    fn tokenizer_handles_quotes_and_escapes() {
        assert_eq!(tokenize("a b c").unwrap(), vec!["a", "b", "c"]);
        assert_eq!(tokenize(r#"a "b c" d"#).unwrap(), vec!["a", "b c", "d"]);
        assert_eq!(tokenize(r"a b\ c").unwrap(), vec!["a", "b c"]);
        assert_eq!(tokenize(r#"a "" b"#).unwrap(), vec!["a", "", "b"]);
        assert!(tokenize(r#"a "unterminated"#).is_err());
    }
}
