//! Peeling wrappers off a command to find the program that will actually run.
//!
//! # Why this exists
//!
//! Every rule in the policy keys on program identity, and the cheapest way past
//! such a ruleset is to not be the program. `sudo rm -rf /` is a `sudo`
//! command. `timeout 5 rm -rf /` is a `timeout` command. `find . -exec rm {} \;`
//! is a `find` command. `xargs rm` is an `xargs` command. None of them match a
//! rule about `rm`, and all of them delete the same files.
//!
//! The answer is not to add `sudo`, `timeout`, `find` and `xargs` to the `rm`
//! rules — that multiplies out and still loses to the combination nobody
//! enumerated. It is to recover the inner command and judge *that*, so one rule
//! about `rm` covers `sudo env timeout 5 nice -n 10 rm -rf /` without anyone
//! having written that down.
//!
//! Unwrapping is applied repeatedly up to a depth limit, so chains are handled;
//! exceeding the limit is reported, not ignored.

use shellguard_parse::{Simple, Span, Word};

/// A command recovered from inside a wrapper.
#[derive(Clone, Debug)]
pub enum Unwrapped<'a> {
    /// The inner command is a run of words from the outer one.
    Argv { words: &'a [Word], via: &'static str },
    /// The inner command is shell source that has to be parsed.
    ShellText { text: String, span: Span, via: &'static str },
}

impl Unwrapped<'_> {
    pub fn via(&self) -> &'static str {
        match self {
            Unwrapped::Argv { via, .. } | Unwrapped::ShellText { via, .. } => via,
        }
    }
}

/// How to skip a wrapper's own options to find where its payload starts.
struct Shape {
    /// Options that consume a following word as their value.
    value_flags: &'static [&'static str],
    /// Positional arguments belonging to the wrapper itself, such as
    /// `timeout`'s duration.
    positionals: usize,
    /// `NAME=value` arguments belong to the wrapper, as with `env`.
    assignments: bool,
}

const PLAIN: Shape = Shape { value_flags: &[], positionals: 0, assignments: false };

fn shape_for(program: &str) -> Option<(Shape, &'static str)> {
    Some(match program {
        "sudo" => (
            Shape {
                value_flags: &[
                    "-u", "-g", "-C", "-p", "-r", "-t", "-h", "--user", "--group", "--prompt",
                    "--close-from", "--role", "--type", "--host",
                ],
                positionals: 0,
                assignments: true,
            },
            "sudo",
        ),
        "doas" => (
            Shape { value_flags: &["-u", "-C"], positionals: 0, assignments: false },
            "doas",
        ),
        "env" => (
            Shape {
                value_flags: &["-u", "-C", "-S", "--unset", "--chdir", "--split-string"],
                positionals: 0,
                assignments: true,
            },
            "env",
        ),
        "nohup" => (PLAIN, "nohup"),
        "setsid" => (PLAIN, "setsid"),
        "eatmydata" => (PLAIN, "eatmydata"),
        "proxychains" | "proxychains4" => (PLAIN, "proxychains"),
        "stdbuf" => (
            Shape { value_flags: &["-i", "-o", "-e"], positionals: 0, assignments: false },
            "stdbuf",
        ),
        "nice" => (
            Shape { value_flags: &["-n", "--adjustment"], positionals: 0, assignments: false },
            "nice",
        ),
        "ionice" => (
            Shape { value_flags: &["-c", "-n", "-p", "-t"], positionals: 0, assignments: false },
            "ionice",
        ),
        // `timeout DURATION COMMAND` — the duration is the wrapper's own.
        "timeout" | "gtimeout" => (
            Shape {
                value_flags: &["-s", "-k", "--signal", "--kill-after"],
                positionals: 1,
                assignments: false,
            },
            "timeout",
        ),
        "taskset" => (
            Shape { value_flags: &["-p", "-c"], positionals: 1, assignments: false },
            "taskset",
        ),
        "watch" => (
            Shape {
                value_flags: &["-n", "-d", "--interval"],
                positionals: 0,
                assignments: false,
            },
            "watch",
        ),
        "strace" | "ltrace" | "dtruss" | "ktrace" => (
            Shape {
                value_flags: &["-o", "-e", "-p", "-s", "-f"],
                positionals: 0,
                assignments: false,
            },
            "trace",
        ),
        "xargs" | "gxargs" => (
            Shape {
                value_flags: &[
                    "-n", "-P", "-I", "-i", "-d", "-s", "-a", "-E", "-L", "--max-args",
                    "--max-procs", "--replace", "--delimiter", "--max-chars", "--arg-file",
                    "--max-lines",
                ],
                positionals: 0,
                assignments: false,
            },
            "xargs",
        ),
        "command" | "builtin" | "exec" => (PLAIN, "command"),
        _ => return None,
    })
}

/// Shells whose `-c` argument is source code rather than a filename.
fn is_shell(program: &str) -> bool {
    matches!(program, "sh" | "bash" | "zsh" | "dash" | "ksh" | "mksh" | "ash" | "busybox")
}

/// Recover every command hidden inside `s`.
///
/// Returns an empty vector when `s` is not a wrapper, which is the common case
/// and costs one string comparison.
pub fn unwrap_wrapper(s: &Simple) -> Vec<Unwrapped<'_>> {
    let Some(program) = s.program_basename() else {
        return Vec::new();
    };

    if is_shell(&program) {
        return shell_dash_c(s);
    }
    if program == "find" {
        return find_exec(s);
    }
    if let Some((shape, via)) = shape_for(&program) {
        return generic(s, &shape, via);
    }
    Vec::new()
}

/// Skip a wrapper's own options and return whatever follows.
fn generic<'a>(s: &'a Simple, shape: &Shape, via: &'static str) -> Vec<Unwrapped<'a>> {
    let args = s.args();
    let mut i = 0;
    let mut positionals_left = shape.positionals;

    while i < args.len() {
        let Some(lit) = args[i].literal() else {
            // A tainted option cannot be classified, so stop rather than
            // guess. The command is still judged on its own terms, and the
            // taint rules cover the uncertainty.
            return Vec::new();
        };

        if lit == "--" {
            i += 1;
            break;
        }

        if shape.assignments && is_assignment(&lit) {
            i += 1;
            continue;
        }

        if lit.starts_with('-') && lit.len() > 1 {
            // `-n 10` consumes a following word; `-n10` and `-n=10` do not.
            let takes_value = shape
                .value_flags
                .iter()
                .any(|f| lit == *f)
                && !lit.contains('=');
            i += 1;
            if takes_value {
                i += 1;
            }
            continue;
        }

        if positionals_left > 0 {
            positionals_left -= 1;
            i += 1;
            continue;
        }
        break;
    }

    if i >= args.len() {
        return Vec::new();
    }
    vec![Unwrapped::Argv { words: &args[i..], via }]
}

/// `sh -c '<source>'`.
///
/// Only a literal payload is recovered. A computed one cannot be parsed without
/// running the expansion that produces it, which is the thing being judged; the
/// `shell.interpreter-c-computed` rule denies that case outright rather than
/// letting it through unexamined.
fn shell_dash_c(s: &Simple) -> Vec<Unwrapped<'_>> {
    let args = s.args();
    let mut i = 0;
    while i < args.len() {
        let Some(lit) = args[i].literal() else { return Vec::new() };
        let is_c = lit == "-c"
            || (lit.starts_with('-')
                && !lit.starts_with("--")
                && lit.len() > 1
                && lit[1..].bytes().all(|c| c.is_ascii_alphabetic())
                && lit.contains('c'));
        if is_c {
            let Some(payload) = args.get(i + 1) else { return Vec::new() };
            let Some(text) = payload.literal() else { return Vec::new() };
            return vec![Unwrapped::ShellText { text, span: payload.span, via: "sh -c" }];
        }
        if !lit.starts_with('-') {
            return Vec::new();
        }
        i += 1;
    }
    Vec::new()
}

/// `find ... -exec CMD ... ;` and its relatives.
///
/// A single `find` can carry several of these, so all are returned. The
/// terminator is `;` or `+`; the shell has already stripped the backslash from
/// `\;`, so the word is a plain `;` by the time it reaches here.
fn find_exec(s: &Simple) -> Vec<Unwrapped<'_>> {
    let args = s.args();
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let Some(lit) = args[i].literal() else {
            i += 1;
            continue;
        };
        let via = match lit.as_str() {
            "-exec" => "find -exec",
            "-execdir" => "find -execdir",
            "-ok" => "find -ok",
            "-okdir" => "find -okdir",
            _ => {
                i += 1;
                continue;
            }
        };
        let start = i + 1;
        let mut end = start;
        while end < args.len() {
            match args[end].literal().as_deref() {
                Some(";") | Some("+") => break,
                _ => end += 1,
            }
        }
        if start < end {
            out.push(Unwrapped::Argv { words: &args[start..end], via });
        }
        i = end.max(start) + 1;
    }
    out
}

fn is_assignment(s: &str) -> bool {
    match s.find('=') {
        Some(0) | None => false,
        Some(i) => {
            let name = &s[..i];
            let mut b = name.bytes();
            match b.next() {
                Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                    b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
                }
                _ => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellguard_parse::{parse, Node};

    fn simple(src: &str) -> Simple {
        match parse(src).unwrap() {
            Node::Simple(s) => s,
            other => panic!("expected a simple command, got {other:?}"),
        }
    }

    /// The recovered program names, in order.
    fn inner(src: &str) -> Vec<String> {
        let s = simple(src);
        unwrap_wrapper(&s)
            .iter()
            .map(|u| match u {
                Unwrapped::Argv { words, .. } => words
                    .first()
                    .and_then(|w| w.literal())
                    .unwrap_or_default(),
                Unwrapped::ShellText { text, .. } => format!("<shell:{text}>"),
            })
            .collect()
    }

    #[test]
    fn plain_commands_are_not_wrappers() {
        assert!(inner("rm -rf /").is_empty());
        assert!(inner("git status").is_empty());
    }

    #[test]
    fn sudo_and_friends() {
        assert_eq!(inner("sudo rm -rf /"), vec!["rm"]);
        assert_eq!(inner("sudo -u root rm -rf /"), vec!["rm"]);
        assert_eq!(inner("doas -u root rm -rf /"), vec!["rm"]);
        assert_eq!(inner("nohup rm -rf /"), vec!["rm"]);
        assert_eq!(inner("setsid rm -rf /"), vec!["rm"]);
    }

    #[test]
    fn env_skips_assignments() {
        assert_eq!(inner("env rm -rf /"), vec!["rm"]);
        assert_eq!(inner("env FOO=bar BAZ=qux rm -rf /"), vec!["rm"]);
        assert_eq!(inner("env -i PATH=/bin rm -rf /"), vec!["rm"]);
        assert_eq!(inner("env -u LD_PRELOAD rm -rf /"), vec!["rm"]);
    }

    #[test]
    fn timeout_skips_its_duration() {
        assert_eq!(inner("timeout 5 rm -rf /"), vec!["rm"]);
        assert_eq!(inner("timeout -s KILL 5 rm -rf /"), vec!["rm"]);
        assert_eq!(inner("timeout --signal=KILL 5 rm -rf /"), vec!["rm"]);
    }

    #[test]
    fn nice_handles_attached_and_separate_values() {
        assert_eq!(inner("nice -n 10 rm -rf /"), vec!["rm"]);
        assert_eq!(inner("nice -n10 rm -rf /"), vec!["rm"]);
        assert_eq!(inner("nice rm -rf /"), vec!["rm"]);
    }

    #[test]
    fn double_dash_ends_options() {
        assert_eq!(inner("sudo -- rm -rf /"), vec!["rm"]);
        assert_eq!(inner("strace -f -- rm -rf /"), vec!["rm"]);
    }

    #[test]
    fn xargs_carries_a_command() {
        assert_eq!(inner("xargs rm -rf"), vec!["rm"]);
        assert_eq!(inner("xargs -0 -n 1 rm -rf"), vec!["rm"]);
        assert_eq!(inner("xargs -I {} rm -rf {}"), vec!["rm"]);
        // With no command, xargs defaults to echo; nothing to recover.
        assert!(inner("xargs").is_empty());
    }

    #[test]
    fn find_exec_in_all_its_forms() {
        assert_eq!(inner(r"find . -exec rm {} \;"), vec!["rm"]);
        assert_eq!(inner(r"find . -execdir rm {} \;"), vec!["rm"]);
        assert_eq!(inner(r"find . -ok rm {} \;"), vec!["rm"]);
        assert_eq!(inner("find . -exec rm {} +"), vec!["rm"]);
        // A find with no -exec yields nothing.
        assert!(inner("find . -name '*.log'").is_empty());
    }

    #[test]
    fn find_with_several_exec_clauses() {
        assert_eq!(
            inner(r"find . -exec chmod 777 {} \; -exec rm {} \;"),
            vec!["chmod", "rm"]
        );
    }

    #[test]
    fn shell_dash_c_yields_source() {
        assert_eq!(inner("bash -c 'rm -rf /'"), vec!["<shell:rm -rf />"]);
        assert_eq!(inner("sh -c 'rm -rf /'"), vec!["<shell:rm -rf />"]);
        // Bundled flags containing `c`.
        assert_eq!(inner("bash -lc 'rm -rf /'"), vec!["<shell:rm -rf />"]);
    }

    #[test]
    fn a_computed_shell_payload_is_not_recovered() {
        // Nothing can be parsed here without running the expansion, so the
        // unwrapper declines and the taint rules take over.
        assert!(inner(r#"bash -c "$PAYLOAD""#).is_empty());
        assert!(inner("bash -c $(gen)").is_empty());
    }

    #[test]
    fn a_tainted_wrapper_option_stops_unwrapping() {
        // `sudo $FLAG rm -rf /` — we cannot tell whether $FLAG consumes `rm`.
        assert!(inner("sudo $FLAG rm -rf /").is_empty());
    }

    #[test]
    fn shell_without_dash_c_is_not_unwrapped() {
        // `bash script.sh` runs a file, whose contents are not in the command.
        assert!(inner("bash script.sh").is_empty());
        assert!(inner("sh -x script.sh").is_empty());
    }

    #[test]
    fn assignment_detection() {
        assert!(is_assignment("FOO=bar"));
        assert!(is_assignment("_x=1"));
        assert!(is_assignment("FOO="));
        assert!(!is_assignment("=bar"));
        assert!(!is_assignment("2FOO=bar"));
        assert!(!is_assignment("--flag"));
        assert!(!is_assignment("plain"));
    }
}
