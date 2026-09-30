//! Where a program writes, when it names the place in its arguments.
//!
//! A redirection is the shell writing on a command's behalf, and the gate has
//! always judged those. A program writing to a path it was *given* is the other
//! half, and was invisible: `tar -xf x.tar -C /` extracts into `/`, `cp tool
//! /usr/local/bin/` overwrites a system file, `truncate -s 0 ~/notes` empties
//! one — and all three were `confine`, judged no differently from writing inside
//! the workspace.
//!
//! Which argument is the destination is the program's business, so it is
//! written down here per program, the way `unwrap` writes down each wrapper's
//! options. The rules then ask only "does it write outside the workspace" and
//! "does it write into a path the system owns"; see the `writes-*` directives.
//!
//! Getting an operand wrong in the permissive direction is the failure that
//! matters, so each program's options that take a value are listed: without
//! them `rsync -a src/ dst/ --exclude .git` would take `.git` for the
//! destination.

use crate::normalize::Arg;

/// A place a program writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Dest {
    /// One of the command's arguments, by index.
    Arg(usize),
    /// A value attached to an option: the `/etc` in `--directory=/etc`.
    Text(String),
    /// The directory the command runs in: `tar -x` and `unzip` with no
    /// destination given extract there.
    Here,
}

/// An option's value: the next argument, or text attached to the option.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Arg(usize),
    Text(String),
}

impl From<Value> for Dest {
    fn from(v: Value) -> Dest {
        match v {
            Value::Arg(i) => Dest::Arg(i),
            Value::Text(t) => Dest::Text(t),
        }
    }
}

/// A command line, split into options (with their values) and operands.
struct Parsed {
    /// Option name as written (`-t`, `--target-directory`), and its value.
    values: Vec<(String, Value)>,
    /// Options that took no value, as written.
    flags: Vec<String>,
    /// Indices of operands.
    operands: Vec<usize>,
}

impl Parsed {
    fn values_of(&self, names: &[&str]) -> Vec<Value> {
        self.values
            .iter()
            .filter(|(n, _)| names.contains(&n.as_str()))
            .map(|(_, v)| v.clone())
            .collect()
    }
    fn has(&self, names: &[&str]) -> bool {
        self.flags.iter().any(|f| names.contains(&f.as_str()))
            || self.values.iter().any(|(n, _)| names.contains(&n.as_str()))
    }
    /// A short flag, set on its own or inside a bundle (`-xzf` sets `x`).
    fn has_short(&self, c: char) -> bool {
        self.flags.iter().any(|f| !f.starts_with("--") && f[1..].contains(c))
    }
}

/// Split `args` for a program whose options in `valued` take the next word.
///
/// `bundle_valued`: short options that take a value even inside a bundle, in
/// the order they appear — `tar -xfC a.tar dir` gives `f` the first word and
/// `C` the second.
fn parse(args: &[Arg], valued: &[&str], bundle_valued: &[char]) -> Parsed {
    let mut p = Parsed { values: Vec::new(), flags: Vec::new(), operands: Vec::new() };
    let mut i = 0;
    let mut only_operands = false;
    while i < args.len() {
        let a = &args[i];
        let text = a.literal.as_deref().unwrap_or(&a.prefix);
        let is_option = !only_operands && text.starts_with('-') && text.len() > 1;
        if !is_option {
            p.operands.push(i);
            i += 1;
            continue;
        }
        if a.literal.is_none() {
            // `--$X`: an option nothing can be said about. Skip it, and the
            // word after is still read as whatever it looks like.
            i += 1;
            continue;
        }
        if text == "--" {
            only_operands = true;
            i += 1;
            continue;
        }
        if let Some((name, value)) = text.split_once('=').filter(|_| text.starts_with("--")) {
            p.values.push((name.to_string(), Value::Text(value.to_string())));
            i += 1;
            continue;
        }
        if valued.contains(&text) {
            if i + 1 < args.len() {
                p.values.push((text.to_string(), Value::Arg(i + 1)));
            }
            i += 2;
            continue;
        }
        if !text.starts_with("--") {
            // A short option that takes a value can have it attached: `-C/tmp`.
            let name = &text[..2];
            if valued.contains(&name) && text.len() > 2 {
                p.values.push((name.to_string(), Value::Text(text[2..].to_string())));
                i += 1;
                continue;
            }
            // Or be one of several in a bundle, each taking the next word.
            let mut next = i + 1;
            for c in text[1..].chars() {
                if bundle_valued.contains(&c) && next < args.len() {
                    p.values.push((format!("-{c}"), Value::Arg(next)));
                    next += 1;
                }
            }
            p.flags.push(text.to_string());
            i = next;
            continue;
        }
        p.flags.push(text.to_string());
        i += 1;
    }
    p
}

/// Where `program` writes, given its arguments.
pub(crate) fn destinations(program: &str, args: &[Arg]) -> Vec<Dest> {
    match program {
        "cp" | "gcp" | "mv" | "gmv" | "ln" | "gln" => {
            let p = parse(args, &["-t", "--target-directory", "-S", "--suffix"], &[]);
            copy_like(&p, program.ends_with("ln"))
        }
        "install" | "ginstall" => {
            let p = parse(
                args,
                &[
                    "-t",
                    "--target-directory",
                    "-S",
                    "--suffix",
                    "-m",
                    "--mode",
                    "-o",
                    "--owner",
                    "-g",
                    "--group",
                    "-B",
                    "-f",
                ],
                &[],
            );
            if p.has(&["-d", "--directory"]) {
                // `install -d a b` creates the directories a and b.
                p.operands.iter().map(|&i| Dest::Arg(i)).collect()
            } else {
                copy_like(&p, false)
            }
        }
        "ditto" => {
            let p = parse(args, &["--arch", "--bom"], &[]);
            last_of_two_or_more(&p)
        }
        "rsync" | "openrsync" => {
            let p = parse(args, RSYNC_VALUED, &[]);
            match last_of_two_or_more(&p).as_slice() {
                // `host:path` and `rsync://` are on another machine.
                [Dest::Arg(i)] if is_remote(&args[*i]) => Vec::new(),
                other => other.to_vec(),
            }
        }
        "tar" | "bsdtar" | "gtar" => tar(args),
        "unzip" => {
            let p = parse(args, &["-d", "-P"], &[]);
            let d = p.values_of(&["-d"]);
            if d.is_empty() {
                vec![Dest::Here]
            } else {
                d.into_iter().map(Dest::from).collect()
            }
        }
        "patch" => {
            let p = parse(args, PATCH_VALUED, &[]);
            let out = p.values_of(&["-o", "--output"]);
            if !out.is_empty() {
                return out.into_iter().map(Dest::from).collect();
            }
            // `patch file < diff` patches `file`; otherwise the files the diff
            // names, relative to `-d` or to where the command runs.
            if let Some(&first) = p.operands.first() {
                return vec![Dest::Arg(first)];
            }
            let d = p.values_of(&["-d", "--directory"]);
            if d.is_empty() {
                vec![Dest::Here]
            } else {
                d.into_iter().map(Dest::from).collect()
            }
        }
        "truncate" | "gtruncate" => {
            let p = parse(args, &["-s", "--size", "-r", "--reference"], &[]);
            p.operands.iter().map(|&i| Dest::Arg(i)).collect()
        }
        "tee" | "gtee" => {
            let p = parse(args, &[], &[]);
            p.operands.iter().map(|&i| Dest::Arg(i)).collect()
        }
        _ => Vec::new(),
    }
}

const RSYNC_VALUED: &[&str] = &[
    "-e",
    "--rsh",
    "--exclude",
    "--include",
    "-f",
    "--filter",
    "--files-from",
    "-T",
    "--temp-dir",
    "--backup-dir",
    "--log-file",
    "--partial-dir",
    "--password-file",
    "-B",
    "--block-size",
    "--port",
    "--bwlimit",
    "--timeout",
    "--chmod",
    "--rsync-path",
    "--exclude-from",
    "--include-from",
    "-M",
    "--remote-option",
    "--compare-dest",
    "--copy-dest",
    "--link-dest",
    "--max-size",
    "--min-size",
    "--suffix",
    "--out-format",
    "--contimeout",
    "--address",
    "--sockopts",
    "--modify-window",
    "--iconv",
];

const PATCH_VALUED: &[&str] = &[
    "-d",
    "--directory",
    "-o",
    "--output",
    "-r",
    "--reject-file",
    "-p",
    "--strip",
    "-i",
    "--input",
    "-B",
    "--prefix",
    "-D",
    "--ifdef",
    "-F",
    "--fuzz",
    "-V",
    "--version-control",
    "-Y",
    "--basename-prefix",
    "-z",
    "--suffix",
    "-g",
    "--get",
];

/// `cp`, `mv`, `ln`, `install`: the target directory if one is given, else the
/// last operand when there are two or more. `ln -s target` alone makes the link
/// in the current directory.
fn copy_like(p: &Parsed, is_ln: bool) -> Vec<Dest> {
    let t = p.values_of(&["-t", "--target-directory"]);
    if !t.is_empty() {
        return t.into_iter().map(Dest::from).collect();
    }
    if is_ln && p.operands.len() == 1 {
        return vec![Dest::Here];
    }
    last_of_two_or_more(p)
}

fn last_of_two_or_more(p: &Parsed) -> Vec<Dest> {
    if p.operands.len() >= 2 {
        vec![Dest::Arg(*p.operands.last().unwrap_or(&0))]
    } else {
        Vec::new()
    }
}

fn is_remote(a: &Arg) -> bool {
    let t = a.literal.as_deref().unwrap_or(&a.prefix);
    t.starts_with("rsync://")
        || match (t.find(':'), t.find('/')) {
            (Some(colon), Some(slash)) => colon < slash,
            (Some(_), None) => true,
            (None, _) => false,
        }
}

/// `tar`: extraction writes into `-C`'s directory, or where the command runs;
/// creating, appending or updating writes the archive `-f` names.
///
/// The mode letter may be in a bundle (`-xzf`), a long option (`--extract`), or
/// the old style with no dash at all (`tar xzf a.tgz`), where every letter is an
/// option and `f` takes the next word.
fn tar(args: &[Arg]) -> Vec<Dest> {
    const VALUED: &[&str] = &[
        "-C",
        "--directory",
        "-f",
        "--file",
        "-T",
        "--files-from",
        "-X",
        "--exclude-from",
        "-b",
        "--blocking-factor",
        "--exclude",
        "-s",
        "--format",
        "-I",
        "--use-compress-program",
        "--newer",
        "--newer-mtime",
    ];
    // Old style: the first word is a bundle without its dash. Read it as one.
    let old_style = args.first().and_then(|a| a.literal.as_deref()).is_some_and(|l| {
        !l.starts_with('-') && !l.is_empty() && l.chars().all(|c| c.is_ascii_alphabetic())
    });
    let p = if old_style {
        let mut rest: Vec<Arg> = args.to_vec();
        let bundle = rest[0].literal.clone().unwrap_or_default();
        rest[0].literal = Some(format!("-{bundle}"));
        rest[0].prefix = format!("-{bundle}");
        parse(&rest, VALUED, &['f', 'C', 'b', 'T', 'X'])
    } else {
        parse(args, VALUED, &['f', 'C', 'b', 'T', 'X'])
    };

    let extract = p.has_short('x') || p.has(&["--extract", "--get"]);
    let writes_archive = p.has_short('c')
        || p.has_short('r')
        || p.has_short('u')
        || p.has(&["--create", "--append", "--update"]);

    let mut out = Vec::new();
    if extract {
        let dirs = p.values_of(&["-C", "--directory"]);
        if dirs.is_empty() {
            out.push(Dest::Here);
        } else {
            out.extend(dirs.into_iter().map(Dest::from));
        }
    }
    if writes_archive {
        for v in p.values_of(&["-f", "--file"]) {
            // `-f -` is standard output.
            let is_stdout = match &v {
                Value::Arg(i) => args[*i].literal.as_deref() == Some("-"),
                Value::Text(t) => t == "-",
            };
            if !is_stdout {
                out.push(v.into());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellguard_parse::{parse as parse_shell, Node};

    fn args_of(src: &str) -> (String, Vec<Arg>) {
        let Node::Simple(s) = parse_shell(src).unwrap() else { panic!("not simple: {src}") };
        let program = s.program_basename().unwrap();
        let args = s
            .args()
            .iter()
            .map(|w| Arg { literal: w.literal(), prefix: w.literal_prefix(), ..Default::default() })
            .collect();
        (program, args)
    }

    /// The destinations of `src`, as text.
    fn dests(src: &str) -> Vec<String> {
        let (program, args) = args_of(src);
        destinations(&program, &args)
            .into_iter()
            .map(|d| match d {
                Dest::Arg(i) => args[i].literal.clone().unwrap_or_else(|| format!("${i}")),
                Dest::Text(t) => t,
                Dest::Here => ".".into(),
            })
            .collect()
    }

    #[test]
    fn copy_like_programs_write_their_last_operand_or_target_directory() {
        assert_eq!(dests("cp a b"), ["b"]);
        assert_eq!(dests("cp -r a b c /dst"), ["/dst"]);
        assert_eq!(dests("cp -t /dst a b"), ["/dst"]);
        assert_eq!(dests("cp --target-directory=/dst a"), ["/dst"]);
        assert_eq!(dests("cp -S .bak a /dst"), ["/dst"]);
        assert_eq!(dests("cp -- -weird /dst"), ["/dst"]);
        assert_eq!(dests("mv a /etc/"), ["/etc/"]);
        assert_eq!(dests("ln -sf a ~/.bashrc"), ["~/.bashrc"]);
        assert_eq!(dests("ln -s /etc/passwd"), ["."]);
        assert_eq!(dests("install -m 755 tool /usr/local/bin/"), ["/usr/local/bin/"]);
        assert_eq!(dests("install -d /opt/a /opt/b"), ["/opt/a", "/opt/b"]);
        assert_eq!(dests("ditto src /dst"), ["/dst"]);
        // One operand writes nothing (and fails).
        assert!(dests("cp a").is_empty());
    }

    #[test]
    fn rsync_skips_option_values_and_remote_destinations() {
        assert_eq!(dests("rsync -a src/ dst/ --exclude .git"), ["dst/"]);
        assert_eq!(dests("rsync -a -e ssh src/ /dst"), ["/dst"]);
        assert!(dests("rsync -a src/ host:/dst").is_empty());
        assert!(dests("rsync -a src/ rsync://host/mod").is_empty());
        // A colon after a slash is part of a local name.
        assert_eq!(dests("rsync -a src/ ./a:b"), ["./a:b"]);
    }

    #[test]
    fn tar_writes_where_it_extracts_or_the_archive_it_creates() {
        assert_eq!(dests("tar -xf x.tar -C /"), ["/"]);
        assert_eq!(dests("tar -xzf x.tgz --directory=/etc"), ["/etc"]);
        assert_eq!(dests("tar -xf x.tar -C/opt"), ["/opt"]);
        assert_eq!(dests("tar xzf x.tgz -C /opt"), ["/opt"]);
        assert_eq!(dests("tar -xf x.tar"), ["."]);
        assert_eq!(dests("tar --extract --file x.tar"), ["."]);
        assert_eq!(dests("tar -xfC x.tar /opt"), ["/opt"]);
        assert_eq!(dests("tar -czf /backup/a.tgz src"), ["/backup/a.tgz"]);
        assert_eq!(dests("tar czf /backup/a.tgz src"), ["/backup/a.tgz"]);
        assert_eq!(dests("tar -rf /backup/a.tar more"), ["/backup/a.tar"]);
        // Listing writes nothing; creating to stdout writes no file.
        assert!(dests("tar -tf x.tar").is_empty());
        assert!(dests("tar -czf - src").is_empty());
        // `-C` while creating is where files are read from.
        assert_eq!(dests("tar -czf out.tgz -C /etc hosts"), ["out.tgz"]);
    }

    #[test]
    fn unzip_patch_truncate_tee() {
        assert_eq!(dests("unzip x.zip -d ~/.ssh"), ["~/.ssh"]);
        assert_eq!(dests("unzip x.zip"), ["."]);
        assert_eq!(dests("unzip -P secret x.zip"), ["."]);
        assert_eq!(dests("patch -p1 -d /etc"), ["/etc"]);
        assert_eq!(dests("patch -o /tmp/out orig"), ["/tmp/out"]);
        assert_eq!(dests("patch /etc/hosts"), ["/etc/hosts"]);
        assert_eq!(dests("patch -p1"), ["."]);
        assert_eq!(dests("truncate -s 0 ~/a ~/b"), ["~/a", "~/b"]);
        assert_eq!(dests("truncate -r ref ~/a"), ["~/a"]);
        assert_eq!(dests("tee -a ~/.zshrc /tmp/x"), ["~/.zshrc", "/tmp/x"]);
        // Programs that are not in the table write nothing the gate knows of.
        assert!(dests("ls /etc").is_empty());
    }
}
