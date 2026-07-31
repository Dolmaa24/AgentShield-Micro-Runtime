//! The syntax tree, and the taint lattice that makes it useful for security.
//!
//! A plain syntax tree is not enough to judge a command. `rm -rf $TARGET` and
//! `rm -rf build/` have identical shapes; only one of them can be reasoned
//! about ahead of time. Every [`Word`] therefore carries a [`Taint`] recording
//! how much of its final value is knowable before the shell expands it, and
//! every [`Simple`] command carries an [`Opacity`] recording whether we even
//! know which program it will run.

use std::fmt;

/// A byte range in the original command text.
///
/// Spans are what let a decision point at the exact substring that triggered
/// it. An agent operator who is told "denied: rule destructive.rm-outside-root"
/// will ask "where?", and a rule that cannot answer that is a rule people
/// eventually turn off.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Span { start: start as u32, end: end as u32 }
    }

    pub fn to(self, other: Span) -> Span {
        Span { start: self.start.min(other.start), end: self.end.max(other.end) }
    }

    pub fn slice<'a>(&self, src: &'a str) -> &'a str {
        let start = (self.start as usize).min(src.len());
        let end = (self.end as usize).min(src.len());
        // Spans come from a byte lexer, so they can in principle land inside a
        // multi-byte character if the input is malformed. Widen to the nearest
        // boundary rather than panicking: this runs on untrusted input.
        let start = floor_char_boundary(src, start);
        let end = ceil_char_boundary(src, end);
        if start <= end {
            &src[start..end]
        } else {
            ""
        }
    }
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

/// How much of a word's final value is knowable before the shell runs.
///
/// This is a join-semilattice ordered `Static < Glob < Variable < Dynamic`.
/// Concatenation joins by taking the maximum: `build/$X` is `Variable` because
/// its most uncertain part is.
///
/// The ordering encodes *how badly* uncertainty defeats analysis, which is not
/// the same as how uncertain the value is. A glob is filesystem-dependent but
/// its shape is still constrained (`*.log` can never expand to `/etc/passwd`).
/// A variable can hold anything, but nothing new *executes* to produce it. A
/// command substitution runs a whole other program to produce the value, so it
/// is both unbounded and itself a thing that needs judging.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub enum Taint {
    /// Fully literal. `rm -rf build/`
    #[default]
    Static = 0,
    /// Contains unquoted glob metacharacters. `rm -rf build/*`
    Glob = 1,
    /// Contains a parameter expansion. `rm -rf $TARGET`
    Variable = 2,
    /// Contains a command or process substitution. ``rm -rf `find . -name x` ``
    Dynamic = 3,
}

impl Taint {
    pub fn join(self, other: Taint) -> Taint {
        if self >= other {
            self
        } else {
            other
        }
    }

    /// Whether the value is fully determined by the command text alone.
    pub fn is_static(self) -> bool {
        self == Taint::Static
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Taint::Static => "static",
            Taint::Glob => "glob",
            Taint::Variable => "variable",
            Taint::Dynamic => "dynamic",
        }
    }
}

/// Whether we know which program a command will actually run.
///
/// This is deliberately separate from [`Taint`]. A tainted *argument* narrows
/// what we can say about a command's effects; a tainted *executable name*
/// means we cannot say anything at all, because the entire ruleset is keyed on
/// program identity. `$CMD -rf /` matches no rule for `rm` — and that is
/// exactly why treating "matched no deny rule" as "allow" is unsound.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum Opacity {
    /// The executable is a literal. `git status`
    #[default]
    Transparent,
    /// The executable comes from a parameter. `$EDITOR file`
    Indirect,
    /// The command text itself is computed at runtime, so no static reading of
    /// this command is faithful. `eval "$payload"`, `bash -c "$x"`
    Opaque,
}

impl Opacity {
    pub fn join(self, other: Opacity) -> Opacity {
        if self >= other {
            self
        } else {
            other
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Opacity::Transparent => "transparent",
            Opacity::Indirect => "indirect",
            Opacity::Opaque => "opaque",
        }
    }
}

/// One piece of a word. Words are sequences of parts because shell words
/// concatenate without delimiters: `--out=$DIR/x` is four parts.
#[derive(Clone, Debug)]
pub enum WordPart {
    /// Literal text, already unescaped and unquoted.
    Literal(String),
    /// `$NAME` or `${NAME...}`. `op` holds any modifier (`:-`, `#`, `/`) so a
    /// rule can tell `${PATH}` from `${PATH##*/}`.
    Variable { name: String, braced: bool, op: Option<String> },
    /// `$(...)` or a backquoted command. Parsed, because its contents need
    /// judging too — the inner command runs with the same privileges.
    CommandSub { node: Box<Node>, backquoted: bool },
    /// `$((...))`. Retained as text; arithmetic has no filesystem effects.
    ArithSub(String),
    /// `<(...)` or `>(...)`. Runs a command *and* creates a pipe path.
    ProcSub { write: bool, node: Box<Node> },
    /// Unquoted glob metacharacters, kept separate so `*` in `rm *` is visible
    /// to rules but `*` in `rm '*'` is just a literal.
    Glob(String),
    /// `~` or `~user`.
    Tilde(String),
}

impl WordPart {
    pub fn taint(&self) -> Taint {
        match self {
            WordPart::Literal(_) | WordPart::Tilde(_) => Taint::Static,
            WordPart::Glob(_) => Taint::Glob,
            WordPart::Variable { .. } => Taint::Variable,
            WordPart::ArithSub(_) => Taint::Variable,
            WordPart::CommandSub { .. } | WordPart::ProcSub { .. } => Taint::Dynamic,
        }
    }
}

/// A single shell word: one argument, one redirect target, one assignment RHS.
#[derive(Clone, Debug)]
pub struct Word {
    pub parts: Vec<WordPart>,
    pub span: Span,
    /// True if any part of the word was inside quotes. Quoting suppresses both
    /// globbing and field splitting, which changes what a value can become:
    /// `rm $X` with `X="a b"` deletes two files, `rm "$X"` deletes one.
    pub quoted: bool,
}

impl Word {
    pub fn new(parts: Vec<WordPart>, span: Span, quoted: bool) -> Self {
        Word { parts, span, quoted }
    }

    pub fn taint(&self) -> Taint {
        self.parts.iter().fold(Taint::Static, |acc, p| acc.join(p.taint()))
    }

    /// The word's value, if it is fully literal. `None` for anything that needs
    /// expansion — callers must not guess a value for those.
    pub fn literal(&self) -> Option<String> {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                WordPart::Literal(s) => out.push_str(s),
                WordPart::Tilde(s) => {
                    out.push('~');
                    out.push_str(s);
                }
                _ => return None,
            }
        }
        Some(out)
    }

    /// The leading run of literal characters.
    ///
    /// Useful precisely where full literals are not: `--output=$F` has no
    /// literal value, but the prefix `--output=` is enough to know it is a flag
    /// that names an output file. Matching on prefixes is how a ruleset stays
    /// useful in the presence of taint instead of giving up at the first `$`.
    pub fn literal_prefix(&self) -> String {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                WordPart::Literal(s) => out.push_str(s),
                WordPart::Tilde(s) => {
                    out.push('~');
                    out.push_str(s);
                }
                _ => break,
            }
        }
        out
    }

    /// Every command substitution and process substitution anywhere in the
    /// word. These are commands in their own right and must be judged.
    pub fn substitutions(&self) -> Vec<&Node> {
        let mut out = Vec::new();
        for part in &self.parts {
            match part {
                WordPart::CommandSub { node, .. } | WordPart::ProcSub { node, .. } => {
                    out.push(node.as_ref())
                }
                _ => {}
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Whether the word looks like an option rather than an operand.
    pub fn is_flag(&self) -> bool {
        let p = self.literal_prefix();
        p.starts_with('-') && p != "-" && p != "--"
    }
}

/// `NAME=value` preceding a command, or a standalone assignment.
#[derive(Clone, Debug)]
pub struct Assignment {
    pub name: String,
    pub value: Word,
    /// `NAME+=value`
    pub append: bool,
    pub span: Span,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedirOp {
    /// `<`
    Read,
    /// `>`
    Write,
    /// `>>`
    Append,
    /// `<>`
    ReadWrite,
    /// `>|` — write even if `noclobber` is set
    Clobber,
    /// `<&`
    DupIn,
    /// `>&`
    DupOut,
    /// `<<` / `<<-`
    Heredoc,
    /// `<<<`
    HereString,
    /// `&>`
    AndWrite,
    /// `&>>`
    AndAppend,
}

impl RedirOp {
    /// Whether this redirection can create or truncate a file. This is the
    /// property rules care about: `cmd > /etc/hosts` is a filesystem write
    /// performed by the shell, not by `cmd`, and a ruleset that only inspects
    /// argv will miss it entirely.
    pub fn writes(self) -> bool {
        matches!(
            self,
            RedirOp::Write
                | RedirOp::Append
                | RedirOp::ReadWrite
                | RedirOp::Clobber
                | RedirOp::AndWrite
                | RedirOp::AndAppend
        )
    }

    /// Whether it truncates an existing file (as opposed to appending).
    pub fn truncates(self) -> bool {
        matches!(self, RedirOp::Write | RedirOp::Clobber | RedirOp::AndWrite)
    }

    pub fn reads(self) -> bool {
        matches!(self, RedirOp::Read | RedirOp::ReadWrite)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RedirOp::Read => "<",
            RedirOp::Write => ">",
            RedirOp::Append => ">>",
            RedirOp::ReadWrite => "<>",
            RedirOp::Clobber => ">|",
            RedirOp::DupIn => "<&",
            RedirOp::DupOut => ">&",
            RedirOp::Heredoc => "<<",
            RedirOp::HereString => "<<<",
            RedirOp::AndWrite => "&>",
            RedirOp::AndAppend => "&>>",
        }
    }
}

#[derive(Clone, Debug)]
pub enum RedirTarget {
    /// A filename (possibly tainted).
    Word(Word),
    /// `>&2`
    Fd(u32),
    /// `<&-` / `>&-`
    Close,
    /// The body of a here-document.
    Heredoc { body: String, quoted: bool },
}

#[derive(Clone, Debug)]
pub struct Redirect {
    /// Explicit fd, as in `2>err`. `None` means the operator's default.
    pub fd: Option<u32>,
    pub op: RedirOp,
    pub target: RedirTarget,
    pub span: Span,
}

/// A simple command: assignments, argv, redirections.
#[derive(Clone, Debug)]
pub struct Simple {
    pub assignments: Vec<Assignment>,
    pub words: Vec<Word>,
    pub redirects: Vec<Redirect>,
    pub span: Span,
}

impl Simple {
    /// The word naming the program, if there is one. A command can be pure
    /// assignment (`FOO=bar`) or pure redirection (`> file`), both of which
    /// have effects but no argv.
    pub fn argv0(&self) -> Option<&Word> {
        self.words.first()
    }

    /// The program name as a literal, if it is one.
    pub fn program(&self) -> Option<String> {
        self.argv0().and_then(|w| w.literal())
    }

    /// The program name reduced to its basename: `/usr/bin/rm` -> `rm`.
    ///
    /// Rules key on this. Note that basename matching alone is not an identity
    /// check — see `shellguard-gate`, which also resolves the path and hashes
    /// the target, because `./rm` and `/bin/rm` share a basename and nothing
    /// else.
    pub fn program_basename(&self) -> Option<String> {
        let p = self.program()?;
        Some(basename(&p).to_string())
    }

    pub fn args(&self) -> &[Word] {
        if self.words.is_empty() {
            &[]
        } else {
            &self.words[1..]
        }
    }

    pub fn opacity(&self) -> Opacity {
        match self.argv0() {
            None => Opacity::Transparent,
            Some(w) => match w.taint() {
                Taint::Static => Opacity::Transparent,
                Taint::Glob => Opacity::Indirect,
                Taint::Variable => Opacity::Indirect,
                Taint::Dynamic => Opacity::Opaque,
            },
        }
    }

    /// The highest taint across all arguments.
    pub fn arg_taint(&self) -> Taint {
        self.args().iter().fold(Taint::Static, |acc, w| acc.join(w.taint()))
    }
}

pub fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ListOp {
    /// `;` or newline
    Seq,
    /// `&&`
    And,
    /// `||`
    Or,
    /// `&`
    Background,
}

#[derive(Clone, Debug)]
pub struct ListItem {
    pub node: Node,
    /// The operator that *follows* this item.
    pub op: ListOp,
}

#[derive(Clone, Debug)]
pub struct CaseArm {
    pub patterns: Vec<Word>,
    pub body: Node,
}

#[derive(Clone, Debug)]
pub enum Node {
    Empty,
    Simple(Simple),
    /// `a | b | c`. `stderr_piped[i]` records whether the pipe after command
    /// `i` was `|&`.
    Pipeline {
        negated: bool,
        commands: Vec<Node>,
        stderr_piped: Vec<bool>,
        span: Span,
    },
    List {
        items: Vec<ListItem>,
        span: Span,
    },
    /// `( ... )` — runs in a child shell.
    Subshell {
        body: Box<Node>,
        redirects: Vec<Redirect>,
        span: Span,
    },
    /// `{ ...; }` — runs in the current shell.
    Group {
        body: Box<Node>,
        redirects: Vec<Redirect>,
        span: Span,
    },
    If {
        cond: Box<Node>,
        then: Box<Node>,
        otherwise: Option<Box<Node>>,
        span: Span,
    },
    For {
        var: String,
        words: Vec<Word>,
        body: Box<Node>,
        span: Span,
    },
    /// `while` / `until`
    Loop {
        until: bool,
        cond: Box<Node>,
        body: Box<Node>,
        span: Span,
    },
    Case {
        word: Word,
        arms: Vec<CaseArm>,
        span: Span,
    },
    Function {
        name: String,
        body: Box<Node>,
        span: Span,
    },
    /// `[[ ... ]]`. Its words can contain substitutions, which still run.
    Cond {
        words: Vec<Word>,
        span: Span,
    },
    /// `(( ... ))`
    Arith {
        text: String,
        span: Span,
    },
}

impl Node {
    pub fn span(&self) -> Span {
        match self {
            Node::Empty => Span::default(),
            Node::Simple(s) => s.span,
            Node::Pipeline { span, .. }
            | Node::List { span, .. }
            | Node::Subshell { span, .. }
            | Node::Group { span, .. }
            | Node::If { span, .. }
            | Node::For { span, .. }
            | Node::Loop { span, .. }
            | Node::Case { span, .. }
            | Node::Function { span, .. }
            | Node::Cond { span, .. }
            | Node::Arith { span, .. } => *span,
        }
    }
}

/// Where a command sits relative to the top level of the input.
///
/// The gate uses this to explain decisions ("denied: `curl | sh` — the piped
/// command is opaque") and to apply depth-sensitive rules. It does *not* use it
/// to discount anything: a command nested inside `if false; then ... fi` is
/// still reported, because deciding it is unreachable would require evaluating
/// the condition, and evaluating conditions is the shell's job, not ours.
#[derive(Clone, Copy, Debug, Default)]
pub struct Context {
    /// Nesting depth in the syntax tree.
    pub depth: u32,
    /// The command appears inside `$(...)`, `` `...` `` or `<(...)`.
    pub in_substitution: bool,
    /// The command appears inside a subshell, function body, loop or branch,
    /// rather than on the straight-line path.
    pub nested: bool,
    /// The command is a stage in a pipeline.
    pub in_pipeline: bool,
}

/// A simple command together with where it was found.
#[derive(Clone, Copy, Debug)]
pub struct CommandRef<'a> {
    pub simple: &'a Simple,
    pub ctx: Context,
}

impl Node {
    /// Visit every simple command in the tree, including those hidden inside
    /// command substitutions, process substitutions, here-strings, redirect
    /// targets and `[[ ]]` operands.
    ///
    /// Completeness here is the whole ballgame. Every place this walk fails to
    /// look is a place an agent can hide a command from the ruleset, and the
    /// interesting ones are not the obvious `$( )`: a redirect target can carry
    /// a substitution (`cat > "$(cmd)"`), and so can a `case` pattern.
    pub fn for_each_command<'a, F: FnMut(CommandRef<'a>)>(&'a self, f: &mut F) {
        self.walk(Context::default(), f);
    }

    fn walk<'a, F: FnMut(CommandRef<'a>)>(&'a self, ctx: Context, f: &mut F) {
        let deeper = Context { depth: ctx.depth + 1, ..ctx };
        let nested = Context { depth: ctx.depth + 1, nested: true, ..ctx };

        match self {
            Node::Empty => {}
            Node::Simple(s) => {
                f(CommandRef { simple: s, ctx });
                for w in &s.words {
                    walk_word(w, deeper, f);
                }
                for a in &s.assignments {
                    walk_word(&a.value, deeper, f);
                }
                for r in &s.redirects {
                    if let RedirTarget::Word(w) = &r.target {
                        walk_word(w, deeper, f);
                    }
                }
            }
            Node::Pipeline { commands, .. } => {
                let pctx = Context { depth: ctx.depth + 1, in_pipeline: true, ..ctx };
                for c in commands {
                    c.walk(pctx, f);
                }
            }
            Node::List { items, .. } => {
                for it in items {
                    it.node.walk(deeper, f);
                }
            }
            Node::Subshell { body, redirects, .. } | Node::Group { body, redirects, .. } => {
                body.walk(nested, f);
                for r in redirects {
                    if let RedirTarget::Word(w) = &r.target {
                        walk_word(w, deeper, f);
                    }
                }
            }
            Node::If { cond, then, otherwise, .. } => {
                cond.walk(nested, f);
                then.walk(nested, f);
                if let Some(o) = otherwise {
                    o.walk(nested, f);
                }
            }
            Node::For { words, body, .. } => {
                for w in words {
                    walk_word(w, nested, f);
                }
                body.walk(nested, f);
            }
            Node::Loop { cond, body, .. } => {
                cond.walk(nested, f);
                body.walk(nested, f);
            }
            Node::Case { word, arms, .. } => {
                walk_word(word, nested, f);
                for arm in arms {
                    for p in &arm.patterns {
                        walk_word(p, nested, f);
                    }
                    arm.body.walk(nested, f);
                }
            }
            Node::Function { body, .. } => body.walk(nested, f),
            Node::Cond { words, .. } => {
                for w in words {
                    walk_word(w, nested, f);
                }
            }
            Node::Arith { .. } => {}
        }
    }
}

fn walk_word<'a, F: FnMut(CommandRef<'a>)>(w: &'a Word, ctx: Context, f: &mut F) {
    let sub = Context { depth: ctx.depth + 1, in_substitution: true, nested: true, ..ctx };
    for part in &w.parts {
        match part {
            WordPart::CommandSub { node, .. } | WordPart::ProcSub { node, .. } => node.walk(sub, f),
            _ => {}
        }
    }
}
