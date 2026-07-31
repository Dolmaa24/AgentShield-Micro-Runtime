//! Recursive-descent bash parser.
//!
//! Scanning and parsing are one pass rather than two layers, because a shell
//! word can contain a whole command (`$(...)`) and a whole command can contain
//! words. Splitting them would need the lexer to call the grammar, so they
//! share a cursor instead.
//!
//! # Failing closed
//!
//! Every error path here is a *deny* signal, never a "couldn't tell, allow".
//! Untrusted input that does not parse is not benign input — it is the shape
//! an evasion attempt takes when it works. The resource limits exist for the
//! same reason: an agent that emits a 40 MB command with 200 000 nested
//! substitutions should get a fast rejection, not a gate that spends its
//! latency budget and then times out into whatever the default was.

use crate::ast::*;
use crate::lex::*;

/// Bounds on what the parser will accept before giving up.
///
/// These are deliberately far above anything a real command needs and far
/// below anything that costs measurable time. A command that exceeds them is
/// not a command, it is a payload.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: u32,
    pub max_nodes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_bytes: 64 * 1024, max_depth: 32, max_nodes: 4096 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge { bytes: usize, limit: usize },
    TooDeep { limit: u32 },
    TooManyNodes { limit: u32 },
    Unterminated { what: &'static str, at: Span },
    Unexpected { found: String, at: Span },
    NotUtf8,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooLarge { bytes, limit } => {
                write!(f, "command is {bytes} bytes, limit is {limit}")
            }
            ParseError::TooDeep { limit } => write!(f, "nesting deeper than {limit}"),
            ParseError::TooManyNodes { limit } => write!(f, "more than {limit} syntax nodes"),
            ParseError::Unterminated { what, at } => write!(f, "unterminated {what} at {at:?}"),
            ParseError::Unexpected { found, at } => {
                write!(f, "unexpected {found} at {at:?}")
            }
            ParseError::NotUtf8 => write!(f, "input is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a command with default limits.
pub fn parse(src: &str) -> Result<Node, ParseError> {
    parse_with_limits(src, Limits::default())
}

pub fn parse_with_limits(src: &str, limits: Limits) -> Result<Node, ParseError> {
    if src.len() > limits.max_bytes {
        return Err(ParseError::TooLarge { bytes: src.len(), limit: limits.max_bytes });
    }
    let mut p = Parser::new(src, limits, 0, 0);
    let node = p.parse_program()?;
    Ok(node)
}

#[derive(Clone, Debug)]
enum Tok {
    Word(Word),
    Op(Op),
    IoNumber(u32),
    Eof,
}

impl Tok {
    fn describe(&self) -> String {
        match self {
            Tok::Word(w) => format!("word `{}`", w.literal_prefix()),
            Tok::Op(o) => format!("`{}`", o.as_str()),
            Tok::IoNumber(n) => format!("fd {n}"),
            Tok::Eof => "end of input".to_string(),
        }
    }
}

struct Parser<'a> {
    text: &'a str,
    src: &'a [u8],
    pos: usize,
    /// Byte offset of this (possibly nested) parser's text within the original
    /// input, so spans stay meaningful inside `$(...)`.
    base: u32,
    limits: Limits,
    depth: u32,
    nodes: u32,
    peeked: Option<(Tok, Span, usize)>,
    /// Where the next here-document body on the current line begins.
    heredoc_cursor: Option<usize>,
    /// A region of the input already consumed as here-document bodies, which
    /// the main cursor must jump over when it reaches it.
    pending_skip: Option<(usize, usize)>,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str, limits: Limits, base: u32, depth: u32) -> Self {
        Parser {
            text,
            src: text.as_bytes(),
            pos: 0,
            base,
            limits,
            depth,
            nodes: 0,
            peeked: None,
            heredoc_cursor: None,
            pending_skip: None,
        }
    }

    fn span(&self, start: usize, end: usize) -> Span {
        Span { start: start as u32 + self.base, end: end as u32 + self.base }
    }

    fn bump_node(&mut self) -> Result<(), ParseError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(ParseError::TooManyNodes { limit: self.limits.max_nodes });
        }
        Ok(())
    }

    // ---------------------------------------------------------------- cursor

    fn peek_byte(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn take_char(&mut self, out: &mut String) {
        match self.text.get(self.pos..).and_then(|s| s.chars().next()) {
            Some(ch) => {
                out.push(ch);
                self.pos += ch.len_utf8();
            }
            None => {
                // Not on a character boundary, which can only happen if a raw
                // slice landed mid-sequence. Advance a byte so we cannot spin.
                self.pos += 1;
            }
        }
    }

    /// Skip blanks, line continuations and comments. Newlines are significant
    /// and are left for the caller.
    fn skip_blanks(&mut self) {
        loop {
            while let Some(c) = self.peek_byte() {
                if is_blank(c) {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.peek_byte() == Some(b'\\') && self.src.get(self.pos + 1) == Some(&b'\n') {
                self.pos += 2;
                continue;
            }
            if self.peek_byte() == Some(b'#') {
                while let Some(c) = self.peek_byte() {
                    if c == b'\n' {
                        break;
                    }
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
    }

    fn skip_newlines(&mut self) -> Result<(), ParseError> {
        loop {
            self.skip_blanks();
            if self.peek_tok()?.0.is_newline() {
                self.next_tok()?;
            } else {
                break;
            }
        }
        Ok(())
    }

    // ----------------------------------------------------------------- token

    fn peek_tok(&mut self) -> Result<(&Tok, Span), ParseError> {
        if self.peeked.is_none() {
            let save = self.pos;
            let (tok, span) = self.scan_token()?;
            let end = self.pos;
            self.pos = save;
            self.peeked = Some((tok, span, end));
        }
        let (t, s, _) = self.peeked.as_ref().expect("just filled");
        Ok((t, *s))
    }

    fn next_tok(&mut self) -> Result<(Tok, Span), ParseError> {
        if let Some((t, s, end)) = self.peeked.take() {
            self.pos = end;
            return Ok((t, s));
        }
        self.scan_token()
    }

    /// Where the lookahead token ends, for the rare place that needs to look at
    /// raw bytes past it (distinguishing `name ()` function definitions).
    fn peek_end(&self) -> usize {
        match &self.peeked {
            Some((_, _, end)) => *end,
            None => self.pos,
        }
    }

    fn scan_token(&mut self) -> Result<(Tok, Span), ParseError> {
        self.skip_blanks();
        let start = self.pos;
        let Some(c) = self.peek_byte() else {
            return Ok((Tok::Eof, self.span(start, start)));
        };

        // `<(` and `>(` are process substitutions, not redirections. Checked
        // before operator scanning because `<` would otherwise win.
        if (c == b'<' || c == b'>') && self.src.get(self.pos + 1) == Some(&b'(') {
            let w = self.scan_word()?;
            let sp = w.span;
            return Ok((Tok::Word(w), sp));
        }

        // A run of digits glued to a redirect operator is an fd number.
        // `2>err` redirects stderr; `2 >err` runs the command `2`.
        if c.is_ascii_digit() {
            let mut j = self.pos;
            while j < self.src.len() && self.src[j].is_ascii_digit() {
                j += 1;
            }
            if matches!(self.src.get(j), Some(b'<') | Some(b'>')) {
                let n: u32 = self.text[self.pos..j].parse().unwrap_or(u32::MAX);
                self.pos = j;
                return Ok((Tok::IoNumber(n), self.span(start, j)));
            }
        }

        if let Some((op, len)) = scan_operator(self.src, self.pos) {
            self.pos += len;
            if op == Op::Newline {
                self.cross_newline();
            }
            return Ok((Tok::Op(op), self.span(start, self.pos)));
        }

        let w = self.scan_word()?;
        let sp = w.span;
        Ok((Tok::Word(w), sp))
    }

    /// After consuming a newline, jump over any here-document bodies that were
    /// read eagerly when their `<<` operator was parsed.
    fn cross_newline(&mut self) {
        if let Some((s, e)) = self.pending_skip {
            if self.pos == s {
                self.pos = e;
            }
        }
        self.pending_skip = None;
        self.heredoc_cursor = None;
    }

    // ------------------------------------------------------------------ word

    fn scan_word(&mut self) -> Result<Word, ParseError> {
        let start = self.pos;
        let mut parts: Vec<WordPart> = Vec::new();
        let mut lit = String::new();
        let mut quoted = false;

        while let Some(c) = self.peek_byte() {
            // Process substitution can begin a segment anywhere in a word.
            if (c == b'<' || c == b'>') && self.src.get(self.pos + 1) == Some(&b'(') {
                flush(&mut parts, &mut lit);
                let write = c == b'>';
                self.pos += 2;
                let close = find_matching(self.src, self.pos, b'(', b')').ok_or(
                    ParseError::Unterminated {
                        what: "process substitution",
                        at: self.span(start, self.pos),
                    },
                )?;
                let inner_start = self.pos;
                let node = self.sub_parse(inner_start, close)?;
                self.pos = close + 1;
                parts.push(WordPart::ProcSub { write, node: Box::new(node) });
                continue;
            }

            if is_meta(c) {
                break;
            }

            match c {
                b'\\' => {
                    if self.src.get(self.pos + 1) == Some(&b'\n') {
                        self.pos += 2;
                        continue;
                    }
                    self.pos += 1;
                    if self.pos < self.src.len() {
                        quoted = true;
                        self.take_char(&mut lit);
                    } else {
                        lit.push('\\');
                    }
                }
                b'\'' => {
                    quoted = true;
                    self.pos += 1;
                    let mut end = self.pos;
                    while end < self.src.len() && self.src[end] != b'\'' {
                        end += 1;
                    }
                    if end >= self.src.len() {
                        return Err(ParseError::Unterminated {
                            what: "single quote",
                            at: self.span(start, self.pos),
                        });
                    }
                    lit.push_str(&String::from_utf8_lossy(&self.src[self.pos..end]));
                    self.pos = end + 1;
                }
                b'"' => {
                    quoted = true;
                    self.pos += 1;
                    self.scan_double_quoted(&mut parts, &mut lit, start)?;
                }
                b'`' => {
                    flush(&mut parts, &mut lit);
                    self.scan_backquote(&mut parts, start)?;
                }
                b'$' => {
                    self.scan_dollar(&mut parts, &mut lit, &mut quoted, start)?;
                }
                b'~' if parts.is_empty() && lit.is_empty() => {
                    self.pos += 1;
                    let mut user = String::new();
                    while let Some(u) = self.peek_byte() {
                        if u.is_ascii_alphanumeric() || matches!(u, b'_' | b'-' | b'.') {
                            user.push(u as char);
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    parts.push(WordPart::Tilde(user));
                }
                b'*' | b'?' => {
                    flush(&mut parts, &mut lit);
                    parts.push(WordPart::Glob((c as char).to_string()));
                    self.pos += 1;
                }
                b'[' => match bracket_glob_end(self.src, self.pos) {
                    Some(end) => {
                        flush(&mut parts, &mut lit);
                        let g = String::from_utf8_lossy(&self.src[self.pos..=end]).into_owned();
                        parts.push(WordPart::Glob(g));
                        self.pos = end + 1;
                    }
                    None => {
                        lit.push('[');
                        self.pos += 1;
                    }
                },
                b'{' => match brace_expansion_end(self.src, self.pos) {
                    Some(end) => {
                        flush(&mut parts, &mut lit);
                        let g = String::from_utf8_lossy(&self.src[self.pos..end]).into_owned();
                        parts.push(WordPart::Glob(g));
                        self.pos = end;
                    }
                    None => {
                        lit.push('{');
                        self.pos += 1;
                    }
                },
                _ => self.take_char(&mut lit),
            }
        }

        flush(&mut parts, &mut lit);
        Ok(Word::new(parts, self.span(start, self.pos), quoted))
    }

    fn scan_double_quoted(
        &mut self,
        parts: &mut Vec<WordPart>,
        lit: &mut String,
        word_start: usize,
    ) -> Result<(), ParseError> {
        loop {
            let Some(c) = self.peek_byte() else {
                return Err(ParseError::Unterminated {
                    what: "double quote",
                    at: self.span(word_start, self.pos),
                });
            };
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(());
                }
                b'\\' => {
                    // Inside double quotes a backslash only escapes these four
                    // characters and a newline. Everywhere else it is literal,
                    // so `"a\b"` really is `a\b`.
                    match self.src.get(self.pos + 1) {
                        Some(n @ (b'$' | b'`' | b'"' | b'\\')) => {
                            lit.push(*n as char);
                            self.pos += 2;
                        }
                        Some(b'\n') => self.pos += 2,
                        _ => {
                            lit.push('\\');
                            self.pos += 1;
                        }
                    }
                }
                b'$' => {
                    let mut q = true;
                    self.scan_dollar(parts, lit, &mut q, word_start)?;
                }
                b'`' => {
                    flush(parts, lit);
                    self.scan_backquote(parts, word_start)?;
                }
                _ => self.take_char(lit),
            }
        }
    }

    fn scan_backquote(
        &mut self,
        parts: &mut Vec<WordPart>,
        word_start: usize,
    ) -> Result<(), ParseError> {
        debug_assert_eq!(self.peek_byte(), Some(b'`'));
        self.pos += 1;
        let inner_start = self.pos;
        let end = find_backquote_end(self.src, self.pos).ok_or(ParseError::Unterminated {
            what: "backquote",
            at: self.span(word_start, self.pos),
        })?;
        // Backquotes have their own escaping rules, so the text has to be
        // unescaped before it is a valid command. That makes inner spans
        // approximate; they are clamped to the substitution as a whole.
        let raw = &self.text[inner_start..end];
        let unescaped = unescape_backquote(raw);
        let node = self.sub_parse_text(&unescaped, inner_start as u32 + self.base)?;
        self.pos = end + 1;
        parts.push(WordPart::CommandSub { node: Box::new(node), backquoted: true });
        Ok(())
    }

    fn scan_dollar(
        &mut self,
        parts: &mut Vec<WordPart>,
        lit: &mut String,
        quoted: &mut bool,
        word_start: usize,
    ) -> Result<(), ParseError> {
        let d = self.pos;
        match self.src.get(d + 1).copied() {
            None => {
                lit.push('$');
                self.pos += 1;
            }
            Some(b'(') if self.src.get(d + 2) == Some(&b'(') => {
                // `$((expr))`, but `$( (subshell) )` has the same prefix. Try
                // arithmetic and fall back if the second `)` is missing.
                if let Some(inner_close) = find_matching(self.src, d + 3, b'(', b')') {
                    if self.src.get(inner_close + 1) == Some(&b')') {
                        let text = self.text[d + 3..inner_close].to_string();
                        self.pos = inner_close + 2;
                        // Arithmetic can still smuggle a command through an
                        // array subscript: `$((a[$(id)]))`. Scan for it.
                        let nested = self.scan_nested_substitutions(d + 3, inner_close)?;
                        flush(parts, lit);
                        parts.push(WordPart::ArithSub(text));
                        parts.extend(nested);
                        return Ok(());
                    }
                }
                self.scan_command_sub(parts, lit, d, word_start)?;
            }
            Some(b'(') => self.scan_command_sub(parts, lit, d, word_start)?,
            Some(b'{') => {
                let close = find_matching(self.src, d + 2, b'{', b'}')
                    .ok_or(ParseError::Unterminated { what: "${", at: self.span(word_start, d) })?;
                let inner = &self.text[d + 2..close];
                let (name, op) = split_param_expansion(inner);
                let nested = self.scan_nested_substitutions(d + 2, close)?;
                flush(parts, lit);
                parts.push(WordPart::Variable { name, braced: true, op });
                parts.extend(nested);
                self.pos = close + 1;
            }
            Some(b'\'') => {
                // `$'...'` decodes to a *static* literal. This matters: it is
                // the standard way to write `rm` so it does not look like `rm`.
                let inner_start = d + 2;
                let mut end = inner_start;
                while end < self.src.len() {
                    if self.src[end] == b'\\' {
                        end += 2;
                        continue;
                    }
                    if self.src[end] == b'\'' {
                        break;
                    }
                    end += 1;
                }
                if end >= self.src.len() {
                    return Err(ParseError::Unterminated {
                        what: "$' quote",
                        at: self.span(word_start, d),
                    });
                }
                *quoted = true;
                lit.push_str(&unescape_ansi_c(&self.src[inner_start..end]));
                self.pos = end + 1;
            }
            Some(b'"') => {
                // `$"..."` is a locale lookup; treat as a double-quoted string.
                *quoted = true;
                self.pos = d + 2;
                self.scan_double_quoted(parts, lit, word_start)?;
            }
            Some(c) if is_name_start(c) => {
                let mut end = d + 1;
                while end < self.src.len() && is_name_char(self.src[end]) {
                    end += 1;
                }
                let name = self.text[d + 1..end].to_string();
                flush(parts, lit);
                parts.push(WordPart::Variable { name, braced: false, op: None });
                self.pos = end;
            }
            Some(c) if is_special_param(c) => {
                flush(parts, lit);
                parts.push(WordPart::Variable {
                    name: (c as char).to_string(),
                    braced: false,
                    op: None,
                });
                self.pos = d + 2;
            }
            _ => {
                lit.push('$');
                self.pos += 1;
            }
        }
        Ok(())
    }

    fn scan_command_sub(
        &mut self,
        parts: &mut Vec<WordPart>,
        lit: &mut String,
        d: usize,
        word_start: usize,
    ) -> Result<(), ParseError> {
        let close = find_matching(self.src, d + 2, b'(', b')')
            .ok_or(ParseError::Unterminated { what: "$( ", at: self.span(word_start, d) })?;
        let node = self.sub_parse(d + 2, close)?;
        self.pos = close + 1;
        flush(parts, lit);
        parts.push(WordPart::CommandSub { node: Box::new(node), backquoted: false });
        Ok(())
    }

    /// Find command substitutions inside a region that is otherwise handled as
    /// text, such as `${X:-$(cmd)}` or `$((a[$(cmd)]))`.
    ///
    /// Without this, a default-value expansion is a blind spot: the parser
    /// records "a variable" and the command hidden in its fallback never
    /// reaches any rule.
    fn scan_nested_substitutions(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<Vec<WordPart>, ParseError> {
        let mut out = Vec::new();
        let mut i = start;
        while i < end {
            match self.src[i] {
                b'\\' => i += 2,
                b'\'' => {
                    i += 1;
                    while i < end && self.src[i] != b'\'' {
                        i += 1;
                    }
                    i += 1;
                }
                b'$' if self.src.get(i + 1) == Some(&b'(')
                    && self.src.get(i + 2) != Some(&b'(') =>
                {
                    match find_matching(self.src, i + 2, b'(', b')') {
                        Some(close) if close < end => {
                            let node = self.sub_parse(i + 2, close)?;
                            out.push(WordPart::CommandSub {
                                node: Box::new(node),
                                backquoted: false,
                            });
                            i = close + 1;
                        }
                        _ => i += 1,
                    }
                }
                b'`' => match find_backquote_end(self.src, i + 1) {
                    Some(close) if close < end => {
                        let unescaped = unescape_backquote(&self.text[i + 1..close]);
                        let node = self.sub_parse_text(&unescaped, i as u32 + 1 + self.base)?;
                        out.push(WordPart::CommandSub { node: Box::new(node), backquoted: true });
                        i = close + 1;
                    }
                    _ => i += 1,
                },
                _ => i += 1,
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------------ sub-parsing

    fn sub_parse(&mut self, start: usize, end: usize) -> Result<Node, ParseError> {
        let text = &self.text[start..end];
        self.sub_parse_text(text, start as u32 + self.base)
    }

    fn sub_parse_text(&mut self, text: &str, base: u32) -> Result<Node, ParseError> {
        if self.depth + 1 > self.limits.max_depth {
            return Err(ParseError::TooDeep { limit: self.limits.max_depth });
        }
        let mut inner = Parser::new(text, self.limits, base, self.depth + 1);
        // Share the node budget so nesting cannot multiply total work.
        inner.nodes = self.nodes;
        let node = inner.parse_program()?;
        self.nodes = inner.nodes;
        Ok(node)
    }

    // --------------------------------------------------------------- grammar

    fn parse_program(&mut self) -> Result<Node, ParseError> {
        let node = self.parse_list(&[])?;
        self.skip_newlines()?;
        let (tok, span) = self.peek_tok()?;
        match tok {
            Tok::Eof => Ok(node),
            other => {
                let found = other.describe();
                Err(ParseError::Unexpected { found, at: span })
            }
        }
    }

    fn parse_list(&mut self, stop: &[&str]) -> Result<Node, ParseError> {
        let start = self.pos;
        let mut items: Vec<ListItem> = Vec::new();
        loop {
            self.skip_newlines()?;
            if self.at_list_end(stop)? {
                break;
            }
            let node = self.parse_and_or(stop)?;
            let op = match self.peek_tok()?.0 {
                Tok::Op(Op::Semi) => {
                    self.next_tok()?;
                    ListOp::Seq
                }
                Tok::Op(Op::Amp) => {
                    self.next_tok()?;
                    ListOp::Background
                }
                Tok::Op(Op::Newline) => {
                    self.next_tok()?;
                    ListOp::Seq
                }
                _ => {
                    items.push(ListItem { node, op: ListOp::Seq });
                    break;
                }
            };
            items.push(ListItem { node, op });
        }

        self.bump_node()?;
        Ok(match items.len() {
            0 => Node::Empty,
            1 if items[0].op == ListOp::Seq => items.pop().expect("len 1").node,
            _ => Node::List { items, span: self.span(start, self.pos) },
        })
    }

    fn at_list_end(&mut self, stop: &[&str]) -> Result<bool, ParseError> {
        let (tok, _) = self.peek_tok()?;
        Ok(match tok {
            Tok::Eof => true,
            Tok::Op(Op::RParen) => true,
            Tok::Op(Op::DSemi) | Tok::Op(Op::SemiAmp) | Tok::Op(Op::DSemiAmp) => true,
            Tok::Word(w) => match w.literal() {
                Some(lit) => stop.contains(&lit.as_str()) || is_list_terminator(&lit),
                None => false,
            },
            _ => false,
        })
    }

    fn parse_and_or(&mut self, stop: &[&str]) -> Result<Node, ParseError> {
        let start = self.pos;
        let first = self.parse_pipeline(stop)?;
        let mut items = vec![ListItem { node: first, op: ListOp::Seq }];
        loop {
            let op = match self.peek_tok()?.0 {
                Tok::Op(Op::AndAnd) => ListOp::And,
                Tok::Op(Op::OrOr) => ListOp::Or,
                _ => break,
            };
            self.next_tok()?;
            self.skip_newlines()?;
            items.last_mut().expect("non-empty").op = op;
            let node = self.parse_pipeline(stop)?;
            items.push(ListItem { node, op: ListOp::Seq });
        }
        self.bump_node()?;
        Ok(if items.len() == 1 {
            items.pop().expect("len 1").node
        } else {
            Node::List { items, span: self.span(start, self.pos) }
        })
    }

    fn parse_pipeline(&mut self, stop: &[&str]) -> Result<Node, ParseError> {
        let start = self.pos;
        let mut negated = false;
        while let Tok::Word(w) = self.peek_tok()?.0 {
            match w.literal().as_deref() {
                Some("!") => {
                    self.next_tok()?;
                    negated = !negated;
                }
                // `time` is a pipeline prefix, not a program. Skipping it here
                // means `time rm -rf /` is judged as `rm -rf /`, which is the
                // only reading that matters.
                Some("time") => {
                    self.next_tok()?;
                }
                _ => break,
            }
        }

        let mut commands = vec![self.parse_command(stop)?];
        let mut stderr_piped = Vec::new();
        loop {
            let piped_stderr = match self.peek_tok()?.0 {
                Tok::Op(Op::Pipe) => false,
                Tok::Op(Op::PipeAmp) => true,
                _ => break,
            };
            self.next_tok()?;
            self.skip_newlines()?;
            stderr_piped.push(piped_stderr);
            commands.push(self.parse_command(stop)?);
        }

        self.bump_node()?;
        Ok(if commands.len() == 1 && !negated {
            commands.pop().expect("len 1")
        } else {
            Node::Pipeline { negated, commands, stderr_piped, span: self.span(start, self.pos) }
        })
    }

    fn parse_command(&mut self, stop: &[&str]) -> Result<Node, ParseError> {
        let (tok, span) = self.peek_tok()?;
        match tok {
            Tok::Op(Op::LParen) => {
                // `((expr))` is arithmetic; `( list )` is a subshell.
                if self.src.get(self.peek_end()) == Some(&b'(') {
                    if let Some(node) = self.try_parse_arith_command()? {
                        return Ok(node);
                    }
                }
                self.parse_subshell()
            }
            Tok::Word(w) => {
                let lit = w.literal();
                match lit.as_deref() {
                    Some("{") => self.parse_group(),
                    Some("if") => self.parse_if(),
                    Some("for") => self.parse_for(),
                    Some("while") => self.parse_loop(false),
                    Some("until") => self.parse_loop(true),
                    Some("case") => self.parse_case(),
                    Some("function") => self.parse_function_keyword(),
                    Some("[[") => self.parse_cond(),
                    Some(name) if self.looks_like_function_def(name) => self.parse_function_posix(),
                    _ => self.parse_simple(stop),
                }
            }
            Tok::Eof => {
                let found = "end of input".to_string();
                Err(ParseError::Unexpected { found, at: span })
            }
            _ => self.parse_simple(stop),
        }
    }

    /// `name () compound` — a POSIX function definition. Needs a peek past the
    /// name token, which is why it works on raw bytes.
    fn looks_like_function_def(&self, name: &str) -> bool {
        if name.is_empty() || is_reserved(name) {
            return false;
        }
        if !name.bytes().all(|c| is_name_char(c) || c == b'-' || c == b'.' || c == b':') {
            return false;
        }
        let mut i = self.peek_end();
        while i < self.src.len() && is_blank(self.src[i]) {
            i += 1;
        }
        if self.src.get(i) != Some(&b'(') {
            return false;
        }
        i += 1;
        while i < self.src.len() && is_blank(self.src[i]) {
            i += 1;
        }
        self.src.get(i) == Some(&b')')
    }

    fn parse_function_posix(&mut self) -> Result<Node, ParseError> {
        let start = self.pos;
        let (tok, _) = self.next_tok()?;
        let name = match tok {
            Tok::Word(w) => w.literal().unwrap_or_default(),
            _ => String::new(),
        };
        self.expect_op(Op::LParen)?;
        self.expect_op(Op::RParen)?;
        self.skip_newlines()?;
        let body = self.parse_command(&[])?;
        self.bump_node()?;
        Ok(Node::Function { name, body: Box::new(body), span: self.span(start, self.pos) })
    }

    fn parse_function_keyword(&mut self) -> Result<Node, ParseError> {
        let start = self.pos;
        self.next_tok()?; // `function`
        let (tok, span) = self.next_tok()?;
        let name = match tok {
            Tok::Word(w) => w.literal().unwrap_or_default(),
            other => {
                let found = other.describe();
                return Err(ParseError::Unexpected { found, at: span });
            }
        };
        // The parentheses are optional after `function`.
        if matches!(self.peek_tok()?.0, Tok::Op(Op::LParen)) {
            self.next_tok()?;
            self.expect_op(Op::RParen)?;
        }
        self.skip_newlines()?;
        let body = self.parse_command(&[])?;
        self.bump_node()?;
        Ok(Node::Function { name, body: Box::new(body), span: self.span(start, self.pos) })
    }

    fn parse_subshell(&mut self) -> Result<Node, ParseError> {
        let start = self.pos;
        self.expect_op(Op::LParen)?;
        let body = self.parse_list(&[])?;
        self.expect_op(Op::RParen)?;
        let redirects = self.parse_redirect_suffix()?;
        self.bump_node()?;
        Ok(Node::Subshell { body: Box::new(body), redirects, span: self.span(start, self.pos) })
    }

    fn parse_group(&mut self) -> Result<Node, ParseError> {
        let start = self.pos;
        self.next_tok()?; // `{`
        let body = self.parse_list(&["}"])?;
        self.expect_word("}")?;
        let redirects = self.parse_redirect_suffix()?;
        self.bump_node()?;
        Ok(Node::Group { body: Box::new(body), redirects, span: self.span(start, self.pos) })
    }

    fn try_parse_arith_command(&mut self) -> Result<Option<Node>, ParseError> {
        let start = self.pos;
        // We are looking at `((`. Find the matching `))`.
        let open = self.peek_end(); // index of the second `(`
        let Some(inner_close) = find_matching(self.src, open + 1, b'(', b')') else {
            return Ok(None);
        };
        if self.src.get(inner_close + 1) != Some(&b')') {
            return Ok(None);
        }
        let text = self.text[open + 1..inner_close].to_string();
        self.peeked = None;
        self.pos = inner_close + 2;
        self.bump_node()?;
        Ok(Some(Node::Arith { text, span: self.span(start, self.pos) }))
    }

    fn parse_cond(&mut self) -> Result<Node, ParseError> {
        let start = self.pos;
        self.next_tok()?; // `[[`
        let mut words = Vec::new();
        loop {
            let (tok, span) = self.peek_tok()?;
            match tok {
                Tok::Eof => {
                    return Err(ParseError::Unterminated { what: "[[", at: span });
                }
                Tok::Word(w) if w.literal().as_deref() == Some("]]") => {
                    self.next_tok()?;
                    break;
                }
                Tok::Word(_) => {
                    if let (Tok::Word(w), _) = self.next_tok()? {
                        words.push(w);
                    }
                }
                _ => {
                    // Operators such as `&&`, `||`, `<`, `>` inside `[[ ]]` are
                    // test operators. They carry no effects of their own, so
                    // recording them is unnecessary; the operands matter.
                    self.next_tok()?;
                }
            }
        }
        self.bump_node()?;
        Ok(Node::Cond { words, span: self.span(start, self.pos) })
    }

    fn parse_if(&mut self) -> Result<Node, ParseError> {
        let start = self.pos;
        self.next_tok()?; // `if`
        let cond = self.parse_list(&["then"])?;
        self.expect_word("then")?;
        let then = self.parse_list(&["elif", "else", "fi"])?;

        let otherwise = match self.peek_word_literal()?.as_deref() {
            Some("elif") => {
                // An `elif` chain is an `if` in the else branch.
                Some(Box::new(self.parse_if_from_elif()?))
            }
            Some("else") => {
                self.next_tok()?;
                let e = self.parse_list(&["fi"])?;
                self.expect_word("fi")?;
                Some(Box::new(e))
            }
            _ => {
                self.expect_word("fi")?;
                None
            }
        };

        self.bump_node()?;
        Ok(Node::If {
            cond: Box::new(cond),
            then: Box::new(then),
            otherwise,
            span: self.span(start, self.pos),
        })
    }

    fn parse_if_from_elif(&mut self) -> Result<Node, ParseError> {
        let start = self.pos;
        self.next_tok()?; // `elif`
        let cond = self.parse_list(&["then"])?;
        self.expect_word("then")?;
        let then = self.parse_list(&["elif", "else", "fi"])?;
        let otherwise = match self.peek_word_literal()?.as_deref() {
            Some("elif") => Some(Box::new(self.parse_if_from_elif()?)),
            Some("else") => {
                self.next_tok()?;
                let e = self.parse_list(&["fi"])?;
                self.expect_word("fi")?;
                Some(Box::new(e))
            }
            _ => {
                self.expect_word("fi")?;
                None
            }
        };
        self.bump_node()?;
        Ok(Node::If {
            cond: Box::new(cond),
            then: Box::new(then),
            otherwise,
            span: self.span(start, self.pos),
        })
    }

    fn parse_for(&mut self) -> Result<Node, ParseError> {
        let start = self.pos;
        self.next_tok()?; // `for`

        // `for ((init; cond; step))` is the arithmetic form.
        if matches!(self.peek_tok()?.0, Tok::Op(Op::LParen))
            && self.src.get(self.peek_end()) == Some(&b'(')
        {
            {
                if let Some(_arith) = self.try_parse_arith_command()? {
                    self.skip_separators()?;
                    self.expect_word("do")?;
                    let body = self.parse_list(&["done"])?;
                    self.expect_word("done")?;
                    self.bump_node()?;
                    return Ok(Node::For {
                        var: String::new(),
                        words: Vec::new(),
                        body: Box::new(body),
                        span: self.span(start, self.pos),
                    });
                }
            }
        }

        let (tok, span) = self.next_tok()?;
        let var = match tok {
            Tok::Word(w) => w.literal().unwrap_or_default(),
            other => {
                let found = other.describe();
                return Err(ParseError::Unexpected { found, at: span });
            }
        };

        let mut words = Vec::new();
        if self.peek_word_literal()?.as_deref() == Some("in") {
            self.next_tok()?;
            loop {
                match self.peek_tok()?.0 {
                    Tok::Word(w) if w.literal().as_deref() != Some("do") => {
                        if let (Tok::Word(w), _) = self.next_tok()? {
                            words.push(w);
                        }
                    }
                    _ => break,
                }
            }
        }
        self.skip_separators()?;
        self.expect_word("do")?;
        let body = self.parse_list(&["done"])?;
        self.expect_word("done")?;
        self.bump_node()?;
        Ok(Node::For { var, words, body: Box::new(body), span: self.span(start, self.pos) })
    }

    fn parse_loop(&mut self, until: bool) -> Result<Node, ParseError> {
        let start = self.pos;
        self.next_tok()?; // `while` / `until`
        let cond = self.parse_list(&["do"])?;
        self.expect_word("do")?;
        let body = self.parse_list(&["done"])?;
        self.expect_word("done")?;
        self.bump_node()?;
        Ok(Node::Loop {
            until,
            cond: Box::new(cond),
            body: Box::new(body),
            span: self.span(start, self.pos),
        })
    }

    fn parse_case(&mut self) -> Result<Node, ParseError> {
        let start = self.pos;
        self.next_tok()?; // `case`
        let (tok, span) = self.next_tok()?;
        let word = match tok {
            Tok::Word(w) => w,
            other => {
                let found = other.describe();
                return Err(ParseError::Unexpected { found, at: span });
            }
        };
        self.skip_newlines()?;
        self.expect_word("in")?;

        let mut arms = Vec::new();
        loop {
            self.skip_newlines()?;
            if self.peek_word_literal()?.as_deref() == Some("esac") {
                self.next_tok()?;
                break;
            }
            if matches!(self.peek_tok()?.0, Tok::Eof) {
                return Err(ParseError::Unterminated {
                    what: "case",
                    at: self.span(start, self.pos),
                });
            }

            // An optional `(` before the first pattern.
            if matches!(self.peek_tok()?.0, Tok::Op(Op::LParen)) {
                self.next_tok()?;
            }
            let mut patterns = Vec::new();
            loop {
                match self.next_tok()? {
                    (Tok::Word(w), _) => patterns.push(w),
                    (Tok::Op(Op::RParen), _) => break,
                    (other, sp) => {
                        let found = other.describe();
                        return Err(ParseError::Unexpected { found, at: sp });
                    }
                }
                match self.peek_tok()?.0 {
                    Tok::Op(Op::Pipe) => {
                        self.next_tok()?;
                    }
                    Tok::Op(Op::RParen) => {
                        self.next_tok()?;
                        break;
                    }
                    _ => {}
                }
            }

            let body = self.parse_list(&["esac"])?;
            match self.peek_tok()?.0 {
                Tok::Op(Op::DSemi) | Tok::Op(Op::SemiAmp) | Tok::Op(Op::DSemiAmp) => {
                    self.next_tok()?;
                }
                _ => {}
            }
            arms.push(CaseArm { patterns, body });
        }

        self.bump_node()?;
        Ok(Node::Case { word, arms, span: self.span(start, self.pos) })
    }

    fn parse_simple(&mut self, _stop: &[&str]) -> Result<Node, ParseError> {
        let start = self.pos;
        let mut assignments = Vec::new();
        let mut words: Vec<Word> = Vec::new();
        let mut redirects = Vec::new();

        loop {
            if let Some(r) = self.try_parse_redirect()? {
                redirects.push(r);
                continue;
            }
            match self.peek_tok()?.0 {
                Tok::Word(_) => {
                    let (tok, _) = self.next_tok()?;
                    let Tok::Word(w) = tok else { unreachable!("peeked a word") };
                    if words.is_empty() {
                        if let Some(a) = as_assignment(&w) {
                            assignments.push(a);
                            continue;
                        }
                    }
                    words.push(w);
                }
                _ => break,
            }
        }

        if assignments.is_empty() && words.is_empty() && redirects.is_empty() {
            let (tok, span) = self.peek_tok()?;
            let found = tok.describe();
            return Err(ParseError::Unexpected { found, at: span });
        }

        self.bump_node()?;
        Ok(Node::Simple(Simple { assignments, words, redirects, span: self.span(start, self.pos) }))
    }

    /// Redirections that follow a compound command: `{ ...; } > log`.
    fn parse_redirect_suffix(&mut self) -> Result<Vec<Redirect>, ParseError> {
        let mut out = Vec::new();
        while let Some(r) = self.try_parse_redirect()? {
            out.push(r);
        }
        Ok(out)
    }

    fn try_parse_redirect(&mut self) -> Result<Option<Redirect>, ParseError> {
        let start = self.pos;
        let fd = match self.peek_tok()?.0 {
            Tok::IoNumber(n) => Some(*n),
            _ => None,
        };
        if fd.is_some() {
            self.next_tok()?;
        }

        let op = match self.peek_tok()?.0 {
            Tok::Op(o) if o.is_redirect() => *o,
            _ => {
                if fd.is_some() {
                    // An fd token is only produced when a redirect follows, so
                    // this is unreachable in practice; be defensive anyway.
                    let (tok, span) = self.peek_tok()?;
                    let found = tok.describe();
                    return Err(ParseError::Unexpected { found, at: span });
                }
                return Ok(None);
            }
        };
        self.next_tok()?;

        let redir_op = match op {
            Op::Less => RedirOp::Read,
            Op::Great => RedirOp::Write,
            Op::DGreat => RedirOp::Append,
            Op::LessGreat => RedirOp::ReadWrite,
            Op::Clobber => RedirOp::Clobber,
            Op::LessAmp => RedirOp::DupIn,
            Op::GreatAmp => RedirOp::DupOut,
            Op::DLess | Op::DLessDash => RedirOp::Heredoc,
            Op::TLess => RedirOp::HereString,
            Op::AndGreat => RedirOp::AndWrite,
            Op::AndDGreat => RedirOp::AndAppend,
            other => {
                let found = format!("`{}`", other.as_str());
                return Err(ParseError::Unexpected { found, at: self.span(start, self.pos) });
            }
        };

        let (tok, span) = self.next_tok()?;
        let Tok::Word(w) = tok else {
            let found = tok.describe();
            return Err(ParseError::Unexpected { found, at: span });
        };

        let target = match redir_op {
            RedirOp::Heredoc => {
                let strip = op == Op::DLessDash;
                let delim = w.literal().unwrap_or_default();
                // A quoted delimiter suppresses expansion inside the body,
                // which decides whether the body can run anything.
                let quoted = w.quoted;
                let body = self.read_heredoc(&delim, strip);
                RedirTarget::Heredoc { body, quoted }
            }
            RedirOp::DupIn | RedirOp::DupOut => match w.literal().as_deref() {
                Some("-") => RedirTarget::Close,
                Some(s) if s.bytes().all(|c| c.is_ascii_digit()) && !s.is_empty() => {
                    RedirTarget::Fd(s.parse().unwrap_or(u32::MAX))
                }
                _ => RedirTarget::Word(w),
            },
            _ => RedirTarget::Word(w),
        };

        Ok(Some(Redirect { fd, op: redir_op, target, span: self.span(start, self.pos) }))
    }

    /// Read a here-document body eagerly and record the region so the main
    /// cursor jumps over it after the current line's newline.
    fn read_heredoc(&mut self, delim: &str, strip: bool) -> String {
        let body_start = match self.heredoc_cursor {
            Some(p) => p,
            None => {
                let mut i = self.pos;
                while i < self.src.len() && self.src[i] != b'\n' {
                    i += 1;
                }
                if i < self.src.len() {
                    i + 1
                } else {
                    i
                }
            }
        };

        let mut i = body_start;
        let mut body = String::new();
        while i < self.src.len() {
            let line_start = i;
            let mut line_end = i;
            while line_end < self.src.len() && self.src[line_end] != b'\n' {
                line_end += 1;
            }
            let raw = &self.src[line_start..line_end];
            let trimmed: &[u8] = if strip {
                let mut k = 0;
                while k < raw.len() && raw[k] == b'\t' {
                    k += 1;
                }
                &raw[k..]
            } else {
                raw
            };
            let past = if line_end < self.src.len() { line_end + 1 } else { line_end };
            if trimmed == delim.as_bytes() {
                i = past;
                break;
            }
            body.push_str(&String::from_utf8_lossy(trimmed));
            body.push('\n');
            if line_end >= self.src.len() {
                i = past;
                break;
            }
            i = past;
        }

        self.heredoc_cursor = Some(i);
        let skip_start = self.pending_skip.map(|(s, _)| s).unwrap_or(body_start);
        self.pending_skip = Some((skip_start, i));
        body
    }

    // ------------------------------------------------------------- utilities

    fn skip_separators(&mut self) -> Result<(), ParseError> {
        while let Tok::Op(Op::Semi) | Tok::Op(Op::Newline) = self.peek_tok()?.0 {
            self.next_tok()?;
        }
        Ok(())
    }

    fn peek_word_literal(&mut self) -> Result<Option<String>, ParseError> {
        Ok(match self.peek_tok()?.0 {
            Tok::Word(w) => w.literal(),
            _ => None,
        })
    }

    fn expect_op(&mut self, want: Op) -> Result<(), ParseError> {
        let (tok, span) = self.next_tok()?;
        match tok {
            Tok::Op(o) if o == want => Ok(()),
            other => {
                let found = other.describe();
                Err(ParseError::Unexpected { found, at: span })
            }
        }
    }

    fn expect_word(&mut self, want: &str) -> Result<(), ParseError> {
        self.skip_newlines()?;
        let (tok, span) = self.next_tok()?;
        match &tok {
            Tok::Word(w) if w.literal().as_deref() == Some(want) => Ok(()),
            other => {
                let found = other.describe();
                Err(ParseError::Unexpected { found, at: span })
            }
        }
    }
}

impl Tok {
    fn is_newline(&self) -> bool {
        matches!(self, Tok::Op(Op::Newline))
    }
}

fn flush(parts: &mut Vec<WordPart>, lit: &mut String) {
    if !lit.is_empty() {
        parts.push(WordPart::Literal(std::mem::take(lit)));
    }
}

/// Split `NAME=value` / `NAME+=value` off the front of a word.
///
/// Only the leading literal part is examined, which is correct: `FOO=$BAR` is
/// an assignment, but `$FOO=bar` is a command whose name happens to contain an
/// equals sign.
fn as_assignment(w: &Word) -> Option<Assignment> {
    let WordPart::Literal(first) = w.parts.first()? else {
        return None;
    };
    let eq = first.find('=')?;
    let (mut name, _) = first.split_at(eq);
    let append = name.ends_with('+');
    if append {
        name = &name[..name.len() - 1];
    }
    if name.is_empty() {
        return None;
    }
    let mut bytes = name.bytes();
    if !is_name_start(bytes.next()?) || !bytes.all(is_name_char) {
        return None;
    }

    let rest = &first[eq + 1..];
    let mut parts: Vec<WordPart> = Vec::new();
    if !rest.is_empty() {
        parts.push(WordPart::Literal(rest.to_string()));
    }
    parts.extend(w.parts[1..].iter().cloned());

    Some(Assignment {
        name: name.to_string(),
        value: Word::new(parts, w.span, w.quoted),
        append,
        span: w.span,
    })
}

/// Split `${NAME:-default}` into its name and its modifier.
fn split_param_expansion(inner: &str) -> (String, Option<String>) {
    let bytes = inner.as_bytes();
    let mut i = 0;
    // `${#VAR}` is a length, `${!VAR}` an indirection. Both are prefixes on the
    // name rather than part of it.
    if matches!(bytes.first(), Some(b'#') | Some(b'!')) && bytes.len() > 1 {
        i = 1;
    }
    let name_start = i;
    if i < bytes.len() && is_special_param(bytes[i]) && !bytes[i].is_ascii_digit() {
        i += 1;
    } else {
        while i < bytes.len() && is_name_char(bytes[i]) {
            i += 1;
        }
    }
    let name = inner[name_start..i].to_string();
    let op = if i < inner.len() { Some(inner[i..].to_string()) } else { None };
    (name, op)
}

/// Inside backquotes, only `` \` ``, `\\` and `\$` are escapes.
fn unescape_backquote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && matches!(b.get(i + 1), Some(b'`' | b'\\' | b'$')) {
            out.push(b[i + 1] as char);
            i += 2;
        } else {
            match s[i..].chars().next() {
                Some(ch) => {
                    out.push(ch);
                    i += ch.len_utf8();
                }
                None => i += 1,
            }
        }
    }
    out
}

/// End index of a `[...]` glob bracket expression, or `None` if it is just a
/// literal bracket.
fn bracket_glob_end(src: &[u8], pos: usize) -> Option<usize> {
    debug_assert_eq!(src.get(pos), Some(&b'['));
    let mut i = pos + 1;
    // A `]` immediately after the opening bracket (or after `!`/`^`) is a
    // literal member, not the terminator.
    if matches!(src.get(i), Some(b'!') | Some(b'^')) {
        i += 1;
    }
    if src.get(i) == Some(&b']') {
        i += 1;
    }
    while i < src.len() {
        match src[i] {
            b']' => return Some(i),
            b'\\' => i += 2,
            c if is_blank(c) || c == b'\n' => return None,
            _ => i += 1,
        }
    }
    None
}
