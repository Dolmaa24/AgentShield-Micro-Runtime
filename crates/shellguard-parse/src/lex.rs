//! Lexical helpers: character classes, operators, and quote-aware balanced
//! scanning.
//!
//! Word scanning itself lives in [`crate::parse`], because a `$(...)` contains
//! a whole command and so the scanner has to be able to call back into the
//! grammar. Splitting those into separate layers buys nothing and costs a
//! circular dependency, so the helpers that *are* independent live here and
//! the rest stays with the parser.

/// Shell operators, including the ones that only matter to us because they
/// move data into a file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Pipe,
    PipeAmp,
    AndAnd,
    OrOr,
    Semi,
    DSemi,
    SemiAmp,
    DSemiAmp,
    Amp,
    LParen,
    RParen,
    Newline,
    Less,
    Great,
    DGreat,
    DLess,
    DLessDash,
    TLess,
    LessAmp,
    GreatAmp,
    LessGreat,
    Clobber,
    AndGreat,
    AndDGreat,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Pipe => "|",
            Op::PipeAmp => "|&",
            Op::AndAnd => "&&",
            Op::OrOr => "||",
            Op::Semi => ";",
            Op::DSemi => ";;",
            Op::SemiAmp => ";&",
            Op::DSemiAmp => ";;&",
            Op::Amp => "&",
            Op::LParen => "(",
            Op::RParen => ")",
            Op::Newline => "\\n",
            Op::Less => "<",
            Op::Great => ">",
            Op::DGreat => ">>",
            Op::DLess => "<<",
            Op::DLessDash => "<<-",
            Op::TLess => "<<<",
            Op::LessAmp => "<&",
            Op::GreatAmp => ">&",
            Op::LessGreat => "<>",
            Op::Clobber => ">|",
            Op::AndGreat => "&>",
            Op::AndDGreat => "&>>",
        }
    }

    /// Whether this operator introduces a redirection (and therefore expects a
    /// target word or fd next).
    pub fn is_redirect(self) -> bool {
        matches!(
            self,
            Op::Less
                | Op::Great
                | Op::DGreat
                | Op::DLess
                | Op::DLessDash
                | Op::TLess
                | Op::LessAmp
                | Op::GreatAmp
                | Op::LessGreat
                | Op::Clobber
                | Op::AndGreat
                | Op::AndDGreat
        )
    }
}

/// Longest-match operator recognition. Returns the operator and its length.
///
/// Order matters: `&>>` must be tried before `&>`, which must be tried before
/// `&`. Getting this wrong silently reinterprets `cmd &>> log` as "background
/// the command, then append", which is a different program.
pub fn scan_operator(src: &[u8], pos: usize) -> Option<(Op, usize)> {
    let rest = &src[pos..];
    const THREE: &[(&[u8], Op)] =
        &[(b"&>>", Op::AndDGreat), (b"<<<", Op::TLess), (b"<<-", Op::DLessDash), (b";;&", Op::DSemiAmp)];
    const TWO: &[(&[u8], Op)] = &[
        (b"&&", Op::AndAnd),
        (b"||", Op::OrOr),
        (b";;", Op::DSemi),
        (b";&", Op::SemiAmp),
        (b">>", Op::DGreat),
        (b"<<", Op::DLess),
        (b"<&", Op::LessAmp),
        (b">&", Op::GreatAmp),
        (b"<>", Op::LessGreat),
        (b">|", Op::Clobber),
        (b"|&", Op::PipeAmp),
        (b"&>", Op::AndGreat),
    ];

    for (pat, op) in THREE {
        if rest.starts_with(pat) {
            return Some((*op, 3));
        }
    }
    for (pat, op) in TWO {
        if rest.starts_with(pat) {
            return Some((*op, 2));
        }
    }
    let one = match *rest.first()? {
        b'|' => Op::Pipe,
        b'&' => Op::Amp,
        b';' => Op::Semi,
        b'(' => Op::LParen,
        b')' => Op::RParen,
        b'<' => Op::Less,
        b'>' => Op::Great,
        b'\n' => Op::Newline,
        _ => return None,
    };
    Some((one, 1))
}

pub fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\r'
}

/// Characters that end an unquoted word.
pub fn is_meta(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n' | b'|' | b'&' | b';' | b'(' | b')' | b'<' | b'>')
}

pub fn is_name_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

pub fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The special parameters: `$?`, `$$`, `$@`, `$*`, `$#`, `$!`, `$-`, `$0`-`$9`.
pub fn is_special_param(c: u8) -> bool {
    matches!(c, b'?' | b'$' | b'@' | b'*' | b'#' | b'!' | b'-' | b'0'..=b'9')
}

/// Reserved words. These are only reserved in command position, which the
/// parser checks — `echo if` is not a conditional.
pub const RESERVED: &[&str] = &[
    "if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "in", "function", "select", "time", "{", "}", "!", "[[", "]]",
];

pub fn is_reserved(w: &str) -> bool {
    RESERVED.contains(&w)
}

/// Words that end a command list and belong to the enclosing construct.
pub fn is_list_terminator(w: &str) -> bool {
    matches!(w, "then" | "elif" | "else" | "fi" | "do" | "done" | "esac" | "}" | ")")
}

/// Scan forward from just after an opening delimiter to its match, respecting
/// quotes, escapes, comments and nesting.
///
/// This is the function that decides whether `$(echo ")")` is one substitution
/// or a syntax error, and it is worth being precise about: a naive paren
/// counter reads that as terminating early, which detaches the rest of the
/// command from the tree and hides it from every rule. Anything that reaches a
/// parser by way of an LLM should be assumed to contain exactly this shape.
///
/// `pos` must point just past the opening delimiter. Returns the index of the
/// matching close, or `None` if the input ends first.
pub fn find_matching(src: &[u8], pos: usize, open: u8, close: u8) -> Option<usize> {
    let mut i = pos;
    let mut depth = 1usize;
    while i < src.len() {
        match src[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'\'' => {
                // Single quotes are literal through and through: not even a
                // backslash escapes inside them.
                i += 1;
                while i < src.len() && src[i] != b'\'' {
                    i += 1;
                }
                if i >= src.len() {
                    return None;
                }
            }
            b'"' => {
                i += 1;
                while i < src.len() && src[i] != b'"' {
                    if src[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if i >= src.len() {
                    return None;
                }
            }
            b'`' => {
                i += 1;
                while i < src.len() && src[i] != b'`' {
                    if src[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if i >= src.len() {
                    return None;
                }
            }
            b'#' => {
                // A comment, but only if it starts a word. `a#b` is one word.
                let starts_word = i == 0 || is_blank(src[i - 1]) || src[i - 1] == b'\n';
                if starts_word {
                    while i < src.len() && src[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
            }
            c if c == open && open != close => depth += 1,
            c if c == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Find the end of a backquoted substitution starting just after the opening
/// backquote. Inside backquotes only `` \` ``, `\\` and `\$` are escapes.
pub fn find_backquote_end(src: &[u8], pos: usize) -> Option<usize> {
    let mut i = pos;
    while i < src.len() {
        match src[i] {
            b'\\' => i += 2,
            b'`' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Decode `$'...'` ANSI-C escapes.
///
/// Worth decoding rather than treating as opaque, because it is a compact way
/// to write a string that does not look like what it is: `$'\x72\x6d'` is
/// `rm`, and a ruleset matching on raw text would never know.
pub fn unescape_ansi_c(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' || i + 1 >= s.len() {
            out.push(s[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        let c = s[i];
        i += 1;
        match c {
            b'n' => out.push('\n'),
            b't' => out.push('\t'),
            b'r' => out.push('\r'),
            b'a' => out.push('\x07'),
            b'b' => out.push('\x08'),
            b'f' => out.push('\x0c'),
            b'v' => out.push('\x0b'),
            b'e' | b'E' => out.push('\x1b'),
            b'\\' => out.push('\\'),
            b'\'' => out.push('\''),
            b'"' => out.push('"'),
            b'0'..=b'7' => {
                let mut val = (c - b'0') as u32;
                let mut n = 1;
                while n < 3 && i < s.len() && (b'0'..=b'7').contains(&s[i]) {
                    val = val * 8 + (s[i] - b'0') as u32;
                    i += 1;
                    n += 1;
                }
                push_byte(&mut out, val);
            }
            b'x' => {
                let mut val = 0u32;
                let mut n = 0;
                while n < 2 && i < s.len() && s[i].is_ascii_hexdigit() {
                    val = val * 16 + hex_val(s[i]);
                    i += 1;
                    n += 1;
                }
                if n > 0 {
                    push_byte(&mut out, val);
                } else {
                    out.push('x');
                }
            }
            b'u' | b'U' => {
                let max = if c == b'u' { 4 } else { 8 };
                let mut val = 0u32;
                let mut n = 0;
                while n < max && i < s.len() && s[i].is_ascii_hexdigit() {
                    val = val * 16 + hex_val(s[i]);
                    i += 1;
                    n += 1;
                }
                if let Some(ch) = char::from_u32(val) {
                    out.push(ch);
                }
            }
            b'c' => {
                // \cX is control-X.
                if i < s.len() {
                    let ch = s[i].to_ascii_uppercase();
                    i += 1;
                    push_byte(&mut out, (ch ^ 0x40) as u32);
                }
            }
            other => {
                out.push('\\');
                out.push(other as char);
            }
        }
    }
    out
}

fn push_byte(out: &mut String, val: u32) {
    // Values above 0x7f are pushed as the corresponding code point rather than
    // a raw byte. The distinction does not matter for rule matching, which
    // works on the decoded text, and it keeps the output valid UTF-8.
    if let Some(ch) = char::from_u32(val) {
        out.push(ch);
    }
}

fn hex_val(c: u8) -> u32 {
    match c {
        b'0'..=b'9' => (c - b'0') as u32,
        b'a'..=b'f' => (c - b'a' + 10) as u32,
        b'A'..=b'F' => (c - b'A' + 10) as u32,
        _ => 0,
    }
}

/// Whether an unquoted `{` at `pos` opens a brace expansion (`{a,b}`, `{1..9}`)
/// rather than being a literal brace. Returns the index just past the `}`.
pub fn brace_expansion_end(src: &[u8], pos: usize) -> Option<usize> {
    debug_assert_eq!(src.get(pos), Some(&b'{'));
    let close = find_matching(src, pos + 1, b'{', b'}')?;
    let inner = &src[pos + 1..close];
    if inner.is_empty() {
        return None;
    }
    // A brace expansion needs either a comma or a `..` range at its top level.
    // Without one, `${` aside, a brace is just a character: `mkdir {}` makes a
    // directory literally named `{}`.
    let mut depth = 0usize;
    let mut i = 0;
    while i < inner.len() {
        match inner[i] {
            b'\\' => i += 1,
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => return Some(close + 1),
            b'.' if depth == 0 && inner.get(i + 1) == Some(&b'.') => return Some(close + 1),
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operators_match_longest_first() {
        assert_eq!(scan_operator(b"&>>x", 0), Some((Op::AndDGreat, 3)));
        assert_eq!(scan_operator(b"&>x", 0), Some((Op::AndGreat, 2)));
        assert_eq!(scan_operator(b"&x", 0), Some((Op::Amp, 1)));
        assert_eq!(scan_operator(b"<<-EOF", 0), Some((Op::DLessDash, 3)));
        assert_eq!(scan_operator(b"<<<x", 0), Some((Op::TLess, 3)));
        assert_eq!(scan_operator(b"abc", 0), None);
    }

    #[test]
    fn balanced_scan_ignores_quoted_delimiters() {
        // The whole point: the `)` inside the string must not terminate.
        let src = b"echo \")\" )";
        assert_eq!(find_matching(src, 0, b'(', b')'), Some(9));
        let src = b"echo ')' )";
        assert_eq!(find_matching(src, 0, b'(', b')'), Some(9));
        let src = b"echo \\) )";
        assert_eq!(find_matching(src, 0, b'(', b')'), Some(8));
    }

    #[test]
    fn balanced_scan_nests() {
        let src = b"a $(b) c)";
        assert_eq!(find_matching(src, 0, b'(', b')'), Some(8));
    }

    #[test]
    fn balanced_scan_reports_unterminated() {
        assert_eq!(find_matching(b"a 'unterminated", 0, b'(', b')'), None);
        assert_eq!(find_matching(b"nothing here", 0, b'(', b')'), None);
    }

    #[test]
    fn ansi_c_decodes_hex_and_octal() {
        assert_eq!(unescape_ansi_c(b"\\x72\\x6d"), "rm");
        assert_eq!(unescape_ansi_c(b"\\162\\155"), "rm");
        assert_eq!(unescape_ansi_c(b"a\\nb"), "a\nb");
        assert_eq!(unescape_ansi_c(b"\\e"), "\x1b");
    }

    #[test]
    fn brace_expansion_needs_comma_or_range() {
        assert_eq!(brace_expansion_end(b"{a,b}", 0), Some(5));
        assert_eq!(brace_expansion_end(b"{1..9}", 0), Some(6));
        assert_eq!(brace_expansion_end(b"{}", 0), None);
        assert_eq!(brace_expansion_end(b"{abc}", 0), None);
    }
}
