//! A small JSON reader and writer.
//!
//! Needed in three places — the Swift VM helper's replies, Firecracker's HTTP
//! API, and gVisor's OCI bundles — which makes it worth the two hundred lines
//! rather than the dependency. It is a strict parser: trailing commas, comments
//! and unquoted keys are errors, because the inputs are machine-generated and
//! anything unusual in them is a signal rather than something to accommodate.
//!
//! Depth is bounded. The parser is recursive and its inputs, while normally
//! trustworthy, include replies from a guest that may be running something
//! hostile — a deeply nested array is the cheapest way to turn a recursive
//! descent parser into a stack overflow.

use std::collections::BTreeMap;

const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_f64().map(|f| f as i64)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(v) => Some(v),
            _ => None,
        }
    }
}

pub fn parse(src: &str) -> Result<Json, String> {
    let mut p = Parser { b: src.as_bytes(), i: 0, depth: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(format!("trailing input at byte {}", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), String> {
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected `{}` at byte {}", c as char, self.i))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("nesting too deep".into());
        }
        let v = match self.b.get(self.i) {
            None => return Err("unexpected end of input".into()),
            Some(b'{') => self.object()?,
            Some(b'[') => self.array()?,
            Some(b'"') => Json::Str(self.string()?),
            Some(b't') => {
                self.lit("true")?;
                Json::Bool(true)
            }
            Some(b'f') => {
                self.lit("false")?;
                Json::Bool(false)
            }
            Some(b'n') => {
                self.lit("null")?;
                Json::Null
            }
            _ => self.number()?,
        };
        self.depth -= 1;
        Ok(v)
    }

    fn lit(&mut self, word: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(())
        } else {
            Err(format!("expected `{word}` at byte {}", self.i))
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.eat(b'{')?;
        let mut m = BTreeMap::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            let v = self.value()?;
            m.insert(k, v);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                _ => return Err(format!("expected `,` or `}}` at byte {}", self.i)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.eat(b'[')?;
        let mut v = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Json::Arr(v));
        }
        loop {
            self.ws();
            v.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(v));
                }
                _ => return Err(format!("expected `,` or `]` at byte {}", self.i)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat(b'"')?;
        let mut s = String::new();
        loop {
            let c = *self.b.get(self.i).ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or("unterminated escape")?;
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\u{8}'),
                        b'f' => s.push('\u{c}'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            let hex =
                                self.b.get(self.i..self.i + 4).ok_or("truncated \\u escape")?;
                            let code = u32::from_str_radix(
                                std::str::from_utf8(hex).map_err(|_| "bad \\u escape")?,
                                16,
                            )
                            .map_err(|_| "bad \\u escape")?;
                            self.i += 4;
                            // Lone surrogates are replaced rather than
                            // rejected: they appear in real output and are not
                            // worth failing a whole reply over.
                            s.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        other => return Err(format!("bad escape `\\{}`", other as char)),
                    }
                }
                _ => {
                    // Copy the whole UTF-8 sequence, not the byte.
                    let start = self.i - 1;
                    let len = utf8_len(c);
                    let end = (start + len).min(self.b.len());
                    match std::str::from_utf8(&self.b[start..end]) {
                        Ok(chunk) => s.push_str(chunk),
                        Err(_) => s.push('\u{fffd}'),
                    }
                    self.i = end;
                }
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        while matches!(self.b.get(self.i), Some(c) if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            self.i += 1;
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad number")?;
        text.parse::<f64>().map(Json::Num).map_err(|_| format!("bad number `{text}`"))
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// Escape a string as a JSON string literal, including the quotes.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scalars() {
        assert_eq!(parse("null").unwrap(), Json::Null);
        assert_eq!(parse("true").unwrap(), Json::Bool(true));
        assert_eq!(parse("-12.5e2").unwrap(), Json::Num(-1250.0));
        assert_eq!(parse(r#""hi""#).unwrap().as_str(), Some("hi"));
    }

    #[test]
    fn parses_a_realistic_reply() {
        let src =
            r#"{"exit_code":0,"timed_out":false,"stdout":"hello\n","stderr":"","bootMs":142.5}"#;
        let v = parse(src).unwrap();
        assert_eq!(v.get("exit_code").and_then(Json::as_i64), Some(0));
        assert_eq!(v.get("timed_out").and_then(Json::as_bool), Some(false));
        assert_eq!(v.get("stdout").and_then(Json::as_str), Some("hello\n"));
        assert_eq!(v.get("bootMs").and_then(Json::as_f64), Some(142.5));
        assert!(v.get("missing").is_none());
    }

    #[test]
    fn parses_nested_structures() {
        let v = parse(r#"{"a":[1,{"b":[true,null]}]}"#).unwrap();
        let a = v.get("a").and_then(Json::as_array).unwrap();
        assert_eq!(a.len(), 2);
        let b = a[1].get("b").and_then(Json::as_array).unwrap();
        assert_eq!(b[0], Json::Bool(true));
        assert_eq!(b[1], Json::Null);
    }

    #[test]
    fn handles_escapes_and_unicode() {
        assert_eq!(parse(r#""a\nb\tc""#).unwrap().as_str(), Some("a\nb\tc"));
        assert_eq!(parse(r#""A""#).unwrap().as_str(), Some("A"));
        assert_eq!(parse(r#""héllo — wörld""#).unwrap().as_str(), Some("héllo — wörld"));
        assert_eq!(parse(r#""\/""#).unwrap().as_str(), Some("/"));
    }

    #[test]
    fn empty_containers() {
        assert_eq!(parse("{}").unwrap(), Json::Obj(BTreeMap::new()));
        assert_eq!(parse("[]").unwrap(), Json::Arr(vec![]));
    }

    #[test]
    fn rejects_malformed_input() {
        // Machine-generated input; anything unusual is a signal.
        assert!(parse("{").is_err());
        assert!(parse(r#"{"a":1,}"#).is_err());
        assert!(parse(r#"{a:1}"#).is_err());
        assert!(parse("[1 2]").is_err());
        assert!(parse(r#""unterminated"#).is_err());
        assert!(parse("{} trailing").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn deep_nesting_is_rejected_rather_than_overflowing_the_stack() {
        let deep = format!("{}1{}", "[".repeat(500), "]".repeat(500));
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn quoting_round_trips() {
        for s in ["plain", "with \"quotes\"", "back\\slash", "new\nline", "tab\there", "é—日本"]
        {
            let encoded = quote(s);
            assert_eq!(parse(&encoded).unwrap().as_str(), Some(s), "round trip of {s:?}");
        }
    }

    #[test]
    fn quoting_escapes_control_characters() {
        let q = quote("bell\u{7}");
        assert!(q.contains("\\u0007"), "{q}");
        assert_eq!(parse(&q).unwrap().as_str(), Some("bell\u{7}"));
    }
}
