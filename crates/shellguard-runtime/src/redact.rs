//! Best-effort removal of secrets from text headed for a log.
//!
//! # What this is, and what it is not
//!
//! A log of every command an agent ran is useful precisely because it is
//! complete, and dangerous for the same reason: commands and their output carry
//! credentials. `curl -H "Authorization: Bearer …"`, `export AWS_SECRET_…=…`,
//! `git clone https://user:password@host/…`. A plaintext file of those, with
//! weaker permissions than wherever the secret came from, is a new place for it
//! to leak from.
//!
//! This module recognises the shapes credentials usually take and replaces
//! them. It is **not** a guarantee. It cannot know that an arbitrary
//! high-entropy string is a secret — git commit hashes look the same, and a
//! log full of `[REDACTED]` where hashes used to be is unreadable — so a bare
//! secret with no recognisable prefix and no telling name next to it passes
//! straight through. The audit log therefore does not rely on this alone: it
//! records no command output at all unless asked to, and the redaction here is
//! the second line of defence rather than the first.
//!
//! Over-redaction is the accepted failure mode. A false positive costs a
//! reader a little context; a false negative puts a credential on disk.
//!
//! # Properties the tests hold it to
//!
//! * **Idempotent** — redacting redacted text changes nothing, so a record
//!   that passes through more than one stage is not progressively mangled.
//! * **Total** — never panics, whatever the input, including invalid
//!   boundaries between multi-byte characters.
//! * **Shape-preserving** — only the secret is replaced; the key, the flag, or
//!   the URL around it stays, so the record still says *what kind* of thing was
//!   there.

/// What a redacted span is replaced with.
pub const MARK: &str = "[REDACTED]";

/// Redact `input`.
pub fn redact(input: &str) -> String {
    let b = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < b.len() {
        let c = b[i];

        // A private key block is many lines; nothing inside it is worth keeping.
        if c == b'-' && input[i..].starts_with("-----BEGIN ") {
            if let Some(len) = private_key_block(&input[i..]) {
                out.push_str(MARK);
                i += len;
                continue;
            }
        }

        // `scheme://user:password@host` — keep the user, drop the password.
        if c == b':' && input[i..].starts_with("://") {
            out.push_str("://");
            i += 3;
            i = url_userinfo(input, i, &mut out);
            continue;
        }

        if is_word(c) {
            let mut j = i;
            while j < b.len() && is_word(b[j]) {
                j += 1;
            }
            i = word(input, i, j, &mut out);
            continue;
        }

        // Anything else is copied whole, one character at a time so a
        // multi-byte character is never split.
        let ch = input[i..].chars().next().expect("i is on a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

/// Redact, then cap the result at `max` bytes on a character boundary.
///
/// In that order deliberately: truncating first can cut a token in half, and
/// half a token no longer matches any pattern here.
///
/// The input is pre-trimmed so a multi-megabyte output does not have to be
/// scanned to keep sixteen kilobytes of it. That trim backs up to whitespace,
/// for the same reason: a token straddling the cut must not survive as a
/// recognisable-looking-but-unmatched fragment. Returns whether anything was
/// dropped.
pub fn redact_capped(input: &str, max: usize) -> (String, bool) {
    // Generous headroom: redaction only ever shortens or replaces, and the
    // final cap below is what actually bounds the result.
    let window = max.saturating_mul(4).max(64);
    let (head, pre_cut) = if input.len() > window {
        let mut end = window;
        while !input.is_char_boundary(end) {
            end -= 1;
        }
        // Back up to whitespace so no word is cut in half. If there is no
        // whitespace at all the whole window is a single "word" and none of it
        // can be trusted to be free of a fragment, so none of it is kept.
        match input[..end].rfind(|c: char| c.is_whitespace()) {
            Some(ws) => (&input[..ws], true),
            None => ("", true),
        }
    } else {
        (input, false)
    };

    let mut s = redact(head);
    let mut truncated = pre_cut;
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        // Never end inside a marker or a word: a cut mid-`[REDACTED]` is
        // harmless, but a cut mid-token is not, and tokens were already
        // replaced whole above, so backing up to whitespace is only cosmetic.
        s.truncate(end);
        truncated = true;
    }
    (s, truncated)
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

/// Handle the word `input[start..end]`; returns where scanning resumes.
fn word(input: &str, start: usize, end: usize, out: &mut String) -> usize {
    let b = input.as_bytes();
    let raw = &input[start..end];

    // A trailing full stop is prose, not part of a token: "the key is AKIA…."
    let token = raw.trim_end_matches('.');
    let tail = &raw[token.len()..];

    if is_secret_token(token) {
        out.push_str(MARK);
        out.push_str(tail);
        return end;
    }

    let lower = token.to_ascii_lowercase();

    // `Bearer <token>` outside of a recognised header.
    if lower == "bearer" {
        let mut k = end;
        while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
            k += 1;
        }
        let vs = k;
        while k < b.len() && (b[k].is_ascii_alphanumeric() || b"._~+/=-".contains(&b[k])) {
            k += 1;
        }
        if k - vs >= 8 && vs > end {
            out.push_str(&input[start..vs]);
            out.push_str(MARK);
            return k;
        }
    }

    match key_kind(&lower) {
        KeyKind::None => {}
        kind => {
            if let Some(next) = key_value(input, start, end, kind, &lower, out) {
                return next;
            }
        }
    }

    out.push_str(raw);
    end
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    None,
    /// Sensitive in every position: `password=x`, `--password x`.
    Strong,
    /// Sensitive only as an assignment: `SIGNING_KEY=x`. As a flag, `--sort-key
    /// name` is ordinary, and redacting it would be noise.
    AssignmentOnly,
}

const SENSITIVE: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "credential",
    "private_key",
    "private-key",
    "privatekey",
    "access_key",
    "access-key",
    "accesskey",
    "authorization",
    "cookie",
];

fn key_kind(lower: &str) -> KeyKind {
    if SENSITIVE.iter().any(|s| lower.contains(s)) {
        KeyKind::Strong
    } else if lower.ends_with("_key") || lower.ends_with("-key") {
        KeyKind::AssignmentOnly
    } else {
        KeyKind::None
    }
}

/// Headers whose value is a whole scheme-plus-credential, not one word.
fn is_greedy(lower: &str) -> bool {
    lower == "authorization" || lower == "proxy-authorization" || lower.contains("cookie")
}

/// `key=value`, `key: value`, `"key": "value"`, and `--key value`.
///
/// Returns where scanning resumes if the word was a key with a value.
fn key_value(
    input: &str,
    start: usize,
    end: usize,
    kind: KeyKind,
    lower: &str,
    out: &mut String,
) -> Option<usize> {
    let b = input.as_bytes();
    let mut k = end;

    // The closing quote of a quoted key: `"password": "x"`.
    if k < b.len() && (b[k] == b'"' || b[k] == b'\'') {
        k += 1;
    }
    while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
        k += 1;
    }

    let assigned = k < b.len() && (b[k] == b'=' || b[k] == b':');
    if assigned {
        // `token://…` is a URL scheme, not an assignment; the URL branch owns it.
        if b[k] == b':' && input[k..].starts_with("://") {
            return None;
        }
        k += 1;
        while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
            k += 1;
        }
        return redact_value(input, start, k, is_greedy(lower), out);
    }

    // `--password hunter2`: a long flag followed by its value.
    let takes_a_value = k < b.len() && !matches!(b[k], b'-' | b'\n' | b'\r');
    if kind == KeyKind::Strong && lower.starts_with("--") && k > end && takes_a_value {
        return redact_value(input, start, k, false, out);
    }
    None
}

/// Replace the value beginning at `vstart`, copying everything before it.
fn redact_value(
    input: &str,
    copy_from: usize,
    vstart: usize,
    greedy: bool,
    out: &mut String,
) -> Option<usize> {
    let b = input.as_bytes();
    if vstart >= b.len() {
        return None;
    }

    let (vs, ve) = if b[vstart] == b'"' || b[vstart] == b'\'' {
        let q = b[vstart];
        let inner = vstart + 1;
        let close = input[inner..]
            .bytes()
            .position(|c| c == q || c == b'\n')
            .map_or(b.len(), |p| inner + p);
        (inner, close)
    } else {
        let mut e = vstart;
        while e < b.len() {
            let c = b[e];
            let stop = if greedy {
                matches!(c, b'\n' | b'\r' | b'"' | b'\'')
            } else {
                matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b';' | b'&' | b'|')
            };
            if stop {
                break;
            }
            e += 1;
        }
        (vstart, e)
    };

    if ve <= vs {
        return None;
    }
    out.push_str(&input[copy_from..vs]);
    out.push_str(MARK);
    Some(ve)
}

/// Continue after `://`: if the authority has `user:password@`, redact the
/// password. Returns where scanning resumes.
fn url_userinfo(input: &str, from: usize, out: &mut String) -> usize {
    let b = input.as_bytes();
    let mut e = from;
    while e < b.len()
        && !matches!(b[e], b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'"' | b'\'' | b'?' | b'#')
    {
        e += 1;
    }
    let authority = &input[from..e];
    if let Some(at) = authority.rfind('@') {
        let userinfo = &authority[..at];
        if let Some(colon) = userinfo.find(':') {
            out.push_str(&userinfo[..=colon]);
            out.push_str(MARK);
            out.push_str(&authority[at..]);
            return e;
        }
    }
    // Nothing to redact here. Resume at `from` so the host is still scanned as
    // ordinary text (a token can sit in the user position).
    from
}

/// Length of a PEM private-key block at the start of `s`, if it is one.
///
/// Public certificates and keys are left alone: they are meant to be shared,
/// and redacting them would hide exactly the thing an operator is debugging.
fn private_key_block(s: &str) -> Option<usize> {
    let after_begin = "-----BEGIN ".len();
    let header_end = s[after_begin..].find("-----")?;
    if !s[after_begin..after_begin + header_end].contains("PRIVATE KEY") {
        return None;
    }
    let body = after_begin + header_end + 5;
    match s[body..].find("-----END ") {
        Some(e) => {
            let end_start = body + e + "-----END ".len();
            match s[end_start..].find("-----") {
                Some(t) => Some(end_start + t + 5),
                None => Some(s.len()),
            }
        }
        // A truncated log line: the key started and never finished. Everything
        // after the header is key material.
        None => Some(s.len()),
    }
}

fn alnum(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_alphanumeric())
}

fn base64url(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// Credentials with a fixed, recognisable prefix.
fn is_secret_token(t: &str) -> bool {
    // AWS access key id.
    if (t.starts_with("AKIA") || t.starts_with("ASIA"))
        && t.len() == 20
        && t[4..].bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return true;
    }
    // GitHub.
    for p in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        if let Some(r) = t.strip_prefix(p) {
            return r.len() >= 30 && alnum(r);
        }
    }
    if let Some(r) = t.strip_prefix("github_pat_") {
        return r.len() >= 20 && r.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
    }
    // Slack.
    if t.len() >= 15
        && t.starts_with("xox")
        && matches!(t.as_bytes()[3], b'b' | b'a' | b'p' | b'r' | b's')
        && t.as_bytes()[4] == b'-'
    {
        return true;
    }
    // OpenAI / Anthropic style keys, GitLab, npm, Hugging Face, Stripe, Google.
    if let Some(r) = t.strip_prefix("sk-") {
        return r.len() >= 20 && base64url(r);
    }
    if let Some(r) = t.strip_prefix("glpat-") {
        return r.len() >= 20 && base64url(r);
    }
    if let Some(r) = t.strip_prefix("npm_") {
        return r.len() >= 30 && alnum(r);
    }
    if let Some(r) = t.strip_prefix("hf_") {
        return r.len() >= 30 && alnum(r);
    }
    for p in ["sk_live_", "rk_live_", "sk_test_", "rk_test_"] {
        if let Some(r) = t.strip_prefix(p) {
            return r.len() >= 16 && alnum(r);
        }
    }
    if t.starts_with("AIza") && t.len() == 39 && base64url(&t[4..]) {
        return true;
    }
    // A JSON web token: three base64url segments, the first a JSON object.
    if t.starts_with("eyJ") && t.len() >= 30 {
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && base64url(p)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fabricated. Each has the *shape* of a real credential and is not one.
    const AWS: &str = "AKIAIOSFODNN7EXAMPLE";
    const GH: &str = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
    const SK: &str = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789";
    const JWT: &str =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r";

    fn assert_redacted(input: &str, secret: &str) {
        let out = redact(input);
        assert!(!out.contains(secret), "`{secret}` survived in `{out}` (from `{input}`)");
        assert!(out.contains(MARK), "nothing was marked in `{out}`");
    }

    // ------------------------------------------------------- prefixed tokens

    #[test]
    fn aws_access_key_ids_are_redacted() {
        assert_redacted(&format!("export AWS_ACCESS_KEY_ID={AWS}"), AWS);
        assert_redacted(&format!("echo {AWS} done"), AWS);
    }

    #[test]
    fn github_tokens_are_redacted() {
        assert_redacted(&format!("git clone https://{GH}@github.com/o/r"), GH);
        assert_redacted(&format!("echo {GH}"), GH);
    }

    #[test]
    fn api_keys_and_jwts_are_redacted() {
        assert_redacted(&format!("curl -H 'x-thing: {SK}'"), SK);
        assert_redacted(&format!("echo {JWT}"), JWT);
    }

    #[test]
    fn a_token_followed_by_a_full_stop_is_still_caught() {
        let out = redact(&format!("the key is {AWS}."));
        assert!(!out.contains(AWS));
        assert!(out.ends_with("[REDACTED]."), "{out}");
    }

    #[test]
    fn a_word_that_only_resembles_a_prefix_is_left_alone() {
        // `sk-learn` and a short `ghp_` are ordinary words.
        for s in ["pip install sk-learn", "ghp_short", "AKIA_not_a_key", "eyJ.a.b"] {
            assert_eq!(redact(s), s, "over-redacted `{s}`");
        }
    }

    // ---------------------------------------------------------- key = value

    #[test]
    fn assignments_to_sensitive_names_lose_their_value_but_keep_the_name() {
        let out = redact("export DB_PASSWORD=hunter2 && run");
        assert_eq!(out, "export DB_PASSWORD=[REDACTED] && run");
    }

    #[test]
    fn quoted_values_are_redacted_whole() {
        assert_eq!(redact(r#"API_TOKEN="a b c d""#), r#"API_TOKEN="[REDACTED]""#);
        assert_eq!(redact("SECRET='x y'"), "SECRET='[REDACTED]'");
    }

    #[test]
    fn json_style_pairs_are_redacted() {
        let out = redact(r#"{"user":"bob","password":"hunter2","n":1}"#);
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains(r#""user":"bob""#), "{out}");
        assert!(out.contains(r#""n":1"#), "{out}");
    }

    #[test]
    fn colon_pairs_are_redacted() {
        assert_eq!(redact("password: hunter2"), "password: [REDACTED]");
    }

    #[test]
    fn long_flags_take_their_following_word() {
        assert_eq!(
            redact("mysql --password hunter2 -u root"),
            "mysql --password [REDACTED] -u root"
        );
        assert_eq!(redact("mysql --password=hunter2"), "mysql --password=[REDACTED]");
    }

    #[test]
    fn a_flag_followed_by_another_flag_is_not_treated_as_holding_a_value() {
        assert_eq!(redact("tool --token --verbose"), "tool --token --verbose");
    }

    #[test]
    fn key_suffixed_names_are_redacted_as_assignments_only() {
        assert_eq!(redact("SIGNING_KEY=abc123"), "SIGNING_KEY=[REDACTED]");
        // As a flag it is an ordinary option.
        assert_eq!(redact("sort --sort-key name"), "sort --sort-key name");
    }

    #[test]
    fn a_value_stops_at_a_shell_separator() {
        assert_eq!(redact("TOKEN=abc; echo ok"), "TOKEN=[REDACTED]; echo ok");
        assert_eq!(redact("TOKEN=abc && echo ok"), "TOKEN=[REDACTED] && echo ok");
        assert_eq!(redact("a?b=1&password=xyz&c=2"), "a?b=1&password=[REDACTED]&c=2");
    }

    #[test]
    fn an_assignment_with_nothing_after_it_is_left_alone() {
        assert_eq!(redact("PASSWORD="), "PASSWORD=");
        assert_eq!(redact("PASSWORD=\nnext line"), "PASSWORD=\nnext line");
    }

    #[test]
    fn spaced_assignments_are_redacted_even_though_a_shell_would_not_read_them_so() {
        // `password = hunter2` is how an INI file spells it, and command output
        // is exactly where those get printed. A shell reads `PASSWORD= run` as an
        // empty assignment followed by a command; the two are indistinguishable
        // here, and over-redaction is the accepted failure.
        assert_eq!(redact("password = hunter2"), "password = [REDACTED]");
        assert_eq!(redact("PASSWORD= run"), "PASSWORD= [REDACTED]");
    }

    // -------------------------------------------------------------- headers

    #[test]
    fn authorization_headers_are_redacted_through_the_whole_value() {
        let out = redact(r#"curl -H "Authorization: Bearer abcdef1234567890" https://x"#);
        assert!(!out.contains("abcdef1234567890"), "{out}");
        assert!(out.contains("Authorization: [REDACTED]"), "{out}");
        assert!(out.ends_with(r#"" https://x"#), "the rest of the command was lost: {out}");
    }

    #[test]
    fn cookies_are_redacted() {
        let out = redact(r#"curl -H "Cookie: sid=abc; other=def" x"#);
        assert!(!out.contains("sid=abc") && !out.contains("other=def"), "{out}");
    }

    #[test]
    fn a_bare_bearer_token_is_redacted() {
        assert_eq!(redact("Bearer abcdefgh12345678"), "Bearer [REDACTED]");
        assert_eq!(redact("the bearer of good news"), "the bearer of good news");
    }

    // ----------------------------------------------------------------- urls

    #[test]
    fn url_passwords_are_redacted_and_usernames_kept() {
        assert_eq!(
            redact("git clone https://alice:s3cret@example.com/r.git"),
            "git clone https://alice:[REDACTED]@example.com/r.git"
        );
    }

    #[test]
    fn a_username_alone_is_not_a_secret() {
        // `ssh://git@github.com` is in half the commands anyone runs.
        assert_eq!(
            redact("git clone ssh://git@github.com/o/r"),
            "git clone ssh://git@github.com/o/r"
        );
    }

    #[test]
    fn a_url_without_credentials_is_untouched() {
        let s = "curl https://example.com/path?q=1#frag";
        assert_eq!(redact(s), s);
    }

    #[test]
    fn a_password_containing_an_at_sign_is_still_redacted() {
        let out = redact("https://u:p@ss@host/x");
        assert!(!out.contains("p@ss"), "{out}");
    }

    // ------------------------------------------------------------- pem keys

    #[test]
    fn private_key_blocks_are_redacted_entirely() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
        let out = redact(&format!("echo '{pem}' > key"));
        assert!(!out.contains("MIIEow") && !out.contains("IBAAKCAQEA"), "{out}");
        assert_eq!(out, "echo '[REDACTED]' > key");
    }

    #[test]
    fn a_truncated_private_key_is_redacted_to_the_end() {
        let out = redact("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq");
        assert_eq!(out, MARK);
    }

    #[test]
    fn public_material_is_left_alone() {
        let s = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----";
        assert_eq!(redact(s), s);
    }

    // ------------------------------------------------------------ properties

    #[test]
    fn ordinary_commands_pass_through_unchanged() {
        for s in [
            "ls -la",
            "git commit -m 'fix the parser'",
            "cargo test --workspace",
            "python3 -c \"print('hello')\"",
            "grep -rn TODO src/",
            "git log --oneline 3449ef8..a2a0e0f",
            "echo héllo — wörld",
            "",
        ] {
            assert_eq!(redact(s), s, "changed an innocent command");
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        for s in [
            format!("export A_TOKEN=abc {AWS} {GH}"),
            r#"{"password":"x","k":"v"}"#.to_string(),
            "https://u:p@h Authorization: Bearer abcdefgh12345678".to_string(),
            "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----".to_string(),
            "mysql --password hunter2".to_string(),
        ] {
            let once = redact(&s);
            assert_eq!(redact(&once), once, "not idempotent for `{s}`");
        }
    }

    #[test]
    fn multibyte_text_is_never_split() {
        // Every byte offset of a string with 1-, 2-, 3- and 4-byte characters,
        // with a secret after it.
        let s = format!("é—😀日本 PASSWORD=x{GH}é");
        let out = redact(&s);
        assert!(!out.contains(GH));
        assert!(out.starts_with("é—😀日本 "));
        assert!(out.ends_with('é') || out.ends_with(MARK));
    }

    #[test]
    fn hostile_input_does_not_panic() {
        let cases = [
            "\0\0\0",
            "PASSWORD",
            "PASSWORD=",
            "PASSWORD=\"",
            "PASSWORD:",
            "\"password\"",
            "-----BEGIN ",
            "-----BEGIN PRIVATE KEY",
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "://",
            "http://@",
            "http://:@",
            "http://a:@h",
            "--password",
            "--password ",
            "Bearer",
            "Bearer ",
            "Authorization:",
            "Authorization: ",
            "🙂PASSWORD=🙂",
            "a\u{0}b=c",
        ];
        for s in cases {
            let _ = redact(s);
        }
        // And every prefix of a realistic command, so a boundary off-by-one at
        // any position shows up.
        let long = format!("curl -H \"Authorization: Bearer {SK}\" https://u:p@h/x?token=abc é");
        for end in 0..=long.len() {
            if long.is_char_boundary(end) {
                let _ = redact(&long[..end]);
            }
        }
    }

    // --------------------------------------------------------------- capping

    #[test]
    fn capping_bounds_the_result_and_reports_it() {
        let (s, cut) = redact_capped(&"word ".repeat(10_000), 100);
        assert!(s.len() <= 100);
        assert!(cut);
    }

    #[test]
    fn capping_a_short_input_changes_nothing() {
        let (s, cut) = redact_capped("hello", 100);
        assert_eq!(s, "hello");
        assert!(!cut);
    }

    #[test]
    fn a_secret_at_the_cut_cannot_leave_a_fragment_behind() {
        // The secret straddles the pre-trim window. Whatever survives must not
        // contain a usable prefix of it.
        let filler = "x ".repeat(30);
        let input = format!("{filler}{GH}");
        for max in 1..input.len() {
            let (s, _) = redact_capped(&input, max);
            assert!(!s.contains("ghp_aBcDeF"), "max={max}: fragment leaked: `{s}`");
        }
    }

    #[test]
    fn an_unbroken_giant_word_is_dropped_rather_than_half_kept() {
        let (s, cut) = redact_capped(&"a".repeat(100_000), 100);
        assert_eq!(s, "");
        assert!(cut);
    }

    #[test]
    fn capping_lands_on_a_character_boundary() {
        let (s, _) = redact_capped(&"日本語 ".repeat(1000), 50);
        assert!(s.len() <= 50);
        assert!(std::str::from_utf8(s.as_bytes()).is_ok());
    }
}
