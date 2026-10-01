//! macOS confinement via Seatbelt.
//!
//! # Why Seatbelt and not Endpoint Security
//!
//! Endpoint Security is the framework that actually intercepts syscalls on
//! macOS: `ES_EVENT_TYPE_AUTH_EXEC`, `AUTH_OPEN`, `AUTH_UNLINK` and friends
//! block the operation until a client responds. It is also gated on the
//! `com.apple.developer.endpoint-security.client` entitlement, which Apple
//! grants case by case, and it requires running as root with Full Disk Access.
//! A library that only works for organisations who have been through that
//! process is not a library most people can use.
//!
//! Seatbelt needs no entitlement, is enforced in the kernel through the MAC
//! framework, and costs nothing per syscall because there is no userspace round
//! trip — the policy is evaluated in kernel context. Its drawback is honest and
//! worth stating plainly: `sandbox_init` has been formally deprecated since
//! macOS 10.8, SBPL is undocumented, and Apple could remove it. It has
//! nevertheless been the mechanism behind Chrome's and Firefox's renderer
//! sandboxes for over a decade, which is the practical argument for depending
//! on it and the reason its removal would be noticed by more people than us.
//!
//! # Two ways to apply it
//!
//! [`apply`] confines the *current* process and cannot be undone. [`command`]
//! builds an argv that runs a program under `sandbox-exec` instead. The second
//! is what the runtime uses: confining a child means the supervisor stays
//! outside the sandbox and can still write the audit log, and a botched profile
//! kills one command instead of the daemon.

use std::ffi::{c_char, c_int, CString};
use std::path::Path;

use crate::agent::AgentProfile;
use crate::profile::{Access, EnforceError, Profile};

/// Directories a process needs to read for `dyld` to load it at all.
///
/// Getting this wrong does not produce a security failure, it produces a
/// sandbox in which nothing runs — which people fix by turning the sandbox off.
const BASE_READ: &[&str] = &[
    "/usr/lib",
    "/usr/share",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/System",
    "/Library/Frameworks",
    "/Library/Apple",
    // The Command Line Tools. `/usr/bin/python3`, `/usr/bin/git` and friends
    // on macOS are shims that re-exec through `xcrun` into here, so without it
    // every one of them fails with a dlopen error about libxcrun that says
    // nothing about sandboxing. Read and execute only, and it is Apple's
    // toolchain rather than anyone's data.
    "/Library/Developer",
    "/private/var/db/dyld",
    "/private/var/select",
    "/opt/homebrew",
    "/opt/local",
];

const BASE_EXEC: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/opt/homebrew",
    "/Library/Developer",
];

const BASE_DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/dtracehelper",
    "/dev/tty",
    "/dev/fd",
];

/// Mach services every confined process may look up, whatever else it is granted.
///
/// A Mach service is a system daemon that acts on a client's behalf, so an
/// unrestricted `mach-lookup` is a way out of the sandbox that has nothing to do
/// with files or sockets: LaunchServices opens URLs and applications,
/// SecurityServer fronts the keychain, `pasteboard.1` is the clipboard, and
/// `nsurlsessiond` fetches URLs in the background. All four were measured
/// reachable from the old profile; none of them is reachable from this one.
///
/// The list is the *minimum that the tools an agent actually runs need*, found
/// by experiment rather than guessed: run a battery of 46 common tools (git, cc,
/// make, python3, perl, tar, awk, ...) under a profile with the allowlist empty,
/// read the sandbox's own denial log for the services each failing tool was
/// refused, add them, and repeat until the battery behaves exactly as it did
/// under the blanket allow. Then drop each entry in turn and keep only the ones
/// whose removal breaks something. One service survived:
///
/// * `opendirectoryd.libinfo` — `getpwuid`, `getgrgid`, `getpwnam`. Anything that
///   asks who it is or who owns a file: `id -un`, `ls -l`, `git commit`'s author
///   fallback, `python3`'s `pwd` and `getpass`.
///
/// # When a tool breaks on some other macOS
///
/// The set was measured on one macOS release, and Apple moves which daemon
/// answers which question. A tool that fails here and works unsandboxed has
/// almost certainly been refused a service. The sandbox says which:
///
/// ```text
/// log show --last 5m --predicate 'eventMessage CONTAINS "deny(1) mach-lookup"'
/// ```
///
/// Decide whether that service is one a sandboxed command should be able to
/// reach before adding it. The answer for the four above is no.
pub const MACH_SERVICES_BASE: &[&str] = &["com.apple.system.opendirectoryd.libinfo"];

/// Mach services added when the profile grants outbound network, and only then.
///
/// * `TrustEvaluationAgent` — certificate-chain evaluation. Without it a TLS
///   handshake completes at the socket layer and then fails verification, so
///   `urllib`, `requests` and anything else using the system trust store cannot
///   reach an HTTPS host that the profile has explicitly been given access to.
///
/// `SystemConfiguration.configd` was also requested by the same tools and was
/// left out on purpose: they ran correctly without it. What it provides is the
/// system-wide proxy configuration, so a machine that reaches the network only
/// through a proxy set in System Settings (rather than `HTTPS_PROXY`) will not
/// have that proxy discovered inside the sandbox. If that is your situation it is
/// the one to add, knowing it also exposes the network configuration (interfaces,
/// DNS servers, Wi-Fi name) to the command.
pub const MACH_SERVICES_NETWORK: &[&str] = &["com.apple.TrustEvaluationAgent"];

/// The services a profile may look up: the base set, plus the network set when
/// outbound network is granted.
fn mach_services(p: &Profile) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = MACH_SERVICES_BASE.to_vec();
    if p.allow_network {
        v.extend_from_slice(MACH_SERVICES_NETWORK);
    }
    v
}

/// The `mach-lookup` rule for a list of services, or nothing at all if the list
/// is empty.
///
/// The empty case is not a detail. In SBPL `(allow mach-lookup)` with no filter
/// means *every service*, and so does `(allow mach-lookup` followed by nothing —
/// measured: with an empty block, `SecurityServer` is reachable. So an allowlist
/// that ends up empty and is written out naively becomes the blanket allow it
/// replaced. Emitting no rule leaves `(deny default)` to refuse everything, which
/// is what an empty list means.
fn mach_rule(services: &[&str]) -> Result<String, EnforceError> {
    if services.is_empty() {
        return Ok(String::new());
    }
    let mut s = String::from("(allow mach-lookup\n");
    for name in services {
        s.push_str(&format!("  (global-name {})\n", sbpl_string(name)?));
    }
    s.push_str(")\n");
    Ok(s)
}

/// Quote a path as an SBPL string literal.
///
/// This is a security boundary, not formatting. SBPL is s-expression source
/// compiled by the kernel, so an unescaped `"` in a workspace path would close
/// the string and let the rest of the path become policy — a directory named
/// `ws") (allow default) (deny nothing` would otherwise disable the sandbox
/// from inside the profile meant to configure it. Anything that is not a plain
/// printable character is escaped or the whole profile is refused.
fn sbpl_string(s: &str) -> Result<String, EnforceError> {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                return Err(EnforceError::Rejected {
                    stage: "profile generation",
                    detail: format!("path contains a control character: {s:?}"),
                });
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

fn path_string(p: &Path) -> Result<String, EnforceError> {
    let s = p.to_str().ok_or_else(|| EnforceError::Rejected {
        stage: "profile generation",
        detail: format!("path is not valid UTF-8: {p:?}"),
    })?;
    if !p.is_absolute() {
        return Err(EnforceError::Rejected {
            stage: "profile generation",
            detail: format!("path must be absolute, got {s:?}"),
        });
    }
    sbpl_string(s)
}

/// Compile a profile to SBPL source.
pub fn profile_sbpl(p: &Profile) -> Result<String, EnforceError> {
    let p = p.canonicalized();
    let mut s = String::with_capacity(2048);

    s.push_str("(version 1)\n");
    s.push_str("(deny default)\n");
    s.push_str("(allow sysctl-read)\n");
    // An allowlist, never a bare `(allow mach-lookup)`: see MACH_SERVICES_BASE.
    s.push_str(&mach_rule(&mach_services(&p))?);
    s.push_str("(allow file-read-metadata)\n");
    s.push_str("(allow signal (target self))\n");

    if p.allow_fork {
        s.push_str("(allow process-fork)\n");
    }

    s.push_str("(allow file-read*\n");
    // The root directory entry itself, and only it — `(literal "/")`, never
    // `(subpath "/")`, which would grant the whole filesystem.
    //
    // Found the hard way: without this, every process dies on SIGABRT during
    // dyld startup with no diagnostic, because `(subpath "/usr")` grants
    // access to things *under* /usr but not the lookup of `/` that reaching
    // them goes through. The failure looks exactly like a profile that is
    // subtly malformed, which is a good way to lose an afternoon.
    s.push_str("  (literal \"/\")\n");
    for d in BASE_READ {
        s.push_str(&format!("  (subpath {})\n", sbpl_string(d)?));
    }
    for d in BASE_DEVICES {
        s.push_str(&format!("  (literal {})\n", sbpl_string(d)?));
    }
    // Every grant is readable, and a writable one is a grant too: a directory
    // a command can write but not read back is nearly useless (`echo x > f;
    // cat f` fails on the read). The list is `Profile::fs_grants`, shared with
    // Landlock and the gVisor mount set, so the three cannot disagree about what
    // the same profile means.
    let grants = p.fs_grants();
    for g in &grants {
        s.push_str(&format!("  (subpath {})\n", path_string(&g.path)?));
    }
    s.push_str(")\n");

    // /dev/null and friends have to be writable or almost every pipeline
    // fails on its first redirect.
    s.push_str("(allow file-write*\n");
    s.push_str(&format!("  (literal {})\n", sbpl_string("/dev/null")?));
    s.push_str(&format!("  (literal {})\n", sbpl_string("/dev/tty")?));
    for g in grants.iter().filter(|g| g.access == Access::Write) {
        s.push_str(&format!("  (subpath {})\n", path_string(&g.path)?));
    }
    s.push_str(")\n");

    if p.allow_exec {
        s.push_str("(allow process-exec\n");
        for d in BASE_EXEC {
            s.push_str(&format!("  (subpath {})\n", sbpl_string(d)?));
        }
        s.push_str(&format!("  (subpath {})\n", path_string(&p.workspace)?));
        s.push_str(")\n");
    }

    if p.allow_network {
        // Seatbelt's network filters do not distinguish outbound connect from
        // inbound accept finely enough to express "connect but never listen",
        // so a profile that wants one gets both here. Landlock ABI 4 on Linux
        // does make that distinction. Stated rather than papered over.
        s.push_str("(allow network-outbound)\n");
        if p.allow_listen {
            s.push_str("(allow network-inbound)\n");
            s.push_str("(allow network-bind)\n");
        }
    }

    Ok(s)
}

/// A path as SBPL will see it: through any symlink in the part that exists, so
/// `/var/folders/...` matches the kernel's `/private/var/folders/...`. The part
/// that does not exist yet is kept as written.
fn real(p: &Path) -> std::path::PathBuf {
    real_within(p, 16)
}

/// [`real`], following at most `hops` symlinks whose targets do not exist yet:
/// `/var/run/docker.sock` names `~/.docker/run/docker.sock` before the daemon
/// that creates it has started, and a rule about the socket must name where it
/// will be.
fn real_within(p: &Path, hops: u8) -> std::path::PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    if hops > 0 {
        if let Ok(target) = std::fs::read_link(p) {
            let next = match p.parent() {
                Some(parent) if target.is_relative() => parent.join(target),
                _ => target,
            };
            return real_within(&next, hops - 1);
        }
    }
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) if parent != p => real_within(parent, hops).join(name),
        _ => p.to_path_buf(),
    }
}

/// A path as an anchored SBPL regular expression matching it and anything that
/// begins with it.
fn sbpl_prefix_regex(p: &Path) -> Result<String, EnforceError> {
    let s = p.to_str().ok_or_else(|| EnforceError::Rejected {
        stage: "profile generation",
        detail: format!("path is not valid UTF-8: {p:?}"),
    })?;
    let mut out = String::from("#\"^");
    for c in s.chars() {
        match c {
            '"' => {
                return Err(EnforceError::Rejected {
                    stage: "profile generation",
                    detail: format!("path contains a quote: {s:?}"),
                })
            }
            c if c.is_control() => {
                return Err(EnforceError::Rejected {
                    stage: "profile generation",
                    detail: format!("path contains a control character: {s:?}"),
                })
            }
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// Compile a whole-session profile to SBPL. The shape — reads open except
/// secrets, writes closed except the workspace and the agent's state — is
/// explained on [`AgentProfile`].
///
/// How SBPL picks between rules, measured rather than assumed (and pinned by
/// `sbpl_precedence_is_what_the_profiles_rely_on`): a rule with a filter beats
/// one without, in either order; among rules with filters, the last that
/// matches wins. So the secret denial overrides the open read wherever it
/// stands, but the frozen directories must come *after* the workspace grant —
/// placed before it, the grant would win and `.git/hooks` would be writable.
pub fn agent_sbpl(p: &AgentProfile) -> Result<String, EnforceError> {
    let mut s = String::with_capacity(4096);
    s.push_str("(version 1)\n");
    s.push_str("(deny default)\n");

    s.push_str("(allow file-read*)\n");
    if !p.secret_dirs.is_empty() {
        // Contents and listings, not existence: denying `stat` breaks tools that
        // only check whether a directory is there.
        s.push_str("(deny file-read-data file-read-xattr\n");
        for d in &p.secret_dirs {
            s.push_str(&format!("  (subpath {})\n", path_string(&real(d))?));
        }
        s.push_str(")\n");
    }

    s.push_str("(allow file-write*\n");
    s.push_str(&format!("  (subpath {})\n", path_string(&real(&p.workspace))?));
    for d in &p.write_dirs {
        s.push_str(&format!("  (subpath {})\n", path_string(&real(d))?));
    }
    for f in &p.write_prefixes {
        s.push_str(&format!("  (regex {})\n", sbpl_prefix_regex(&real(f))?));
    }
    for dev in ["/dev/null", "/dev/zero", "/dev/tty", "/dev/ptmx", "/dev/dtracehelper"] {
        s.push_str(&format!("  (literal {})\n", sbpl_string(dev)?));
    }
    s.push_str("  (regex #\"^/dev/ttys[0-9]+$\")\n");
    s.push_str(")\n");
    if !p.frozen_dirs.is_empty() {
        s.push_str("(deny file-write*\n");
        for d in &p.frozen_dirs {
            s.push_str(&format!("  (subpath {})\n", path_string(&real(d))?));
        }
        s.push_str(")\n");
    }

    // A terminal: the agent is interactive, and the tools it runs open ptys.
    s.push_str(
        "(allow file-ioctl (literal \"/dev/tty\") (literal \"/dev/ptmx\") \
         (literal \"/dev/dtracehelper\") (regex #\"^/dev/ttys[0-9]+$\"))\n",
    );
    s.push_str("(allow pseudo-tty)\n");
    s.push_str("(allow process-exec)\n");
    s.push_str("(allow process-fork)\n");
    s.push_str("(allow sysctl-read)\n");
    // The agent stops what it started; nothing else.
    s.push_str("(allow signal (target same-sandbox))\n");

    let mut services: Vec<&str> = MACH_SERVICES_BASE.to_vec();
    if p.allow_network {
        services.extend_from_slice(MACH_SERVICES_NETWORK);
    }
    for m in &p.mach_services {
        if !services.contains(&m.as_str()) {
            services.push(m);
        }
    }
    s.push_str(&mach_rule(&services)?);

    if p.allow_network {
        s.push_str("(allow network-outbound)\n");
    }
    if p.allow_local_listen {
        s.push_str("(allow network-bind (local ip \"localhost:*\"))\n");
        s.push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
    }
    if p.block_ssh_agent || !p.blocked_sockets.is_empty() || !p.blocked_socket_dirs.is_empty() {
        // The kernel checks the socket's resolved path, so each is named as it
        // resolves: blocking a symlink's own path blocks nothing (measured).
        s.push_str("(deny network-outbound\n");
        for d in &p.blocked_socket_dirs {
            let mut under = real(d);
            under.push("");
            s.push_str(&format!(
                "  (remote unix-socket (path-regex {}))\n",
                sbpl_prefix_regex(&under)?
            ));
        }
        if p.block_ssh_agent {
            // The socket launchd creates for the SSH agent, whatever its id.
            s.push_str(
                "  (remote unix-socket (path-regex \
                 #\"^/private/var/run/com\\.apple\\.launchd\\.[^/]+/Listeners$\"))\n",
            );
        }
        for sock in &p.blocked_sockets {
            s.push_str(&format!(
                "  (remote unix-socket (path-literal {}))\n",
                path_string(&real(sock))?
            ));
        }
        s.push_str(")\n");
    }
    Ok(s)
}

/// An argv that runs `program` for a whole session under `p`.
pub fn agent_command(
    p: &AgentProfile,
    program: &str,
    args: &[String],
) -> Result<Vec<String>, EnforceError> {
    let mut argv = vec!["/usr/bin/sandbox-exec".to_string(), "-p".to_string(), agent_sbpl(p)?];
    argv.push(program.to_string());
    argv.extend(args.iter().cloned());
    Ok(argv)
}

/// Build an argv that runs `program` under this profile via `sandbox-exec`.
///
/// Preferred over [`apply`]: the supervisor stays outside the sandbox, so it
/// can still write the audit record for a command that gets killed inside it.
pub fn command(p: &Profile, program: &str, args: &[&str]) -> Result<Vec<String>, EnforceError> {
    let sbpl = profile_sbpl(p)?;
    let mut argv = vec!["/usr/bin/sandbox-exec".to_string(), "-p".to_string(), sbpl];
    argv.push(program.to_string());
    argv.extend(args.iter().map(|a| a.to_string()));
    Ok(argv)
}

// The SBPL-source form of `sandbox_init`. Deprecated since 10.8 and still the
// only way to confine a process without an entitlement.
extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Confine the current process. Irreversible.
///
/// # Safety contract
///
/// This is safe to call, but it is not safe to *undo*: once applied the
/// restriction holds for the life of the process and every child it forks.
/// Calling it in a supervisor confines the supervisor.
pub fn apply(p: &Profile) -> Result<(), EnforceError> {
    let sbpl = profile_sbpl(p)?;
    let c = CString::new(sbpl).map_err(|_| EnforceError::Rejected {
        stage: "profile generation",
        detail: "profile contains an interior NUL".into(),
    })?;

    let mut err: *mut c_char = std::ptr::null_mut();
    // SAFETY: `c` is a valid NUL-terminated C string that outlives the call,
    // and `err` is a valid out-pointer. `sandbox_init` writes an owned string
    // there on failure, which is freed below with the matching deallocator.
    let rc = unsafe { sandbox_init(c.as_ptr(), 0, &mut err) };
    if rc == 0 {
        return Ok(());
    }

    let detail = if err.is_null() {
        format!("sandbox_init returned {rc}")
    } else {
        // SAFETY: non-null means the kernel wrote a NUL-terminated string.
        let msg = unsafe { std::ffi::CStr::from_ptr(err) }.to_string_lossy().into_owned();
        // SAFETY: `err` came from `sandbox_init` and is freed exactly once.
        unsafe { sandbox_free_error(err) };
        msg
    };
    Err(EnforceError::Rejected { stage: "sandbox_init", detail })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shellguard_policy::Capability;
    use std::process::Command;

    fn ws() -> std::path::PathBuf {
        let p = std::env::temp_dir().join("shellguard-seatbelt-tests");
        std::fs::create_dir_all(&p).unwrap();
        p.canonicalize().unwrap()
    }

    #[test]
    fn a_profile_denies_by_default() {
        let sbpl = profile_sbpl(&Profile::locked_down(ws())).unwrap();
        assert!(sbpl.starts_with("(version 1)\n(deny default)"));
    }

    #[test]
    fn writes_appear_only_when_granted() {
        let p = Profile::locked_down(ws());
        let sbpl = profile_sbpl(&p).unwrap();
        // The workspace is readable but not writable.
        assert!(sbpl.contains(&format!("(subpath \"{}\")", ws().display())));
        let write_block = sbpl.split("(allow file-write*").nth(1).unwrap();
        let write_block = write_block.split(")\n(").next().unwrap();
        assert!(!write_block.contains(&ws().display().to_string()));

        let p = Profile::from_capabilities(ws(), &[Capability::FsWrite]);
        let sbpl = profile_sbpl(&p).unwrap();
        let write_block = sbpl.split("(allow file-write*").nth(1).unwrap();
        assert!(write_block.contains(&ws().display().to_string()));
    }

    #[test]
    fn a_writable_path_is_also_readable() {
        // Found by a runtime test: the private scratch directory was writable
        // but not readable, so `echo x > $TMPDIR/f; cat $TMPDIR/f` failed on
        // the read.
        let p = Profile::from_capabilities(ws(), &[Capability::FsWrite])
            .with_private_tmp(ws().join("scratch"));
        std::fs::create_dir_all(ws().join("scratch")).unwrap();
        let sbpl = profile_sbpl(&p).unwrap();
        let read_block = sbpl.split("(allow file-read*").nth(1).unwrap();
        let read_block = read_block.split(")\n(").next().unwrap();
        for w in p.canonicalized().writable() {
            assert!(
                read_block.contains(&w.display().to_string()),
                "{} is writable but not readable",
                w.display()
            );
        }
    }

    #[test]
    fn network_appears_only_when_granted() {
        let sbpl = profile_sbpl(&Profile::locked_down(ws())).unwrap();
        assert!(!sbpl.contains("network-outbound"));
        let p = Profile::from_capabilities(ws(), &[Capability::NetConnect]);
        assert!(profile_sbpl(&p).unwrap().contains("network-outbound"));
    }

    // ------------------------------------------------------------ mach services

    /// The text of the `(allow mach-lookup ...)` block, or None if there is none.
    fn mach_block(sbpl: &str) -> Option<String> {
        let start = sbpl.find("(allow mach-lookup")?;
        let rest = &sbpl[start..];
        // The block closes with a lone `)` on its own line; `")\n` alone is only
        // the end of an entry.
        Some(rest[..rest.find("\n)\n")? + 2].to_string())
    }

    fn mach_names(sbpl: &str) -> Vec<String> {
        mach_block(sbpl)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().strip_prefix("(global-name \""))
            .filter_map(|l| l.strip_suffix("\")"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn mach_lookup_is_an_allowlist_never_a_blanket_allow() {
        for p in [
            Profile::locked_down(ws()),
            Profile::from_capabilities(ws(), &[Capability::FsWrite]),
            Profile::from_capabilities(ws(), &[Capability::NetConnect]),
        ] {
            let sbpl = profile_sbpl(&p).unwrap();
            // A bare `(allow mach-lookup)` — or any mach-lookup rule that is not
            // scoped to a named service — lets a command talk to every daemon
            // on the machine. Checked on lines because the SBPL is line-shaped.
            assert!(
                !sbpl.lines().any(|l| l.trim() == "(allow mach-lookup)"),
                "blanket mach-lookup:\n{sbpl}"
            );
            let block = mach_block(&sbpl).expect("no mach-lookup rule at all");
            assert!(block.contains("(global-name \""), "rule names no service:\n{block}");
            assert!(!block.contains("regex"), "a regex service match is a blanket in disguise");
            assert_eq!(sbpl.matches("mach-lookup").count(), 1, "more than one mach rule:\n{sbpl}");
        }
    }

    #[test]
    fn an_empty_allowlist_emits_no_rule_because_an_empty_rule_allows_everything() {
        // `(allow mach-lookup` with no filter is the blanket allow (verified
        // against the kernel: SecurityServer is reachable through it). So the
        // generator must write nothing for an empty list, not an empty block.
        assert_eq!(mach_rule(&[]).unwrap(), "");
        let one = mach_rule(&["com.example.a"]).unwrap();
        assert_eq!(one, "(allow mach-lookup\n  (global-name \"com.example.a\")\n)\n");
        // Names go through the string escaper like every other SBPL literal.
        let hostile = mach_rule(&["x\") (allow default) (\""]).unwrap();
        assert!(!hostile.lines().any(|l| l.trim() == "(allow default)"), "{hostile}");
        assert!(mach_rule(&["bad\nname"]).is_err());
    }

    #[test]
    fn the_offline_profile_gets_the_base_services_and_nothing_else() {
        let sbpl = profile_sbpl(&Profile::from_capabilities(ws(), &[Capability::FsWrite])).unwrap();
        assert_eq!(mach_names(&sbpl), MACH_SERVICES_BASE);
        for n in MACH_SERVICES_NETWORK {
            assert!(!sbpl.contains(n), "{n} is granted without a network grant");
        }
    }

    #[test]
    fn a_network_grant_adds_exactly_the_network_services() {
        let sbpl =
            profile_sbpl(&Profile::from_capabilities(ws(), &[Capability::NetConnect])).unwrap();
        let mut want: Vec<&str> = MACH_SERVICES_BASE.to_vec();
        want.extend_from_slice(MACH_SERVICES_NETWORK);
        assert_eq!(mach_names(&sbpl), want);
    }

    #[test]
    fn the_services_that_act_on_the_users_behalf_are_in_no_allowlist() {
        // The reason the allowlist exists. If one of these is ever added because
        // a tool needed it, this fails and the reason has to be written down here
        // — it is a decision about what a sandboxed command can make the system
        // do for it, not a compatibility patch.
        let forbidden = [
            "launchservices",            // open a URL or an application
            "SecurityServer",            // the keychain
            "securityd",                 // ditto
            "pasteboard",                // the clipboard
            "nsurlsessiond",             // background URL fetches
            "pboard",                    // older clipboard name
            "usernoted",                 // post notifications
            "distributed_notifications", // broadcast to every app
        ];
        for n in MACH_SERVICES_BASE.iter().chain(MACH_SERVICES_NETWORK) {
            for f in forbidden {
                assert!(
                    !n.to_lowercase().contains(&f.to_lowercase()),
                    "{n} matches `{f}`: a sandboxed command would be able to make the system act for it"
                );
            }
        }
        // Names are SBPL string literals and go through the same escaping.
        for n in MACH_SERVICES_BASE.iter().chain(MACH_SERVICES_NETWORK) {
            assert_eq!(sbpl_string(n).unwrap(), format!("\"{n}\""), "{n} needs escaping");
        }
    }

    // A tool an agent runs, and the fixture it runs against. `script` is run by
    // `/bin/sh` inside `dir`, first with no sandbox (the control) and then under
    // the profile; the two must agree on exit status and stdout.
    const TOOLS: &[(&str, &str)] = &[
        // Anything that asks who it is or who owns a file needs opendirectoryd.
        // This is the entry whose removal from the allowlist breaks the most.
        (
            "ownership",
            "id -un; ls -l a.txt | awk '{print $3}'; stat -f %Su a.txt; groups | wc -w | tr -d ' '",
        ),
        (
            "python-user-database",
            "python3 -c 'import pwd,grp,os,getpass; \
             print(pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name, getpass.getuser())'",
        ),
        (
            "git",
            "git -c user.email=a@b.c -c user.name=n -c init.defaultBranch=main init -q . \
             && git add -A \
             && git -c user.email=a@b.c -c user.name=n commit -qm one \
             && echo two >> a.txt && git status --short && git diff --stat | tail -1 && git log --format=%s",
        ),
        ("cc", "cc hello.c -o hello && ./hello"),
        ("make", "make"),
        (
            "archives",
            "tar czf x.tgz a.txt && tar tzf x.tgz; gzip -c a.txt | gunzip | wc -l; \
             zip -q x.zip a.txt && unzip -l x.zip | tail -1",
        ),
        (
            "text-tools",
            "grep -c foo a.txt; sort data.txt | uniq -c | wc -l; sed s/foo/bar/ a.txt | head -1; \
             awk '{print $1}' a.txt | head -1; find . -name '*.txt' | sort | head -2",
        ),
        (
            "interpreters",
            "perl -e 'print 1+1, \"\\n\"'; node -e 'console.log(2+2)'; sqlite3 :memory: 'select 3'; \
             bash -c 'echo b'; zsh -c 'echo z'",
        ),
        (
            "python-runs-a-subprocess",
            "python3 -c 'import subprocess; print(subprocess.run([\"ls\"],capture_output=True).stdout.decode().split())'",
        ),
        ("system-info", "uname -s; date +%Y >/dev/null; hostname >/dev/null; locale | head -1; xcrun --show-sdk-path >/dev/null; echo done"),
    ];

    fn reset_fixture(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir.join("tmp")).unwrap();
        std::fs::write(dir.join("a.txt"), "foo one\nbar two\nfoo three\n").unwrap();
        std::fs::write(dir.join("data.txt"), "x,1\ny,2\nx,3\n").unwrap();
        std::fs::write(
            dir.join("hello.c"),
            "#include <stdio.h>\nint main(){puts(\"hello\");return 0;}\n",
        )
        .unwrap();
        std::fs::write(dir.join("Makefile"), "all:\n\t@echo built\n").unwrap();
    }

    fn tool_env(cmd: &mut Command, dir: &Path) {
        cmd.current_dir(dir)
            .env("HOME", dir)
            .env("TMPDIR", dir.join("tmp"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C");
    }

    /// (exit code, stdout) of `script`, unsandboxed or under `p`.
    fn outcome(p: Option<&Profile>, dir: &Path, script: &str) -> (Option<i32>, String) {
        reset_fixture(dir);
        let mut c = match p {
            None => {
                let mut c = Command::new("/bin/sh");
                c.args(["-c", script]);
                c
            }
            Some(p) => {
                let argv = command(p, "/bin/sh", &["-c", script]).unwrap();
                let mut c = Command::new(&argv[0]);
                c.args(&argv[1..]);
                c
            }
        };
        tool_env(&mut c, dir);
        let out = c.output().expect("spawn");
        (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
    }

    #[test]
    fn ordinary_tools_behave_the_same_under_the_mach_allowlist_as_without_a_sandbox() {
        // The allowlist is only acceptable if it costs nothing that people use.
        // Each tool runs twice: with no sandbox, then under the profile. A tool
        // that needs a service the allowlist withholds fails or prints something
        // different, and the assertion names it.
        //
        // The control is what stops this being vacuous: a tool missing from this
        // machine (no node, say) fails the same way both times and proves nothing,
        // so those are skipped and counted, and the test wants most to have run.
        let dir = ws().join("mach-tools");
        let p = Profile::from_capabilities(ws(), &[Capability::FsWrite]);

        let mut compared = Vec::new();
        let mut skipped = Vec::new();
        let mut broken = Vec::new();
        for (name, script) in TOOLS {
            let control = outcome(None, &dir, script);
            if control.0 != Some(0) || control.1.trim().is_empty() {
                skipped.push(*name);
                continue;
            }
            let confined = outcome(Some(&p), &dir, script);
            if confined != control {
                broken.push(format!("{name}: control {control:?}, confined {confined:?}"));
            } else {
                compared.push(*name);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            broken.is_empty(),
            "tools that work without a sandbox break under the mach allowlist \
             (read the refused service from `log show`, see MACH_SERVICES_BASE):\n{}",
            broken.join("\n")
        );
        assert!(
            compared.len() >= 8,
            "only {} tools could be compared ({compared:?}); skipped, control failed: {skipped:?}",
            compared.len()
        );
    }

    // ----------------------------------------------------- profile injection

    #[test]
    fn a_quote_in_a_path_cannot_escape_the_profile_string() {
        // Without escaping this closes the string and the rest of the path
        // becomes policy, disabling the sandbox from inside the profile meant
        // to configure it.
        let evil = std::path::PathBuf::from(r#"/tmp/ws") (allow default) (deny nothing"#);
        let p = Profile { workspace: evil, ..Profile::locked_down("/tmp") };
        let sbpl = profile_sbpl(&p).unwrap();

        // The injected text still appears — as escaped data inside a string
        // literal, which is the point. What must not appear is a directive at
        // the top level of the s-expression.
        assert!(
            !sbpl.lines().any(|l| l.trim() == "(allow default)"),
            "profile injection succeeded:\n{sbpl}"
        );
        assert!(sbpl.contains(r#"\""#), "the quote was not escaped:\n{sbpl}");
    }

    #[test]
    fn a_control_character_in_a_path_is_refused() {
        let p = Profile {
            workspace: std::path::PathBuf::from("/tmp/ws\nnewline"),
            ..Profile::locked_down("/tmp")
        };
        assert!(matches!(profile_sbpl(&p), Err(EnforceError::Rejected { .. })));
    }

    #[test]
    fn a_relative_path_is_refused() {
        let p = Profile::locked_down("relative/path");
        assert!(matches!(profile_sbpl(&p), Err(EnforceError::Rejected { .. })));
    }

    #[test]
    fn sbpl_escaping() {
        assert_eq!(sbpl_string("/a/b").unwrap(), r#""/a/b""#);
        assert_eq!(sbpl_string(r#"/a"b"#).unwrap(), r#""/a\"b""#);
        assert_eq!(sbpl_string(r"/a\b").unwrap(), r#""/a\\b""#);
        assert!(sbpl_string("/a\tb").is_err());
    }

    // ------------------------------------------------ end-to-end enforcement

    fn run_confined(p: &Profile, script: &str) -> std::process::Output {
        let argv = command(p, "/bin/sh", &["-c", script]).unwrap();
        Command::new(&argv[0])
            .args(&argv[1..])
            // Inside the workspace, as the runtime does. Inheriting the
            // caller's directory means the shell cannot even `getcwd`, which
            // fails in a way that looks nothing like the thing being tested.
            .current_dir(ws())
            .output()
            .expect("sandbox-exec should run")
    }

    #[test]
    fn a_confined_command_still_works() {
        let p = Profile::from_capabilities(ws(), &[Capability::FsWrite]);
        let out = run_confined(&p, "echo hello");
        assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
    }

    #[test]
    fn the_kernel_actually_blocks_a_write_outside_the_workspace() {
        // The whole point. If this passes, confinement is real on this host.
        let p = Profile::from_capabilities(ws(), &[Capability::FsWrite]);
        let out = run_confined(&p, "echo pwned > /tmp/shellguard-should-not-exist");
        assert!(!out.status.success(), "a write outside the workspace succeeded");
        assert!(!Path::new("/tmp/shellguard-should-not-exist").exists());
    }

    #[test]
    fn the_kernel_allows_a_write_inside_the_workspace() {
        let p = Profile::from_capabilities(ws(), &[Capability::FsWrite]);
        let target = ws().join("allowed.txt");
        let _ = std::fs::remove_file(&target);
        let out = run_confined(&p, &format!("echo ok > {}", target.display()));
        assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(std::fs::read_to_string(&target).unwrap().trim(), "ok");
        let _ = std::fs::remove_file(&target);
    }

    #[test]
    fn the_command_line_tools_are_reachable() {
        // `/usr/bin/python3` and `/usr/bin/git` on macOS re-exec through
        // `xcrun` into /Library/Developer. Without it they fail with a dlopen
        // error that gives no hint the sandbox caused it.
        let p = Profile::from_capabilities(ws(), &[Capability::FsWrite]);
        let out = run_confined(&p, "python3 -c 'print(1+1)'");
        assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "2");
    }

    #[test]
    fn a_read_outside_the_allowed_set_is_blocked() {
        let p = Profile::from_capabilities(ws(), &[Capability::FsWrite]);
        // /etc/passwd is world-readable and outside every granted subpath.
        let out = run_confined(&p, "cat /etc/passwd > /dev/null");
        assert!(!out.status.success(), "a read outside the profile succeeded");
    }
}

#[cfg(test)]
mod agent_session_tests {
    //! A whole agent session, against the real kernel, with a stand-in agent.
    //!
    //! The agent is a shell and the processes it starts, in a fixture with a fake
    //! home directory, so nothing here can touch the real one. Each refusal is
    //! paired with an unsandboxed control showing the same action succeeds when
    //! nothing stops it — otherwise "refused" could mean "broken".

    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Fixture {
            let root = std::env::temp_dir()
                .join(format!("shellguard-agent-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            for d in ["ws/.git/hooks", "home/.ssh", "home/.claude", "outside", "tmp"] {
                std::fs::create_dir_all(root.join(d)).unwrap();
            }
            std::fs::write(root.join("home/.ssh/id_rsa"), "PRIVATE KEY").unwrap();
            std::fs::write(root.join("home/notes.txt"), "notes").unwrap();
            std::fs::write(root.join("outside/keep.txt"), "keep").unwrap();
            std::fs::write(root.join("ws/f.txt"), "f").unwrap();
            Fixture { root: root.canonicalize().unwrap() }
        }
        fn p(&self, rel: &str) -> PathBuf {
            self.root.join(rel)
        }
        fn profile(&self) -> AgentProfile {
            AgentProfile::for_program("claude", &self.p("ws"), &self.p("home"), &self.p("tmp"))
        }
        /// (exit status, stdout+stderr) of `script`, sandboxed or not.
        fn run(&self, script: &str, sandboxed: bool) -> (bool, String) {
            let mut c = if sandboxed {
                let argv = agent_command(&self.profile(), "/bin/sh", &["-c".into(), script.into()])
                    .unwrap();
                let mut c = Command::new(&argv[0]);
                c.args(&argv[1..]);
                c
            } else {
                let mut c = Command::new("/bin/sh");
                c.args(["-c", script]);
                c
            };
            let out = c
                .current_dir(self.p("ws"))
                .env("HOME", self.p("home"))
                .env("TMPDIR", self.p("tmp"))
                .env("OUT", self.p("outside"))
                .output()
                .expect("spawn");
            let text = String::from_utf8_lossy(&out.stdout).into_owned()
                + &String::from_utf8_lossy(&out.stderr);
            (out.status.success(), text)
        }
        /// `script` works without the sandbox and fails inside it.
        fn refused(&self, script: &str) {
            let (ok, out) = self.run(script, false);
            assert!(ok, "control failed, so the test proves nothing: {script}\n{out}");
            self.reset();
            let (ok, out) = self.run(script, true);
            assert!(!ok, "the session allowed: {script}\n{out}");
        }
        fn allowed(&self, script: &str) {
            let (ok, out) = self.run(script, true);
            assert!(ok, "the session refused: {script}\n{out}");
        }
        /// Put back whatever an unsandboxed control changed.
        fn reset(&self) {
            let _ = std::fs::write(self.p("home/notes.txt"), "notes");
            let _ = std::fs::write(self.p("outside/keep.txt"), "keep");
            let _ = std::fs::remove_file(self.p("outside/new.txt"));
            let _ = std::fs::remove_file(self.p("ws/.git/hooks/pre-commit"));
            let _ = std::fs::remove_dir_all(self.p("home/newdir"));
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn nothing_outside_the_workspace_is_written_by_the_agent_or_anything_it_starts() {
        let fx = Fixture::new("writes");
        for script in [
            "echo x > \"$OUT/new.txt\"",
            "echo changed > \"$OUT/keep.txt\"",
            "rm \"$OUT/keep.txt\"",
            "echo changed > \"$HOME/notes.txt\"",
            "mkdir \"$HOME/newdir\"",
            "mv f.txt \"$OUT/\"",
            // Two and three processes down: what the agent runs, and what that runs.
            "bash -c 'echo x > \"$OUT/new.txt\"'",
            "python3 -c 'import os; open(os.environ[\"OUT\"]+\"/new.txt\",\"w\").write(\"x\")'",
            "sh -c \"bash -c 'rm \\\"$OUT/keep.txt\\\"'\"",
        ] {
            fx.reset();
            fx.refused(script);
        }
        assert_eq!(std::fs::read_to_string(fx.p("outside/keep.txt")).unwrap(), "keep");
    }

    #[test]
    fn the_workspace_the_agents_state_and_its_temp_directory_are_writable() {
        let fx = Fixture::new("state");
        fx.allowed("echo x > new.txt && mkdir -p d/e && echo y > d/e/f && rm f.txt");
        fx.allowed("echo s > \"$HOME/.claude/settings.json\"");
        // The file beside the home directory, and the copy written before a rename.
        fx.allowed(
            "echo j > \"$HOME/.claude.json.tmp.1\" && mv \"$HOME/.claude.json.tmp.1\" \"$HOME/.claude.json\"",
        );
        fx.allowed("echo t > \"$TMPDIR/t\"");
        fx.allowed("python3 -c 'print(1)' > /dev/null");
    }

    #[test]
    fn secrets_cannot_be_read_but_ordinary_files_can() {
        let fx = Fixture::new("secrets");
        fx.refused("cat \"$HOME/.ssh/id_rsa\"");
        fx.refused("ls \"$HOME/.ssh\"");
        fx.refused("python3 -c 'import os; open(os.environ[\"HOME\"]+\"/.ssh/id_rsa\").read()'");
        // Existence is not a secret: tools look before they read.
        fx.allowed("test -d \"$HOME/.ssh\"");
        fx.allowed("cat \"$HOME/notes.txt\" >/dev/null && ls \"$HOME\" >/dev/null");
    }

    #[test]
    fn a_git_hook_cannot_be_planted_for_the_person_to_run_later() {
        let fx = Fixture::new("hooks");
        fx.refused("echo 'curl evil' > .git/hooks/pre-commit");
        fx.allowed("echo ref > .git/ORIG_HEAD");
    }

    #[test]
    fn the_session_can_reach_the_network_and_serve_on_loopback() {
        let fx = Fixture::new("net");
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        fx.allowed(&format!(
            "python3 -c 'import socket; socket.create_connection((\"127.0.0.1\",{port}),2)'"
        ));
        fx.allowed(
            "python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\",0)); s.listen(1)'",
        );
    }

    #[test]
    fn the_ssh_agent_socket_is_refused_and_other_sockets_are_not() {
        let fx = Fixture::new("sock");
        // Short names, connected to relatively: an absolute path under the temp
        // directory is longer than a Unix socket address can be.
        let ws = fx.p("ws");
        let agent = std::os::unix::net::UnixListener::bind(ws.join("agent.sock")).unwrap();
        let other = std::os::unix::net::UnixListener::bind(ws.join("other.sock")).unwrap();
        let connect = |name: &str, profile: Option<&AgentProfile>| -> bool {
            let script =
                format!("import socket; s=socket.socket(socket.AF_UNIX); s.connect('{name}')");
            let mut c = match profile {
                Some(p) => {
                    let argv =
                        agent_command(p, "/usr/bin/python3", &["-c".into(), script]).unwrap();
                    let mut c = Command::new(&argv[0]);
                    c.args(&argv[1..]);
                    c
                }
                None => {
                    let mut c = Command::new("/usr/bin/python3");
                    c.args(["-c", &script]);
                    c
                }
            };
            c.current_dir(&ws).output().unwrap().status.success()
        };
        let mut p = fx.profile();
        p.blocked_sockets.push(ws.join("agent.sock"));
        assert!(connect("agent.sock", None), "control: the socket accepts unsandboxed");
        assert!(!connect("agent.sock", Some(&p)), "the session reached the blocked agent socket");
        assert!(connect("other.sock", Some(&p)), "an unrelated socket was refused too");
        drop((agent, other));
    }

    #[test]
    fn a_container_daemon_socket_is_refused_wherever_the_runtime_keeps_it() {
        let fx = Fixture::new("docker");
        let ws = fx.p("ws");
        std::fs::create_dir_all(ws.join("run")).unwrap();
        let daemon = std::os::unix::net::UnixListener::bind(ws.join("run/d.sock")).unwrap();
        // Reached through a symlink, as /var/run/docker.sock is.
        std::os::unix::fs::symlink("run/d.sock", ws.join("docker.sock")).unwrap();
        let other = std::os::unix::net::UnixListener::bind(ws.join("ok.sock")).unwrap();
        let mut p = fx.profile();
        p.blocked_socket_dirs.push(ws.join("run"));
        let connect = |name: &str| -> bool {
            let script =
                format!("import socket; s=socket.socket(socket.AF_UNIX); s.connect('{name}')");
            let argv = agent_command(&p, "/usr/bin/python3", &["-c".into(), script]).unwrap();
            Command::new(&argv[0])
                .args(&argv[1..])
                .current_dir(&ws)
                .output()
                .unwrap()
                .status
                .success()
        };
        assert!(!connect("run/d.sock"), "the daemon's socket was reachable");
        assert!(!connect("docker.sock"), "the daemon's socket was reachable through a symlink");
        assert!(connect("ok.sock"), "an unrelated socket was refused");
        drop((daemon, other));
    }

    #[test]
    fn a_symlink_whose_target_does_not_exist_yet_is_named_by_its_target() {
        let fx = Fixture::new("dangling");
        std::os::unix::fs::symlink(fx.p("outside/later.sock"), fx.p("ws/link.sock")).unwrap();
        assert_eq!(real(&fx.p("ws/link.sock")), fx.p("outside/later.sock"));
    }

    #[test]
    fn a_command_inside_cannot_be_given_a_narrower_sandbox_on_macos() {
        // The measured limitation that shapes the design: inside a session, the
        // per-command sandbox cannot be applied. If this ever starts passing, the
        // session can layer per-command confinement after all.
        let fx = Fixture::new("nest");
        let (ok, out) = fx.run(
            "/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' /bin/echo nested",
            true,
        );
        assert!(!ok && out.contains("Operation not permitted"), "{out}");
    }

    /// The rule precedence the session profile depends on, against the kernel.
    /// If a macOS release changes it, this fails before a profile quietly stops
    /// meaning what it says.
    #[test]
    fn sbpl_precedence_is_what_the_profiles_rely_on() {
        let fx = Fixture::new("precedence");
        let x = fx.p("home/.ssh");
        let read = |rules: &str| -> bool {
            let sbpl = format!("(version 1)(allow default){rules}");
            Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &sbpl, "/bin/cat"])
                .arg(x.join("id_rsa"))
                .output()
                .unwrap()
                .status
                .success()
        };
        let d = x.display();
        // A filtered rule beats an unfiltered one, in either order.
        assert!(!read(&format!("(allow file-read*)(deny file-read-data (subpath \"{d}\"))")));
        assert!(!read(&format!("(deny file-read-data (subpath \"{d}\"))(allow file-read*)")));
        // Among filtered rules, the last match wins.
        assert!(read(&format!(
            "(deny file-read-data (subpath \"{d}\"))(allow file-read-data (subpath \"{d}\"))"
        )));
        assert!(!read(&format!(
            "(allow file-read-data (subpath \"{d}\"))(deny file-read-data (subpath \"{d}\"))"
        )));
    }

    #[test]
    fn the_profile_puts_each_exception_after_the_rule_it_narrows() {
        let fx = Fixture::new("order");
        let sbpl = agent_sbpl(&fx.profile()).unwrap();
        let at =
            |needle: &str| sbpl.find(needle).unwrap_or_else(|| panic!("no `{needle}`:\n{sbpl}"));
        assert!(at("(allow file-read*)") < at("(deny file-read-data"));
        assert!(at("(allow file-write*") < at("(deny file-write*"));
        assert!(sbpl.starts_with("(version 1)\n(deny default)\n"));
        assert!(!sbpl.lines().any(|l| l.trim() == "(allow mach-lookup)"), "blanket mach-lookup");
    }
}
