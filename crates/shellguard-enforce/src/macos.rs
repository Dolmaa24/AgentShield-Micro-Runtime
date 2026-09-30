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
    s.push_str("(allow mach-lookup)\n");
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
