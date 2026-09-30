//! Exfiltration: what stops a command from sending data out.
//!
//! Rollback restores local files. It cannot recall a secret that has already left
//! the machine, so the only defence is that the command never gets the network.
//! `tests/exfiltration.txt` lists the commands and, for each, *what* is supposed to
//! stop it — the gate (`blocked`), an explicit and visible grant (`granted`), or
//! the kernel sandbox alone (`sandbox`).
//!
//! Three things are checked, in increasing order of how much they can be trusted:
//!
//! 1. **Classification.** Each command is judged and must land in its class. A
//!    policy change that moves one is a decision someone has to make, not an
//!    accident.
//! 2. **No implicit network.** For every command, the profile the engine would
//!    build has network *if and only if* the decision names a network capability.
//! 3. **Containment, against the real kernel.** The `sandbox` commands that aim at a
//!    loopback listener are actually run. Each is first run *unsandboxed* as a
//!    control — if the control cannot reach the listener, the command proves
//!    nothing and is not counted — and then sandboxed, where nothing may arrive.
//!
//! The third is the one that matters, and the control is what stops it being
//! vacuous: a command that fails to start would "deliver nothing" too.

use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use shellguard_enforce::Profile;
use shellguard_gate::{Gate, GateConfig};
use shellguard_policy::{Capability, Verdict};
use shellguard_runtime::Engine;
#[cfg(target_os = "macos")]
use shellguard_runtime::{LocalRuntime, Payload, Runtime};

const SPEC: &str = include_str!("../../../tests/exfiltration.txt");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Blocked,
    Granted,
    Sandbox,
}

struct Case {
    line: usize,
    class: Class,
    /// With `{TCP}` and `{UDP}` still in it.
    template: String,
}

impl Case {
    /// Ports that nothing listens on, for classification.
    fn classified(&self) -> String {
        self.template.replace("{TCP}", "9").replace("{UDP}", "9")
    }

    /// Whether it aims at a local listener, and so can be run for real.
    fn targets_a_listener(&self) -> bool {
        self.template.contains("{TCP}")
            || self.template.contains("{UDP}")
            || self.template.contains("u.sock")
    }
}

fn cases() -> Vec<Case> {
    SPEC.lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let l = raw.trim_end();
            if l.trim().is_empty() || l.trim_start().starts_with('#') {
                return None;
            }
            let (class, cmd) = l.split_once('\t').unwrap_or_else(|| {
                panic!("exfiltration.txt:{}: expected `class<TAB>command`", i + 1)
            });
            let class = match class {
                "blocked" => Class::Blocked,
                "granted" => Class::Granted,
                "sandbox" => Class::Sandbox,
                other => panic!("exfiltration.txt:{}: unknown class `{other}`", i + 1),
            };
            Some(Case { line: i + 1, class, template: cmd.to_string() })
        })
        .collect()
}

fn is_network(c: &Capability) -> bool {
    matches!(c, Capability::NetConnect | Capability::NetListen | Capability::PackageInstall)
}

/// A workspace under a short path: a Unix-domain socket path is limited to about
/// a hundred bytes, and the default temp directory on macOS alone is half that.
struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn new(name: &str) -> Workspace {
        let root = PathBuf::from("/tmp").join(format!("sgx-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ws")).unwrap();
        // A file worth stealing, so the commands have something to name.
        std::fs::write(root.join("ws/secrets.txt"), "hunter2\n").unwrap();
        Workspace { root: root.canonicalize().unwrap() }
    }
    fn ws(&self) -> PathBuf {
        self.root.join("ws")
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// An engine whose gate has a generous deadline.
///
/// The gate fails closed when it exceeds its deadline (100 ms by default), which
/// on a loaded machine can turn an innocent command into a `deny` and a classification test
/// into a coin flip. These tests are about *which* verdict the rules give, not
/// how fast; latency is measured elsewhere.
fn engine(ws: &Path) -> Engine {
    let mut cfg = GateConfig::from_env(ws);
    cfg.cwd = ws.to_path_buf();
    cfg.deadline = Duration::from_secs(30);
    Engine::new(ws)
        .unwrap()
        .with_gate(Gate::with_default_policy(cfg))
        .with_timeout(Duration::from_secs(20))
}

// ---------------------------------------------------------------- 1. classification

#[test]
fn every_command_lands_in_the_class_the_specification_gives_it() {
    let sb = Workspace::new("classify");
    let e = engine(&sb.ws());
    let mut wrong = Vec::new();

    for c in cases() {
        let d = e.evaluate(&c.classified());
        assert!(d.incomplete.is_none(), "line {}: the gate gave up: {:?}", c.line, d.incomplete);
        let sees_network = d.capabilities.iter().any(is_network);

        let ok = match c.class {
            Class::Blocked => d.verdict >= Verdict::Ask,
            Class::Granted => sees_network,
            Class::Sandbox => d.verdict < Verdict::Ask && !sees_network,
        };
        if !ok {
            wrong.push(format!(
                "  exfiltration.txt:{}  expected `{:?}`, gate said {} with capabilities {:?}\n    {}",
                c.line,
                c.class,
                d.verdict.as_str(),
                d.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                c.classified()
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} commands are not where the specification puts them.\n\
         Moving one is a decision — a `sandbox` command the gate now recognises \
         should become `blocked` or `granted` on purpose, not by accident.\n\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_specification_has_all_three_classes_in_quantity() {
    let all = cases();
    for class in [Class::Blocked, Class::Granted, Class::Sandbox] {
        let n = all.iter().filter(|c| c.class == class).count();
        assert!(n >= 2, "only {n} `{class:?}` cases");
    }
    assert!(all.len() >= 30, "the specification has shrunk to {} commands", all.len());
}

// ---------------------------------------------------------------- 2. no implicit network

#[test]
fn a_profile_has_network_exactly_when_the_decision_names_a_network_capability() {
    // Whatever class a command is in, the network must come only from a
    // capability the gate actually reported, so it shows in the record. A profile
    // that could gain network some other way would make `sandbox` a lie.
    let sb = Workspace::new("implicit");
    let e = engine(&sb.ws());
    for c in cases() {
        let d = e.evaluate(&c.classified());
        let profile = e.profile_for(&d);
        let granted_by_capability = d.capabilities.iter().any(is_network);
        assert_eq!(
            profile.allow_network,
            granted_by_capability,
            "line {} `{}`: profile network={}, but the decision's capabilities were {:?}",
            c.line,
            c.classified(),
            profile.allow_network,
            d.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>()
        );
    }
}

#[test]
fn a_command_the_gate_does_not_recognise_as_networking_gets_a_profile_without_network() {
    let sb = Workspace::new("unrecognised");
    let e = engine(&sb.ws());
    let mut checked = 0;
    for c in cases().iter().filter(|c| c.class == Class::Sandbox) {
        let d = e.evaluate(&c.classified());
        let p = e.profile_for(&d);
        assert!(!p.allow_network && !p.allow_listen, "line {}: {}", c.line, c.classified());
        checked += 1;
    }
    assert!(checked >= 15, "only {checked} sandbox-class commands were checked");
}

// ---------------------------------------------------------------- 3. containment

/// Loopback listeners that count what reaches them.
struct Listeners {
    tcp_port: u16,
    udp_port: u16,
    tcp: Arc<AtomicUsize>,
    udp: Arc<AtomicUsize>,
    unix: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Listeners {
    fn start(ws: &Path) -> Listeners {
        let stop = Arc::new(AtomicBool::new(false));
        let (tcp, udp, unix) = (
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );

        let t = TcpListener::bind("127.0.0.1:0").unwrap();
        t.set_nonblocking(true).unwrap();
        let tcp_port = t.local_addr().unwrap().port();
        spawn_poller(&stop, tcp.clone(), move || t.accept().is_ok());

        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        u.set_nonblocking(true).unwrap();
        let udp_port = u.local_addr().unwrap().port();
        spawn_poller(&stop, udp.clone(), move || u.recv_from(&mut [0u8; 4096]).is_ok());

        #[cfg(unix)]
        {
            let x = std::os::unix::net::UnixListener::bind(ws.join("u.sock")).unwrap_or_else(|e| {
                panic!("cannot bind {}: {e} (path too long?)", ws.join("u.sock").display())
            });
            x.set_nonblocking(true).unwrap();
            spawn_poller(&stop, unix.clone(), move || x.accept().is_ok());
        }

        Listeners { tcp_port, udp_port, tcp, udp, unix, stop }
    }

    fn fill(&self, template: &str) -> String {
        template
            .replace("{TCP}", &self.tcp_port.to_string())
            .replace("{UDP}", &self.udp_port.to_string())
    }

    fn total(&self) -> usize {
        self.tcp.load(Ordering::SeqCst)
            + self.udp.load(Ordering::SeqCst)
            + self.unix.load(Ordering::SeqCst)
    }

    /// Let anything in flight arrive before counting.
    fn settle(&self) {
        std::thread::sleep(Duration::from_millis(250));
    }
}

impl Drop for Listeners {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn spawn_poller(
    stop: &Arc<AtomicBool>,
    counter: Arc<AtomicUsize>,
    mut poll: impl FnMut() -> bool + Send + 'static,
) {
    let stop = stop.clone();
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            if poll() {
                counter.fetch_add(1, Ordering::SeqCst);
            } else {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    });
}

/// Run `cmd` with no sandbox at all. The control: can this command reach a
/// listener when nothing stops it? Only ever pointed at loopback.
fn run_unsandboxed(cmd: &str, cwd: &Path) -> bool {
    let mut child = match Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s.success(),
            Ok(None) if start.elapsed() < Duration::from_secs(15) => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// The containment property, shared by the platforms that should satisfy it.
fn assert_sandboxed_commands_reach_nothing() {
    let sb = Workspace::new("contain");
    let ws = sb.ws();
    let l = Listeners::start(&ws);
    let e = engine(&ws);

    let mut capable = Vec::new();
    let mut incapable = Vec::new();
    let mut breaches = Vec::new();

    for c in cases().iter().filter(|c| c.class == Class::Sandbox && c.targets_a_listener()) {
        let cmd = l.fill(&c.template);

        // Control: unsandboxed, the command must reach a listener, or it tells
        // us nothing (no such interpreter, wrong syntax, ...).
        let before = l.total();
        run_unsandboxed(&cmd, &ws);
        l.settle();
        if l.total() <= before {
            incapable.push(c.template.clone());
            continue;
        }
        capable.push(c.template.clone());

        // The real thing: through the engine, under the real sandbox.
        let before = l.total();
        let run = e.execute_with_rollback(&cmd).expect("the engine failed");
        l.settle();
        let delivered = l.total() - before;

        assert!(run.ran(), "line {}: the gate refused a `sandbox`-class command: {cmd}", c.line);
        if delivered > 0 {
            breaches.push(format!(
                "  line {}: {delivered} delivery(ies) from a sandboxed `{cmd}`",
                c.line
            ));
        }
    }

    assert!(
        breaches.is_empty(),
        "{} sandboxed commands reached a listener with no network granted:\n{}",
        breaches.len(),
        breaches.join("\n")
    );
    // The harness must have been able to see something, or silence means nothing.
    assert!(
        capable.len() >= 3,
        "only {} commands could reach a listener even unsandboxed ({:?}); \
         incapable here: {:?}",
        capable.len(),
        capable,
        incapable
    );
    eprintln!(
        "contained: {} commands; not runnable here (control failed): {:?}",
        capable.len(),
        incapable
    );
}

#[cfg(target_os = "macos")]
#[test]
fn sandboxed_commands_without_a_network_grant_reach_no_listener() {
    assert_sandboxed_commands_reach_nothing();
}

/// The same property on Linux — which is not expected to hold.
///
/// Landlock's network rules (ABI 4+) cover TCP `bind` and `connect` only. They do
/// not cover UDP or Unix-domain sockets, and this project's seccomp filter does
/// not deny `socket`, `sendto` or `connect`. So a command with no network grant
/// can still send UDP datagrams (DNS exfiltration) and connect to Unix sockets.
/// Read from the code; never run, because there is no Linux host here.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "KNOWN GAP on Linux: UDP and Unix sockets are not restricted (DESIGN.md 12); run with --ignored on a Linux host"]
fn sandboxed_commands_without_a_network_grant_reach_no_listener() {
    assert_sandboxed_commands_reach_nothing();
}

#[cfg(target_os = "macos")]
#[test]
fn the_control_is_real_a_granted_profile_does_reach_the_listeners() {
    // The other side of the containment test. If a profile that *is* granted
    // network could not reach the listeners either, silence under no grant would
    // mean the harness was broken, not that the sandbox was working.
    let sb = Workspace::new("granted");
    let ws = sb.ws();
    let l = Listeners::start(&ws);

    let tcp = format!(
        "python3 -c \"import socket; socket.create_connection(('127.0.0.1',{}),2)\"",
        l.tcp_port
    );
    let udp = format!(
        "python3 -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'x',('127.0.0.1',{}))\"",
        l.udp_port
    );
    let unix = "python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); s.connect('u.sock')\""
        .to_string();

    let mut profile = Profile::locked_down(&ws).with_private_tmp(ws.join("tmp"));
    std::fs::create_dir_all(ws.join("tmp")).unwrap();
    profile.write_paths.push(ws.clone());
    profile.allow_network = true;

    let rt = LocalRuntime::new();
    for (label, cmd, counter) in
        [("tcp", tcp, &l.tcp), ("udp", udp, &l.udp), ("unix", unix, &l.unix)]
    {
        let before = counter.load(Ordering::SeqCst);
        let payload =
            Payload::new(&cmd, &ws, profile.clone()).with_timeout(Duration::from_secs(15));
        let res = rt.execute(&payload).expect("runtime");
        l.settle();
        assert!(
            counter.load(Ordering::SeqCst) > before,
            "a profile WITH network could not reach the {label} listener (exit {:?}, stderr: {}); \
             the containment test would be measuring a broken harness",
            res.exit_code,
            String::from_utf8_lossy(&res.stderr)
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn hostnames_do_not_resolve_without_a_network_grant() {
    // DNS carries data in the name it is asked about, so a resolver reachable from
    // the sandbox is an exfiltration channel that needs no socket. macOS reaches
    // its resolver over a Unix-domain socket, which is denied along with the rest;
    // this pins that.
    //
    // Skipped, loudly, when the machine cannot resolve at all: a failure inside the
    // sandbox is then indistinguishable from having no DNS, and passing on it would
    // prove nothing.
    let sb = Workspace::new("dns");
    let ws = sb.ws();

    let mut out = String::new();
    let control = Command::new("python3")
        .arg("-c")
        .arg("import socket; print(socket.gethostbyname('example.com'))")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut c| {
            c.stdout.take().unwrap().read_to_string(&mut out)?;
            c.wait()
        });
    if !control.map(|s| s.success()).unwrap_or(false) || out.trim().is_empty() {
        eprintln!("SKIPPED: this machine cannot resolve example.com, so the sandbox result would prove nothing");
        return;
    }

    let e = engine(&ws);
    let run = e
        .execute_with_rollback(
            "python3 -c \"import socket; print(socket.gethostbyname('example.com'))\"",
        )
        .unwrap();
    let stdout = run
        .exec
        .as_ref()
        .map(|x| String::from_utf8_lossy(&x.stdout).into_owned())
        .unwrap_or_default();
    assert!(run.ran(), "the gate refused a plain lookup");
    assert!(
        !run.exec.as_ref().unwrap().ok() && !stdout.chars().any(|c| c.is_ascii_digit()),
        "a sandboxed command with no network grant resolved a hostname: {stdout:?}"
    );
}

/// Asks the Mach bootstrap server whether the calling process may look up a
/// service. Success or refusal is unambiguous, and nothing is launched, opened or
/// read — which is why this is the probe used, after `open -a NoSuchApp` proved
/// useless: it resolves application names locally and answers the same either way.
///
/// The names are the two the profile grants (`libinfo` always, `TrustEvaluationAgent`
/// with a network grant), `logd` and `configd` as services tools do ask for and the
/// profile deliberately does not grant, and the four that act on the user's behalf.
#[cfg(target_os = "macos")]
const MACH_PROBE: &str = r#"
import ctypes
libc = ctypes.CDLL(None)
libc.bootstrap_look_up.argtypes = [ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]
libc.bootstrap_look_up.restype = ctypes.c_int
bp = ctypes.c_uint.in_dll(libc, "bootstrap_port")
for name in ["com.apple.system.opendirectoryd.libinfo", "com.apple.TrustEvaluationAgent",
             "com.apple.logd", "com.apple.SystemConfiguration.configd",
             "com.apple.coreservices.launchservicesd", "com.apple.SecurityServer",
             "com.apple.pasteboard.1", "com.apple.nsurlsessiond"]:
    port = ctypes.c_uint()
    kr = libc.bootstrap_look_up(bp, name.encode(), ctypes.byref(port))
    print("REACHABLE" if kr == 0 else "refused  ", name)
"#;

/// The services that act on a client's behalf, which no profile may grant: open a
/// URL or an application (LaunchServices), read the keychain (SecurityServer),
/// read or write the clipboard (pasteboard), fetch URLs in the background
/// (nsurlsessiond).
#[cfg(target_os = "macos")]
const ACT_ON_BEHALF: &[&str] = &[
    "com.apple.coreservices.launchservicesd",
    "com.apple.SecurityServer",
    "com.apple.pasteboard.1",
    "com.apple.nsurlsessiond",
];

/// Names the probe found reachable, from its output.
#[cfg(target_os = "macos")]
fn reachable(out: &str) -> std::collections::BTreeSet<String> {
    out.lines().filter_map(|l| l.strip_prefix("REACHABLE ")).map(|n| n.trim().to_string()).collect()
}

/// A check that `reachable` is what the profile grants, and that the probe worked.
#[cfg(target_os = "macos")]
fn assert_reachable_is_exactly(out: &str, granted: &[&str], what: &str) {
    let got = reachable(out);
    let want: std::collections::BTreeSet<String> = granted.iter().map(|s| s.to_string()).collect();
    // The harness must have worked, or "refused" would mean nothing: a probe that
    // printed nothing would pass a test that asks for an empty set.
    assert_eq!(
        out.lines().filter(|l| l.starts_with("REACHABLE") || l.starts_with("refused")).count(),
        8,
        "the probe did not report all 8 services: {out}"
    );
    for n in ACT_ON_BEHALF {
        assert!(
            !got.contains(*n),
            "{what}: reachable {n}, which acts on the user's behalf:\n{out}"
        );
    }
    assert_eq!(got, want, "{what}: reachable services differ from the granted set:\n{out}");
}

/// A command with no network grant may look up only the services in
/// `MACH_SERVICES_BASE`.
///
/// This was a known gap (an `#[ignore]`d test) while the Seatbelt profile allowed
/// *every* `mach-lookup`: all four services that act on the user's behalf were
/// reachable, measured. It is now an allowlist, and this states what the allowlist
/// means to the kernel rather than to the SBPL text.
///
/// Reachable is not the same as exploitable, and this project has NOT tested
/// whether any of them could be made to leak — doing so means opening URLs and
/// reading a clipboard and keychain on the developer's machine. The property is
/// the cheaper, stronger one: they cannot be asked at all.
#[cfg(target_os = "macos")]
#[test]
fn privileged_system_services_are_not_reachable_from_the_sandbox() {
    let sb = Workspace::new("mach");
    let ws = sb.ws();
    std::fs::write(ws.join("machprobe.py"), MACH_PROBE).unwrap();

    let run = engine(&ws).execute_with_rollback("python3 machprobe.py").unwrap();
    let out =
        String::from_utf8_lossy(&run.exec.expect("the probe did not run").stdout).into_owned();

    assert_reachable_is_exactly(
        &out,
        shellguard_enforce::macos::MACH_SERVICES_BASE,
        "no network grant",
    );
}

/// A network grant adds the certificate-trust service, and still not the four.
///
/// Granting network must not be a way to reach the keychain or the clipboard:
/// the two grants are independent, and this is the test that says so.
#[cfg(target_os = "macos")]
#[test]
fn a_network_grant_does_not_open_the_services_that_act_on_the_users_behalf() {
    let sb = Workspace::new("machnet");
    let ws = sb.ws();
    std::fs::write(ws.join("machprobe.py"), MACH_PROBE).unwrap();

    let mut profile = Profile::locked_down(&ws).with_private_tmp(ws.join("tmp"));
    std::fs::create_dir_all(ws.join("tmp")).unwrap();
    profile.write_paths.push(ws.clone());
    profile.allow_network = true;

    let res = LocalRuntime::new()
        .execute(
            &Payload::new("python3 machprobe.py", &ws, profile)
                .with_timeout(Duration::from_secs(15)),
        )
        .expect("runtime");
    let out = String::from_utf8_lossy(&res.stdout).into_owned();

    let mut granted: Vec<&str> = shellguard_enforce::macos::MACH_SERVICES_BASE.to_vec();
    granted.extend_from_slice(shellguard_enforce::macos::MACH_SERVICES_NETWORK);
    assert_reachable_is_exactly(&out, &granted, "network grant");
}

/// The other half of the network allowlist: with the grant, TLS verification
/// actually works, so the trust service is there for a reason and not by habit.
///
/// Ignored because it needs the internet and a third party's server to be up;
/// run it with `--ignored` after touching the network services.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "needs internet access; run with --ignored after changing MACH_SERVICES_NETWORK"]
fn a_network_grant_is_enough_to_complete_a_tls_handshake_and_verify_it() {
    let sb = Workspace::new("tls");
    let ws = sb.ws();
    let mut profile = Profile::locked_down(&ws).with_private_tmp(ws.join("tmp"));
    std::fs::create_dir_all(ws.join("tmp")).unwrap();
    profile.write_paths.push(ws.clone());
    profile.allow_network = true;

    let cmd = "python3 -c \"import urllib.request; \
               print(urllib.request.urlopen('https://example.com', timeout=15).status)\"";
    let res = LocalRuntime::new()
        .execute(&Payload::new(cmd, &ws, profile).with_timeout(Duration::from_secs(30)))
        .expect("runtime");
    assert_eq!(
        String::from_utf8_lossy(&res.stdout).trim(),
        "200",
        "exit {:?}, stderr: {}",
        res.exit_code,
        String::from_utf8_lossy(&res.stderr)
    );
}

#[test]
fn counts_by_class_are_reported() {
    // Not an assertion about behaviour: a readable summary for `--nocapture`.
    let mut by: BTreeMap<String, usize> = BTreeMap::new();
    for c in cases() {
        *by.entry(format!("{:?}", c.class)).or_default() += 1;
    }
    eprintln!("exfiltration.txt: {by:?}");
}
