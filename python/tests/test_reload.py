"""Replacing a running engine's rules, through the Python bindings.

Real library, real gate. What is held to account here: a command is judged by
one whole policy, a bad or weakening policy never displaces the one in force,
and an engine handle built after a reload does not quietly run the old rules.

Build the library first:

    cargo build --release -p shellguard-ffi
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_sandbox import PolicyRejected, SandboxEngine, SandboxError  # noqa: E402
from agent_sandbox.binding import LibraryNotFound, find_library  # noqa: E402

DEFAULT_POLICY = (Path(__file__).resolve().parents[2] / "policies" / "default.policy").read_text()

#: The built-in rules plus one more — a strengthening, so it reloads strictly.
PLUS_DENY_ECHO = (
    DEFAULT_POLICY
    + "\n\nrule test.no-echo deny\n  reason echo is forbidden in this test\n"
    "  program echo\n  cap fs.read\nend\n"
)


@pytest.fixture(scope="session", autouse=True)
def _require_library() -> None:
    try:
        find_library()
    except LibraryNotFound as e:
        pytest.skip(str(e), allow_module_level=True)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    repo = tmp_path / "work"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main", ".")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")
    (repo / "tracked.txt").write_text("committed\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial")
    return repo.resolve()


# ---------------------------------------------------------------------------
# It takes effect


def test_a_reload_changes_what_the_engine_decides(workspace: Path) -> None:
    with SandboxEngine(workspace=workspace) as engine:
        assert engine.decide("echo hi").verdict == "allow"
        before = engine.policy_fingerprint

        report = engine.reload_policy(PLUS_DENY_ECHO)

        assert engine.decide("echo hi").verdict == "deny"
        assert report["before"] == before
        assert report["after"] == engine.policy_fingerprint != before
        assert report["changed"] is True
        assert report["added"] == ["test.no-echo"]
        assert report["removed"] == [] and report["weakened"] == []


def test_a_decision_names_the_policy_that_made_it(workspace: Path) -> None:
    with SandboxEngine(workspace=workspace) as engine:
        d0 = engine.decide("echo hi")
        engine.reload_policy(PLUS_DENY_ECHO)
        d1 = engine.decide("echo hi")

        assert d0.policy and d1.policy and d0.policy != d1.policy
        assert d1.policy == engine.policy_fingerprint
        assert len(d0.policy) == 16


def test_a_reloaded_policy_governs_execution_too(workspace: Path) -> None:
    marker = workspace / "ran.txt"
    with SandboxEngine(workspace=workspace) as engine:
        assert engine.execute_with_rollback("echo ran > ran.txt", str(workspace)).ran
        marker.unlink()

        engine.reload_policy(PLUS_DENY_ECHO)
        result = engine.execute_with_rollback("echo ran > ran.txt", str(workspace))

        assert result.blocked and result.decision.verdict == "deny"
        assert not marker.exists(), "a command the new policy forbids ran"


def test_reloading_the_same_policy_reports_no_change(workspace: Path) -> None:
    with SandboxEngine(workspace=workspace) as engine:
        engine.reload_policy(PLUS_DENY_ECHO)
        report = engine.reload_policy(PLUS_DENY_ECHO)
        assert report["changed"] is False
        assert report["added"] == report["removed"] == report["modified"] == []


# ---------------------------------------------------------------------------
# A bad reload never displaces a good policy


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "this is not a policy",
        "version 1\nrule x deny\n  reason r\n  program echo\n",  # unterminated
        "version 1\nrule x maybe\n  reason r\n  program echo\nend\n",  # unknown verdict
        "\x01\x02\x7f",
    ],
)
def test_a_malformed_policy_is_refused_and_changes_nothing(workspace: Path, bad: str) -> None:
    with SandboxEngine(workspace=workspace) as engine:
        engine.reload_policy(PLUS_DENY_ECHO)
        fingerprint = engine.policy_fingerprint

        with pytest.raises(PolicyRejected, match="previous policy still in force"):
            engine.reload_policy(bad, allow_weakening=True)

        assert engine.policy_fingerprint == fingerprint
        assert engine.decide("echo hi").verdict == "deny"


def test_a_duplicated_rule_is_refused(workspace: Path) -> None:
    # The mistake that shipped in a real policy edit: a block pasted twice.
    block = "rule dup.x deny\n  reason x\n  program nc\n  cap net.connect\nend\n"
    with SandboxEngine(workspace=workspace) as engine:
        fingerprint = engine.policy_fingerprint
        with pytest.raises(PolicyRejected, match="duplicate rule id"):
            engine.reload_policy(DEFAULT_POLICY + "\n" + block + "\n" + block)
        assert engine.policy_fingerprint == fingerprint


def test_a_policy_that_lowers_protection_is_refused_unless_allowed(workspace: Path) -> None:
    with SandboxEngine(workspace=workspace) as engine:
        fingerprint = engine.policy_fingerprint
        weaker = "version 1\ndefault allow\n"

        with pytest.raises(PolicyRejected, match="lower protection"):
            engine.reload_policy(weaker)

        assert engine.policy_fingerprint == fingerprint
        assert engine.decide("rm -rf /etc").verdict == "deny", "protection was lost anyway"

        report = engine.reload_policy(weaker, allow_weakening=True)
        assert report["weakened"], "an allowed weakening must still say what it weakened"
        assert engine.decide("rm -rf /etc").verdict == "allow"


def test_a_policy_file_cut_short_is_caught_at_every_line(workspace: Path) -> None:
    # A failed write leaves a prefix of the file. Cut the real policy at each
    # line: whatever parses as a smaller policy must not be accepted silently.
    lines = DEFAULT_POLICY.splitlines()
    accepted_strictly = 0
    with SandboxEngine(workspace=workspace) as engine:
        for cut in range(1, len(lines) - 1):
            prefix = "\n".join(lines[:cut])
            try:
                engine.reload_policy(prefix)  # strict
            except PolicyRejected:
                continue
            accepted_strictly += 1
            # If a truncation got in, it must have dropped nothing that
            # restricts — otherwise the guard missed it.
            assert engine.decide("rm -rf /etc").verdict == "deny", (
                f"a policy cut at line {cut} was accepted and lost protection"
            )
            engine.reload_policy(DEFAULT_POLICY, allow_weakening=True)  # reset
    # Some cuts are harmless (nothing restrictive lost); the assertion above is
    # what matters. This just documents that the loop exercised both outcomes.
    assert accepted_strictly < len(lines)


def test_the_guard_compares_against_what_is_in_force_not_what_began(workspace: Path) -> None:
    with SandboxEngine(workspace=workspace) as engine:
        engine.reload_policy(PLUS_DENY_ECHO)  # stronger than the built-in
        # Going back is now a weakening, though it is where we started.
        with pytest.raises(PolicyRejected, match="lower protection"):
            engine.reload_policy(DEFAULT_POLICY)


# ---------------------------------------------------------------------------
# Several workspaces, one engine


def test_a_workspace_first_used_after_a_reload_runs_the_reloaded_rules(
    workspace: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    with SandboxEngine(workspace=workspace) as engine:
        engine.reload_policy(PLUS_DENY_ECHO)

        # `other` has never been used, so its handle is built now. It must not
        # come up with the built-in rules.
        result = engine.execute_with_rollback("echo hi", str(other))

        assert result.blocked and result.decision.verdict == "deny"
        assert result.decision.policy == engine.policy_fingerprint


def test_handles_that_already_existed_are_all_updated(workspace: Path, tmp_path: Path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    with SandboxEngine(workspace=workspace) as engine:
        # Handles are built lazily, one per workspace; use both.
        assert engine.execute_with_rollback("true", str(workspace)).ran
        assert engine.execute_with_rollback("true", str(other)).ran
        assert len(engine._engines) == 2

        engine.reload_policy(PLUS_DENY_ECHO)

        for ws in (workspace, other):
            assert engine.execute_with_rollback("echo hi", str(ws)).blocked, ws


def test_a_refused_reload_is_refused_for_every_handle_or_none(
    workspace: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    with SandboxEngine(workspace=workspace) as engine:
        engine.execute_with_rollback("true", str(other))
        with pytest.raises(PolicyRejected):
            engine.reload_policy("version 1\ndefault allow\n")
        for ws in (workspace, other):
            assert engine.execute_with_rollback("rm -rf /etc", str(ws)).blocked


# ---------------------------------------------------------------------------
# The audit trail


def test_reloads_are_recorded_and_decisions_can_be_traced_to_them(
    workspace: Path, tmp_path: Path
) -> None:
    log = tmp_path / "log" / "audit.jsonl"
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        engine.decide("ls")
        engine.reload_policy(PLUS_DENY_ECHO)
        engine.decide("ls")
        with pytest.raises(PolicyRejected):
            engine.reload_policy("version 1\ndefault allow\n")

    recs: list[dict[str, Any]] = [json.loads(x) for x in log.read_text().splitlines()]
    assert [r["kind"] for r in recs] == ["header", "evaluate", "policy", "evaluate", "policy"]

    applied, rejected = recs[2], recs[4]
    assert applied["outcome"] == "applied"
    assert applied["sha256"] == hashlib.sha256(PLUS_DENY_ECHO.encode()).hexdigest()
    assert applied["before"] == recs[1]["policy"], "the record does not link to the policy before"
    assert applied["after"] == recs[3]["policy"], "the record does not link to the policy after"
    assert applied["added"] == ["test.no-echo"]

    assert rejected["outcome"] == "rejected"
    assert "lower protection" in rejected["error"]
    assert rejected["weakened"], "a refused weakening must record what it would have weakened"


# ---------------------------------------------------------------------------
# Racing


def test_judgments_racing_reloads_are_always_wholly_one_policy(workspace: Path) -> None:
    with SandboxEngine(workspace=workspace) as engine:
        engine.reload_policy(DEFAULT_POLICY, allow_weakening=True)
        fp_plain = engine.policy_fingerprint
        engine.reload_policy(PLUS_DENY_ECHO)
        fp_deny = engine.policy_fingerprint

        stop = threading.Event()
        problems: list[str] = []
        seen: set[str] = set()

        def evaluate() -> None:
            while not stop.is_set():
                d = engine.decide("echo hi")
                seen.add(d.policy)
                expected = {fp_plain: "allow", fp_deny: "deny"}.get(d.policy)
                if expected is None:
                    problems.append(f"named a policy never installed: {d.policy}")
                elif d.verdict != expected:
                    problems.append(f"{d.policy} carried {d.verdict}, expected {expected}")

        threads = [threading.Thread(target=evaluate) for _ in range(3)]
        for t in threads:
            t.start()
        for i in range(300):
            engine.reload_policy(
                PLUS_DENY_ECHO if i % 2 == 0 else DEFAULT_POLICY, allow_weakening=True
            )
        stop.set()
        for t in threads:
            t.join()

        assert not problems, problems[:3]
        assert seen == {fp_plain, fp_deny}, f"only saw {seen}; the test raced nothing"


# ---------------------------------------------------------------------------
# Misuse


def test_reload_policy_wants_text_not_a_path(workspace: Path) -> None:
    with SandboxEngine(workspace=workspace) as engine:
        with pytest.raises(TypeError, match="str"):
            engine.reload_policy(Path("policies/default.policy"))  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            engine.reload_policy(b"version 1")  # type: ignore[arg-type]


def test_reloading_on_a_closed_engine_raises(workspace: Path) -> None:
    engine = SandboxEngine(workspace=workspace)
    engine.close()
    with pytest.raises(SandboxError):
        engine.reload_policy(PLUS_DENY_ECHO)
