"""The audit log through the Python bindings.

Real library, real kernel sandbox, real git repository — as in test_harness.py.
The point of each test is a property an operator relies on: that a credential
never reaches the file, that a required log stops a command it cannot record,
that a best-effort log which fails says so rather than going quiet.

Build the library first:

    cargo build --release -p shellguard-ffi
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_sandbox import SandboxEngine, SandboxError  # noqa: E402
from agent_sandbox.binding import LibraryNotFound, find_library  # noqa: E402

# Fabricated; each has the shape of a real credential and is not one.
TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"


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


@pytest.fixture
def log(tmp_path: Path) -> Path:
    """Outside the workspace: a log inside it is an untracked file, and a
    rollback that restored it would erase the record of the rollback."""
    return tmp_path / "log" / "audit.jsonl"


def records(path: Path) -> list[dict[str, Any]]:
    # splitlines() rather than iterating the file: it splits on more characters
    # than "\n", and a log that survives it is one no line-oriented reader can
    # be tricked into reading as two records.
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def kinds(path: Path) -> list[str]:
    return [r["kind"] for r in records(path)]


# ---------------------------------------------------------------------------
# What gets recorded


def test_an_executed_command_leaves_a_header_a_start_and_a_finish(
    workspace: Path, log: Path
) -> None:
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        result = engine.execute_with_rollback("python3 -c \"print('hello')\"", str(workspace))

    assert result.ok, result.stderr
    assert result.audit_error is None
    assert kinds(log) == ["header", "start", "finish"]

    header, start, finish = records(log)
    assert header["source"] == "ffi"
    assert "only commands submitted" in header["coverage"]
    assert start["id"] == finish["id"]
    assert start["command"] == "python3 -c \"print('hello')\""
    assert finish["exit_code"] == 0
    assert finish["rolled_back"] is False


def test_a_refused_command_is_recorded_as_refused_and_never_as_started(
    workspace: Path, log: Path
) -> None:
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        result = engine.execute_with_rollback("rm -rf /", str(workspace))

    assert result.blocked
    assert kinds(log) == ["header", "refused"]
    refused = records(log)[1]
    assert refused["verdict"] == "deny"
    assert refused["ran"] is False
    assert refused["findings"], "a refusal with no finding cannot be reviewed"


def test_evaluating_is_recorded_and_does_not_execute(workspace: Path, log: Path) -> None:
    marker = workspace / "side-effect.txt"
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        engine.eval_command(f"echo x > {marker}")

    assert kinds(log) == ["header", "evaluate"]
    assert not marker.exists()


def test_a_rollback_and_why_it_happened_are_recorded(workspace: Path, log: Path) -> None:
    with SandboxEngine(
        workspace=workspace, audit_log=log, rollback_on_failure=True
    ) as engine:
        result = engine.execute_with_rollback("echo damaged > tracked.txt; exit 1", str(workspace))

    assert result.ran, f"the command did not run: {result.decision}"
    assert result.rolled_back
    finish = records(log)[-1]
    assert finish["kind"] == "finish"
    assert finish["rolled_back"] is True
    assert any("exited 1" in r for r in finish["rollback_reasons"])
    # And the record of the rollback is still there after the rollback.
    assert log.exists()


def test_one_engine_over_several_workspaces_writes_one_log(
    workspace: Path, tmp_path: Path, log: Path
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        engine.execute_with_rollback("true", str(workspace))
        engine.execute_with_rollback("true", str(other))

    starts = [r for r in records(log) if r["kind"] == "start"]
    assert {r["workspace"] for r in starts} == {str(workspace), str(other.resolve())}
    # Two handles, one file, one header.
    assert kinds(log).count("header") == 1


# ---------------------------------------------------------------------------
# What must never be recorded


def test_credentials_in_a_command_never_reach_the_file(workspace: Path, log: Path) -> None:
    cmd = (
        'curl -H "Authorization: Bearer abcdef1234567890" '
        f"https://alice:hunter2@example.com/x?token=sekrit && echo {TOKEN}"
    )
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        engine.eval_command(cmd)
        engine.execute_with_rollback(cmd, str(workspace))

    raw = log.read_text(encoding="utf-8")
    for secret in ("abcdef1234567890", "hunter2", "sekrit", TOKEN):
        assert secret not in raw, f"`{secret}` reached the audit file"
    assert "[REDACTED]" in raw


def test_output_is_not_recorded_by_default(workspace: Path, log: Path) -> None:
    # "zxyyqv" exists only in stdout: printf assembles it, so the command text
    # that *is* recorded never contains it.
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        result = engine.execute_with_rollback("printf 'zx%sqv' yy", str(workspace))

    assert result.stdout == "zxyyqv"
    assert "zxyyqv" not in log.read_text(encoding="utf-8")
    assert "stdout" not in records(log)[-1]


def test_verbose_records_output_but_still_redacts_it(workspace: Path, log: Path) -> None:
    with SandboxEngine(workspace=workspace, audit_log=log, audit_verbose=True) as engine:
        engine.execute_with_rollback(f"printf 'zx%sqv %s' yy {TOKEN}", str(workspace))

    raw = log.read_text(encoding="utf-8")
    assert TOKEN not in raw
    assert "zxyyqv" in records(log)[-1]["stdout"]
    assert "[REDACTED]" in records(log)[-1]["stdout"]


def test_the_log_is_private_to_its_owner(workspace: Path, log: Path) -> None:
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        engine.eval_command("ls")
    assert log.stat().st_mode & 0o777 == 0o600


def test_characters_a_line_splitter_would_split_on_do_not_split_a_record(
    workspace: Path, log: Path
) -> None:
    # U+2028, U+0085 and friends are line breaks to str.splitlines(). A record
    # containing one raw would be read as two, the second controlled by
    # whoever wrote the command.
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        engine.eval_command("echo a b\u0085c\x0bd\x1ce")

    text = log.read_text(encoding="utf-8")
    assert len(text.splitlines()) == len(text.split("\n")) - 1 == 2  # header + one record
    assert records(log)[1]["command"] == "echo a b\u0085c\x0bd\x1ce"


# ---------------------------------------------------------------------------
# When the log fails


def test_a_required_log_that_fails_refuses_the_command(workspace: Path, log: Path) -> None:
    marker = workspace / "ran.txt"
    with SandboxEngine(workspace=workspace, audit_log=log, audit_required=True) as engine:
        engine.runtime()  # builds the engine handle, and so opens the log
        shutil.rmtree(log.parent)

        with pytest.raises(SandboxError, match="not run"):
            engine.execute_with_rollback(f"echo x > {marker}", str(workspace))

    assert not marker.exists(), "the command ran although it could not be recorded"


def test_a_best_effort_log_that_fails_says_so_and_the_command_still_runs(
    workspace: Path, log: Path
) -> None:
    marker = workspace / "ran.txt"
    with SandboxEngine(workspace=workspace, audit_log=log) as engine:
        engine.runtime()
        assert engine.audit_failures == 0
        shutil.rmtree(log.parent)

        result = engine.execute_with_rollback("echo ran > ran.txt", str(workspace))

        assert result.ran and result.exit_code == 0
        assert marker.read_text() == "ran\n"
        assert result.audit_error is not None
        assert "start record" in result.audit_error and "finish record" in result.audit_error
        assert engine.audit_failures >= 2


def test_a_log_that_cannot_be_opened_raises_and_leaves_no_engine_behind(
    workspace: Path, tmp_path: Path
) -> None:
    a_directory = tmp_path / "not-a-file"
    a_directory.mkdir()
    engine = SandboxEngine(workspace=workspace, audit_log=a_directory)

    with pytest.raises(SandboxError):
        engine.execute_with_rollback("echo x > ran.txt", str(workspace))

    assert engine._engines == {}, "a half-configured engine was cached"
    assert not (workspace / "ran.txt").exists()
    engine.close()


def test_audit_options_without_a_log_are_an_error_not_silently_ignored(
    workspace: Path,
) -> None:
    with pytest.raises(SandboxError, match="audit_log"):
        SandboxEngine(workspace=workspace, audit_required=True)
    with pytest.raises(SandboxError, match="audit_log"):
        SandboxEngine(workspace=workspace, audit_verbose=True)


def test_without_a_log_there_is_nothing_to_fail(workspace: Path) -> None:
    with SandboxEngine(workspace=workspace) as engine:
        result = engine.execute_with_rollback("true", str(workspace))
        assert result.audit_error is None
        assert engine.audit_failures == 0
