"""Python bindings for the AgentShield micro-runtime.

``ctypes`` rather than CFFI. The C surface is nine functions and no structs, so
CFFI's compile step would buy nothing and cost a build dependency in a project
whose whole premise is not having any — see DESIGN.md § 10. ``ctypes`` ships with
CPython and works from a wheel with no toolchain present.

The header is ``include/agent_sandbox.h``; the library it declares is
``libshellguard`` with ``sg_``-prefixed symbols. The header is named for the
project and the library for the component inside it — the two refer to the
same thing.

    from agent_sandbox import SandboxEngine

    with SandboxEngine() as engine:
        print(engine.eval_command("rm -rf /")["verdict"])        # 'deny'
        result = engine.execute_with_rollback("pytest -q", "/srv/work")
        if result.rolled_back:
            print("reverted:", result.rollback_reasons)

One thing worth knowing before using it: a ``deny`` is a *successful* call that
reports ``ran=False``. It does not raise. Refusing to run a command is the
library working, not failing, and a binding that raised on it would push callers
towards ``try/except: pass``.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "SandboxEngine",
    "ExecutionResult",
    "Decision",
    "Finding",
    "Verdict",
    "SandboxError",
    "LibraryNotFound",
    "find_library",
]


#: Roll back when the command exits non-zero.
ROLLBACK_ON_FAILURE = 1 << 0
#: Run commands the gate escalates rather than stopping at them.
RUN_ON_ASK = 1 << 1

#: Audit log: also record stdout and stderr (redacted).
AUDIT_VERBOSE = 1 << 0
#: Audit log: refuse to run a command whose record cannot be written.
AUDIT_REQUIRED = 1 << 1


class SandboxError(RuntimeError):
    """The engine could not be built, or the library misbehaved."""


class LibraryNotFound(SandboxError):
    """libshellguard could not be located."""


class Verdict:
    """Verdicts, ordered by severity."""

    ALLOW = "allow"
    CONFINE = "confine"
    ASK = "ask"
    DENY = "deny"

    _ORDER = {ALLOW: 0, CONFINE: 1, ASK: 2, DENY: 3}

    @classmethod
    def severity(cls, verdict: str) -> int:
        return cls._ORDER.get(verdict, cls._ORDER[cls.DENY])

    @classmethod
    def at_least(cls, verdict: str, floor: str) -> bool:
        return cls.severity(verdict) >= cls.severity(floor)


# --------------------------------------------------------------------------
# Locating the shared library


def _candidate_paths() -> list[Path]:
    suffix = {"darwin": ".dylib", "win32": ".dll"}.get(sys.platform, ".so")
    name = f"libshellguard{suffix}" if sys.platform != "win32" else "shellguard.dll"

    here = Path(__file__).resolve()
    # python/agent_sandbox/binding.py -> repository root
    root = here.parent.parent.parent

    out: list[Path] = []
    env = os.environ.get("SHELLGUARD_LIB")
    if env:
        out.append(Path(env))
    out.append(here.parent / name)  # vendored beside the package, for a wheel
    out.append(root / "target" / "release" / name)
    out.append(root / "target" / "debug" / name)
    return out


def find_library() -> Path:
    """Locate libshellguard, or explain precisely where it was looked for."""
    tried = _candidate_paths()
    for p in tried:
        if p.is_file():
            return p
    raise LibraryNotFound(
        "could not find libshellguard. Build it with\n"
        "    cargo build --release -p shellguard-ffi\n"
        "or set SHELLGUARD_LIB to its path.\n"
        "Looked in:\n" + "\n".join(f"  {p}" for p in tried)
    )


def _bind(lib: ctypes.CDLL) -> None:
    """Declare every signature.

    Not optional. Without ``argtypes`` ctypes passes an ``int`` where a pointer
    is expected, which on 64-bit truncates the address and hands the library
    half a pointer — a crash that looks random and has nothing to do with the
    call site that caused it.
    """
    c, p = ctypes.c_char_p, ctypes.POINTER(ctypes.c_char)

    lib.sg_engine_new.argtypes = [c, c, ctypes.c_uint64, ctypes.c_uint32, ctypes.POINTER(p)]
    lib.sg_engine_new.restype = ctypes.c_void_p

    lib.sg_engine_free.argtypes = [ctypes.c_void_p]
    lib.sg_engine_free.restype = None

    lib.sg_engine_runtime.argtypes = [ctypes.c_void_p]
    lib.sg_engine_runtime.restype = c

    lib.sg_engine_set_audit.argtypes = [ctypes.c_void_p, c, ctypes.c_uint32, ctypes.POINTER(p)]
    lib.sg_engine_set_audit.restype = ctypes.c_int

    lib.sg_engine_audit_failures.argtypes = [ctypes.c_void_p]
    lib.sg_engine_audit_failures.restype = ctypes.c_uint64

    # Returned as a raw pointer, never as c_char_p: ctypes converts c_char_p to
    # bytes and discards the pointer, so the allocation could never be freed.
    lib.sg_engine_eval_json.argtypes = [ctypes.c_void_p, c]
    lib.sg_engine_eval_json.restype = p

    lib.sg_engine_execute_json.argtypes = [ctypes.c_void_p, c]
    lib.sg_engine_execute_json.restype = p

    lib.sg_string_free.argtypes = [p]
    lib.sg_string_free.restype = None

    lib.sg_version.argtypes = []
    lib.sg_version.restype = c

    lib.sg_backend.argtypes = []
    lib.sg_backend.restype = c


_LIB: ctypes.CDLL | None = None
_LIB_LOCK = threading.Lock()


def _library() -> ctypes.CDLL:
    global _LIB
    with _LIB_LOCK:
        if _LIB is None:
            lib = ctypes.CDLL(str(find_library()))
            _bind(lib)
            _LIB = lib
        return _LIB


def _take_string(lib: ctypes.CDLL, ptr: Any) -> str:
    """Read an owned C string and free it.

    The library allocated it; only the library can free it. Reading through a
    cast and then freeing the *original* pointer is the whole dance, and
    skipping the free leaks a few hundred bytes per command — invisible in a
    test and material in a long-running agent.
    """
    if not ptr:
        raise SandboxError("the library returned NULL; an argument was unusable")
    try:
        return ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8", "replace")
    finally:
        lib.sg_string_free(ptr)


# --------------------------------------------------------------------------
# Results


@dataclass(frozen=True)
class Finding:
    """One rule that fired, and why."""

    rule: str
    verdict: str
    reason: str
    excerpt: str = ""
    program: str | None = None
    via: str | None = None
    capabilities: tuple[str, ...] = ()

    def __str__(self) -> str:
        where = f" [{self.program} via {self.via}]" if self.program and self.via else ""
        return f"{self.verdict.upper()} {self.rule}{where}: {self.reason}"

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Finding:
        return cls(
            rule=d.get("rule", ""),
            verdict=d.get("verdict", Verdict.DENY),
            reason=d.get("reason", ""),
            excerpt=d.get("excerpt", ""),
            program=d.get("program"),
            via=d.get("via"),
            capabilities=tuple(d.get("capabilities", ())),
        )


@dataclass(frozen=True)
class Decision:
    """What the gate concluded, without running anything."""

    command: str
    verdict: str
    complete: bool
    findings: tuple[Finding, ...] = ()
    capabilities: tuple[str, ...] = ()
    incomplete: str | None = None
    elapsed_ns: int = 0

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    @property
    def denied(self) -> bool:
        return self.verdict == Verdict.DENY

    @property
    def needs_human(self) -> bool:
        return self.verdict == Verdict.ASK

    @property
    def reason(self) -> str:
        """The most severe finding's reason, or why evaluation was incomplete."""
        if self.findings:
            return self.findings[0].reason
        if self.incomplete:
            return self.incomplete
        return "no rule matched; the policy default applies"

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Decision:
        return cls(
            command=d.get("command", ""),
            verdict=d.get("verdict", Verdict.DENY),
            complete=bool(d.get("complete", False)),
            findings=tuple(Finding.from_json(f) for f in d.get("findings", ())),
            capabilities=tuple(d.get("capabilities", ())),
            incomplete=d.get("incomplete"),
            elapsed_ns=int(d.get("elapsed_ns", 0)),
        )


@dataclass(frozen=True)
class ExecutionResult:
    """Everything that happened to one command."""

    command: str
    decision: Decision
    ran: bool
    exit_code: int | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    rolled_back: bool = False
    rollback_reasons: tuple[str, ...] = ()
    health_failures: tuple[str, ...] = ()
    changed_protected: tuple[str, ...] = ()
    acquire_ms: float = 0.0
    run_ms: float = 0.0
    #: Why this run could not be fully recorded in the audit log, or ``None``.
    #: Always ``None`` when no audit log is configured. A best-effort log that
    #: fails does not raise; this is where it says so.
    audit_error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def ok(self) -> bool:
        """The command ran, succeeded, and was not reverted."""
        return self.ran and self.exit_code == 0 and not self.timed_out and not self.rolled_back

    @property
    def blocked(self) -> bool:
        """The gate refused, so nothing ran."""
        return not self.ran

    def __str__(self) -> str:
        if not self.ran:
            return f"{self.decision.verdict.upper()}: {self.decision.reason}"
        state = "rolled back" if self.rolled_back else f"exit {self.exit_code}"
        return f"ran ({state})"

    @classmethod
    def from_json(cls, command: str, d: dict[str, Any]) -> ExecutionResult:
        if "error" in d and "decision" not in d:
            raise SandboxError(d["error"])

        decision = Decision.from_json(d.get("decision", {}))
        ex = d.get("execution") or {}
        rb = d.get("rollback") or {}
        return cls(
            command=command,
            decision=decision,
            ran=bool(d.get("ran", False)),
            exit_code=ex.get("exit_code"),
            timed_out=bool(ex.get("timed_out", False)),
            stdout=ex.get("stdout", ""),
            stderr=ex.get("stderr", ""),
            rolled_back=bool(rb.get("rolled_back", False)),
            rollback_reasons=tuple(rb.get("reasons", ())),
            health_failures=tuple(rb.get("health_failures", ())),
            changed_protected=tuple(rb.get("changed_protected", ())),
            acquire_ms=float(ex.get("acquire_ms", 0.0)),
            run_ms=float(ex.get("run_ms", 0.0)),
            audit_error=d.get("audit_error"),
            raw=d,
        )


# --------------------------------------------------------------------------
# The engine


class SandboxEngine:
    """Judges and runs shell commands on an agent's behalf.

    One engine holds one gate and one rollback policy. Because the underlying
    engine is rooted at a workspace, and ``execute_with_rollback`` takes a
    workspace per call, engines are created lazily per workspace and cached —
    building one costs a policy compile, and doing that per command would put it
    on the hot path of the thing whose selling point is its latency.

    Not thread-safe for a single workspace: the underlying engine holds mutable
    evaluation caches. Use one instance per thread, or hold the lock this class
    already takes around each call.
    """

    def __init__(
        self,
        workspace: str | os.PathLike[str] | None = None,
        *,
        protected: list[str] | None = None,
        timeout: float | None = None,
        rollback_on_failure: bool = False,
        run_on_ask: bool = False,
        audit_log: str | os.PathLike[str] | None = None,
        audit_verbose: bool = False,
        audit_required: bool = False,
        library: str | os.PathLike[str] | None = None,
    ) -> None:
        if library is not None:
            lib = ctypes.CDLL(str(library))
            _bind(lib)
            self._lib = lib
        else:
            self._lib = _library()

        self._default_workspace = Path(workspace).resolve() if workspace else Path.cwd()
        self._protected = list(protected or [])
        self._timeout_ms = int(timeout * 1000) if timeout else 0
        self._flags = (ROLLBACK_ON_FAILURE if rollback_on_failure else 0) | (
            RUN_ON_ASK if run_on_ask else 0
        )
        if (audit_verbose or audit_required) and audit_log is None:
            raise SandboxError("audit_verbose and audit_required need audit_log=<path>")
        self._audit_path = str(Path(audit_log).resolve()) if audit_log is not None else None
        self._audit_flags = (AUDIT_VERBOSE if audit_verbose else 0) | (
            AUDIT_REQUIRED if audit_required else 0
        )
        self._engines: dict[Path, int] = {}
        self._lock = threading.Lock()
        self._closed = False

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> SandboxEngine:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Release every engine handle. Idempotent."""
        with self._lock:
            for handle in self._engines.values():
                self._lib.sg_engine_free(ctypes.c_void_p(handle))
            self._engines.clear()
            self._closed = True

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            # A destructor that raises during interpreter shutdown turns a
            # clean exit into a confusing traceback about nothing.
            pass

    # -- properties --------------------------------------------------------

    @property
    def version(self) -> str:
        return self._lib.sg_version().decode()

    @property
    def backend(self) -> str:
        """The kernel confinement backend: 'seatbelt' or 'landlock+seccomp'."""
        return self._lib.sg_backend().decode()

    @property
    def audit_failures(self) -> int:
        """Audit records that failed to write, summed over every workspace.

        Zero with no audit log. Worth alerting on: a best-effort log that starts
        failing does not raise, so this counter (and ``ExecutionResult.audit_error``)
        is the only sign that the record has gaps.
        """
        with self._lock:
            return sum(
                int(self._lib.sg_engine_audit_failures(ctypes.c_void_p(h)))
                for h in self._engines.values()
            )

    def runtime(self, workspace: str | os.PathLike[str] | None = None) -> str:
        """The execution runtime: 'local', 'vz', 'firecracker', 'gvisor'."""
        handle = self._handle(self._resolve(workspace))
        out = self._lib.sg_engine_runtime(ctypes.c_void_p(handle))
        return out.decode() if out else "unknown"

    # -- the API -----------------------------------------------------------

    def eval_command(self, cmd: str) -> dict[str, Any]:
        """Judge a command without running it.

        Returns the raw decision as a dict — verdict, findings, capabilities,
        timing. Use :meth:`decide` for the same thing as a typed object.
        """
        handle = self._handle(self._default_workspace)
        ptr = self._lib.sg_engine_eval_json(ctypes.c_void_p(handle), cmd.encode())
        return json.loads(_take_string(self._lib, ptr))

    def decide(self, cmd: str) -> Decision:
        """:meth:`eval_command`, typed."""
        return Decision.from_json(self.eval_command(cmd))

    def execute_with_rollback(
        self,
        cmd: str,
        workspace_path: str | os.PathLike[str] | None = None,
    ) -> ExecutionResult:
        """Gate, checkpoint, execute, verify, and roll back if warranted.

        A refused command returns normally with ``ran=False``; it does not
        raise. Refusing is the library working.
        """
        ws = self._resolve(workspace_path)
        handle = self._handle(ws)
        with self._lock:
            ptr = self._lib.sg_engine_execute_json(ctypes.c_void_p(handle), cmd.encode())
            payload = _take_string(self._lib, ptr)
        return ExecutionResult.from_json(cmd, json.loads(payload))

    # -- internals ---------------------------------------------------------

    def _resolve(self, workspace: str | os.PathLike[str] | None) -> Path:
        return Path(workspace).resolve() if workspace else self._default_workspace

    def _handle(self, workspace: Path) -> int:
        if self._closed:
            raise SandboxError("this engine has been closed")

        with self._lock:
            cached = self._engines.get(workspace)
            if cached is not None:
                return cached

            err = ctypes.POINTER(ctypes.c_char)()
            protected = "\n".join(self._protected).encode() if self._protected else None
            handle = self._lib.sg_engine_new(
                str(workspace).encode(),
                protected,
                ctypes.c_uint64(self._timeout_ms),
                ctypes.c_uint32(self._flags),
                ctypes.byref(err),
            )
            if not handle:
                message = "sg_engine_new failed"
                if err:
                    message = _take_string(self._lib, err)
                raise SandboxError(f"{message} (workspace: {workspace})")

            if self._audit_path is not None:
                err = ctypes.POINTER(ctypes.c_char)()
                rc = self._lib.sg_engine_set_audit(
                    ctypes.c_void_p(handle),
                    self._audit_path.encode(),
                    ctypes.c_uint32(self._audit_flags),
                    ctypes.byref(err),
                )
                if rc != 0:
                    message = _take_string(self._lib, err) if err else "sg_engine_set_audit failed"
                    # Do not leave a half-configured engine behind: one that
                    # silently runs commands with no log, when a log was asked for.
                    self._lib.sg_engine_free(ctypes.c_void_p(handle))
                    raise SandboxError(message)

            self._engines[workspace] = handle
            return handle
