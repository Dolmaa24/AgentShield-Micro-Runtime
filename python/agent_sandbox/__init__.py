"""AgentShield micro-runtime — judge and run an AI agent's shell commands.

    from agent_sandbox import SandboxEngine

    with SandboxEngine(workspace="/srv/agent/work") as engine:
        if engine.decide(cmd).denied:
            ...
        result = engine.execute_with_rollback(cmd, "/srv/agent/work")

See ``binding.py`` for the whole surface, and DESIGN.md for why an ``allow``
verdict is not a safety guarantee.
"""

from agent_sandbox.binding import (
    Decision,
    ExecutionResult,
    Finding,
    LibraryNotFound,
    PolicyRejected,
    SandboxEngine,
    SandboxError,
    Verdict,
    find_library,
)

__all__ = [
    "SandboxEngine",
    "ExecutionResult",
    "Decision",
    "Finding",
    "Verdict",
    "SandboxError",
    "PolicyRejected",
    "LibraryNotFound",
    "find_library",
]

__version__ = "0.1.0"
