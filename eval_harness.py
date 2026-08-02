import sys
import time
import json
from pathlib import Path

# Ensure 'python/' directory is in the module lookup path
repo_root = Path(__file__).parent.resolve()
python_dir = repo_root / "python"
if str(python_dir) not in sys.path:
    sys.path.insert(0, str(python_dir))

from agent_sandbox.binding import SandboxEngine, ExecutionResult

class AgentSafetyHarness:
    def __init__(self, workspace_path: str):
        self.workspace = Path(workspace_path).resolve()
        self.engine = SandboxEngine(workspace=str(self.workspace))
        self.telemetry_log = Path("telemetry_evals.jsonl")

    def run_agent_command(self, agent_id: str, prompt: str, command: str) -> dict:
        start_time = time.perf_counter()
        
        # Execute command through AgentShield micro-runtime
        result: ExecutionResult = self.engine.execute_with_rollback(
            cmd=command,
            workspace_path=str(self.workspace),
        )
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Format decision string cleanly
        decision_str = str(getattr(result, "decision", "Unknown"))

        # Structured telemetry record mapping directly to ExecutionResult
        telemetry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "agent_id": agent_id,
            "prompt": prompt,
            "command": command,
            "verdict": decision_str,
            "ran": getattr(result, "ran", False),
            "stdout": getattr(result, "stdout", ""),
            "stderr": getattr(result, "stderr", ""),
            "exit_code": getattr(result, "exit_code", None),
            "timed_out": getattr(result, "timed_out", False),
            "rolled_back": getattr(result, "rolled_back", False),
            "rollback_reasons": list(getattr(result, "rollback_reasons", ())),
            "health_failures": list(getattr(result, "health_failures", ())),
            "changed_protected": list(getattr(result, "changed_protected", ())),
            "acquire_ms": getattr(result, "acquire_ms", 0.0),
            "run_ms": getattr(result, "run_ms", 0.0),
            "total_harness_ms": round(elapsed_ms, 2)
        }

        # Save record to JSONL for evaluation
        with open(self.telemetry_log, "a") as f:
            f.write(json.dumps(telemetry) + "\n")

        return telemetry