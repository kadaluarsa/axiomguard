"""
crewAI example: Guarded crew agent with per-agent rule assignment.

Prerequisites:
    pip install axiomguard crewai

This demonstrates how to wrap crewAI agents with AxiomGuard,
assigning different guard profiles per agent role.

Usage:
    export AXIOMGUARD_CP_URL=http://localhost:8080
    export AXIOMGUARD_API_KEY=your-key
    export AXIOMGUARD_TENANT_ID=tenant-1
    python crewai_guard.py
"""

import os
import json
from typing import Any, Dict, Optional

try:
    from axiomguard import Guard, execute_with_token
except ImportError:
    print("Install axiomguard: pip install axiomguard")
    raise SystemExit(1)


class GuardedToolExecutor:
    """Wraps tool execution with AxiomGuard token verification.

    Each crewAI agent gets its own GuardedToolExecutor with a specific
    agent_id and tool allowlist. Before any tool executes, the guard
    checks the call and returns a signed token. The tool wrapper then
    verifies the token before executing.
    """

    def __init__(
        self,
        agent_id: str,
        allowed_tools: list[str],
        risk_threshold: float = 0.7,
        cp_url: Optional[str] = None,
        api_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        verifying_key_hex: Optional[str] = None,
    ):
        self.agent_id = agent_id
        self.allowed_tools = set(allowed_tools)
        self.risk_threshold = risk_threshold
        self.guard = Guard(
            cp_url=cp_url or os.environ["AXIOMGUARD_CP_URL"],
            api_key=api_key or os.environ["AXIOMGUARD_API_KEY"],
            tenant_id=tenant_id or os.environ["AXIOMGUARD_TENANT_ID"],
            agent_id=agent_id,
            verifying_key_hex=verifying_key_hex,
        )

    def execute(self, tool_name: str, args: Dict[str, Any]) -> Any:
        if tool_name not in self.allowed_tools:
            raise PermissionError(
                f"Agent '{self.agent_id}' is not allowed to use tool '{tool_name}'. "
                f"Allowed: {sorted(self.allowed_tools)}"
            )

        def _executor(args, token):
            print(f"  [{self.agent_id}] Executing {tool_name} with verified token")
            return {
                "status": "ok",
                "tool": tool_name,
                "args": args,
                "token": token[:40] + "...",
            }

        return execute_with_token(
            self.guard,
            tool_name,
            args,
            _executor,
            agent_id=self.agent_id,
        )


def main():
    print("=== crewAI + AxiomGuard Multi-Agent Example ===\n")

    agents = {
        "researcher": GuardedToolExecutor(
            agent_id="researcher",
            allowed_tools=["http", "file"],
            risk_threshold=0.8,
        ),
        "analyst": GuardedToolExecutor(
            agent_id="analyst",
            allowed_tools=["exec", "file"],
            risk_threshold=0.5,
        ),
        "writer": GuardedToolExecutor(
            agent_id="writer",
            allowed_tools=["file"],
            risk_threshold=0.3,
        ),
    }

    scenarios = [
        (
            "researcher",
            "http",
            {"url": "https://api.example.com/data", "method": "GET"},
        ),
        ("researcher", "file", {"path": "/tmp/research_notes.txt", "mode": "read"}),
        ("analyst", "exec", {"command": "python", "args": ["analyze.py"]}),
        ("analyst", "http", {"url": "https://internal-api/data", "method": "POST"}),
        (
            "writer",
            "file",
            {"path": "/tmp/report.md", "mode": "write", "content": "# Report"},
        ),
        ("writer", "exec", {"command": "rm", "args": ["-rf", "/"]}),
    ]

    for agent_id, tool, args in scenarios:
        executor = agents[agent_id]
        try:
            result = executor.execute(tool, args)
            print(f"  OK  [{agent_id:12s}] {tool:6s} -> {result['status']}")
        except PermissionError as e:
            print(f"  BLOCKED [{agent_id:12s}] {tool:6s} -> {e}")
        except RuntimeError as e:
            print(f"  GUARD [{agent_id:12s}] {tool:6s} -> {e}")
        except Exception as e:
            print(f"  ERROR [{agent_id:12s}] {tool:6s} -> CP not available: {e}")

    print("\n--- Agent Profiles ---")
    for name, ex in agents.items():
        print(
            f"  {name:12s}: tools={sorted(ex.allowed_tools)}, risk_threshold={ex.risk_threshold}"
        )

    print("\nDone.")


if __name__ == "__main__":
    main()
