"""
OpenAI Agents SDK example: Guarded agent with tool verification.

This demonstrates how to integrate AxiomGuard with the OpenAI Agents SDK,
using execution tokens to verify each tool call before execution.

Prerequisites:
    pip install axiomguard openai-agents

Usage:
    export AXIOMGUARD_CP_URL=http://localhost:8080
    export AXIOMGUARD_API_KEY=your-key
    export AXIOMGUARD_TENANT_ID=tenant-1
    python openai_agents_guard.py
"""

import os
import json
from typing import Any, Dict, Optional

try:
    from axiomguard import (
        Guard,
        GuardResult,
        execute_with_token,
        compute_hash,
        verify_token_with_checks,
    )
except ImportError:
    print("Install axiomguard: pip install axiomguard")
    raise SystemExit(1)


class GuardedOpenAIAgent:
    """OpenAI Agent wrapper with AxiomGuard tool verification.

    Each agent has its own guard profile with specific tool allowlist
    and risk threshold. Tool calls are verified before execution.
    """

    def __init__(
        self,
        name: str,
        agent_id: str,
        allowed_tools: list[str],
        risk_threshold: float = 0.7,
        verifying_key_hex: Optional[str] = None,
    ):
        self.name = name
        self.agent_id = agent_id
        self.allowed_tools = set(allowed_tools)
        self.risk_threshold = risk_threshold
        self.guard = Guard(
            cp_url=os.environ.get("AXIOMGUARD_CP_URL", "http://localhost:8080"),
            api_key=os.environ.get("AXIOMGUARD_API_KEY", "dev-key"),
            tenant_id=os.environ.get("AXIOMGUARD_TENANT_ID", "default"),
            agent_id=agent_id,
            verifying_key_hex=verifying_key_hex,
        )
        self.call_log: list[Dict[str, Any]] = []

    def check_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check a tool call against the guard policy.

        Returns a dict with:
        - allowed: bool
        - reason: str
        - token: Optional[str]
        """
        if tool_name not in self.allowed_tools:
            return {
                "allowed": False,
                "reason": f"Tool '{tool_name}' not in allowlist for agent '{self.agent_id}'",
                "token": None,
            }

        try:
            result = self.guard.check(
                tool_name,
                args,
                agent_id=self.agent_id,
                session_id=session_id,
            )
            entry = {
                "tool": tool_name,
                "agent_id": self.agent_id,
                "decision": result.decision,
                "risk_score": result.risk_score,
                "allowed": result.allowed,
            }
            self.call_log.append(entry)
            return {
                "allowed": result.allowed,
                "reason": result.reason,
                "token": result.token,
            }
        except RuntimeError as e:
            return {
                "allowed": False,
                "reason": str(e),
                "token": None,
            }

    def get_stats(self) -> Dict[str, Any]:
        total = len(self.call_log)
        allowed = sum(1 for c in self.call_log if c["allowed"])
        blocked = total - allowed
        return {
            "agent": self.name,
            "agent_id": self.agent_id,
            "total_calls": total,
            "allowed": allowed,
            "blocked": blocked,
            "tools": sorted(self.allowed_tools),
            "risk_threshold": self.risk_threshold,
        }


def main():
    print("=== OpenAI Agents SDK + AxiomGuard Example ===\n")

    agents = {
        "data_processor": GuardedOpenAIAgent(
            name="Data Processor",
            agent_id="data-processor-v1",
            allowed_tools=["exec", "file", "http"],
            risk_threshold=0.5,
        ),
        "customer_bot": GuardedOpenAIAgent(
            name="Customer Bot",
            agent_id="customer-bot-v1",
            allowed_tools=["http"],
            risk_threshold=0.8,
        ),
    }

    tool_calls = [
        ("data_processor", "exec", {"command": "python", "args": ["transform.py"]}),
        ("data_processor", "file", {"path": "/data/input.csv", "mode": "read"}),
        (
            "data_processor",
            "http",
            {"url": "https://api.service.com/ingest", "method": "POST"},
        ),
        (
            "customer_bot",
            "http",
            {"url": "https://api.service.com/users", "method": "GET"},
        ),
        ("customer_bot", "exec", {"command": "curl", "args": ["https://evil.com"]}),
        ("customer_bot", "file", {"path": "/etc/shadow", "mode": "read"}),
    ]

    for agent_key, tool, args in tool_calls:
        agent = agents[agent_key]
        result = agent.check_tool_call(tool, args, session_id="demo-session")
        status = "ALLOW" if result["allowed"] else "BLOCK"
        icon = "+" if result["allowed"] else "-"
        print(f"  [{icon}] [{status:5s}] agent={agent.agent_id:22s} tool={tool:6s}")

        if not result["allowed"]:
            print(f"      Reason: {result['reason']}")
        elif result["token"]:
            print(f"      Token: {result['token'][:40]}...")

    print("\n--- Agent Statistics ---\n")
    for agent in agents.values():
        stats = agent.get_stats()
        print(f"  {stats['agent']:20s} ({stats['agent_id']})")
        print(
            f"    Calls: {stats['total_calls']} (allowed={stats['allowed']}, blocked={stats['blocked']})"
        )
        print(f"    Tools: {stats['tools']}, risk_threshold={stats['risk_threshold']}")

    print("\n--- Args Hash Demo ---\n")
    hash1 = compute_hash('{"command": "ls", "args": ["-la"]}')
    hash2 = compute_hash('{"args": ["-la"], "command": "ls"}')
    print(f"  Hash (key order 1): {hash1[:32]}...")
    print(f"  Hash (key order 2): {hash2[:32]}...")
    print(f"  Equal (canonical):  {hash1 == hash2}")

    print("\nDone.")


if __name__ == "__main__":
    main()
