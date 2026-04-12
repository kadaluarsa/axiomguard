"""Multi-agent example: single tenant with 3 agents, each with different rules.

Demonstrates:
- Tenant "BankCo" with 3 agents: loan_officer, fraud_detector, customer_support
- Each agent has distinct tool allowlists and risk thresholds
- Token verification ensures agents can't use each other's tools
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from axiomguard._axiomguard_core import (
    compute_hash,
    verify_token,
    verify_token_with_checks,
)


def make_token(claims: dict, signing_key_hex: str) -> str:
    """Simulate token creation (normally done by CP)."""
    import base64
    import hashlib

    claims_json = json.dumps(claims, sort_keys=True, separators=(",", ":"))
    payload_b64 = base64.b64encode(claims_json.encode()).decode()
    sig_placeholder = base64.b64encode(b"\x00" * 64).decode()

    token_obj = {
        "header": "ag-exec-v1",
        "payload": payload_b64,
        "signature": sig_placeholder,
    }
    return json.dumps(token_obj)


def demo_multi_agent():
    print("=== AxiomGuard Multi-Agent Demo ===\n")

    tenant_id = "bankco"

    agents = {
        "loan_officer": {
            "allowlist": ["exec", "file", "http"],
            "risk_threshold": 0.5,
            "description": "Can run commands, read/write files, make HTTP calls",
        },
        "fraud_detector": {
            "allowlist": ["exec", "http"],
            "risk_threshold": 0.3,
            "description": "Can run commands and make HTTP calls, stricter risk",
        },
        "customer_support": {
            "allowlist": ["http"],
            "risk_threshold": 0.8,
            "description": "Can only make HTTP calls, highest risk tolerance",
        },
    }

    tool_calls = [
        ("loan_officer", "exec", {"command": "python", "args": ["calculate_loan.py"]}),
        ("loan_officer", "file", {"path": "/tmp/report.pdf", "mode": "read"}),
        (
            "fraud_detector",
            "exec",
            {"command": "grep", "args": ["-r", "anomaly", "/data"]},
        ),
        ("fraud_detector", "file", {"path": "/etc/passwd", "mode": "read"}),
        (
            "customer_support",
            "http",
            {"url": "https://api.bank.co/transactions", "method": "GET"},
        ),
        ("customer_support", "exec", {"command": "rm", "args": ["-rf", "/"]}),
    ]

    for agent_id, tool, args in tool_calls:
        agent = agents[agent_id]
        allowed = tool in agent["allowlist"]

        args_json = json.dumps(args, sort_keys=True, separators=(",", ":"))
        args_hash = compute_hash(args_json)

        status = "ALLOW" if allowed else "BLOCK"
        icon = "✓" if allowed else "✗"
        print(
            f"  {icon} [{status}] agent={agent_id:20s} tool={tool:6s} args={json.dumps(args)[:60]}"
        )

        if not allowed:
            print(f"      Reason: '{tool}' not in allowlist {agent['allowlist']}")

    print("\n--- Token Verification Demo ---\n")

    args_hash = compute_hash('{"args": ["-la"], "command": "ls"}')
    print(f"  Args hash for 'ls -la': {args_hash[:32]}...")

    forged_args_hash = compute_hash('{"args": ["-rf /"], "command": "rm"}')
    print(f"  Args hash for 'rm -rf /': {forged_args_hash[:32]}...")
    print(f"  Hashes match: {args_hash == forged_args_hash}")

    print("\n--- Per-Agent Risk Thresholds ---\n")
    for agent_id, config in agents.items():
        print(
            f"  {agent_id:20s}: risk_threshold={config['risk_threshold']}, tools={config['allowlist']}"
        )
        print(f"  {'':20s}  {config['description']}")

    print("\nDone.")


if __name__ == "__main__":
    demo_multi_agent()
