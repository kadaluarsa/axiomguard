# axiomguard-runtime

Official Python runtime wrapper for AxiomGuard.

Provides `RuntimeGuard` — a background-loop wrapper that automatically:
- Flushes audit events to the Control Plane every 30s
- Refreshes policy every 300s
- Handles graceful shutdown with context-manager support

## Usage

```python
from axiomguard_runtime import RuntimeGuard

with RuntimeGuard(
    cp_url="http://localhost:8080",
    api_key="your-api-key",
    tenant_id="tenant-1",
    agent_id="agent-1",
) as guard:
    result = guard.check("exec", {"command": "ls"})
    if result.allowed:
        print("Token:", result.token)
```

## Install

```bash
pip install -e .
```
