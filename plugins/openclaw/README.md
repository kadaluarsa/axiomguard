# @axiomguard/openclaw-plugin

Security guardrails for [OpenClaw](https://github.com/openclaw/openclaw) AI agents. Block risky tools, track session risk, enforce approval policies.

## Features

- **Standalone mode** — works with zero infrastructure, no control plane needed
- **Managed mode** — connect to AxiomGuard control plane for centralized policy management
- **Tool blocklists** — block specific tools or entire categories
- **Session risk tracking** — cumulative risk scoring with auto-block when threshold exceeded
- **Approval gates** — require human approval before dangerous tools execute
- **Per-tool overrides** — customize category, risk multiplier, and approval per tool
- **MCP tool support** — automatic pattern matching for `mcp-*` bridge tools

## Installation

```bash
openclaw plugins install @axiomguard/openclaw-plugin
```

## Quick Start

Add to your `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "axiomguard": {
        "config": {
          "blockedTools": ["bash"],
          "requireApprovalCategories": ["exec", "secrets"],
          "sessionRiskLimit": 0.8
        }
      }
    }
  }
}
```

This configuration:
- Blocks the `bash` tool entirely
- Requires human approval before any `exec` or `secrets` tool
- Auto-blocks sessions that accumulate too much risk (threshold: 0.8)

## Configuration Reference

### Standalone Mode (default)

No control plane required. All decisions are local.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable or disable the plugin |
| `failOpen` | `boolean` | `true` | Allow tools when control plane is unreachable (managed mode) |
| `blockedTools` | `string[]` | `[]` | Tool names to always block |
| `blockedCategories` | `string[]` | `[]` | Tool categories to always block |
| `requireApprovalCategories` | `string[]` | `[]` | Categories that require human approval |
| `sessionRiskLimit` | `number` | `0.8` | Cumulative session risk threshold (0–1) |
| `toolOverrides` | `object` | `{}` | Per-tool overrides (see below) |

### Managed Mode

Connects to an AxiomGuard control plane for centralized policies and audit trails. Activated by setting `cpUrl`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cpUrl` | `string` | — | AxiomGuard control plane URL (enables managed mode) |
| `apiKey` | `string` | — | API key for control plane authentication |
| `tenantId` | `string` | — | Tenant ID for multi-tenant isolation |
| `agentId` | `string` | `"openclaw-default"` | Agent identifier |
| `timeout` | `number` | `5000` | Control plane request timeout (ms) |
| `auditFlushIntervalMs` | `number` | `30000` | Audit flush interval (ms) |

### Tool Overrides

Customize behavior per tool:

```json
{
  "toolOverrides": {
    "fs_read": { "riskMultiplier": 0.5 },
    "browser": { "requireApproval": true },
    "cron": { "block": true },
    "web-search": { "category": "http", "riskMultiplier": 0.2 }
  }
}
```

## Tool Categories

OpenClaw tools are mapped to categories with default risk multipliers:

| Category | Tools | Risk |
|----------|-------|------|
| `exec` | `bash`, `exec`, `spawn`, `shell`, `terminal` | 1.0 |
| `file_write` | `fs_write` (0.6), `fs_delete` (0.7), `fs_move` (0.5) | 0.5–0.7 |
| `file_read` | `fs_read` | 0.3 |
| `http` | `web-search`, `web-fetch` | 0.4 |
| `browser` | `browser` | 0.5 |
| `automation` | `cron` | 0.7 |
| `system` | `gateway`, `nodes` | 0.7 |
| `sessions` | `sessions`, `subagents` | 0.4 |
| `secrets` | `secrets` | 0.8 |
| `mcp` | `mcp-*` (pattern match) | 0.5 |
| `unknown` | unmapped tools | 0.8 |

## How Session Risk Works

Each tool call adds its risk multiplier to the session's cumulative risk score. When the total reaches `sessionRiskLimit` (default 0.8), all further tool calls in that session are blocked.

Example with `sessionRiskLimit: 0.8`:
1. `fs_read` (0.3) → total: 0.3 → **allowed**
2. `web-search` (0.4) → total: 0.7 → **allowed**
3. `fs_read` (0.3) → total: 1.0 → **blocked** (0.7 + 0.3 = 1.0 >= 0.8)

Sessions are tracked in-memory with auto-eviction after 1 hour of inactivity (max 10,000 concurrent sessions).

## How Approval Works

When a tool is in `requireApprovalCategories`, the plugin returns a `requireApproval` result with a title and description instead of blocking or allowing. OpenClaw's hook merger handles presenting this to the user for approval.

```json
{
  "requireApproval": {
    "id": "ag-secrets-1713024000000",
    "title": "Approval required: secrets",
    "description": "Tool \"secrets\" (category: secrets) requires human approval before execution.",
    "severity": "warning"
  }
}
```

## Example Configurations

### Minimal — block only dangerous exec
```json
{ "blockedTools": ["bash", "shell", "spawn"] }
```

### Medium — block exec + require approval for secrets
```json
{
  "blockedTools": ["bash", "shell"],
  "requireApprovalCategories": ["secrets"]
}
```

### Strict — high security
```json
{
  "blockedCategories": ["exec", "secrets"],
  "requireApprovalCategories": ["file_write", "automation", "system"],
  "sessionRiskLimit": 0.5
}
```

### Enterprise — managed mode with control plane
```json
{
  "cpUrl": "https://axiomguard.example.com",
  "apiKey": "ag-key-xxx",
  "tenantId": "org-123",
  "agentId": "production-agent",
  "failOpen": false,
  "sessionRiskLimit": 0.6,
  "requireApprovalCategories": ["exec", "file_write", "secrets"]
}
```

## Architecture

```
OpenClaw agent calls tool
        │
        ▼
  before_tool_call hook
        │
        ├── resolveToolMapping(toolName)
        │       │
        │       ▼
        │   Tool → Category + Risk
        │
        ├── evaluateLocal(input, config, risk, mapping)
        │       │
        │       ├─ blockedTool? ──────► { block: true }
        │       ├─ blockedCategory? ──► { block: true }
        │       ├─ riskExceeded? ─────► { block: true }
        │       ├─ needsApproval? ────► { requireApproval: {...} }
        │       └─ safe ──────────────► void (allow)
        │
        ├── [standalone] return local decision
        │
        └── [managed] await control plane ──► merge CP + local decision
                │
                └─ update SessionTracker
```

## Development

```bash
cd plugins/openclaw
npm install
npm run build    # TypeScript compilation
npm test         # 71 tests across 8 suites
```

## License

MIT
