# OpenClaw Integration

AxiomGuard ships with a first-party plugin for **OpenClaw**, the AI agent gateway. Instead of manually wrapping every tool call, you can drop AxiomGuard into OpenClaw's `before_tool_call` hook and get **sub-millisecond security decisions** with zero code changes to your agents.

## What It Does

The `@axiomguard/openclaw-plugin` intercepts every tool call flowing through OpenClaw and applies a **synchronous, in-process decision pipeline**:

1. **Tool Mapping** — Maps OpenClaw tool names (e.g. `write`, `exec`, `web_search`) to AxiomGuard risk categories.
2. **Block List Check** — Blocks explicit tools or entire categories instantly.
3. **Session Risk Limit** — Tracks cumulative risk per session and blocks when the limit is exceeded.
4. **Approval Gate** — Forces human approval for high-risk categories.
5. **Fire-and-Forget Audit** — Sends the event asynchronously to the AxiomGuard Control Plane for analytics, policy updates, and compliance.

All local decisions are **synchronous** (`<1ms`). The Control Plane call happens in the background so it never slows down the agent.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ OpenClaw    │────>│ AG Plugin    │────>│ Allow / Block   │
│ Gateway     │     │ (in-process) │     │ / Require Appr  │
└─────────────┘     └──────┬───────┘     └─────────────────┘
                           │
                           ▼ (async)
                    ┌──────────────┐
                    │ Control Plane│
                    │ (audit + CP) │
                    └──────────────┘
```

## Installation

```bash
npm install @axiomguard/openclaw-plugin
```

## Plugin Configuration

Add the plugin to your OpenClaw gateway configuration:

```json
{
  "plugins": [
    {
      "id": "axiomguard",
      "entry": "node_modules/@axiomguard/openclaw-plugin/dist/index.js",
      "config": {
        "enabled": true,
        "cpUrl": "http://localhost:8080",
        "apiKey": "your-cp-api-key",
        "tenantId": "tenant_abc123",
        "agentId": "openclaw-gateway-01",
        "sessionRiskLimit": 0.8,
        "failOpen": true,
        "blockedTools": ["dangerous_legacy_exec"],
        "blockedCategories": ["automation"],
        "requireApprovalCategories": ["exec"],
        "toolOverrides": {
          "custom_scraper": {
            "category": "http",
            "riskMultiplier": 0.5,
            "requireApproval": true
          }
        },
        "timeout": 5000,
        "auditFlushIntervalMs": 30000
      }
    }
  ]
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | `boolean` | `true` | Master switch. If `false`, the plugin unloads with zero overhead. |
| `cpUrl` | `string` | — | AxiomGuard Control Plane URL. |
| `apiKey` | `string` | — | CP API key for authentication. |
| `tenantId` | `string` | — | Tenant identifier (required for multi-tenant isolation). |
| `agentId` | `string` | `"openclaw-default"` | Agent ID used for audit and policy lookup. |
| `sessionRiskLimit` | `number` | `0.8` | Cumulative risk threshold per session (0.0–1.0). |
| `failOpen` | `boolean` | `true` | If the local decision engine fails, allow the call through. |
| `blockedTools` | `string[]` | `[]` | Explicit list of OpenClaw tool names to block. |
| `blockedCategories` | `string[]` | `[]` | Categories to block entirely. |
| `requireApprovalCategories` | `string[]` | `[]` | Categories that require human approval. |
| `toolOverrides` | `object` | `{}` | Override default mappings per tool name. |
| `timeout` | `number` | `5000` | CP request timeout in milliseconds. |
| `auditFlushIntervalMs` | `number` | `30000` | Interval for flushing audit events to the CP. |

## Default Tool Mappings

The plugin comes with built-in mappings for common OpenClaw tools:

| OpenClaw Tool | AG Category | Risk Multiplier |
|---------------|-------------|-----------------|
| `exec`, `process`, `code_execution` | `exec` | `1.0` |
| `write`, `edit`, `apply_patch` | `file_write` | `0.6` |
| `read` | `file_read` | `0.3` |
| `web_search`, `web_fetch`, `x_search` | `http` | `0.4` |
| `browser` | `browser` | `0.5` |
| `message` | `message` | `0.2` |
| `cron`, `gateway` | `automation` | `0.7` |
| `image_generate`, `music_generate`, `video_generate`, `tts` | `media_gen` | `0.3` |
| `sessions_create`, `sessions_list`, `sessions_delete`, `subagents`, `session_status` | `sessions` | `0.4` |
| `memory_search`, `memory_get` | `memory` | `0.2` |
| `image`, `canvas`, `nodes` | `system` | `0.3` |
| *(unknown)* | `unknown` | `0.8` |

You can override any mapping via `toolOverrides` in the plugin config.

## Decision Flow

When a tool call arrives, the plugin evaluates it in this exact order:

1. **Explicit tool block** — Is the tool in `blockedTools` or marked `block` in overrides?
2. **Category block** — Is the mapped category in `blockedCategories`?
3. **Session risk exceeded** — Does `currentRisk + riskMultiplier >= sessionRiskLimit`?
4. **Require approval** — Is the category in `requireApprovalCategories`?
5. **Allow** — Pass the call through to the tool executor.

## Session Tracking

The plugin maintains an **in-memory session risk tracker** per OpenClaw session. It:

- Auto-evicts sessions idle for >1 hour
- Caps total tracked sessions at 10,000 to prevent memory leaks
- Updates cumulative risk immediately on every tool call
- Caps per-session risk at `1.0`

## Zero-Overhead Disable

If `enabled: false` or required fields (`cpUrl`, `apiKey`, `tenantId`) are missing, the plugin **self-disables on registration** and imposes exactly zero runtime overhead.

## Testing

Run the OpenClaw plugin test suite:

```bash
cd plugins/openclaw
npm test
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| All calls allowed, no CP traffic | Plugin disabled (missing config) | Check `enabled`, `cpUrl`, `apiKey`, `tenantId` |
| High latency on tool calls | CP unreachable | Verify `cpUrl` and network connectivity |
| Session risk never resets | Expected behavior | Sessions auto-evict after 1 hour of inactivity |
| Custom tools mapped to `unknown` | No default mapping | Add a `toolOverrides` entry |
