# AxiomGuard v4

[![Rust](https://img.shields.io/badge/Rust-1.78%2B-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-200%2B%20passing-green.svg)](#testing)
[![License: Sustainable Use](https://img.shields.io/badge/License-Sustainable%20Use-purple.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-AxiomGuard-blue.svg)](https://kadaluarsa.github.io/axiomguard/)

> **The last security layer your AI agents will ever need.**

AxiomGuard isn't just another security wrapper — it's a **fundamental reinvention** of how we protect AI agents in production. While everyone else is still routing every tool call through sluggish cloud APIs (40–100ms of dead latency per call), AxiomGuard embeds a **battle-tested Rust core directly into your agent's process** and makes allow/block decisions in **less than 1 millisecond**. Zero network hops. Zero excuses.

📖 **[Read the Docs](https://kadaluarsa.github.io/axiomguard/)** · 🚀 **[Quick Start](#quick-start)** · 🔒 **[Security Model](#why-axiomguard-is-different)**

---

## Why AxiomGuard Is Different

The old world of "interceptor-as-a-service" is **broken**. If your agent makes 50 tool calls, you're burning 2–5 seconds on *pure security overhead*. That's not production-grade. That's not even acceptable.

**AxiomGuard kills that model entirely.**

We moved the security engine **in-process**. We replaced opaque AI black boxes with **deterministic, auditable JSONLogic rules** that execute faster than you can blink. And we invented a **cryptographic execution token system** (Ed25519-signed, arg-scoped, 60s TTL) that ensures tool wrappers literally *cannot* execute unauthorized commands — mathematically guaranteed.

This isn't an incremental improvement. This is a **paradigm shift**.

```
Old Way:  Agent → Network → Cloud API → Network → Decision → Tool (40-100ms)
AxiomGuard: Agent → SDK (in-process) → Decision → Tool (<1ms)
                              │
                              ▼
                    Control Plane (tokens, audit, policy sync)
```

---

## The Killer Features

- ⚡ **<1ms In-Process Rules** — The fastest AI agent guardrail on the planet. No network hop, no latency tax, no compromises.
- 🔐 **Cryptographic Execution Tokens** — Ed25519-signed, `args_hash`-scoped, anti-replay tokens. If the math doesn't check out, the tool **does not run**. Period.
- 🧠 **ML-Powered PII & Injection Detection** — Hybrid regex + ML pipeline sanitizes PII and blocks prompt injections in <2ms, before content reaches AI backends.
- 🏢 **Enterprise Multi-Tenancy** — PostgreSQL Row Level Security at the database layer. True tenant isolation enforced by the DB engine itself.
- 🧠 **Session Recovery** — Agent restarts? No problem. The SDK rehydrates its full risk state from the Control Plane's audit log. Attack pattern detection survives process death.
- 🛡️ **Military-Grade Crypto** — AES-256-GCM policy encryption with random nonces. ZeroizeOnDrop signing keys. We didn't skim on the hard stuff.
- 🌐 **Polyglot SDKs** — Native support for **Rust, Python, Node.js, and WASM**.
- 🔌 **OpenClaw Integration** — Drop-in plugin for the OpenClaw AI gateway. Zero code changes to your agents.
- 📊 **Real-Time Dashboard** — Vite + React 19 operator panel. Manage agents, rules, sessions, and bypass alerts like a boss.

---

## Architecture: Beauty Meets Brutal Efficiency

```
┌─────────────────────────────────────────────────────────────────┐
│  AI Agent Process                                               │
│  ┌──────────┐    ┌──────────────────────────────────────────┐   │
│  │ Agent    │───>│ AxiomGuard SDK (Rust / Py / Node / WASM)│   │
│  │ (LLM)    │    │                                          │   │
│  │          │<───│ 1. Evaluate JSONLogic rules (<1ms)       │   │
│  │          │    │ 2. Request execution token from CP       │   │
│  └──────────┘    │ 3. Pass token to tool wrapper             │   │
│                  └──────────────┬───────────────────────────┘   │
│                                 │                               │
│  ┌──────────┐    ┌──────────────▼───────────────────────────┐   │
│  │ Tool     │<───│ Tool Wrappers (exec, file, http)          │   │
│  │ Executor │    │ Verify Ed25519 token before executing     │   │
│  └──────────┘    └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Control Plane (Axum REST API)                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ Token Engine │  │ Policy Engine│  │ Agent Manager         │  │
│  │ Ed25519 sign │  │ AES-256-GCM  │  │ CRUD, rules, audit    │  │
│  └─────────────┘  └──────────────┘  └───────────────────────┘  │
│                              │                                   │
│              ┌───────────────▼───────────────┐                  │
│              │ TimescaleDB + PostgreSQL (RLS) │                  │
│              │ Hypertables, soft deletes      │                  │
│              └────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

### Data Model

```
Tenant ──< Agents (N) ──< Sessions (N per agent)
```

Every query runs under PostgreSQL RLS with an explicit `tenant_id` context. Cross-tenant data leakage is **architecturally impossible**.

---

## Quick Start

Get the entire stack running in under 60 seconds:

```bash
# Clone the future of agent security
git clone https://github.com/kadaluarsa/axiomguard.git
cd axiomguard

# Run the test suite — 179 tests, zero tolerance for failure
cargo test --workspace

# Build and launch the Control Plane
cargo run --release -p axiomguard-cp  # Now listening on :8080
```

### Python SDK — Deploy in 3 Lines

```python
from axiomguard import Guard

guard = Guard(
    cp_url="http://localhost:8080",
    api_key="key1",
    agent_id="agent_abc123"
)

# Classify a potentially dangerous tool call
result = guard.classify("bash", {"command": "rm -rf /"})

if result.decision == "allow":
    token = guard.request_token("bash", {"command": "rm -rf /"})
    # Execute with cryptographic confidence
```

### OpenClaw Gateway — Zero-Friction Security

If you run **OpenClaw**, you don't need to touch a single line of agent code:

```bash
npm install @axiomguard/openclaw-plugin
```

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
        "blockedCategories": ["automation"],
        "requireApprovalCategories": ["exec"]
      }
    }
  ]
}
```

Every tool call flowing through OpenClaw is now guarded in **<1ms** with block lists, session risk limits, and cryptographic audit trails.

### Node.js SDK — Just as Ruthless

```javascript
const { Guard } = require("@axiomguard/sdk-node");

const guard = new Guard({
  cpUrl: "http://localhost:8080",
  apiKey: "key1",
  agentId: "agent_abc123"
});

const result = guard.classify("bash", { command: "rm -rf /" });
// Malicious commands get blocked before they touch your infrastructure
```

---

## API Reference

### SDK Routes (authenticated)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/token/issue` | POST | Get cryptographically signed execution token |
| `/v1/token/verify` | POST | Verify token integrity |
| `/v1/policy/pull` | POST | Pull encrypted policy bundle |
| `/v1/audit/batch` | POST | Stream batched audit events |
| `/v1/bypass/report` | POST | Report bypass attempts in real-time |
| `/v1/sdk/heartbeat` | POST | SDK health ping |
| `/v1/health` | GET | Deep health check (includes DB liveness) |
| `/v1/session/state` | POST | Reconstruct full session state from audit log |
| `/v1/escalate` | POST | Escalate flagged decisions for AI analysis |

### Admin Routes (`CP_ADMIN_KEYS` required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/agents` | GET/POST | List / create agents |
| `/admin/agents/{id}` | GET/PUT/DELETE | Agent CRUD |
| `/admin/agents/{id}/rules` | GET/POST | List / assign agent rules |
| `/admin/agents/{id}/rules/{rule_id}` | DELETE | Unassign rule |
| `/admin/rules` | GET/POST | List / create rules |
| `/admin/rules/{id}` | PUT/DELETE | Update / delete rules |
| `/admin/bypass-alerts` | GET | List bypass alerts |

---

## Operator Dashboard

A **blazing-fast** Vite + React 19 + TypeScript dashboard with 7 power pages:

**Agents** · **Rules** · **Sessions** · **Audit** · **Analytics** · **Keys** · **Bypass Alerts**

Monitor your entire agent fleet in real-time. Spot attacks before they escalate. Manage policies with the confidence of a system built for Fortune 500 deployments.

---

## MCP Integration

Drop AxiomGuard directly into Claude, Cursor, or any MCP-compatible client.

### Install Globally

```bash
npx -y @axiomguard/mcp-server --api-key YOUR_API_KEY
```

### MCP Client Config

```json
{
  "mcpServers": {
    "axiomguard": {
      "command": "npx",
      "args": ["-y", "@axiomguard/mcp-server", "--api-key", "YOUR_API_KEY"]
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `classify_content` | Real-time threat classification |
| `explain_decision` | Transparent decision breakdown with remediation |
| `analyze_root_cause` | RAG-powered RCA over historical events |
| `get_health_status` | Full-system health diagnostics |

### Run MCP Server Locally

```bash
cargo run --release -p mcp-server -- --transport stdio
```

---

## Performance: Numbers That Don't Lie

| Operation | Latency | Notes |
|-----------|---------|-------|
| SDK in-process rules | **<1ms** | Zero network overhead. Zero AI cost. |
| ML PII + injection | **<2ms** | Regex sanitization + injection short-circuit |
| SDK with CP token | **<10ms** | Single network round-trip |
| Control Plane policy pull | **<5ms** | P99 on same-AZ LAN |
| Tool wrapper verify | **<0.1ms** | Pure Ed25519 signature verification |
| Cache hit | **<0.01ms** | `moka` concurrent cache |

Your competitors are still waiting for their cloud API to respond. You're already executing the next tool call.

---

## Configuration

```bash
# Control Plane
CP_BIND_ADDRESS=0.0.0.0:8080
CP_API_KEYS=key1,key2
CP_SIGNING_KEY_SEED=<32-byte seed>
CP_ENCRYPTION_KEY=<32-byte key>
CP_REQUIRE_AUTH=true

# Database
DATABASE_URL=postgresql://user:pass@localhost/axiomguard
```

**Note:** `CP_SIGNING_KEY_SEED` and `CP_ENCRYPTION_KEY` are mandatory. The Control Plane will **refuse to start** if they are missing. We don't do insecure defaults.

---

## Testing & Security Hardening

```bash
cargo test --workspace          # 200+ tests — no mercy
cargo test -p axiomguard-cp    # Control Plane isolation tests
cargo test -p axiomguard-sdk   # SDK unit + integration tests
cargo test -p ag-tool-common   # Tool wrapper common tests
```

### Security Bypass Suite

**13 automated attack scenarios** covering token forgery, replay attacks, rule evasion, privilege escalation, and more. We don't just claim we're secure — we **brutally test it every single build**.

```bash
cargo test -p axiomguard -- bypass
```

---

## Project Structure

```
axiomguard/
├── sdk/                    # Rust SDK core (pipeline, JSONLogic, PII, schema)
├── sdk-py/                 # Python SDK (PyO3 + pure Python Guard)
├── sdk-node/               # Node.js SDK (napi-rs + JS wrapper)
├── sdk-wasm/               # WASM target (wasm-bindgen)
├── control-plane/          # REST API (Axum), token engine, policy engine, agent manager
├── tool-wrappers/          # Token-verified tool execution (exec, file, http)
├── operator-dashboard/     # Vite + React 19 admin dashboard (7 pages)
├── engine/                 # ShieldEngine with ML-powered guard pipeline
├── common/                 # Shared types, database, models
├── proxy/                  # Legacy v3 HTTP/WS proxy
├── service/                # Legacy v3 gRPC service
├── mcp-server/             # MCP server (classify, explain, RCA, health)
├── ml/                     # ML crate — PII, injection detection, risk scoring
├── security/bypass_suite/  # 13 automated bypass test scenarios
├── proto/                  # Protocol Buffers (legacy)
└── plugins/openclaw/       # First-party OpenClaw gateway plugin
```

---

## Managed Cloud & Licensing

This repository contains the **full source code** of AxiomGuard, licensed under the **Sustainable Use License** (Fair-Code).

- **Free for self-hosting:** Download, modify, and run the entire stack for your business or personal use at **zero cost**.
- **Managed Cloud:** Don't want to operate it yourself? A fully managed offering is available at [axiomguard.io](https://axiomguard.io).
- **Enterprise License:** SSO, audit log streaming, dedicated support, and custom SLA for large organizations.

### What You Can Do
- Self-host the complete platform
- Modify the code for your own needs
- Build internal tools on top of AxiomGuard

### What You Cannot Do
- Take the code and offer a competing managed AxiomGuard-as-a-Service without a commercial agreement

For commercial licensing inquiries, contact us at [hello@frugale.app](mailto:hello@frugale.app).

---

## Contributing

We welcome warriors who want to push the boundary of agent security.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/game-changer`)
3. Commit changes (`git commit -m 'Add game-changing feature'`)
4. Push to branch (`git push origin feature/game-changer`)
5. Open a Pull Request

---

## License

[Apache 2.0](LICENSE)

---

<p align="center">
  <b>Built for the agents that will build the future.</b><br>
  <a href="https://kadaluarsa.github.io/axiomguard/">Documentation</a> ·
  <a href="https://github.com/kadaluarsa/axiomguard">GitHub</a> ·
  <a href="https://axiomguard.io">Website</a>
</p>
