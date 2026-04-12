# AxiomGuard: Why the Architecture Must Pivot

> **Status: IMPLEMENTED.** The pivot described in this document has been completed. All 6 phases of the v4 implementation plan are done with 170 tests passing.

**Date:** 2026-04-11  
**Context:** Strategic analysis of the interceptor-as-a-service model vs market needs  

---

## The Problem Is Real

Guardrails AI ($7.5M), Lakera ($20M), Protect AI ($35M), CalypsoAI ($38M) — all raised on the AI guardrails thesis. Every enterprise deploying AI agents will need safety controls. The demand is not the question. **The architecture shape is.**

---

## The Core Problem: Wrong Position in the Stack

### Current Model: Interceptor Service in the Hot Path

```
AI Agent ──tool call──► [Interceptor Service (40-100ms)] ──► Tool
                            │
                            ├─ gRPC/HTTP network hop
                            ├─ Serialization round-trip
                            ├─ 3 LRU caches, 3 RwLocks
                            └─ AI inference on every call
```

Every single tool call pays **40-100ms of network overhead** for decisions that are 90% trivial.

### The Math That Kills Adoption

| Metric | Value |
|--------|-------|
| Tool calls per coding task | 20-50 |
| Interceptor overhead per call | 40ms avg |
| **Overhead per task** | **0.8 - 2 seconds** |
| Agent latency tolerance (user-facing) | <500ms perceived |
| **Result** | **Agent feels broken** |

A coding agent that takes 2 seconds of pure guardrail overhead on top of its own execution time will get disabled by frustrated developers.

---

## Why Function-Level Wins for 90% of Cases

### The Simple Threats Don't Need a Service

| Threat | Tool-Level Enforcement | Interceptor Service |
|--------|----------------------|-------------------|
| Block `rm -rf /` in exec | **0.01ms** — command allowlist at call site | 40-100ms — overkill |
| Restrict file access to `/workspace/` | **0.01ms** — path prefix check in tool | 40-100ms — overkill |
| Block external network calls | **0.01ms** — domain/IP allowlist | 40-100ms — overkill |
| Block tool calls with `sudo` | **0.01ms** — string match on args | 40-100ms — overkill |
| Rate limit tool calls per session | **0.1ms** — in-process counter | 40-100ms — overkill |

Frameworks are already building this natively:

- **OpenAI** — function-level permission scopes
- **Anthropic** — tool-level input validation
- **LangChain** — tool guardrails and output parsers
- **AutoGPT/crewAI** — built-in tool allowlisting

These solve 90% of threats at 0.01ms with zero infrastructure. The interceptor competes here — and loses on both latency and complexity.

---

## Where the Interceptor Actually Wins (The 10%)

The remaining threats are things **individual tools cannot know** because they lack cross-tool, cross-session, and cross-agent visibility:

| Threat | Why Tool-Level Fails | Why Interceptor Wins |
|--------|---------------------|---------------------|
| **Multi-step exfiltration** | `read_file` is safe. `base64` is safe. `http_post` is safe. Individually. | Session-level pattern: read → encode → send = attack chain |
| **Prompt injection in tool args** | Tool doesn't know what "normal" looks like | Centralized detector with policy + AI analysis |
| **Cross-agent attacks** | Agent A can't see Agent B's behavior | Centralized service sees all agents |
| **SOC2/HIPAA audit trail** | Fragmented across 20 tools | Single audit plane with TimescaleDB |
| **Centralized policy management** | Every tool re-implements its own rules | One policy engine, distributed enforcement |
| **Anomaly detection** | No baseline for "normal" tool usage patterns | Historical analysis with pgvector similarity |

**This is the real product.** Not the hot-path proxy. The control plane and the slow-path analysis.

---

## The Pivot: Control Plane + In-Process SDK

### Analogies That Work

This is the **OPA/Gatekeeper** model, not the **API gateway** model:

| Layer | OPA Analogy | AxiomGuard |
|-------|-------------|------------|
| **Data plane** | OPA agent (in-process, <1ms) | Rust/Python SDK embedded in agent runtime |
| **Control plane** | OPA server (policy distribution) | Policy engine + rule sync + audit collection |
| **Slow path** | — | AI-assisted session analysis, anomaly detection |

Also analogous to **Istio CNI** vs **Istio sidecar** — the industry learned that sidecars add too much latency and moved toward in-process.

### The Target Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AI Agent Runtime                       │
│                                                          │
│   Agent Logic ──► [AxiomGuard SDK (<0.1ms)] ──► Tool    │
│                      │                                   │
│                      ├─ Tool allowlist (regex/allowlist) │
│                      ├─ Argument validation (JSON schema)│
│                      ├─ Path/command restrictions        │
│                      ├─ Rate limiting (in-process)       │
│                      │                                   │
│                      │ on FLAG / SUSPICIOUS:              │
│                      └──────────────┐                    │
│                                     ▼                    │
│                    ┌─────────────────────────────┐       │
│                    │  AxiomGuard Control Plane    │       │
│                    │  (async, non-blocking)        │       │
│                    │                               │       │
│                    │  ├─ AI session analysis       │       │
│                    │  ├─ Anomaly detection         │       │
│                    │  ├─ Cross-agent correlation   │       │
│                    │  ├─ Prompt injection detector │       │
│                    │  └─ Audit trail (TimescaleDB) │       │
│                    │                               │       │
│                    │  ◄── Policy Distribution ───► │       │
│                    │      Rules sync (push/pull)   │       │
│                    └─────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

### What Stays (Valuable, Reusable)

| Component | Current Role | After Pivot |
|-----------|-------------|-------------|
| **JSONLogic engine** | Hot-path rule eval | **SDK fast-path** — compile to WASM or native, embed in SDK |
| **Tool parser + risk scoring** | Post-classification analysis | **SDK fast-path** — argument inspection at call site |
| **Policy engine + rule sync** | In-process | **Control plane** — centralized policy, LISTEN/NOTIFY distribution |
| **AI inference (vLLM/VertexAI)** | Every suspicious call | **Slow-path only** — session analysis, anomaly detection |
| **TimescaleDB + pgvector** | Event persistence | **Control plane** — audit, RCA, similarity search |
| **PII redaction** | In-process | **SDK + control plane** — redact before tool executes |
| **MCP server** | Agent integration | **SDK wrapper** — MCP tool that wraps other tools with guards |
| **Quota management** | Per-request check | **Control plane** — usage tracking, billing |
| **Circuit breaker** | AI backend protection | **Control plane** — protects slow-path AI calls |

### What Gets Removed

| Component | Why |
|-----------|-----|
| **gRPC proxy service** | SDK replaces hot-path; control plane is async |
| **HTTP/WS/SSE edge proxy** | SDK replaces hot-path |
| **3x LRU caches with RwLock** | SDK has in-process cache; no network hop |
| **5x serialization steps** | No Proto↔JSON↔Proto round-trips |
| **100ms decisive timer** | SDK is synchronous; slow-path is async and non-blocking |

---

## Latency Comparison

| Scenario | Current Architecture | After Pivot |
|----------|---------------------|-------------|
| Safe tool call (`read_file("/workspace/main.rs")`) | 40ms (rules + cache miss) | **<0.1ms** (in-process allowlist) |
| Dangerous tool call (`exec("rm -rf /")`) | 40ms (rules block) | **<0.1ms** (in-process block) |
| Suspicious tool call (prompt injection in args) | 60ms (rules + AI) | **0.1ms** (flag) + async AI analysis |
| Multi-step attack (session-level) | **Missed** (no session scoring) | **Detected** (control plane sees full session) |
| Audit event persistence | 0ms (fire-and-forget spawn) | **0ms** (async batch to control plane) |
| **50 tool calls overhead** | **2 seconds** | **<5ms** |

---

## Go-to-Market Implications

### Current Pitch (Hard Sell)

> "Put our service between your agent and every tool call. It adds 40-100ms per call but keeps your agents safe."

**Developer reaction:** "My agent is slow enough already. I'll just write a regex."

### Pivoted Pitch (Easy Sell)

> "Add our SDK to your agent runtime. It's 3 lines of code, adds <0.1ms per call, and gives you centralized policy management, session-level threat detection, and a full audit trail."

**Developer reaction:** "Sure, why not."

### Pricing Model Shift

| Current | Pivoted |
|---------|---------|
| Per-classification (AI inference cost on every call) | Per-agent/per-session (SDK is free, control plane is priced) |
| High AI cost = high price = low adoption | Low marginal cost = lower price = higher adoption |
| Customers pay for 100ms latency | Customers pay for **insight** (audit, analytics, anomaly detection) |

---

## Competitive Positioning After Pivot

| Competitor | Their Model | AxiomGuard's Advantage |
|------------|-----------|----------------------|
| **Guardrails AI** | Python-only, no Rust SDK | Rust SDK = 10x faster, WASM-portable |
| **Lakera** | Cloud-only, no in-process | Hybrid: in-process SDK + cloud control plane |
| **Protect AI** | Enterprise-only, heavy | Developer-first SDK, self-hosted control plane |
| **OpenAI native guards** | OpenAI ecosystem only | Framework-agnostic, works with any LLM |

---

## Migration Path (Incremental, Not Rewrite)

### Step 1: Extract SDK (Week 1-2)

- Package `jsonlogic/`, `tool_parser.rs`, `pii.rs` as a standalone Rust crate
- Add Python bindings via PyO3
- 3-line integration: `guard = AxiomGuardSDK::new(policy_url); guard.check(tool_name, args)`

### Step 2: Keep Control Plane (Week 3-4)

- Existing service becomes the control plane
- Add async session analysis endpoint (not in hot path)
- SDK reports audit events to control plane in batch
- Policy distribution via HTTP pull (like OPA)

### Step 3: Deprecate Hot-Path Proxy (Week 5-6)

- Proxy becomes optional (for legacy integrations)
- MCP server stays (wraps SDK for MCP-native agents)
- gRPC service becomes control-plane-only (policy, audit, RCA)

---

## Summary

| | Current | After Pivot |
|--|---------|-------------|
| **Position** | Hot-path interceptor | Control plane + in-process SDK |
| **Latency** | 40-100ms per call | <0.1ms per call (fast path) |
| **AI spend** | Every suspicious call | Session analysis only |
| **Developer friction** | Deploy service, configure proxy | Add SDK dependency |
| **Value prop** | "We block bad calls" | "We give you visibility + centralized control" |
| **Competitive moat** | Speed (shared with everyone) | Session-level AI analysis (unique) |
| **Revenue model** | Per-classification | Per-agent / per-seat / per-session |

**The hot-path interceptor competes with a regex. The control plane + SDK competes with nothing.**
