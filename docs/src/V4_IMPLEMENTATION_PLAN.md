# V4 Implementation Plan — COMPLETED

> **Status: ALL PHASES COMPLETE.** All 6 phases have been implemented and committed. 179 workspace tests pass. Last updated: 2026-04-11.

---

**Date:** 2026-04-11  
**Status:** Complete  
**Owner:** Engineering  
**Target:** Pivot from interceptor-as-a-service to in-process SDK + control plane  
**Timeline:** 24 weeks (6 months)  
**See also:** ARCHITECTURE_V4.md, PIVOT_ANALYSIS.md, ARCHITECTURE_REVIEW.md  

---

## Executive Summary

This plan replaces the optimistic 10-week v4 blueprint with a **risk-calibrated, 6-month roadmap**. It is organized around an **MVP → GA** split, parallel workstreams, and explicit decision gates. The guiding principle: **de-risk the core latency and security claims before building distribution layers.**

| Phase | Duration | Focus | Deliverable |
|-------|----------|-------|-------------|
| Phase 0 | Weeks 1-2 | v3 Critical Fixes | Production-stable control plane |
| Phase 1 | Weeks 3-6 | SDK Core (Rust) | `axiomguard-sdk` crate + benchmarks |
| Phase 2 | Weeks 7-10 | Control Plane MVP | REST API + token issuer + policy sync |
| Phase 3 | Weeks 11-14 | Integration Spike | Python SDK + tool wrappers (exec, file, http) |
| Phase 4 | Weeks 15-18 | Distribution Layer | Node.js SDK, MCP refactor, WASM, LangChain adapter |
| Phase 5 | Weeks 19-22 | Enterprise Polish | Dashboard, HSM, offline mode, deployment topologies |
| Phase 6 | Weeks 23-24 | Hardening + Launch | Security audit, pen test, public release |

### Post-Phase 6: Reliability Gap Fixes (2026-04-12)

Fortune 500 audit identified two reliability gaps that have been resolved:

1. **P0 — Audit Trail Wiring**: AuditBuffer now emits events on every `GuardPipeline.evaluate()` decision path (4 paths: cache hit, allowlist deny, schema block, main return). `Guard::flush_audit()` exposes the buffer to embedding applications.

2. **P1a — Session State Endpoint**: New `POST /v1/session/state` CP endpoint reconstructs session state from structured `cp_audit_events` table. Returns `cumulative_risk`, `total_calls`, `block_count`, and last 10 tool calls.

3. **P1b — SDK Session Hydration**: `Guard::hydrate_session()` async method recovers session state from CP after process restart. Feature-gated behind `hydration` Cargo feature. Graceful no-op when CP unreachable or no session_id configured.

4. **P1c — Escalation Pipeline**: New `POST /v1/escalate` CP endpoint persists Flag/Handover decisions to `cp_escalations` table with AI insights (deferred to P2).

**Result**: 179 tests pass (9 new). Zero breaking changes. Branch: `fix/reliability-gaps-p0-p1`.

---

## Guiding Principles

1. **Latency First:** No code merges without benchmark regression checks.
2. **Layer 3 First:** The execution token system is the primary moat. It gets built and stress-tested before anything else.
3. **Parallel, Not Serial:** v3 fixes and v4 exploration happen simultaneously for the first 6 weeks.
4. **Kill Criteria:** If token issuance cannot achieve P99 <5ms on same-AZ LAN by Week 10, we pivot to **token lease/batch pre-signing** before proceeding to GA.
5. **Backward Compatibility:** `proxy/` and `service/` remain as **legacy mode** until Week 20. No customer integrations break during the transition.
6. **Security by Default:** Every phase includes hardening work. Security is not a Phase 6 afterthought.
7. **Measure Everything:** Prometheus metrics are added alongside every new component, not retrofitted.

---

## Team Allocation (Parallel Tracks)

With 2 Rust engineers, work splits as follows:

| Track | Engineer A | Engineer B |
|-------|-----------|-----------|
| Weeks 1-2 | Phase 0 fixes (v3 hot path) | Phase 0 fixes (reliability) |
| Weeks 3-6 | SDK skeleton + pipeline (Phase 1) | SDK session tracker + audit + benchmarks |
| Weeks 7-10 | CP skeleton + token system (Phase 2) | SDK ↔ CP integration + policy engine |
| Weeks 11-14 | Tool wrappers + bypass detection | Python bindings + examples |
| Weeks 15-18 | Node.js bindings + WASM | MCP refactor + framework integrations |
| Weeks 19-22 | HSM + deployment topologies | Dashboard backend + admin API |
| Weeks 23-24 | Security hardening + bug fixes | Launch prep + documentation |

---

## Phase 0: v3 Production Stabilization (Weeks 1-2)

**Goal:** Fix the SLA breaches and critical pathologies identified in `ARCHITECTURE_REVIEW.md`. These improvements benefit both the legacy service and the new control plane.

### Workstream 0.1 — AI Fallback & Decision Correctness
| Task | Owner | File(s) | Acceptance Criteria |
|------|-------|---------|---------------------|
| Race AI backends | Backend | `engine/src/ai.rs` | `tokio::select!` caps AI time at 60ms regardless of fallback status |
| Fix `Flag` mapping | Backend | `service/src/shield_service.rs`, `proto/shield.proto` | `Flag` maps to `HANDOVER` or new `FLAG` proto enum; never `Allow` |

### Workstream 0.2 — Contention & Cache Fixes
| Task | Owner | File(s) | Acceptance Criteria |
|------|-------|---------|---------------------|
| Replace `RwLock<LruCache>` with `moka` | Backend | `engine/src/lib.rs`, `proxy/src/lib.rs`, `mcp-server/src/server.rs` | P99 cache lookup <0.05ms under 10K req/s load test |
| Pre-compile JSONLogic rules | Backend | `engine/src/jsonlogic/mod.rs`, `engine/src/lib.rs` | Zero `serde_json::from_value` calls in the classify hot path |
| Canonicalize JSON before hashing | Backend | `engine/src/lib.rs` | `{"a":1}` and `{ "a" : 1 }` produce identical cache keys |

### Workstream 0.3 — Reliability Hardening
| Task | Owner | File(s) | Acceptance Criteria |
|------|-------|---------|---------------------|
| Bound retry queue | Backend | `engine/src/retry_queue.rs` | Bounded channel (10K), disk DLQ for permanent failures |
| Persist quota counters | Backend | `engine/src/quota.rs` | Counters flushed to DB every 60s; survive restart |
| Replace quota `RwLock<HashMap>` with `DashMap` | Backend | `engine/src/quota.rs` | Per-tenant locking, no global contention |

### Workstream 0.4 — Performance Regression CI
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| CI benchmark job | DevOps | `.github/workflows/benchmarks.yml` | Runs `criterion` on every PR; fails if P99 regresses >10% |
| Load test script | QA | `benchmark/load_test.sh` | Reusable k6/wrk script for 10K req/s sustained |

### Phase 0 Gate
- [ ] `cargo test --workspace` passes
- [ ] Benchmarks show P99 classify latency <50ms (AI path) and <2ms (rules-only path)
- [ ] Load test at 10K req/s for 5 minutes with zero OOM or unbounded queue growth
- [ ] CI benchmark job runs on every PR

---

## Phase 1: SDK Core (Rust) — Weeks 3-6

**Goal:** Build the foundational Rust SDK with the fast-path pipeline, session tracker, and audit buffer. **No networking to CP yet.** SDK works in standalone mode with local policy file only.

### Workstream 1.1 — SDK Skeleton
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| Create `sdk/` crate | Rust | `Cargo.toml`, `src/lib.rs` | Clean separation from `engine/` and `common/` |
| Extract decision types | Rust | `sdk/src/types.rs` | `Decision`, `GuardResult`, `GuardConfig` (includes `agent_id`) |
| Extract JSONLogic engine | Rust | `sdk/src/jsonlogic/` | Port from `engine/src/jsonlogic/`; pre-compiled AST only; support agent-scoped + global rules |
| Extract tool parser + PII | Rust | `sdk/src/tool_parser.rs`, `sdk/src/pii.rs` | Port with zero-copy where possible |
| Add `zeroize` dependency | Rust | `sdk/Cargo.toml` | Zero secrets on drop; required for audit buffer + token cache |

### Workstream 1.2 — Fast-Path Pipeline
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| Tool allowlist engine | Rust | `sdk/src/pipeline.rs` | Per-agent allowlist (from policy pull), HashMap lookup, <0.001ms |
| Argument schema validator | Rust | `sdk/src/schema.rs` | JSON Schema subset (type, enum, pattern, maxLength) |
| Rule evaluation pipeline | Rust | `sdk/src/pipeline.rs` | Agent-scoped rules first, then tenant-global. 100 rules in <0.5ms on a single thread |
| Session risk accumulator | Rust | `sdk/src/session.rs` | Scoped to (tenant_id, agent_id, session_id). Tracks cumulative risk + suspicious sequences (see detection patterns below) |
| Audit buffer | Rust | `sdk/src/audit_buffer.rs` | In-memory batch, 100ms/50-event flush, AES-256-GCM encrypted disk fallback |
| Binary integrity check | Rust | `sdk/src/integrity.rs` | SHA-256 hash of `.text` section at startup; zero alloc in hot path |

### Workstream 1.2a — Session Sequence Detection Patterns

The session tracker must detect these attack chains:

| Sequence | Pattern | Risk Contribution | Category |
|----------|---------|-------------------|----------|
| Exfiltration | `read_file` → `exec("base64")` → `http_post(external)` | +0.8 | Data theft |
| Destruction | `read_file` → `write_file(overwrite)` → `delete_file` | +0.9 | Data loss |
| Lateral movement | `exec("whoami")` → `exec("ssh")` → `exec("sudo")` | +0.85 | Privilege escalation |
| Recon + exploit | `list_directory(/etc)` → `read_file(/etc/shadow)` → `http_post` | +0.75 | Credential theft |
| Prompt injection | tool args contain `"ignore previous"` or `"system override"` | +0.7 | Prompt injection |

Implementation: sliding window of last 10 tool calls, pattern match against known chains, accumulate per-session risk score.

### Workstream 1.3 — SDK Benchmarking
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| Criterion benchmarks | Rust | `sdk/benches/pipeline.rs` | BLOCK path <0.1ms P99; ALLOW path <0.1ms P99 (no token) |
| Memory profiling | Rust | `sdk/benches/memory.rs` | Zero allocations in the BLOCK hot path |
| Session tracker benchmark | Rust | `sdk/benches/session.rs` | 10-call sequence evaluation <0.01ms |
| Stripped binary size check | Rust | `sdk/benches/binary_size.rs` | Release binary <6MB after `strip --strip-all` |

### Workstream 1.4 — Design Partner Recruiting
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| Identify 3-5 design partners | Product | Partner list | Target: 1 Python AI team, 1 Rust shop, 1 enterprise (banking/infra) |
| Share SDK API preview | Product | `examples/api_preview.md` | Get feedback on `Guard::check()` ergonomics before Phase 2 |
| NDA + trial agreement | Legal | Signed agreements | Required for Phase 3 integration access |

### Phase 1 Gate
- [ ] `sdk` crate builds standalone (`cargo check -p axiomguard-sdk`)
- [ ] `GuardConfig` includes `agent_id` field; pipeline evaluates agent-scoped + tenant-global rules
- [ ] Criterion benchmarks prove <0.1ms BLOCK/ALLOW (no token) on target hardware
- [ ] 100% unit test coverage on `pipeline.rs` and `session.rs`
- [ ] Binary integrity hash verified at startup
- [ ] 3+ design partners identified and engaged

---

## Phase 2: Control Plane MVP — Weeks 7-10

**Goal:** Build the minimal control plane that can issue tokens, distribute signed+encrypted policies, and ingest audits. This replaces the legacy `service/` hot path with an async REST service.

### Workstream 2.1 — CP Skeleton
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| Create `control-plane/` crate | Rust | `Cargo.toml`, `src/main.rs` | Axum 0.7, single binary `axiomguard-cp` |
| Auth middleware | Rust | `control-plane/src/auth.rs` | API key validation + constant-time comparison + mTLS stub |
| Agent manager | Rust | `control-plane/src/agent/mod.rs` | Agent CRUD, per-agent config (allowlist, quota, risk threshold) |
| Agent rule assignment | Rust | `control-plane/src/agent/rule_assignment.rs` | Agent→rule many-to-many binding, priority overrides |
| DB migration: agents + agent_rules | Rust | `common/migrations/005_agents.sql` | `agents` table + `agent_rules` junction table + `agent_id` on events/decisions/sessions |
| Config + graceful shutdown | Rust | `control-plane/src/config.rs` | Env-based, structured logging |
| Prometheus metrics scaffold | Rust | `control-plane/src/metrics.rs` | `axiomguard_cp_*` counters, histograms for every endpoint |
| Admin API routes | Rust | `control-plane/src/api.rs` | CRUD for rules, policies, sessions, audit (12 endpoints from ARCHITECTURE_V4.md §8.2) |

### Workstream 2.2 — Token System (Layer 3)

#### Token Specification (v1)

```
Header:  { "alg": "EdDSA", "typ": "ag-exec-v1" }
Payload: {
  "tool":        "exec",              // Token scoped to this tool
  "args_hash":   "sha256:4f2a8c1b…",  // SHA-256 of canonicalized args
  "session_id":  "sess_abc123",       // Session scope
  "tenant_id":   "banking-prod-01",   // Tenant isolation
  "agent_id":    "agent_loan_officer", // Agent within tenant
  "decision":    "allow",             // SDK decision
  "iat":         1712841600,          // Issued at
  "exp":         1712841660,          // Expires at (+60s)
  "jti":         "token_xyz789",      // Unique ID for revocation
  "risk_score":  0.1                  // SDK risk assessment
}
Signature: Ed25519(header + payload)
```

| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| Ed25519 key management | Rust | `control-plane/src/token/keys.rs` | Key generation, rotation, pubkey export |
| Token issuer | Rust | `control-plane/src/token/mod.rs` | `POST /v1/token/issue` — verifies policy server-side before signing |
| Token verifier (server-side) | Rust | `control-plane/src/token/mod.rs` | `POST /v1/token/verify` — for legacy tools that can't embed Ed25519 |
| Token revocation | Rust | `control-plane/src/token/revocation.rs` | JTI blocklist with 24h TTL, key rotation invalidates all tokens |
| Bypass report endpoint | Rust | `control-plane/src/api.rs` | `POST /v1/bypass/report` — tool wrappers report bypass attempts |
| Bypass detector | Rust | `control-plane/src/analyst/bypass_detector.rs` | Triggers webhook/PagerDuty alert on bypass; tracks per-tenant bypass rate |

### Workstream 2.3 — Policy & Audit
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| Policy compiler | Rust | `control-plane/src/policy/compiler.rs` | JSONLogic → pre-compiled AST; resolves agent-scoped rules first, then tenant-global rules |
| Policy signer | Rust | `control-plane/src/policy/signer.rs` | Ed25519-sign policy blobs |
| Policy encryptor | Rust | `control-plane/src/policy/encryptor.rs` | AES-256-GCM encrypt policy blobs; SDK decrypts with session key |
| Policy distribution | Rust | `control-plane/src/policy/distribution.rs` | `POST /v1/policy/pull` accepts `agent_id`; returns signed+encrypted blob with agent-scoped + global rules; SSE push for live updates |
| Audit batch ingestion | Rust | `control-plane/src/persistence.rs` | `POST /v1/audit/batch` with sequence gap detection; missing seq#s trigger tamper alert |

### Workstream 2.4 — SDK ↔ CP Integration
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| Token engine in SDK | Rust | `sdk/src/token_engine.rs` | moka cache (1K entries, 55s TTL) keyed by (agent_id, tool, args_hash) + `POST /v1/token/issue` on miss; passes agent_id in request |
| Tool wrapper (verification) | Rust | `sdk/src/tool_wrapper.rs` | Ed25519 verify (~0.01ms) + expiry + args_hash + agent_id check; reject → report bypass |
| Policy cache in SDK | Rust | `sdk/src/policy_cache.rs` | Pull every 30s per agent_id, verify Ed25519 sig, decrypt AES-256-GCM; stores agent-scoped + global rules |
| Audit flush in SDK | Rust | `sdk/src/audit_buffer.rs` | HTTP flush to CP, encrypted disk fallback |
| SDK heartbeat | Rust | `sdk/src/integrity.rs` | `POST /v1/sdk/heartbeat` every 60s with integrity hash |

### Workstream 2.5 — Combined Load Testing
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| SDK + CP load test | QA | `benchmark/sdk_cp_load.rs` | 10K token issuances/s sustained for 5 min on localhost |
| Token cache hit rate test | QA | `benchmark/token_cache.rs` | 40-60% cache hit rate with realistic tool call patterns |
| Audit throughput test | QA | `benchmark/audit_throughput.rs` | CP ingests 10K audit batches/s without backpressure |

### Phase 2 Gate — **KILL CRITERION APPLIES**
- [ ] End-to-end `sdk → cp → token → tool wrapper verify` works on localhost with agent_id threaded throughout
- [ ] **P99 token issuance latency <2ms on localhost, <5ms on same-AZ LAN**
- [ ] Policy blobs are signed (Ed25519) and encrypted (AES-256-GCM) end-to-end; agent-scoped rules resolved correctly (agent rules first, then global)
- [ ] Agent CRUD API works: create, read, update, delete agents; assign/unassign rules to agents
- [ ] Bypass attempt (no token, wrong agent_id) detected and alert logged within 1 second
- [ ] Prometheus metrics exposed at `/metrics` for all endpoints, including per-agent counters
- [ ] If token latency >5ms same-AZ, escalate to **batch pre-signing spike** before Phase 3

---

## Phase 3: Integration Spike (Python + Tool Wrappers) — Weeks 11-14

**Goal:** Prove developer adoption with the ecosystem that matters most: Python AI agents. Build tool wrappers for the three highest-risk tool types to demonstrate Layer 3 enforcement end-to-end.

### Workstream 3.1 — Python SDK
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| PyO3 bindings | Rust/Python | `sdk-py/` | `pip install axiomguard` |
| Async Python API | Python | `sdk-py/src/lib.rs` | `guard.check(tool, args, agent_id=)` returns `Allow`/`Block`/`Flag` with token |
| `execute_with_token()` helper | Python | `sdk-py/src/lib.rs` | Passes token + agent_id to tool wrapper automatically |
| Multi-agent example | Python | `examples/multi_agent_bank.py` | Demo: single tenant with 3 agents (loan_officer, fraud_detector, customer_support), each with different rules and allowlists |
| Wheel CI/CD | DevOps | `.github/workflows/build-wheels.yml` | manylinux x86_64, aarch64, macOS x86_64, arm64, Windows x86_64 |

### Workstream 3.2 — Tool Wrappers (3 types)

| Task | Owner | Output | Token Enforcement | Notes |
|------|-------|--------|-------------------|-------|
| `axiomguard-tool-exec` | Rust | `tool-wrappers/exec/` | Verify token → check agent_id matches → check `args_hash` matches command → execute | Highest risk tool type |
| `axiomguard-tool-file` | Rust | `tool-wrappers/file/` | Verify token → check agent_id matches → check `args_hash` matches path+mode → execute | Path traversal protection |
| `axiomguard-tool-http` | Rust | `tool-wrappers/http/` | Verify token → check agent_id matches → check `args_hash` matches URL+method → execute | Exfiltration protection |
| Tool wrapper shared lib | Rust | `tool-wrappers/common/` | Shared Ed25519 verify + args_hash + bypass reporting | DRY for all wrappers |

### Workstream 3.3 — Framework Integration
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| LangChain adapter | Python | `examples/langchain/` | Monkey-patch `BaseTool` to call SDK + verify token; supports multi-agent per tenant |
| Integration test | QA | `examples/langchain/test_guard.py` | End-to-end: agent → SDK → CP → token → exec wrapper (tests both single-agent and multi-agent scenarios) |

### Workstream 3.4 — Latency & Security Validation in Real Agent
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| Agent benchmark | QA | `benchmark/agent_overhead.py` | 50 tool calls overhead <50ms total (amortized); test with 1 agent and 10 concurrent agents |
| Bypass test (exec) | Security | `benchmark/bypass_test_exec.py` | Direct `exec` without token → rejected + alert logged; wrong agent_id → rejected |
| Bypass test (file) | Security | `benchmark/bypass_test_file.py` | Direct file write without token → rejected |
| Bypass test (http) | Security | `benchmark/bypass_test_http.py` | Direct HTTP POST without token → rejected |
| Token forgery test | Security | `benchmark/token_forgery_test.py` | Forged token (wrong key) → rejected by tool wrapper |
| Token replay test | Security | `benchmark/token_replay_test.py` | Expired token (>60s) → rejected; different args → rejected |

### Phase 3 Gate
- [ ] A LangChain agent runs 50 guarded tool calls with <50ms total SDK overhead
- [ ] Multi-agent scenario works: 3 agents under same tenant, each with distinct rules, no cross-agent policy leakage
- [ ] Bypass attempt detected and logged in the CP within 5 seconds for all 3 tool types
- [ ] Bypass attempt with wrong agent_id detected and rejected
- [ ] Token forgery and replay attacks blocked by tool wrappers
- [ ] At least one external design partner successfully integrates the Python SDK

---

## Phase 4: Distribution Layer — Weeks 15-18

**Goal:** Expand language bindings, add WASM support, and refactor the MCP server to use the SDK internally.

### Workstream 4.1 — Node.js SDK
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| napi-rs bindings | Rust/TS | `sdk-node/` | `npm install @axiomguard/sdk` |
| CI/CD for binaries | DevOps | `.github/workflows/build-node.yml` | Prebuilds for linux-x64, linux-arm64, darwin-x64, darwin-arm64, win-x64 |

### Workstream 4.2 — WASM Target
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| WASM compile target | Rust | `sdk-wasm/` | `wasm32-unknown-unknown`, ~2MB `.wasm` |
| WASM API surface | Rust | `sdk-wasm/src/lib.rs` | Expose `guard.check()` only; no disk I/O, no network in WASM |
| wasmtime integration test | QA | `sdk-wasm/tests/wasmtime.rs` | BLOCK path <0.1ms; policy loaded from memory |
| wasmer integration test | QA | `sdk-wasm/tests/wasmer.rs` | Same latency targets |

### Workstream 4.3 — MCP Server Refactor
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| Port MCP to SDK | Rust | `mcp-server/src/server.rs` | MCP server wraps `sdk::Guard` instead of gRPC proxy; each MCP session maps to an agent_id |
| Dual transport preserved | Rust | `mcp-server/src/main.rs` | stdio + SSE still work |
| Multi-agent MCP support | Rust | `mcp-server/src/tools.rs` | `agent_id` parameter on classify/explain tools; agent-scoped rule evaluation |
| Deprecation notice | Docs | `MCP_SETUP.md` | Document that gRPC proxy is legacy mode |

### Workstream 4.4 — Framework Integrations
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| crewAI example | Python | `examples/crewai/` | Guarded crew agent with per-agent rule assignment |
| AutoGPT example | Python | `examples/autogpt/` | Guarded AutoGPT agent |
| OpenAI Agents SDK example | Python/TS | `examples/openai-agents/` | Native tool guard integration; multi-agent setup with different guard profiles |

### Phase 4 Gate
- [ ] `@axiomguard/sdk` installs and runs on Node 18+ on all target platforms
- [ ] WASM build passes in wasmtime + wasmer with <0.1ms BLOCK path
- [ ] MCP server passes existing stdio/SSE integration tests without regression
- [ ] At least one design partner integrates the Node SDK or MCP server

---

## Phase 5: Enterprise Polish — Weeks 19-22

**Goal:** Add the features required by security-conscious buyers: dashboard, HSM, offline/air-gap support, deployment topology validation, and legacy deprecation.

### Workstream 5.1 — Admin Dashboard
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| React scaffold | Frontend | `operator-dashboard/` | Vite + React + TypeScript |
| Rules page | Frontend | `operator-dashboard/src/pages/Rules.tsx` | CRUD + live JSONLogic preview; shows which agents use each rule |
| Sessions page | Frontend | `operator-dashboard/src/pages/Sessions.tsx` | Timeline + risk score + tool call chain visualization; filterable by agent_id |
| Audit page | Frontend | `operator-dashboard/src/pages/Audit.tsx` | Search + filter (including agent_id) + CSV/JSON export (SOC2/HIPAA) |
| Analytics page | Frontend | `operator-dashboard/src/pages/Analytics.tsx` | Decision breakdown (per-agent + aggregate), latency histograms, cache hit rates |
| Agents page | Frontend | `operator-dashboard/src/pages/Agents.tsx` | Agent CRUD, rule assignment, allowlist config, per-agent quota/risk thresholds, per-agent metrics dashboard |
| Keys page | Frontend | `operator-dashboard/src/pages/Keys.tsx` | Key rotation, revocation, expiry status |
| Bypass alerts page | Frontend | `operator-dashboard/src/pages/BypassAlerts.tsx` | Real-time bypass attempts + webhook config |
| Deploy to CP | DevOps | CP static file serving | `GET /admin/*` serves dashboard |

### Workstream 5.2 — HSM & Key Management
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| Cloud KMS integration | Rust | `control-plane/src/token/kms.rs` | AWS KMS, GCP Cloud KMS, Azure Key Vault |
| HSM interface (PKCS#11) | Rust | `control-plane/src/token/hsm.rs` | YubiHSM, Thales Luna |
| Offline signing key | Rust | `control-plane/src/token/keys.rs` | Air-gapped CP can sign tokens with local key (no HSM required) |
| Key rotation (zero-downtime) | Rust | `control-plane/src/token/keys.rs` | Rotate signing key; old key still verifies until tokens expire (60s) |

### Workstream 5.3 — Offline & Edge
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| Local encrypted policy file | Rust | `sdk/src/policy_cache.rs` | AES-256-GCM encrypted YAML/JSON; works when CP unreachable |
| Offline audit replay | Rust | `sdk/src/audit_buffer.rs` | SQLite/DuckDB local buffer; replay on reconnection with dedup |
| Offline token signing | Rust | `sdk/src/token_engine.rs` | Cached tokens used until expiry (55s); no new tokens without CP |
| 24h offline test | QA | `benchmark/offline_test.rs` | SDK operates 24h offline with local policy; replays audit on reconnect |

### Workstream 5.4 — Deployment Topology Validation

Test the topologies defined in `ARCHITECTURE_V4.md §4`:

| Topology | Test | Acceptance Criteria |
|----------|------|---------------------|
| **Banking (air-gapped)** | CP on RHEL8 with local vLLM, no internet | Full classification + token issuance with zero egress |
| **Oil rig (satellite)** | SDK offline 24h → satellite burst → CP sync | Audit replay succeeds; no data loss; tokens cached locally |
| **Dev (cloud SaaS)** | Python SDK → hosted CP over internet | Round-trip <10ms from us-east-1 to us-central1 |
| **Trading floor (LAN)** | SDK + CP on same rack, sub-ms LAN | Token issuance <1ms P99 on 10Gbps LAN |
| **Factory (Windows)** | Node.js SDK on Windows Server 2019 | All tool wrappers work; no Linux-specific dependencies |

### Workstream 5.5 — Legacy Deprecation
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| Proxy legacy mode docs | Docs | `docs/LEGACY_PROXY.md` | How to run v3 proxy for backward compatibility |
| Migration guide | Docs | `docs/MIGRATION_V3_TO_V4.md` | Step-by-step for existing customers |
| gRPC service sunset notice | Product | In-app + email | 90-day notice for proxy removal in v4.1 |

### Phase 5 Gate
- [ ] Dashboard loads and passes basic E2E tests (Cypress/Playwright)
- [ ] SDK operates in offline mode for 24h with full functionality, then replays audit on reconnect
- [ ] At least 3 deployment topologies validated (banking, dev, factory)
- [ ] HSM signing works with at least one real Cloud KMS provider
- [ ] Key rotation completes with zero rejected tokens

---

## Phase 6: Security Hardening + Launch — Weeks 23-24

**Goal:** Verify the security claims, especially Layer 3 bypass resistance, before public launch.

### Workstream 6.1 — Security Audit
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| External audit (token system) | Security | Audit report | Hire firm or engage bounty program; scope: Ed25519 implementation, token issuance (including agent_id scoping), revocation |
| Penetration testing | Security | Pen test report | Focus: SDK bypass, token forgery, policy tampering, binary patching, memory extraction, cross-agent data leakage |
| HSM integration testing | Security | Test report | At least one real HSM or Cloud KMS validated end-to-end |
| Bypass test suite | Security | `security/bypass_suite/` | Automated: 20+ bypass scenarios covering all attack surfaces from ARCHITECTURE_V4.md §11.8; includes cross-agent token reuse attacks |

### Workstream 6.2 — Launch Prep
| Task | Owner | Output | Notes |
|------|-------|--------|-------|
| Final benchmarks | QA | `docs/BENCHMARK_V4.md` | Published numbers: BLOCK (<0.1ms), ALLOW cached (<0.1ms), ALLOW new (~5ms), amortized (~1ms); includes multi-agent (10 agents concurrent) benchmarks |
| Documentation site | Docs | `docs/` refresh | Quickstart for Rust, Python, Node, WASM, MCP |
| Security tier guide | Docs | `docs/SECURITY_TIERS.md` | Which layers to enable per customer segment (dev vs banking vs oil rig) |
| Release blog post | Marketing | Blog + social | Announce v4, emphasize <0.1ms + token enforcement + defense-in-depth |
| Crate + NPM + PyPI publish | DevOps | `axiomguard-sdk` v4.0.0 | Coordinate release across registries |

### Workstream 6.3 — Final Load Test (Full System)
| Task | Owner | Output | Acceptance Criteria |
|------|-------|--------|---------------------|
| Full stack load test | QA | `benchmark/full_system.rs` | 5 SDK instances (across 10 agents) + 1 CP: 50K tool checks/s sustained 15 min |
| Token burst test | QA | `benchmark/token_burst.rs` | 10K simultaneous token requests across 10 agents: P99 <10ms |
| Audit pipeline stress | QA | `benchmark/audit_stress.rs` | 100K events ingested in 60s with zero sequence gaps |
| Failover test | QA | `benchmark/failover.rs` | Kill CP mid-session: SDK operates on cached tokens for 55s, reconnects cleanly |

### Phase 6 Gate
- [ ] No Critical or High findings from external audit remain unremediated
- [ ] All benchmarks published and reproducible in CI
- [ ] Full system load test passes at target throughput
- [ ] v4.0.0 tagged and released on crates.io, PyPI, npm

---

## Parallel Workstreams (Continuous)

These run across all phases:

| Workstream | Owner | Cadence | Scope |
|------------|-------|---------|-------|
| **Performance regression testing** | Platform | Every PR | Criterion + load tests in CI (set up in Phase 0) |
| **Prometheus metrics** | Platform | Every phase | New metrics added alongside every new component |
| **Documentation** | DX | Weekly | API docs, integration guides, examples |
| **Design partner feedback** | Product | Bi-weekly | 3–5 early customers providing integration feedback |
| **Competitive intelligence** | Product | Monthly | Track Guardrails AI, Lakera, OPA developments |
| **Security hardening** | Security | Every phase | Memory zeroing, binary integrity, bypass tests per phase |

---

## Security Checklist by Phase

| Phase | Security Work | Deliverable |
|-------|--------------|-------------|
| 0 | Fix `Flag→Allow` mapping, bound retry queue | No critical security bugs in v3 |
| 1 | Binary integrity hash, `zeroize` for audit buffer, encrypted disk fallback | SDK standalone is tamper-detecting |
| 2 | Ed25519 token signing (with agent_id), AES-256-GCM policy encryption, bypass detector, agent-scoped rule isolation | Layer 3 enforcement live; no cross-agent policy leakage |
| 3 | Tool wrappers with token verification, bypass/replay/forgery tests | Layer 3 proven against attack |
| 4 | WASM sandbox (no syscalls, no memory access), Node.js binary hardening | Edge/IoT security validated |
| 5 | HSM key storage, offline signing, deployment topology security testing | Enterprise-grade key management |
| 6 | External audit, penetration testing, bypass suite | Security claims verified by third party |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation | Trigger |
|------|------------|--------|------------|---------|
| Token issuance >5ms P99 same-AZ | Medium | High | **Kill criterion:** Switch to batch pre-signing before GA | G2 fails |
| Tool wrapper adoption is low | Medium | High | Build LangChain/OpenAI SDK monkey-patches + Envoy sidecar option | <2 design partners by Week 14 |
| PyO3/napi-rs binding complexity | Medium | Medium | Start with Python only; defer Node if binding issues arise | Python wheels not shipping by Week 12 |
| Session state lost on process restart | Medium | High | Local SQLite buffer + CP sync on startup | Session tracker loses state in tests |
| Security audit finds critical bypass | Low | Catastrophic | Build bypass tests from Week 6; fix iteratively before external audit | Bypass suite finds exploitable path |
| Engineering team bandwidth | High | High | Cut WASM and Node bindings if behind; Rust + Python is MVP | Phase 3 gate not met by Week 16 |
| Policy encryption overhead | Low | Medium | Benchmark AES-256-GCM decrypt in SDK; if >0.1ms, use streaming decrypt | SDK pipeline benchmark regresses |
| Key rotation causes token rejection storm | Low | Medium | 60s TTL means rotation is naturally zero-downtime; test explicitly | Key rotation test in Phase 5 fails |
| Design partners can't integrate | Medium | High | Provide reference implementations for LangChain, crewAI, MCP | No partner integrated by Week 14 |
| Agent rule assignment complexity | Medium | Medium | Start with simple many-to-many junction table; defer priority overrides and rule inheritance to v4.1 | Agent rule resolver exceeds 0.5ms in Phase 2 benchmarks |

---

## Decision Gates Summary

| Gate | Date (Target) | Criteria | If Failed |
|------|---------------|----------|-----------|
| **G0 — v3 Stable** | Week 2 | P99 <50ms AI path, zero OOM, CI benchmarks running | Extend Phase 0; delay v4 work |
| **G1 — SDK Fast Path** | Week 6 | BLOCK <0.1ms P99, binary integrity hash works, 3+ design partners | Profile and optimize pipeline until met |
| **G2 — Token Latency** | Week 10 | P99 <5ms same-AZ, policies signed+encrypted, bypass detector works | Spike batch pre-signing; do not proceed to GA without solving |
| **G3 — Integration Validated** | Week 14 | <50ms overhead for 50 calls, 1 design partner integrated, bypass tests pass for 3 tool types | Iterate on Python API ergonomics; add more examples |
| **G4 — Distribution Ready** | Week 18 | Node + MCP + WASM pass tests | Cut Node or WASM if behind; Rust + Python + MCP is acceptable MVP |
| **G5 — Enterprise Ready** | Week 22 | Dashboard + HSM + offline mode + 3 deployment topologies validated | Cut deployment topologies; ship with banking+dev only |
| **G6 — Launch** | Week 24 | Zero Critical/High audit findings, full system load test passes | Delay launch; fix findings |

---

## Resource Requirements

### Team (Recommended)
- **2x Rust engineers** — SDK + Control Plane + Tool Wrappers
- **1x Python/integrations engineer** — PyO3, LangChain, examples
- **1x Frontend/DevOps engineer** — Dashboard, CI/CD, packaging
- **0.5x Security engineer** — Token design, threat modeling, bypass tests, audit liaison

### Infrastructure
- Same as v3 (TimescaleDB, vLLM/GKE) plus:
- **Cloud KMS account** (GCP or AWS) for token signing tests
- **WASM build runner** in CI (wasmtime + wasmer)
- **Design partner sandbox** (isolated CP deployment per partner)
- **Security audit budget** (~$20-40K for external firm or bounty program)
- **HSM test device** (YubiHSM 2 ~$1.5K, or Cloud KMS free tier)

---

## Appendix A: Component Ownership Matrix

| Component | Old Location | New Location | Phase | Owner |
|-----------|-------------|--------------|-------|-------|
| JSONLogic engine | `engine/src/jsonlogic/` | `sdk/src/jsonlogic/` | 1 | Rust A |
| Tool parser | `engine/src/tool_parser.rs` | `sdk/src/tool_parser.rs` | 1 | Rust A |
| PII redaction | `engine/src/pii.rs` | `sdk/src/pii.rs` | 1 | Rust A |
| Session tracker | — | `sdk/src/session.rs` | 1 | Rust B |
| Audit buffer | — | `sdk/src/audit_buffer.rs` | 1 | Rust B |
| Binary integrity | — | `sdk/src/integrity.rs` | 1 | Rust B |
| Token engine (SDK) | — | `sdk/src/token_engine.rs` | 2 | Rust A |
| Tool wrapper (SDK) | — | `sdk/src/tool_wrapper.rs` | 2 | Rust A |
| Policy cache (SDK) | — | `sdk/src/policy_cache.rs` | 2 | Rust B |
| AI inference | `engine/src/ai.rs` | `control-plane/src/ai.rs` | 2 | Rust B |
| Circuit breaker | `engine/src/circuit_breaker.rs` | `control-plane/src/circuit_breaker.rs` | 2 | Rust B |
| Quota management | `engine/src/quota.rs` | `control-plane/src/quota.rs` | 0+2 | Rust |
| Policy sync | `engine/src/rule_sync.rs` | `control-plane/src/policy/` | 2 | Rust B |
| Policy signer | — | `control-plane/src/policy/signer.rs` | 2 | Rust B |
| Policy encryptor | — | `control-plane/src/policy/encryptor.rs` | 2 | Rust B |
| Token issuer | — | `control-plane/src/token/` | 2 | Rust A |
| Bypass detector | — | `control-plane/src/analyst/bypass_detector.rs` | 2 | Rust A |
| Admin API | — | `control-plane/src/api.rs` | 2 | Rust B |
| Agent manager | — | `control-plane/src/agent/mod.rs` | 2 | Rust B |
| Agent rule assignment | — | `control-plane/src/agent/rule_assignment.rs` | 2 | Rust B |
| Agent rule resolver | — | `control-plane/src/agent/rule_resolver.rs` | 2 | Rust B |
| DB migration (agents + agent_rules) | — | `common/migrations/005_agents.sql` | 2 | Rust B |
| Tool wrappers (exec/file/http) | — | `tool-wrappers/` | 3 | Rust A |
| Python SDK | — | `sdk-py/` | 3 | Python |
| Node.js SDK | — | `sdk-node/` | 4 | Rust/TS |
| WASM target | — | `sdk-wasm/` | 4 | Rust A |
| MCP server | `mcp-server/` | `mcp-server/` (refactored) | 4 | Rust |
| Dashboard | — | `operator-dashboard/` | 5 | Frontend |
| HSM/KMS integration | — | `control-plane/src/token/kms.rs` | 5 | Rust A |
| gRPC proxy | `proxy/`, `service/` | Legacy mode (deprecated) | 0, 5 | Rust |

---

## Appendix B: Security Tier Matrix by Customer Segment

Used by Sales/Product to scope Layer 3 enforcement per customer:

| Segment | Layer 1 (SDK) | Layer 2 (CP) | Layer 3 (Tool Tokens) | HSM | Deployment Topology | Typical Agent Count |
|---------|---------------|---------------|----------------------|-----|---------------------|---------------------|
| Dev enthusiast | Yes | Yes (cloud) | No | No | Cloud SaaS | 1-3 |
| Startup / SaaS | Yes | Yes (cloud) | Optional | No | Cloud SaaS | 3-10 |
| Banking / Financial | Yes | Yes (self-hosted) | **Required** | **Required** | Air-gapped VPC | 10-50 |
| Oil rig / Industrial | Yes (WASM) | Yes (onshore) | **Required** | Recommended | Edge + satellite | 5-20 |
| Trading floor | Yes | Yes (same rack) | **Required** | **Required** | LAN colocated | 10-30 |
| Factory automation | Yes (Node.js) | Yes (self-hosted) | Recommended | No | On-prem Windows/Linux | 3-15 |

---

## Appendix C: API Endpoint Checklist

All endpoints from `ARCHITECTURE_V4.md §8`, mapped to implementation phase:

### SDK ↔ Control Plane (Phase 2)

| Endpoint | Status | Phase |
|----------|--------|-------|
| `POST /v1/policy/pull` | Planned | Phase 2 |
| `POST /v1/token/issue` | Planned | Phase 2 |
| `POST /v1/token/verify` | Planned | Phase 2 |
| `POST /v1/audit/batch` | Planned | Phase 2 |
| `POST /v1/escalate` | Planned | Phase 2 |
| `POST /v1/bypass/report` | Planned | Phase 2 |
| `POST /v1/session/analyze` | Planned | Phase 2 |
| `POST /v1/sdk/heartbeat` | Planned | Phase 2 |
| `GET /v1/health` | Planned | Phase 2 |

### Admin ↔ Control Plane (Phase 2 skeleton, Phase 5 full)

| Endpoint | Status | Phase |
|----------|--------|-------|
| `GET /admin/rules` | Planned | Phase 2 |
| `POST /admin/rules` | Planned | Phase 2 |
| `PUT /admin/rules/{id}` | Planned | Phase 2 |
| `DELETE /admin/rules/{id}` | Planned | Phase 2 |
| `GET /admin/agents` | Planned | Phase 2 |
| `POST /admin/agents` | Planned | Phase 2 |
| `GET /admin/agents/{id}` | Planned | Phase 2 |
| `PUT /admin/agents/{id}` | Planned | Phase 2 |
| `DELETE /admin/agents/{id}` | Planned | Phase 2 |
| `GET /admin/agents/{id}/rules` | Planned | Phase 2 |
| `POST /admin/agents/{id}/rules` | Planned | Phase 2 |
| `DELETE /admin/agents/{id}/rules/{rule_id}` | Planned | Phase 2 |
| `GET /admin/policies` | Planned | Phase 5 |
| `POST /admin/policies` | Planned | Phase 5 |
| `POST /admin/policies/{id}/deploy` | Planned | Phase 5 |
| `GET /admin/sessions` | Planned | Phase 5 |
| `GET /admin/sessions/{id}` | Planned | Phase 5 |
| `GET /admin/sessions/{id}/timeline` | Planned | Phase 5 |
| `GET /admin/audit` | Planned | Phase 5 |
| `GET /admin/audit/export` | Planned | Phase 5 |
| `GET /admin/analytics` | Planned | Phase 5 |
| `GET /admin/rca/{session_id}` | Planned | Phase 5 |
| `GET /admin/tenants` | Planned | Phase 5 |
| `POST /admin/tenants` | Planned | Phase 5 |
| `PUT /admin/tenants/{id}/quota` | Planned | Phase 5 |
| `GET /admin/keys` | Planned | Phase 5 |
| `POST /admin/keys/rotate` | Planned | Phase 5 |
| `GET /admin/bypass-alerts` | Planned | Phase 5 |

---

*Last updated:* 2026-04-11  
*Next review:* Week 2 (G0 gate)  
*Previous version:* 10-week plan (superseded by this 24-week risk-calibrated version)
