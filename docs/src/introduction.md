# AxiomGuard

Welcome to the AxiomGuard documentation. AxiomGuard is an SDK-first, multi-agent security guardrail system that protects AI agents from executing malicious, unauthorized, or risky tool calls.

## What is AxiomGuard?

AxiomGuard v4 is a complete rethink of AI agent security. Instead of routing every tool call through a slow network service, the AxiomGuard **SDK runs in-process** inside your AI agent, making security decisions in **less than 1 millisecond** using deterministic JSONLogic rules. The **Control Plane** manages policies, issues cryptographically signed execution tokens, and provides audit and analytics.

```
┌─────────────────────────────────────────────────────────────────┐
│  AI Agent Process                                               │
│  ┌──────────┐    ┌──────────────────────────────────────────┐   │
│  │ Agent    │───>│ AxiomGuard SDK (Rust / Python / Node)    │   │
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
```

## Key Features

- **<1ms Hot Path**: Deterministic rules run in-process with zero network hops for the fast path
- **Cryptographic Execution Tokens**: Ed25519-signed tokens with 60s TTL, scoped to `args_hash` and `agent_id`
- **Multi-Agent & Multi-Tenant**: N agents per tenant, each with independent rules, quotas, and risk thresholds
- **PostgreSQL RLS**: Row Level Security guarantees complete tenant isolation at the database layer
- **Session Recovery**: SDK hydrates session state from the Control Plane after process restart
- **MCP Server**: Built-in Model Context Protocol server for classification, explanations, and root-cause analysis
- **OpenClaw Plugin**: First-party drop-in plugin for the OpenClaw AI agent gateway

## Quick Start

### 1. Install the SDK

**Rust:**
```toml
[dependencies]
axiomguard-sdk = "0.4"
```

**Python:**
```bash
pip install axiomguard
```

**Node.js:**
```bash
npm install axiomguard
```

**OpenClaw Gateway:**
```bash
npm install @axiomguard/openclaw-plugin
```

### 2. Run the Control Plane

```bash
cargo run --release -p axiomguard-cp
```

### 3. Guard Your First Tool Call

See the [Architecture Overview](./ARCHITECTURE_V4.md) to understand how the pieces fit together, jump straight into the [Deterministic Rules Guide](./DETERMINISTIC_RULES.md) to write your first security rule, or check out the [OpenClaw Integration](./integrations/openclaw.md) for zero-code gateway deployment.

## Documentation Structure

- **[Architecture](./ARCHITECTURE_V4.md)** — System design, data model, and component interactions
- **[SDK Guides](./DETERMINISTIC_RULES.md)** — How to embed the SDK in Rust, Python, Node.js, or WASM
- **[Deterministic Rules](./DETERMINISTIC_RULES.md)** — JSONLogic rule reference and examples
- **[Control Plane API](./DATABASE_SCHEMA.md)** — Database schema and API design
- **[Security](./SECURITY_TIERS.md)** — Threat model, bypass detection, and security tiers
- **[Operations](./operations/cost-model.md)** — Cost model and deployment guidance
- **[Reference](./V4_IMPLEMENTATION_PLAN.md)** — Implementation plan, benchmarks, and migration notes

## License

AxiomGuard is released under the [Sustainable Use License](https://github.com/justlogout/axiomguard/blob/main/LICENSE).
