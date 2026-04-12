# AxiomGuard Security Tiers

## Layer Overview

| Layer | Name | What it does | Latency | Where |
|-------|------|-------------|---------|-------|
| L1 | SDK Pipeline | Deterministic rules + tool allowlist + schema validation + session tracking | <0.1ms | In-process |
| L2 | Control Plane | Policy distribution + token issuance + audit + bypass detection | ~5ms | Network |
| L3 | Tool Tokens | Ed25519 signed tokens verified before tool execution | <0.1ms | In-process |

## Security Tier Matrix

### Dev Enthusiast
- **Layers**: L1 + L2 (cloud)
- **L3 Tool Tokens**: No
- **HSM**: No
- **Deployment**: Cloud SaaS
- **Agents**: 1-3
- **Cost**: Free tier

### Startup / SaaS
- **Layers**: L1 + L2 (cloud)
- **L3 Tool Tokens**: Optional
- **HSM**: No
- **Deployment**: Cloud SaaS
- **Agents**: 3-10
- **Cost**: Pro tier

### Banking / Financial
- **Layers**: L1 + L2 (self-hosted) + L3 (required)
- **L3 Tool Tokens**: Required
- **HSM**: Required (Cloud KMS or PKCS#11)
- **Deployment**: Air-gapped VPC
- **Agents**: 10-50
- **Cost**: Enterprise tier

### Oil Rig / Industrial
- **Layers**: L1 (WASM) + L2 (onshore) + L3 (required)
- **L3 Tool Tokens**: Required
- **HSM**: Recommended
- **Deployment**: Edge + satellite burst
- **Agents**: 5-20
- **Offline**: 24h policy cache + audit replay

### Trading Floor
- **Layers**: L1 + L2 (same rack) + L3 (required)
- **L3 Tool Tokens**: Required
- **HSM**: Required
- **Deployment**: LAN colocated (sub-ms)
- **Agents**: 10-30
- **Latency SLA**: Token issuance <1ms P99

### Factory Automation
- **Layers**: L1 (Node.js) + L2 (self-hosted)
- **L3 Tool Tokens**: Recommended
- **HSM**: No
- **Deployment**: On-prem Windows/Linux
- **Agents**: 3-15

## Recommendations

1. **Always enable L1** — it's free (in-process), sub-0.1ms, and catches 90% of issues
2. **Enable L3 for any production workload** — it's the primary security moat
3. **Use HSM for regulated industries** — token signing keys must be hardware-protected
4. **Configure offline mode for edge deployments** — policy cache + audit buffer
5. **Set agent-specific risk thresholds** — tighter for privileged agents, looser for read-only
