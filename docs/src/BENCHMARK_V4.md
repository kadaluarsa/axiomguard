# AxiomGuard v4 Benchmarks

## Performance Targets

| Path | Target P99 | Notes |
|------|-----------|-------|
| BLOCK (deterministic) | <0.1ms | JSONLogic rule match, no AI |
| ALLOW (cached) | <0.1ms | LRU/moka cache hit |
| ALLOW (new, rules-only) | <1ms | Full pipeline, no AI |
| ALLOW (new, with AI) | ~5ms | Sequential: rules miss → AI fallback |
| Amortized (mixed load) | ~1ms | 90% cached/BLOCK + 10% AI |
| Token issuance (CP) | <5ms P99 | Same-AZ LAN |
| Token verification (SDK) | <0.1ms | Ed25519 verify |

## Multi-Agent Overhead

| Scenario | Agents | Overhead per call |
|----------|--------|-------------------|
| Single agent | 1 | Baseline |
| 10 agents concurrent | 10 | <0.01ms additional |
| 50 agents concurrent | 50 | <0.05ms additional |
| Agent rule resolution | N | Agent-specific first, then global (2 lookups) |

## Tool Wrapper Latency

| Wrapper | Verify + Execute | Verify Only |
|---------|-----------------|-------------|
| exec | ~1ms (command dependent) | <0.1ms |
| file | ~0.5ms (I/O dependent) | <0.1ms |
| http | Network dependent | <0.1ms |

## Cache Performance

| Metric | Value |
|--------|-------|
| Cache hit rate (steady state) | >90% |
| moka concurrent reads | Zero lock contention |
| Cache entry size | ~256 bytes |
| Max cache entries | 10,000 (configurable) |

## Key Management

| Operation | Latency |
|-----------|---------|
| Key rotation | <1ms (in-memory swap) |
| Old key verification | Still works until tokens expire (60s TTL) |
| LocalKMS sign | <0.1ms |

## Offline Mode

| Metric | Value |
|--------|-------|
| Policy cache TTL | 1 hour (configurable) |
| Cached token lifetime | 55s (of 60s TTL) |
| Audit buffer (memory) | 10,000 events |
| Disk fallback (policy) | AES-256-GCM encrypted file |

## Benchmark Commands

```bash
# SDK pipeline benchmarks
cargo bench -p axiomguard-sdk

# Full workspace tests (includes security bypass suite)
cargo test --workspace

# Token throughput (requires running CP)
cargo run -p axiomguard-cp
```
