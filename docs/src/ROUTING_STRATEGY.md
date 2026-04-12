# Classification Routing Strategy

This document explains how AxiomGuard's ShieldEngine decides between deterministic (JSONLogic) rules and AI-based classification.

## Overview

AxiomGuard uses a **hybrid classification system** that combines:
- **Deterministic rules** (JSONLogic): <1ms latency, 100% predictable
- **AI classification** (vLLM): ~40ms latency, handles complex semantic analysis

The routing strategy determines when to use each component to meet the **<100ms SLA** while maximizing accuracy.

## Routing Modes

### 1. RulesOnly Mode
```rust
RoutingMode::RulesOnly
```
**Use case**: Zero AI cost, strict compliance requirements

```
Flow:
┌─────────────────┐
│ JSONLogic Rules │──> Decision
└─────────────────┘
        │
        ▼
   No match → ALLOW
```

- **Pros**: Fastest, cheapest, deterministic
- **Cons**: Cannot handle novel threats
- **Latency**: <1ms

### 2. AiOnly Mode
```rust
RoutingMode::AiOnly
```
**Use case**: Complex semantic analysis, initial rule development

```
Flow:
┌─────────────────┐
│   AI (vLLM)     │──> Decision
└─────────────────┘
```

- **Pros**: Handles any content complexity
- **Cons**: Higher cost, ~40ms latency
- **Latency**: ~40ms

### 3. Sequential Mode (Default)
```rust
RoutingMode::Sequential
```
**Use case**: Fast path for known patterns, AI for unknown

```
Flow:
┌─────────────────┐    Match    ┌──────────┐
│ JSONLogic Rules │────────────>│ Decision │
└─────────────────┘             └──────────┘
        │
   No match
        │
        ▼
┌─────────────────┐
│   AI (vLLM)     │──> Decision
└─────────────────┘
```

- **Pros**: Best of both worlds
- **Fast path**: Known threats blocked in <1ms
- **Slow path**: Novel threats handled by AI
- **Latency**: <1ms (hit) or ~40ms (miss)

### 4. Speculative Mode
```rust
RoutingMode::Speculative
```
**Use case**: Maximum accuracy, parallel execution

```
Flow:
                    ┌─────────────────┐
         ┌─────────>│ JSONLogic Rules │
         │          └─────────────────┘
   Content│                  │
         │                  ▼
         │          ┌───────────────┐
         │          │  Combine      │──> Decision
         │          │  Results      │    (highest confidence)
         │          └───────────────┘
         │                  ▲
         │          ┌───────┘
         │          ▼
         └─────────>│   AI (vLLM)   │
                    └─────────────────┘
                         (parallel)
```

- **Pros**: Rules + AI consensus = highest accuracy
- **Cons**: Always uses AI (higher cost)
- **Latency**: ~40ms (parallel, not sequential)
- **Conflict resolution**: When rule and AI disagree, rule wins (deterministic guarantee)

### 5. Smart Mode
```rust
RoutingMode::Smart
```
**Use case**: Automatic optimization based on content

```
Flow:
┌─────────────────────────────────────────────────────────────┐
│  Content Analysis                                            │
│  ├─ Length < threshold? ──> Rules only                       │
│  ├─ Contains simple keywords? ──> Rules only                 │
│  ├─ High complexity score? ──> AI required                   │
│  └─ Ambiguous? ──> Rules + AI (sequential)                   │
└─────────────────────────────────────────────────────────────┘
```

**Complexity Score Calculation**:
```rust
fn analyze_content_complexity(content: &str) -> f32 {
    let mut score = 0.0;
    
    // Suspicious indicators increase score
    if content.contains("fraud") { score += 0.4; }
    if content.contains("password") { score += 0.3; }
    if content.contains("verify") { score += 0.2; }
    
    // Very short content uses rules
    if content.len() < 50 { score -= 0.3; }
    
    // Special characters suggest complexity
    if special_chars > 5 { score += 0.2; }
    
    score.clamp(0.0, 1.0)
}
```

- **Pros**: Adaptive, cost-effective
- **Cons**: Slightly more complex decision logic
- **Latency**: Varies based on content (1ms - 40ms)

## Configuration

### Environment Variable
```bash
# Set routing mode via environment
AXIOMGUARD_ROUTING_MODE=smart

# Options: rules_only, ai_only, sequential, speculative, smart
```

### Runtime Configuration
```rust
use engine::ShieldEngine;
use engine::routing::RoutingMode;

// Create engine with specific mode
let engine = ShieldEngine::with_routing_mode(RoutingMode::Smart);

// Or change mode at runtime
engine.set_routing_mode(RoutingMode::Sequential);

// Configure smart routing thresholds
let engine = ShieldEngine::with_routing_mode(RoutingMode::Smart)
    .with_smart_config(
        200,   // content_length_threshold (chars)
        0.6,   // complexity_threshold (0.0-1.0)
        50,    // speculative_timeout_ms
    );
```

### Per-Request Override (Future)
```json
{
  "content": "...",
  "routing_hint": "use_ai"
}
```

## Decision Flowchart

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Incoming Request                                │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Check Cache                                                        │
│  └─ Hit → Return cached result (<0.1ms)                            │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼ Miss
┌─────────────────────────────────────────────────────────────────────┐
│  Check Routing Mode                                                 │
├─────────────────────────────────────────────────────────────────────┤
│  RulesOnly  → Run rules → Return (max 1ms)                         │
│  AiOnly     → Run AI → Return (max 100ms)                          │
│  Sequential → Rules → If match → Return                            │
│                           └─ No match → AI → Return                 │
│  Speculative → Rules + AI (parallel) → Combine → Return            │
│  Smart      → Analyze → Route to appropriate mode → Return          │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Timeout Check (>100ms)                                             │
│  └─ Timeout → HANDOVER to human review                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Performance Characteristics

| Mode         | Avg Latency | P99 Latency | AI Cost | Accuracy |
|--------------|-------------|-------------|---------|----------|
| RulesOnly    | 0.5ms       | 1ms         | $0      | Medium   |
| AiOnly       | 40ms        | 80ms        | High    | High     |
| Sequential   | 5ms*        | 40ms        | Low     | High     |
| Speculative  | 40ms        | 80ms        | High    | Highest  |
| Smart        | 10ms*       | 40ms        | Medium  | High     |

*Depends on cache hit rate and rule coverage

## Best Practices

### 1. Start with Sequential (Default)
- Covers 80% of use cases
- Good balance of speed and accuracy

### 2. Use Smart Mode for Cost Optimization
- Automatically reduces AI calls by 40-60%
- Maintains high accuracy for complex content

### 3. Use Speculative Mode for Critical Applications
- When false negatives are very expensive
- When regulatory requirements demand dual-verification

### 4. Use RulesOnly for Known Attack Patterns
- Blocklists, regex patterns, simple heuristics
- Perfect for high-volume, simple checks

### 5. Use AiOnly for Novel Threat Detection
- Zero-day attack patterns
- Complex social engineering detection

## Metrics

Track routing effectiveness:

```
axiomguard_routing_decisions_total{mode="sequential", ai_used="true"} 1250
axiomguard_routing_decisions_total{mode="sequential", ai_used="false"} 8750

axiomguard_routing_latency_ms{mode="rules"} 0.8
axiomguard_routing_latency_ms{mode="ai"} 42.3

axiomguard_smart_routing_complexity_score_sum 450.2
axiomguard_smart_routing_complexity_score_count 1000
```

## Rule Hints (Future)

Rules can embed routing hints in JSONLogic:

```json
{
  "and": [
    {">": [{"var": "amount"}, 10000]},
    {"__hint": "use_ai_for_verification"}
  ]
}
```

Hints:
- `skip_ai`: Never use AI for this rule
- `use_ai`: Always confirm with AI
- `parallel`: Run AI in parallel with this rule

## See Also

- [Architecture Overview](../README.md)
- [JSONLogic Rules](./JSONLOGIC_RULES.md)
- [AI Classification](./AI_CLASSIFICATION.md)
