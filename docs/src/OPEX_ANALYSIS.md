# AxiomGuard OPEX Analysis & Pricing Model

## Cost Breakdown (Per Unit)

### 1. Infrastructure Costs (Singapore Region)

| Component | Unit Cost | Notes |
|-----------|-----------|-------|
| **Cloud Run GPU (vLLM)** | SGD $2.34/hour | NVIDIA L4, 8 vCPU, 32GB RAM |
| **Cloud Run (Proxy/Service)** | SGD $0.000024/vCPU-s | Burstable, scale-to-zero |
| **TimescaleDB (Cloud SQL)** | SGD $150/month | db-g1-small with HA |
| **GKE (if used)** | SGD $200/month | e2-standard-4 for control plane |
| **Vertex AI (fallback)** | SGD $0.00125/1K tokens | Gemini 1.5 Pro |
| **Load Balancer** | SGD $20/month + $0.008/GB | Global HTTP(S) LB |
| **Monitoring** | SGD $50/month | Cloud Monitoring + Alerting |

### 2. AI Inference Costs

| Model | Cost per 1K requests | Avg Latency |
|-------|---------------------|-------------|
| **vLLM (Mistral 7B)** | SGD $0.20 | 40ms |
| **vLLM (Gemma 2B)** | SGD $0.05 | 20ms |
| **Vertex AI (Gemini Flash)** | SGD $0.35 | 60ms |
| **Vertex AI (Gemini Pro)** | SGD $1.25 | 100ms |

*Assuming average 500 tokens per request*

### 3. Compute Costs by Request Type

| Request Type | Resources | Cost |
|--------------|-----------|------|
| **Rules-only** | 1ms CPU | SGD $0.000001 |
| **Cache hit** | 0.1ms CPU | SGD $0.0000001 |
| **AI (vLLM)** | 40ms GPU | SGD $0.0002 |
| **AI (Vertex)** | 60ms + API | SGD $0.0005 |

---

## 3-Tier Quota Model

### Architecture Decision: Per-Tenant vs Per-Agent

**Recommendation: PER-TENANT quotas**

```
Tenant (Company/Organization)
├── quota_realtime_per_day: 10,000
├── quota_deep_analysis_per_month: 100
├── quota_rules_max: 50
└── Agents (users/devices within tenant)
    ├── agent_1: uses tenant quota
    ├── agent_2: uses tenant quota
    └── agent_n: uses tenant quota
```

**Why Per-Tenant?**
- Easier for customers to understand (one bill)
- Prevents agent sprawl abuse
- Simpler quota tracking
- Industry standard (Datadog, Cloudflare, etc.)

---

## Tier Definitions

### Tier 1: Free

| Feature | Quota |
|---------|-------|
| Real-time classifications | 100/day |
| Deep analysis (AI) | 1/month |
| Rules max | 5 |
| Data retention | 7 days |
| Support | Community |

**Cost to us**: ~SGD $2/month/user  
**Suggested price**: FREE (acquisition cost)

---

### Tier 2: Pro

| Feature | Quota |
|---------|-------|
| Real-time classifications | 10,000/day |
| Deep analysis (AI) | 500/month |
| Rules max | 50 |
| Data retention | 90 days |
| Support | Email |
| API rate limit | 100/sec |

**Cost calculation**:
- Base: $150 (DB) / 100 users = $1.50
- Compute: 10K × $0.000001 × 30 = $0.30
- AI: 500 × $0.0002 = $0.10
- GPU amortized: $2.34 × 24 × 30 / 100 = $16.85
- **Total**: ~SGD $19/user/month

**Suggested price**: SGD $49/month (60% gross margin)

---

### Tier 3: Enterprise

| Feature | Quota |
|---------|-------|
| Real-time classifications | Custom (100K+/day) |
| Deep analysis (AI) | Custom (10K+/month) |
| Rules max | Unlimited |
| Data retention | Custom (1+ years) |
| Support | Dedicated Slack + phone |
| SLA | 99.9% uptime |
| Features | SSO, audit logs, custom model |

**Pricing**: SGD $499+/month (custom contract)

---

## Quota Enforcement Implementation

### Database Schema

```sql
-- Tenant quotas
create table tenant_quotas (
    tenant_id uuid primary key,
    plan_type text check (plan_type in ('free', 'pro', 'enterprise')),
    
    -- Real-time (rules + cache)
    quota_realtime_per_day integer default 100,
    quota_realtime_burst integer default 10,  -- per second
    
    -- Deep analysis (AI calls)
    quota_deep_analysis_per_month integer default 1,
    quota_deep_analysis_max_tokens integer default 10000,  -- per request
    
    -- Rules
    quota_rules_max integer default 5,
    quota_rules_complexity_score integer default 1000,  -- sum of rule complexities
    
    -- Data retention
    quota_data_retention_days integer default 7,
    
    -- Usage tracking (counters reset by cron)
    used_realtime_today integer default 0,
    used_deep_analysis_this_month integer default 0,
    last_reset_date date default current_date,
    
    -- Hard/soft limits
    hard_limit_enabled boolean default true,
    alert_threshold_percent integer default 80
);

-- Agent tracking (optional - for analytics only)
create table agent_usage (
    agent_id text,
    tenant_id uuid,
    realtime_calls_today integer default 0,
    deep_analysis_calls_this_month integer default 0,
    foreign key (tenant_id) references tenant_quotas(tenant_id)
);
```

### Quota Enforcement Logic

```rust
pub struct QuotaManager {
    db: Arc<Database>,
    redis: Option<Redis>,  // for real-time rate limiting
}

impl QuotaManager {
    /// Check and consume quota for classification
    pub async fn check_classification_quota(
        &self,
        tenant_id: &str,
        classification_type: ClassificationType,
        content_size: usize,
    ) -> Result<QuotaStatus, QuotaError> {
        let quota = self.get_tenant_quota(tenant_id).await?;
        
        // Check if it's a new day/month for reset
        self.maybe_reset_counters(tenant_id, &quota).await?;
        
        match classification_type {
            ClassificationType::Realtime => {
                // Check rate limit (requests per second)
                self.check_rate_limit(tenant_id, quota.quota_realtime_burst).await?;
                
                // Check daily quota
                if quota.used_realtime_today >= quota.quota_realtime_per_day {
                    if quota.hard_limit_enabled {
                        return Err(QuotaError::DailyLimitExceeded {
                            used: quota.used_realtime_today,
                            limit: quota.quota_realtime_per_day,
                            resets_in: self.time_until_midnight(),
                        });
                    } else {
                        // Soft limit: allow but alert
                        self.send_quota_alert(tenant_id).await?;
                    }
                }
                
                // Consume quota
                self.increment_realtime_counter(tenant_id).await?;
                
                Ok(QuotaStatus::Allowed {
                    remaining: quota.quota_realtime_per_day - quota.used_realtime_today - 1,
                })
            }
            
            ClassificationType::DeepAnalysis { estimated_tokens } => {
                // Check monthly quota
                if quota.used_deep_analysis_this_month >= quota.quota_deep_analysis_per_month {
                    return Err(QuotaError::MonthlyLimitExceeded {
                        used: quota.used_deep_analysis_this_month,
                        limit: quota.quota_deep_analysis_per_month,
                        upgrade_url: "https://axiomguard.com/upgrade".to_string(),
                    });
                }
                
                // Check max content size for deep analysis
                if estimated_tokens > quota.quota_deep_analysis_max_tokens {
                    return Err(QuotaError::ContentTooLarge {
                        size: estimated_tokens,
                        max: quota.quota_deep_analysis_max_tokens,
                    });
                }
                
                // Consume quota BEFORE calling AI (prevent abuse)
                self.increment_deep_analysis_counter(tenant_id).await?;
                
                Ok(QuotaStatus::Allowed {
                    remaining: quota.quota_deep_analysis_per_month - quota.used_deep_analysis_this_month - 1,
                })
            }
        }
    }
}
```

---

## Implementation Plan

### Phase 1: Critical Quota Enforcement (This Week)

1. **Add quota tables** to database
2. **Implement QuotaManager** with per-tenant tracking
3. **Enforce in ShieldEngine**:
   - Check quota before AI call
   - Check quota before rule evaluation
   - Return proper error messages with upgrade prompts

### Phase 2: Content Limits (This Week)

1. **Request size limits**: 1MB max payload
2. **Content size limits**:
   - Real-time: 10KB max
   - Deep analysis: 100KB max
3. **Rate limiting**: Per-tenant burst limits

### Phase 3: Cost Controls (Next Week)

1. **Cost tracking dashboard**
2. **Automatic alerting** at 80% quota
3. **Overage protection** (hard stops)

---

## Pricing Tiers Summary

| Tier | Monthly Price | Quota (Realtime) | Quota (AI) | Target Margin |
|------|--------------|------------------|------------|---------------|
| Free | SGD $0 | 100/day | 1/month | -SGD $2 (acquisition) |
| Pro | SGD $49 | 10,000/day | 500/month | 60% |
| Enterprise | SGD $499+ | Custom | Custom | 70%+ |

**Break-even**: ~20 Pro users cover infrastructure costs  
**Target**: 100 Pro users = SGD $4,900/month revenue  
**Costs**: SGD $2,000/month  
**Profit**: SGD $2,900/month (59% margin)

---

## Next Steps

1. **Confirm pricing** - Does $49/month for Pro work for your market?
2. **Implement quota enforcement** - I'll code this now
3. **Add upgrade prompts** - When users hit limits
4. **Set up monitoring** - Track quota usage and costs
