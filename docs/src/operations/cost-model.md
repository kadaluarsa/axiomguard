# AxiomGuard Cloud Run GPU Cost Model

> **Document Version:** 1.0  
> **Last Updated:** April 2026  
> **Region:** asia-southeast1 (Singapore)  
> **Currency:** SGD (Singapore Dollars)

---

## 1. Overview

This document provides a comprehensive cost model for the AxiomGuard LLM inference service running on Google Cloud Run with NVIDIA L4 GPUs in the Singapore region.

### Service Configuration

| Parameter | Value |
|-----------|-------|
| GPU Type | NVIDIA L4 |
| GPU Count per Instance | 1 |
| vCPU per Instance | 8 |
| Memory per Instance | 32 GiB |
| Min Instances | 2 |
| Max Instances | 16 |
| Region | asia-southeast1 |

---

## 2. Detailed Cost Breakdown

### 2.1 Base Resource Costs (per instance per hour)

| Resource | Unit | Unit Price (SGD) | Quantity | Hourly Cost (SGD) |
|----------|------|------------------|----------|-------------------|
| **NVIDIA L4 GPU** | GPU-hour | $1.8925 | 1 | $1.8925 |
| **vCPU** | vCPU-hour | $0.0380 | 8 | $0.3040 |
| **Memory** | GiB-hour | $0.0042 | 32 | $0.1344 |
| **Request Handling** | Million requests | $0.40 | ~0.001 | ~$0.0004 |
| **Egress (est.)** | GB | $0.12 | ~0.1 | ~$0.012 |
| **TOTAL per instance/hour** | | | | **$2.3433** |

> **Note:** Prices based on asia-southeast1 Cloud Run pricing as of April 2026. Always verify current pricing at [Google Cloud Pricing Calculator](https://cloud.google.com/products/calculator).

### 2.2 Monthly Base Cost Calculation (Minimum Configuration)

With **2 minimum instances** running 24/7:

```
Hourly cost per instance: SGD $2.3433
Daily cost per instance:  $2.3433 × 24 = $56.2392
Monthly cost per instance: $56.2392 × 30 = $1,687.18

Total for 2 instances: $1,687.18 × 2 = SGD $3,374.36/month
```

### 2.3 Cost at Different Utilization Levels

| Scenario | Instance Count | Monthly Cost (SGD) | Annual Cost (SGD) |
|----------|---------------|-------------------|-------------------|
| **Minimum (2 instances)** | 2 | $3,374 | $40,488 |
| **Low Load (4 instances avg)** | 4 | $6,748 | $80,976 |
| **Medium Load (8 instances avg)** | 8 | $13,497 | $161,964 |
| **Peak Load (12 instances)** | 12 | $20,245 | $242,940 |
| **Maximum (16 instances)** | 16 | $26,994 | $323,928 |

---

## 3. Cost Optimization Strategies

### 3.1 Schedule-Based Scaling (60-70% Savings)

Implement time-based scaling to reduce min instances during off-peak hours:

| Schedule | Min Instances | Monthly Savings |
|----------|-----------------|-----------------|
| Business Hours (8h × 5d) | 2 | Baseline |
| Off-Hours + Weekends | 0 | ~$2,025 |
| **Effective Savings** | | **~60%** |

**Implementation:**
```hcl
# Cloud Scheduler to scale min instances
resource "google_cloud_scheduler_job" "scale_up" {
  name             = "axiomguard-scale-up"
  schedule         = "0 8 * * 1-5"  # 8 AM weekdays
  time_zone        = "Asia/Singapore"
  
  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/services/axiomguard-inference"
    headers = {
      "Content-Type" = "application/json"
      "Authorization" = "Bearer ${data.google_client_config.default.access_token}"
    }
    body = base64encode(jsonencode({
      template = {
        scaling = {
          min_instance_count = 2
        }
      }
    }))
  }
}
```

### 3.2 Spot Instances / Preemptible VMs (40-60% Discount)

**Current Limitation:** Cloud Run doesn't natively support spot instances. However, you can:

1. **Use GKE Autopilot with Spot nodes:**
   - Migrate to GKE Autopilot with GPU node pools
   - Configure spot instances for 60% discount
   - Trade-off: Potential interruptions (handle with graceful degradation)

2. **Request-based over provisioned instances:**
   - Keep 1 always-on instance
   - Use Cloud Functions for burst handling

### 3.3 Committed Use Discounts (CUD) (30-50% Discount)

For predictable baseline load, purchase 1-year or 3-year commitments:

| Commitment Term | Discount | Monthly Cost (2 instances) | Annual Savings |
|-----------------|----------|---------------------------|----------------|
| On-Demand | 0% | $3,374 | - |
| 1-Year CUD | 30% | $2,362 | $12,146 |
| 3-Year CUD | 50% | $1,687 | $20,244 |

**Recommendation:** Purchase 1-year CUD for the baseline 2-instance minimum.

### 3.4 Model Optimization Techniques

| Technique | Latency Impact | Cost Impact | Implementation Complexity |
|-----------|---------------|-------------|---------------------------|
| **INT8 Quantization** | +10-15% throughput | -30% (fewer instances) | Low |
| **FP16 Mixed Precision** | Baseline | Baseline | None |
| **Model Pruning** | +5-10% throughput | -15% | Medium |
| **Speculative Decoding** | -30-40% latency | -20% | High |
| **Continuous Batching** | +50% throughput | -33% | Low (vLLM native) |

### 3.5 Request Batching and Caching

| Strategy | Expected Savings |
|----------|------------------|
| **Semantic Cache (Redis)** | 20-30% for repeated queries |
| **Request Batching** | 40-50% throughput improvement |
| **Prompt Caching** | 15-25% for template-based requests |

---

## 4. Cost Monitoring and Alerting

### 4.1 Cost Anomaly Detection

```hcl
# Cost anomaly alert
resource "google_monitoring_alert_policy" "cost_anomaly" {
  display_name = "AxiomGuard: Daily Cost Anomaly"
  combiner     = "OR"
  
  conditions {
    display_name = "Daily cost exceeds 150% of 7-day average"
    
    condition_threshold {
      filter = <<-EOT
        resource.type="global"
        metric.type="billing.googleapis.com/invoice/total"
      EOT
      
      aggregations {
        alignment_period     = "86400s"
        per_series_aligner   = "ALIGN_SUM"
      }
      
      comparison      = "COMPARISON_GT"
      threshold_value = 1.5  # 150% of baseline (adjust based on historical data)
      duration        = "0s"
    }
  }
  
  notification_channels = var.notification_channels
  severity = "WARNING"
}
```

### 4.2 Budget Alerts

| Budget Level | Alert Threshold | Action |
|--------------|-----------------|--------|
| Daily | $150 (125% of $120 baseline) | Warning notification |
| Weekly | $1,050 | Review scaling settings |
| Monthly | $4,500 (133% of $3,374 baseline) | Emergency review + auto-scale down |

### 4.3 Cost Attribution Tags

All resources should be tagged for cost tracking:

```hcl
labels = {
  service      = "axiomguard-llm"
  environment  = "production"
  team         = "ml-platform"
  cost_center  = "engineering-ai"
  project      = "axiomguard-inference"
}
```

---

## 5. ROI and Business Impact

### 5.1 Cost Comparison: Cloud Run vs. Alternatives

| Platform | Monthly Cost (2 instances) | Pros | Cons |
|----------|---------------------------|------|------|
| **Cloud Run GPU** | $3,374 | Serverless, auto-scale, pay-per-use | Higher per-hour cost, GPU availability |
| **GKE Autopilot** | $2,800 | More control, spot instances | Management overhead |
| **Compute Engine** | $2,600 | Full control, CUD eligible | Manual scaling, maintenance |
| **Vertex AI** | $4,200 | Managed, integrated with GCP | Higher cost, less control |
| **AWS SageMaker** | $3,600 | Cross-cloud | Egress costs, complexity |

### 5.2 Performance per Dollar

| Metric | Value |
|--------|-------|
| Requests per dollar | ~1,500 requests/USD |
| Tokens per dollar | ~750K tokens/USD |
| Latency per dollar | 0.03 ms/USD (p95) |

---

## 6. Appendix

### A. Quick Reference: Cost Calculation Formula

```
Monthly Cost = (
  GPU Hours × GPU Rate +
  vCPU Hours × vCPU Rate +
  Memory GiB-Hours × Memory Rate +
  Egress GB × Egress Rate
) × Instance Count
```

### B. Glossary

| Term | Definition |
|------|------------|
| **CUD** | Committed Use Discount - prepaid capacity discount |
| **GiB** | Gibibyte (1024^3 bytes) |
| **GPU-hour** | One GPU running for one hour |
| **Spot instance** | Preemptible compute at discounted rates |
| **vCPU** | Virtual CPU core |

### C. Related Documents

- [AxiomGuard Runbook](./runbook.md) - Operational procedures
- [Architecture Overview](../architecture/README.md) - System design
- [Terraform Configuration](../../infra/README.md) - Infrastructure code

---

*Document generated: April 2026*  
*For questions or updates, contact: ml-platform@axiomguard.io*
