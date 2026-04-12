# AxiomGuard Kubernetes Deployment

> **Legacy v3 deployment.** The v4 Control Plane is a single binary that can be deployed with minimal Kubernetes resources. This directory covers the v3 GKE deployment.

This directory contains Kubernetes manifests for deploying AxiomGuard on GKE (Google Kubernetes Engine).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         GKE Cluster                              │
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Proxy     │───▶│   Shield    │───▶│    TimescaleDB      │ │
│  │  (3+ pods)  │    │  (3+ pods)  │    │   (+ pgvector)      │ │
│  │  HTTP/WS    │    │  gRPC       │    │                     │ │
│  └─────────────┘    └──────┬──────┘    └─────────────────────┘ │
│                            │                                     │
│                            ▼                                     │
│                     ┌─────────────┐                              │
│                     │    vLLM     │                              │
│                     │  (GPU node) │                              │
│                     │  Mistral 7B │                              │
│                     └─────────────┘                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. **GKE Cluster** with:
   - Autopilot or Standard mode
   - GPU node pool (NVIDIA L4 for vLLM)
   - Workload Identity enabled

2. **Tools**:
   ```bash
   gcloud components install kubectl gke-gcloud-auth-plugin
   ```

3. **Container Images**:
   ```bash
   # Build and push images
   docker build -t gcr.io/PROJECT_ID/axiomguard-shield:latest .
   docker build -t gcr.io/PROJECT_ID/axiomguard-proxy:latest .
   docker push gcr.io/PROJECT_ID/axiomguard-shield:latest
   docker push gcr.io/PROJECT_ID/axiomguard-proxy:latest
   ```

## Deployment

### 1. Set up GKE Cluster

```bash
# Create cluster with GPU support
gcloud container clusters create axiomguard-cluster \
  --zone=us-central1-a \
  --accelerator=type=nvidia-l4,count=1 \
  --machine-type=n1-standard-4 \
  --num-nodes=1 \
  --min-nodes=1 \
  --max-nodes=5 \
  --enable-autoscaling \
  --enable-autorepair

# Install NVIDIA drivers
gcloud container node-pools update default-pool \
  --cluster=axiomguard-cluster \
  --zone=us-central1-a \
  --update-accelerator=type=nvidia-l4,count=1
```

### 2. Configure Secrets

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Generate and set secrets
DB_PASSWORD=$(openssl rand -base64 32)
kubectl create secret generic axiomguard-secrets \
  --from-literal=DB_PASSWORD="$DB_PASSWORD" \
  --from-literal=API_KEYS="$(openssl rand -base64 32)" \
  -n axiomguard
```

### 3. Deploy Services

```bash
# Deploy all components
kubectl apply -k .

# Or deploy individually
kubectl apply -f namespace.yaml
kubectl apply -f secret.yaml
kubectl apply -f configmap.yaml
kubectl apply -f postgres.yaml
kubectl apply -f vllm.yaml
kubectl apply -f shield.yaml
kubectl apply -f proxy.yaml
kubectl apply -f ingress.yaml
```

### 4. Verify Deployment

```bash
# Check pods
kubectl get pods -n axiomguard -w

# Check services
kubectl get svc -n axiomguard

# Check logs
kubectl logs -n axiomguard -l app=shield -f
kubectl logs -n axiomguard -l app=proxy -f
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | TimescaleDB connection string | - |
| `AI_BACKEND` | Primary AI backend | `vllm-grpc` |
| `VLLM_ENDPOINT` | vLLM service endpoint | `http://vllm:8000/v1` |
| `DECISIVE_TIMER_MS` | Request timeout | `80` |
| `RUST_LOG` | Log level | `info` |

### Scaling

```bash
# Manual scaling
kubectl scale deployment shield --replicas=5 -n axiomguard
kubectl scale deployment proxy --replicas=5 -n axiomguard

# Update HPA
kubectl patch hpa shield-hpa -n axiomguard -p '{"spec":{"maxReplicas":30}}'
```

## Monitoring

### Prometheus/Grafana

```bash
# Install Prometheus
gcloud container clusters get-credentials axiomguard-cluster --zone=us-central1-a
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/bundle.yaml

# Access Grafana
kubectl port-forward svc/grafana 3000:3000 -n monitoring
```

### Key Metrics

- `axiomguard_shield_processing_time_ms` - Request latency
- `axiomguard_shield_total_events` - Total requests
- `axiomguard_shield_blocked_events` - Blocked requests
- `axiomguard_shield_cache_hits` - Cache hit rate

## Troubleshooting

### Pod not starting

```bash
# Check events
kubectl get events -n axiomguard --sort-by=.lastTimestamp

# Check pod logs
kubectl logs -n axiomguard deployment/shield --previous
```

### Database connection issues

```bash
# Test database connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -n axiomguard -- psql postgres://axiomguard:$DB_PASSWORD@postgres:5432/axiomguard

# Check TimescaleDB logs
kubectl logs -n axiomguard -l app=postgres -f
```

### vLLM GPU issues

```bash
# Check GPU allocation
kubectl describe node | grep nvidia.com/gpu

# Check vLLM logs
kubectl logs -n axiomguard -l app=vllm -f
```

## Cleanup

```bash
# Delete all resources
kubectl delete -k .

# Delete cluster
gcloud container clusters delete axiomguard-cluster --zone=us-central1-a
```

## Production Checklist

- [ ] Change default passwords in secrets
- [ ] Configure SSL certificates
- [ ] Set up backup for TimescaleDB
- [ ] Configure network policies
- [ ] Enable Pod Security Standards
- [ ] Set up log aggregation (Cloud Logging)
- [ ] Configure alerting
- [ ] Load testing completed

## References

- [GKE Documentation](https://cloud.google.com/kubernetes-engine/docs)
- [vLLM Documentation](https://docs.vllm.ai/)
- [pgvector Documentation](https://github.com/pgvector/pgvector)
