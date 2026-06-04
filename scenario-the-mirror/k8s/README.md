# Kubernetes Manifests for The Mirror

This directory contains all Kubernetes/OpenShift manifests for deploying The Mirror agent.

## Directory Structure

```
k8s/
├── README.md                           # This file
├── namespace.yaml                      # cyber-riposte namespace
├── agent-configmap.yaml                # Action pool and user-agent signatures
├── agent-deployment.yaml               # Mirror agent Deployment
├── agent-service.yaml                  # Service for health checks
├── agent-secret.yaml                   # Secrets (API keys, DB credentials)
├── agent-rbac.yaml                     # ServiceAccount, Role, RoleBinding
├── ingress-route.yaml                  # OpenShift Route for red team domain
├── istio/                              # Istio service mesh configuration
│   ├── installation.yaml               # Istio operator installation
│   ├── gateway.yaml                    # Istio Gateway for domain
│   └── virtualservice-template.yaml    # Template for attacker redirection
└── staging/                            # Staging environment manifests
```

## Deployment Order

### Prerequisites

1. OpenShift cluster with cluster-admin access
2. `oc` CLI installed and logged in
3. Domain for red team entrypoint (configured in DNS)
4. TLS certificate for the domain

### Phase 1: Core Agent (Current)

```bash
# 1. Create namespace
oc apply -f namespace.yaml

# 2. Create ConfigMap from YAML files
oc create configmap mirror-agent-config \
  --from-file=action-pool.yaml=../action-pool.yaml \
  --from-file=suspicious-user-agents.yaml=../suspicious-user-agents.yaml \
  -n cyber-riposte

# 3. Create secrets (replace with actual values)
oc create secret generic mirror-agent-secrets \
  --from-literal=SHODAN_API_KEY=your-shodan-key \
  --from-literal=DATABASE_URL=postgresql://user:pass@postgres:5432/mirror \
  --from-literal=GITHUB_TOKEN=ghp_your-token \
  --from-literal=SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK \
  -n cyber-riposte

# 4. Create RBAC resources
oc apply -f agent-rbac.yaml

# 5. Deploy the agent
oc apply -f agent-deployment.yaml
oc apply -f agent-service.yaml

# 6. Check status
oc get pods -n cyber-riposte
oc logs -f deployment/mirror-agent -n cyber-riposte
```

### Phase 4: Istio Service Mesh

```bash
# 1. Install Istio operator
oc apply -f istio/installation.yaml

# 2. Create TLS certificate secret in istio-system namespace
oc create secret tls mirror-tls-cert \
  --cert=fullchain.pem \
  --key=privkey.pem \
  -n istio-system

# 3. Create Istio Gateway
oc apply -f istio/gateway.yaml

# 4. Create OpenShift Route for your domain
# Edit ingress-route.yaml first - replace 'your-domain.com' with actual domain
oc apply -f ingress-route.yaml

# 5. Configure DNS
# Point your domain's A record to the OpenShift ingress IP
oc get svc -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

## Configuration

### ConfigMap (`agent-configmap.yaml`)

Contains:
- `action-pool.yaml` - Pre-approved actions the agent can execute
- `suspicious-user-agents.yaml` - Tool signatures for detection

To update:
```bash
# Edit the source files
vim ../action-pool.yaml
vim ../suspicious-user-agents.yaml

# Recreate ConfigMap
oc create configmap mirror-agent-config \
  --from-file=action-pool.yaml=../action-pool.yaml \
  --from-file=suspicious-user-agents.yaml=../suspicious-user-agents.yaml \
  -n cyber-riposte \
  --dry-run=client -o yaml | oc apply -f -

# Restart agent to pick up changes (or wait for Phase 9 hot-reload)
oc rollout restart deployment/mirror-agent -n cyber-riposte
```

### Secrets (`agent-secret.yaml`)

Required secrets:
- `SHODAN_API_KEY` - Shodan API key for OSINT lookups
- `DATABASE_URL` - PostgreSQL connection string (Phase 3)
- `GITHUB_TOKEN` - GitHub personal access token for issue creation (Phase 8)
- `SLACK_WEBHOOK_URL` - Slack incoming webhook URL (Phase 8)

### Environment Variables

Set in `agent-deployment.yaml`:
- `EVENT_SOURCE` - `stdin` or `kafka` (Phase 2)
- `KAFKA_BOOTSTRAP_SERVERS` - Kafka brokers (Phase 2)
- `KAFKA_TOPIC` - Topic name for Suricata EVE events (Phase 2)
- `HONEYPOT_IP` - Honeypot service address (default: `honeypot-service.cyber-riposte.svc.cluster.local`)
- `LOG_LEVEL` - Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`)
- `LOG_FORMAT` - `json` or `text`

## Health Checks

The agent exposes three HTTP endpoints:

- `GET /healthz` - Liveness probe (is process running?)
- `GET /readyz` - Readiness probe (is agent ready to process events?)
- `GET /metrics` - Metrics endpoint (Phase 7 will add Prometheus metrics)

Default port: `8080`

## Troubleshooting

### Agent not starting

```bash
# Check pod status
oc get pods -n cyber-riposte

# View logs
oc logs deployment/mirror-agent -n cyber-riposte

# Describe pod
oc describe pod -l app=mirror-agent -n cyber-riposte
```

### ConfigMap not loading

```bash
# Verify ConfigMap exists
oc get configmap mirror-agent-config -n cyber-riposte

# Check mounted files
oc exec deployment/mirror-agent -n cyber-riposte -- ls -la /etc/mirror/config/

# Verify content
oc exec deployment/mirror-agent -n cyber-riposte -- cat /etc/mirror/config/action-pool.yaml
```

### Secrets not available

```bash
# Verify secret exists
oc get secret mirror-agent-secrets -n cyber-riposte

# Check environment variables in pod
oc exec deployment/mirror-agent -n cyber-riposte -- env | grep -E 'SHODAN|DATABASE|GITHUB|SLACK'
```

## Testing

### Test with fake Suricata EVE event

```bash
# Send a test event to the agent via stdin
oc exec -it deployment/mirror-agent -n cyber-riposte -- /bin/bash
python3 -m agent.main <<EOF
{"event_type": "alert", "src_ip": "203.0.113.42", "timestamp": "2024-06-15T03:14:07Z", "alert": {"signature": "ET SCAN Nmap Scripting Engine", "category": "Attempted Recon", "severity": 2}, "http": {"http_user_agent": "Nmap Scripting Engine"}}
EOF
```

### Check health endpoints

```bash
# From inside the cluster
oc exec deployment/mirror-agent -n cyber-riposte -- curl http://localhost:8080/healthz
oc exec deployment/mirror-agent -n cyber-riposte -- curl http://localhost:8080/readyz
oc exec deployment/mirror-agent -n cyber-riposte -- curl http://localhost:8080/metrics

# Port-forward for local access
oc port-forward deployment/mirror-agent 8080:8080 -n cyber-riposte
curl http://localhost:8080/healthz
```

## Upgrading

### Build and push new image

```bash
# Build image
cd ~/REPOS/cyber-riposte/scenario-the-mirror
docker build -t quay.io/your-org/mirror-agent:v1.0.0 .

# Push to registry
docker push quay.io/your-org/mirror-agent:v1.0.0

# Update deployment
oc set image deployment/mirror-agent mirror-agent=quay.io/your-org/mirror-agent:v1.0.0 -n cyber-riposte

# Watch rollout
oc rollout status deployment/mirror-agent -n cyber-riposte
```

### Rollback

```bash
# View rollout history
oc rollout history deployment/mirror-agent -n cyber-riposte

# Rollback to previous version
oc rollout undo deployment/mirror-agent -n cyber-riposte
```

## Next Phases

- **Phase 2**: Kafka integration - replace stdin with Kafka consumer
- **Phase 3**: PostgreSQL - replace file-based audit log with database
- **Phase 4**: Istio VirtualService - replace nftables with K8s-native traffic routing
- **Phase 5**: Honeypot workloads - deploy Cowrie/Glastopf as StatefulSets
- **Phase 6**: Redis caching - add OSINT result caching
- **Phase 7**: Observability - Prometheus metrics and OpenTelemetry traces
- **Phase 8**: GitHub Issues - auto-create incidents
- **Phase 9**: Hot-reload - ConfigMap changes without pod restart
- **Phase 10**: CI/CD - automated testing and deployment
