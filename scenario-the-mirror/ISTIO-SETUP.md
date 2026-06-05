# Phase 4: Istio Service Mesh Setup Guide

This guide covers installing Istio and configuring VirtualService for dynamic traffic redirection - the **core Mirror functionality**.

---

## Why Istio?

**Phase 1-3** could detect and log attacks, but couldn't **redirect** traffic:
- ❌ NetworkPolicy only blocks, doesn't redirect
- ❌ nftables requires host privileges (no SCC in OpenShift)
- ❌ Ingress can't route based on source IP dynamically
- ❌ No way to send attacker to honeypot while keeping app live

**Phase 4 (Istio)** solves this:
- ✅ VirtualService routes by source IP, headers, URI, method
- ✅ Dynamic rules created via Kubernetes API
- ✅ Traffic mirrored to honeypot without blocking legitimate users
- ✅ L7 visibility for HTTP/gRPC traffic
- ✅ No host-level privileges required

---

## Quick Start

### Option 1: Development (Istio Operator)

```bash
# 1. Install Istio Operator
oc apply -f k8s/istio/operator.yaml

# 2. Wait for operator ready
oc wait --for=condition=ready pod -l name=istio-operator -n istio-operator --timeout=300s

# 3. Deploy Istio control plane
oc apply -f k8s/istio/controlplane.yaml

# 4. Wait for Istio ready
oc wait --for=condition=ready pod -l app=istiod -n istio-system --timeout=300s

# 5. Deploy Gateway and default VirtualService
oc apply -f k8s/istio/gateway.yaml

# 6. Grant agent RBAC for VirtualService creation
oc apply -f k8s/agent-rbac-istio.yaml

# 7. Deploy/update agent with Istio support
oc apply -f k8s/agent-deployment-kafka.yaml
```

### Option 2: Production (OpenShift Service Mesh)

See "Production Deployment" section below.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Internet / Red Team                                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Istio Ingress   │
                    │  Gateway         │
                    │                  │
                    │  redteam.        │
                    │  example.com     │
                    └──────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│ Default     │       │ Attacker    │       │ Attacker    │
│ Route       │       │ 203.0.113.  │       │ 198.51.100. │
│             │       │ 42          │       │ 15          │
│ → webapp    │       │ → honeypot  │       │ → honeypot  │
└─────────────┘       └─────────────┘       └─────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
┌─────────────┐       ┌─────────────────────────────┐
│ Real App    │       │ Honeypot (Cowrie + Glasto) │
│ (legitimate │       │ (attackers only)           │
│ users)      │       │                            │
└─────────────┘       └─────────────────────────────┘
```

**Flow**:
1. Mirror agent detects reconnaissance from IP `203.0.113.42`
2. Agent creates VirtualService via Kubernetes API
3. Istio evaluates VirtualServices by priority (lower = higher precedence)
4. Traffic from `203.0.113.42` routes to honeypot
5. All other traffic routes to real app (default VirtualService)
6. After 24 hours, agent deletes VirtualService (auto-expire)

---

## Istio Installation (Development)

### 1. Install Istio Operator

```bash
cd ~/REPOS/cyber-riposte/scenario-the-mirror

# Deploy Istio operator
oc apply -f k8s/istio/operator.yaml

# Verify operator running
oc get pods -n istio-operator
# Should see: istio-operator-xxxxx

# Wait for ready
oc wait --for=condition=ready pod -l name=istio-operator -n istio-operator --timeout=300s
```

### 2. Deploy Istio Control Plane

```bash
# Deploy control plane
oc apply -f k8s/istio/controlplane.yaml

# Check control plane components
oc get pods -n istio-system
# Should see: istiod-xxxxx, istio-ingressgateway-xxxxx

# Wait for ready
oc wait --for=condition=ready pod -l app=istiod -n istio-system --timeout=300s
oc wait --for=condition=ready pod -l app=istio-ingressgateway -n istio-system --timeout=300s
```

### 3. Enable Sidecar Injection

```bash
# Label namespace for automatic sidecar injection
oc label namespace cyber-riposte istio-injection=enabled

# Verify label
oc get namespace cyber-riposte --show-labels

# Restart pods to inject sidecar
oc rollout restart deployment/mirror-agent-kafka -n cyber-riposte
oc rollout restart deployment/webapp -n cyber-riposte  # Your real app

# Verify sidecar injected (should have 2 containers: app + istio-proxy)
oc get pods -n cyber-riposte
```

---

## Gateway and VirtualService Setup

### 1. Deploy Gateway

The Gateway is the **entry point** for red team traffic.

```bash
# Deploy Gateway
oc apply -f k8s/istio/gateway.yaml

# Verify Gateway created
oc get gateway -n cyber-riposte
# Should see: redteam-gateway

# Get Gateway external IP
oc get svc istio-ingressgateway -n istio-system
# Note the EXTERNAL-IP or LoadBalancer hostname
```

**DNS Setup**: Point your red team domain to the Gateway external IP:
```bash
# Example:
# redteam.example.com → A record → 203.0.113.100 (Gateway IP)
```

### 2. Deploy Default VirtualService

Routes all traffic to your real app (unless overridden by attacker-specific rules).

```bash
# Edit gateway.yaml to set your real app service
# Change: webapp-service → your-app-service

oc apply -f k8s/istio/gateway.yaml

# Verify VirtualService
oc get virtualservice -n cyber-riposte
# Should see: default-route

# Test default route
curl -H "Host: redteam.example.com" http://<GATEWAY_IP>/
# Should reach your real app
```

---

## Agent RBAC for VirtualService Creation

The agent needs **Kubernetes API permissions** to create/delete VirtualServices dynamically.

### 1. Create ServiceAccount and RBAC

```bash
# Deploy RBAC manifests
oc apply -f k8s/agent-rbac-istio.yaml

# Verify ServiceAccount
oc get serviceaccount mirror-agent -n cyber-riposte

# Verify Role
oc get role mirror-agent-istio -n cyber-riposte

# Verify RoleBinding
oc get rolebinding mirror-agent-istio -n cyber-riposte
```

**What this grants**:
- `GET, LIST, WATCH` on VirtualServices (read existing)
- `CREATE, DELETE, PATCH` on VirtualServices (create/delete attacker rules)
- Scoped to `cyber-riposte` namespace only

### 2. Update Agent Deployment

Agent deployment already references `serviceAccountName: mirror-agent`:

```bash
# Agent uses this ServiceAccount for Kubernetes API calls
oc get deployment mirror-agent-kafka -n cyber-riposte -o jsonpath='{.spec.template.spec.serviceAccountName}'
# Should output: mirror-agent
```

---

## Agent Integration (Kubernetes API)

The agent creates VirtualServices via Kubernetes Python client.

### Update executor.py

We need to replace the nftables placeholder with Kubernetes API calls:

**File**: `agent/executor.py`

**Old (Phase 1-3)**: Placeholder nftables command
```python
def _execute_redirect_to_honeypot(self, ip: str, duration: str) -> Tuple[str, bool]:
    # Placeholder - will be replaced with Istio VirtualService in Phase 4
    cmd = ["nft", "add", "rule", "inet", "filter", "forward", ...]
    result = subprocess.run(cmd, capture_output=True, text=True)
```

**New (Phase 4)**: Kubernetes API VirtualService creation
```python
def _execute_redirect_to_honeypot(self, ip: str, duration: str) -> Tuple[str, bool]:
    from kubernetes import client, config
    
    # Load in-cluster config
    config.load_incluster_config()
    
    # Create VirtualService for this attacker
    vs_name = f"redirect-{ip.replace('.', '-')}"
    vs = {
        "apiVersion": "networking.istio.io/v1beta1",
        "kind": "VirtualService",
        "metadata": {
            "name": vs_name,
            "namespace": "cyber-riposte",
            "labels": {
                "app": "mirror-agent",
                "attacker_ip": ip
            }
        },
        "spec": {
            "hosts": ["*"],
            "gateways": ["redteam-gateway"],
            "http": [{
                "match": [{
                    "headers": {
                        "x-forwarded-for": {"exact": ip}
                    }
                }],
                "route": [{
                    "destination": {
                        "host": "honeypot-service",
                        "port": {"number": 8080}
                    }
                }]
            }],
            "priority": 10  # Higher precedence than default
        }
    }
    
    api = client.CustomObjectsApi()
    api.create_namespaced_custom_object(
        group="networking.istio.io",
        version="v1beta1",
        namespace="cyber-riposte",
        plural="virtualservices",
        body=vs
    )
    
    return vs_name, True
```

---

## Testing

### End-to-End Test

```bash
# 1. Get Gateway IP
GATEWAY_IP=$(oc get svc istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# 2. Test default route (should reach real app)
curl -H "Host: redteam.example.com" http://$GATEWAY_IP/
# Response from real app

# 3. Trigger detection (generate fake event)
python3 event-producer-sim.py --kafka localhost:9092 --scenario single --count 1

# 4. Check agent logs for VirtualService creation
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep -i virtualservice
# Should see: "Created VirtualService redirect-203-0-113-42"

# 5. Verify VirtualService exists
oc get virtualservice -n cyber-riposte
# Should see: redirect-203-0-113-42

# 6. Test attacker route (should reach honeypot)
curl -H "Host: redteam.example.com" -H "X-Forwarded-For: 203.0.113.42" http://$GATEWAY_IP/
# Response from honeypot

# 7. Test non-attacker (should still reach real app)
curl -H "Host: redteam.example.com" http://$GATEWAY_IP/
# Response from real app
```

---

## Production Deployment (OpenShift Service Mesh)

For production, use **Red Hat OpenShift Service Mesh** (based on Istio).

### 1. Install Service Mesh Operators

```bash
# Install in order:
# 1. Elasticsearch Operator (for Jaeger)
# 2. Jaeger Operator
# 3. Kiali Operator
# 4. Red Hat OpenShift Service Mesh Operator

# Via OpenShift Console:
# Operators → OperatorHub → Search "Service Mesh"
# Install all 4 operators

# Or via CLI (example for Service Mesh operator):
cat <<EOF | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: servicemeshoperator
  namespace: openshift-operators
spec:
  channel: stable
  name: servicemeshoperator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF
```

### 2. Create ServiceMeshControlPlane

```bash
# Create istio-system namespace
oc new-project istio-system

# Deploy control plane
cat <<EOF | oc apply -f -
apiVersion: maistra.io/v2
kind: ServiceMeshControlPlane
metadata:
  name: basic
  namespace: istio-system
spec:
  version: v2.5
  tracing:
    type: Jaeger
    sampling: 10000  # 100% sampling for development
  gateways:
    ingress:
      enabled: true
      service:
        type: LoadBalancer
  policy:
    type: Istiod
  telemetry:
    type: Istiod
EOF

# Wait for control plane ready
oc wait --for=condition=ready smcp/basic -n istio-system --timeout=300s
```

### 3. Create ServiceMeshMemberRoll

```bash
# Add cyber-riposte namespace to mesh
cat <<EOF | oc apply -f -
apiVersion: maistra.io/v1
kind: ServiceMeshMemberRoll
metadata:
  name: default
  namespace: istio-system
spec:
  members:
  - cyber-riposte
EOF

# Verify membership
oc get smmr -n istio-system
```

---

## VirtualService Lifecycle

### Creation (Automatic)

When agent detects an attack:
1. Agent calls Kubernetes API to create VirtualService
2. Istio control plane propagates config to Envoy proxies (~1-2 seconds)
3. Traffic from attacker IP routes to honeypot
4. Agent records VirtualService in database (`virtualservices` table)

### Expiration (Automatic)

VirtualServices auto-expire after 24 hours:
1. Agent tracks `expires_at` in database
2. Background job queries expired VirtualServices
3. Deletes VirtualService via Kubernetes API
4. Updates database: `status = 'expired', deleted_at = NOW()`

### Manual Deletion

```bash
# List all attacker VirtualServices
oc get virtualservice -n cyber-riposte -l app=mirror-agent

# Delete specific VirtualService
oc delete virtualservice redirect-203-0-113-42 -n cyber-riposte

# Delete all expired
oc delete virtualservice -n cyber-riposte -l app=mirror-agent,status=expired
```

---

## Monitoring

### Check VirtualServices

```bash
# List all VirtualServices
oc get virtualservice -n cyber-riposte

# Describe specific VirtualService
oc describe virtualservice redirect-203-0-113-42 -n cyber-riposte

# Get VirtualService YAML
oc get virtualservice redirect-203-0-113-42 -n cyber-riposte -o yaml
```

### Istio Traffic

```bash
# View Envoy config (includes all VirtualServices)
istioctl proxy-config routes deployment/istio-ingressgateway -n istio-system

# View active routes
istioctl proxy-config routes deployment/istio-ingressgateway -n istio-system -o json | jq '.[] | select(.name | contains("80"))'
```

### Database Queries

```bash
# List active redirects
oc exec postgres-0 -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT vs_name, attacker_ip, created_at, expires_at
   FROM virtualservices
   WHERE status = 'active'
   ORDER BY created_at DESC;"

# Count redirects by status
oc exec postgres-0 -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT status, COUNT(*) FROM virtualservices GROUP BY status;"
```

---

## Troubleshooting

### VirtualService Not Created

```bash
# Check agent logs
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep -i virtualservice

# Common errors:
# 1. "Forbidden" - RBAC not configured
# 2. "Connection refused" - Can't reach Kubernetes API
# 3. "Already exists" - VirtualService already created

# Test Kubernetes API access from agent pod
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')
oc exec -it $AGENT_POD -n cyber-riposte -- python3 -c "
from kubernetes import client, config
config.load_incluster_config()
api = client.CustomObjectsApi()
print('Kubernetes API access: OK')
"
```

### Traffic Not Redirected

```bash
# Check VirtualService exists
oc get virtualservice redirect-203-0-113-42 -n cyber-riposte

# Check Gateway exists
oc get gateway redteam-gateway -n cyber-riposte

# Check Envoy config includes VirtualService
istioctl proxy-config routes deployment/istio-ingressgateway -n istio-system | grep redirect

# Check honeypot service exists
oc get svc honeypot-service -n cyber-riposte

# Test with curl
curl -v -H "X-Forwarded-For: 203.0.113.42" http://$GATEWAY_IP/
```

### Sidecar Not Injected

```bash
# Check namespace label
oc get namespace cyber-riposte --show-labels | grep istio-injection

# If missing, add label
oc label namespace cyber-riposte istio-injection=enabled

# Restart deployment
oc rollout restart deployment/mirror-agent-kafka -n cyber-riposte

# Verify sidecar
oc get pods -n cyber-riposte
# Should show 2/2 containers (app + istio-proxy)
```

---

## Security Considerations

### 1. RBAC Least Privilege

Agent can ONLY:
- Create/delete VirtualServices in `cyber-riposte` namespace
- Cannot modify Gateway, DestinationRule, or other Istio resources
- Cannot access other namespaces

### 2. VirtualService Validation

Agent should validate VirtualService spec before creation:
- IP address format (IPv4 or IPv6)
- No wildcards (only exact IP match)
- Destination exists (honeypot-service)
- Expires in <= 24 hours

### 3. Rate Limiting

Prevent VirtualService exhaustion:
- Max 100 active VirtualServices per cluster
- Max 10 VirtualServices created per minute
- Auto-delete expired VirtualServices

---

## Next Steps

After Phase 4 is working:

- **Phase 5**: Deploy honeypots (Cowrie, Glastopf) as Kubernetes workloads
- **Phase 7**: Observability (Istio metrics, traces)
- **Phase 8**: GitHub integration (create issues with VirtualService details)

---

## Summary

**Phase 4 Complete** when:

✅ Istio operator installed  
✅ Istio control plane running (istiod, ingress gateway)  
✅ Namespace has sidecar injection enabled  
✅ Gateway deployed (redteam.example.com)  
✅ Default VirtualService routes to real app  
✅ Agent has RBAC for VirtualService creation  
✅ Agent creates VirtualService via Kubernetes API  
✅ Attacker traffic redirected to honeypot  
✅ Legitimate traffic still reaches real app  
✅ VirtualServices tracked in database  
✅ Auto-expiration working

The Mirror now performs its **core function**: dynamically redirecting attackers to honeypots while keeping the real app accessible! 🎯
