# The Mirror - Quick Start Guide

Fast-track deployment guide for The Mirror on OpenShift.

---

## Prerequisites Checklist

- [ ] OpenShift cluster access (`oc login`)
- [ ] Domain name (example: `target.yourdomain.com`)
- [ ] DNS access (to create A records)
- [ ] TLS certificate (Let's Encrypt or commercial)
- [ ] Container registry access (Quay.io, Docker Hub, or internal)

---

## 5-Minute Quick Start (Phase 1 Only)

### 1. Clone and Build

```bash
cd ~/REPOS
git clone https://github.com/hlipsig/cyber-riposte.git
cd cyber-riposte/scenario-the-mirror

# Build container
docker build -t quay.io/your-org/mirror-agent:v1.0.0 .

# Push to registry
docker push quay.io/your-org/mirror-agent:v1.0.0
```

### 2. Configure Your Domain

See **DOMAIN-SETUP.md** for full instructions. Quick version:

```bash
# 1. Get OpenShift ingress IP
oc get svc -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}'

# 2. Create DNS A record
#    Name: target.yourdomain.com
#    Value: <OpenShift-ingress-IP>

# 3. Create TLS certificate
certbot certonly --manual --preferred-challenges dns \
  -d target.yourdomain.com -d '*.target.yourdomain.com'

# 4. Upload to OpenShift
oc create secret tls mirror-tls-cert \
  --cert=/etc/letsencrypt/live/target.yourdomain.com/fullchain.pem \
  --key=/etc/letsencrypt/live/target.yourdomain.com/privkey.pem \
  -n istio-system
```

### 3. Deploy to OpenShift

```bash
cd ~/REPOS/cyber-riposte/scenario-the-mirror

# Create namespace
oc apply -f k8s/namespace.yaml

# Create ConfigMap
oc create configmap mirror-agent-config \
  --from-file=action-pool.yaml \
  --from-file=suspicious-user-agents.yaml \
  -n cyber-riposte

# Create secrets
oc create secret generic mirror-agent-secrets \
  --from-literal=SHODAN_API_KEY=your-shodan-api-key \
  -n cyber-riposte

# Deploy agent
oc apply -f k8s/agent-rbac.yaml
oc apply -f k8s/agent-pvc.yaml

# Edit deployment - update image to your registry
vim k8s/agent-deployment.yaml
# Change: quay.io/your-org/mirror-agent:latest

oc apply -f k8s/agent-deployment.yaml
oc apply -f k8s/agent-service.yaml

# Edit gateway - replace 'your-domain.com' with actual domain
sed -i '' 's/your-domain.com/target.yourdomain.com/g' k8s/istio/gateway.yaml

# Deploy Istio Gateway
oc apply -f k8s/istio/gateway.yaml

# Deploy a test app (or use your own)
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: legitimate-app
  namespace: cyber-riposte
spec:
  replicas: 1
  selector:
    matchLabels:
      app: legitimate-app
  template:
    metadata:
      labels:
        app: legitimate-app
    spec:
      containers:
      - name: httpd
        image: registry.access.redhat.com/ubi9/httpd-24:latest
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: legitimate-app-service
  namespace: cyber-riposte
spec:
  selector:
    app: legitimate-app
  ports:
  - port: 80
    targetPort: 8080
EOF
```

### 4. Verify

```bash
# Check pods
oc get pods -n cyber-riposte

# Check logs
oc logs -f deployment/mirror-agent -n cyber-riposte

# Test health endpoints
oc port-forward deployment/mirror-agent 8080:8080 -n cyber-riposte
curl http://localhost:8080/healthz

# Test domain (from browser or curl)
curl https://target.yourdomain.com
```

---

## Test with Fake Attack

```bash
# Get agent pod
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')

# Send fake Suricata EVE event
oc exec -it $AGENT_POD -n cyber-riposte -- python3 -m agent.main <<'EOF'
{"event_type": "alert", "src_ip": "198.51.100.42", "timestamp": "2024-06-15T03:14:07Z", "alert": {"signature": "ET SCAN Nmap Scripting Engine", "category": "Attempted Recon", "severity": 2}, "http": {"http_user_agent": "Nmap Scripting Engine"}}
EOF

# Check logs for detection
oc logs $AGENT_POD -n cyber-riposte | tail -30

# Check if VirtualService was created
oc get virtualservice -n cyber-riposte

# Check audit log
oc exec $AGENT_POD -n cyber-riposte -- cat /var/log/cyber-riposte/audit.jsonl | tail -5
```

---

## Common Issues

### Pods not starting

```bash
# Check events
oc get events -n cyber-riposte --sort-by='.lastTimestamp' | tail -10

# Check pod details
oc describe pod -l app=mirror-agent -n cyber-riposte
```

### ConfigMap not loading

```bash
# Verify ConfigMap
oc get configmap mirror-agent-config -n cyber-riposte -o yaml

# Check mounted files
oc exec deployment/mirror-agent -n cyber-riposte -- ls -la /etc/mirror/config/
```

### Domain not resolving

```bash
# Check DNS
dig target.yourdomain.com +short

# Check from different DNS
dig @8.8.8.8 target.yourdomain.com +short

# Wait for propagation (5 min - 48 hours)
```

### Certificate errors

```bash
# Check TLS secret
oc get secret mirror-tls-cert -n istio-system

# Check certificate content
oc get secret mirror-tls-cert -n istio-system -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -text | grep -A2 "Subject Alternative Name"
```

---

## Next Phases

**Phase 2: Kafka Integration**
- Deploy Kafka/AMQ Streams
- Create fake event generator
- Update agent to consume from Kafka

**Phase 4: Istio VirtualService**
- Agent creates VirtualServices for detected attackers
- Traffic routing to honeypot

**Phase 5: Honeypot Deployment**
- Deploy Cowrie (SSH honeypot)
- Deploy Glastopf (HTTP honeypot)
- PCAP collection

---

## Red Team Quick Start

Send this to your red team:

**Target**: `https://target.yourdomain.com`

**Try these attacks**:
```bash
# Port scan
nmap -sV target.yourdomain.com

# Directory brute-force  
gobuster dir -u https://target.yourdomain.com -w /path/to/wordlist.txt

# Vulnerability scan
nikto -h https://target.yourdomain.com

# SQL injection
sqlmap -u "https://target.yourdomain.com/page?id=1"
```

**What happens**:
1. You attack → Suricata detects (or will in Phase 2)
2. Mirror agent detects reconnaissance pattern
3. You get redirected to honeypot (transparent, you won't notice)
4. Your actions are logged in honeypot
5. Agent runs OSINT on your IP
6. Incident report generated for blue team review

---

## Useful Commands

```bash
# Watch logs
oc logs -f deployment/mirror-agent -n cyber-riposte

# Watch VirtualServices
watch oc get virtualservice -n cyber-riposte

# Check audit logs
oc exec deployment/mirror-agent -n cyber-riposte -- tail -f /var/log/cyber-riposte/audit.jsonl

# Port-forward for testing
oc port-forward deployment/mirror-agent 8080:8080 -n cyber-riposte

# Restart agent
oc rollout restart deployment/mirror-agent -n cyber-riposte

# Scale up/down
oc scale deployment/mirror-agent --replicas=3 -n cyber-riposte
```

---

## Documentation

- **Full plan**: `~/Documents/cyber-riposte-openshift-plan.md`
- **Domain setup**: `DOMAIN-SETUP.md`
- **Phase 1 summary**: `~/Documents/cyber-riposte-phase1-complete.md`
- **K8s deployment**: `k8s/README.md`

---

## Support

Issues? Check:
1. Pod logs: `oc logs deployment/mirror-agent -n cyber-riposte`
2. Events: `oc get events -n cyber-riposte`
3. Pod status: `oc describe pod -l app=mirror-agent -n cyber-riposte`
4. Documentation: All `.md` files in this repo

---

**Status**: Phase 1 Complete ✅  
**Next**: Phase 2 (Kafka Integration)  
**Ready for**: Red team domain attacks (after domain setup)
