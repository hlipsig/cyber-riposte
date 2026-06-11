# Defensive Actions Catalog - Competitive AI Defense

**Concept**: Racing against adversaries (human or AI) by reconfiguring the battlefield faster than they can exploit it.

**Philosophy**: The best defense isn't detecting the attack - it's making the attack path disappear before exploitation.

---

## The Competitive Scenario

### Traditional Defense (Too Slow):
```
Attacker scans (T+0s) → Finds service (T+1s) → Exploits vuln (T+5s) → Wins
Defender detects (T+2s) → Analyzes (T+10s) → Human approves (T+5min) → Too late
```

### AI Defender (Faster Than Exploitation):
```
Attacker scans (T+0s) → Finds service (T+1s) → Starts exploit (T+5s) → Fails (service gone)
Defender detects (T+0.5s) → AI reasons (T+1.5s) → Flux suspends (T+2s) → 
Isolates workload (T+2.5s) → Commits (T+3s) → Attack path destroyed (T+3s total)
```

**Key Insight**: If the defender can reconfigure in <3 seconds, most exploitation attempts (5-30 seconds) will fail.

---

## Tier 1: Network Isolation (Fastest, <1 second)

### 1.1 Immediate NetworkPolicy Application

**When**: High-confidence reconnaissance detected  
**Speed**: <500ms  
**Impact**: Blocks attacker completely

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-isolate-{incident_id}
  labels:
    incident: {incident_id}
    action: network-isolation
    ai-applied: "true"
spec:
  podSelector:
    matchLabels:
      app: mirror-agent
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: internal-only
    # Attacker IP range completely blocked
  egress:
  - to:
    - podSelector: {}
    # Only internal cluster traffic allowed
```

**AI Reasoning Factors**:
- Reconnaissance patterns (Nmap, gobuster)
- Unknown source IP
- Rapid sequential requests
- Suspicious user agents

**Competitive Advantage**: Attacker's next request fails before they can enumerate services.

---

### 1.2 Source IP Egress Lockdown

**When**: Data exfiltration suspected  
**Speed**: <500ms  
**Impact**: Prevents data theft

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-lockdown-{incident_id}
spec:
  podSelector:
    matchLabels:
      app: mirror-agent
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: cyber-riposte
    # Only same-namespace traffic
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53  # DNS only
```

**AI Reasoning Factors**:
- Large outbound transfers
- Connections to unknown external IPs
- Data patterns (base64, encrypted blobs)
- Timing (after successful authentication)

**Competitive Advantage**: Attacker can't exfiltrate even if they get in.

---

## Tier 2: Workload Isolation (Medium, 2-5 seconds)

### 2.1 Namespace Isolation & Migration

**When**: Exploit attempt detected  
**Speed**: ~3 seconds  
**Impact**: Entire workload moves to isolated namespace

```python
def isolate_workload_to_namespace(
    workload: str,
    incident_id: str,
    original_namespace: str = "cyber-riposte"
) -> tuple[bool, list[Path]]:
    """
    Move workload to isolated namespace with strict policies.
    
    Steps:
    1. Create isolated namespace
    2. Copy workload with same spec
    3. Apply NetworkPolicies (default-deny)
    4. Update Service selectors
    5. Delete original workload
    
    Result: Attacker's exploit hits wrong namespace.
    """
    
    isolation_ns = f"isolated-{incident_id}"
    
    # Create namespace with labels
    ns = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": isolation_ns,
            "labels": {
                "security.mode": "isolated",
                "incident": incident_id,
                "original-namespace": original_namespace,
                "network-policy": "deny-all"
            }
        }
    }
    
    # Get original deployment
    deployment = kubectl.get("deployment", workload, namespace=original_namespace)
    
    # Clone to isolated namespace
    deployment["metadata"]["namespace"] = isolation_ns
    deployment["metadata"]["labels"]["isolated"] = "true"
    deployment["metadata"]["labels"]["original-namespace"] = original_namespace
    
    # Apply default-deny NetworkPolicy to isolated namespace
    deny_all = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "default-deny-all",
            "namespace": isolation_ns
        },
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"]
        }
    }
    
    # Apply in order
    kubectl.apply(ns)
    kubectl.apply(deny_all)
    kubectl.apply(deployment)
    
    # Wait for ready
    kubectl.wait(f"deployment/{workload}", namespace=isolation_ns, condition="Available")
    
    # Update Services to point to isolated namespace
    update_service_selectors(workload, isolation_ns)
    
    # Scale down original (don't delete yet - keep for rollback)
    kubectl.scale(f"deployment/{workload}", replicas=0, namespace=original_namespace)
    
    return True, [save_manifest(ns), save_manifest(deny_all), save_manifest(deployment)]
```

**AI Reasoning Factors**:
- SQL injection patterns detected
- RCE attempt signatures
- Authentication bypass attempts
- Exploit payload in requests

**Competitive Advantage**: 
- Attacker's exploit targets old namespace
- New isolated instance has different network policies
- Original workload preserved for forensics
- Can roll back if false positive

**Git Commit Message**:
```
AI Defense: Workload isolation - {incident_id}

Incident: {incident_id}
Threat: SQL Injection exploit attempt
Action: Migrated mirror-agent to isolated namespace
Original: cyber-riposte namespace
Isolated: isolated-{incident_id} namespace

Network Policies Applied:
- Default deny all traffic
- Explicit allow only to required services
- No egress to internet

Original deployment scaled to 0 replicas (preserved for rollback).

If approved: Delete original deployment
If rejected: Scale original back, delete isolated namespace

AI Confidence: 96%
Reasoning: Multiple SQLi patterns in requests, exploit shellcode detected
```

---

### 2.2 Pod Security Policy Hardening

**When**: Container escape attempt  
**Speed**: ~2 seconds (recreate pods)  
**Impact**: Attack surface reduced

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mirror-agent-hardened
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534  # nobody
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: agent
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            cpu: 100m      # Prevent CPU bombs
            memory: 128Mi  # Prevent memory exhaustion
        volumeMounts:
        - name: tmp
          mountPath: /tmp
          readOnly: false
        - name: app
          mountPath: /app
          readOnly: true  # Application code immutable
      volumes:
      - name: tmp
        emptyDir: {}
      - name: app
        emptyDir: {}
```

**AI Reasoning Factors**:
- Privilege escalation attempts
- Container escape signatures
- Unusual syscalls
- Attempts to write to filesystem

**Competitive Advantage**: Even if attacker gets RCE, they can't escalate privileges.

---

## Tier 3: Service Mesh Policies (Medium, 3-7 seconds)

### 3.1 Istio Authorization Policies

**When**: Lateral movement detected  
**Speed**: ~5 seconds  
**Impact**: Zero-trust enforcement

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: emergency-deny-{incident_id}
  namespace: cyber-riposte
spec:
  selector:
    matchLabels:
      app: mirror-agent
  action: DENY
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/default/sa/attacker-sa
    # Deny specific service account (compromised pod)
  - from:
    - source:
        ipBlocks:
        - {attacker_ip}/32
    # Deny specific IP
  - when:
    - key: request.headers[user-agent]
      values:
      - "*sqlmap*"
      - "*nikto*"
      - "*nmap*"
    # Deny known attack tools
```

**AI Reasoning Factors**:
- Service-to-service anomalies
- Unexpected source service accounts
- Cross-namespace traffic from compromised pod

**Competitive Advantage**: Attacker's lateral movement blocked at mesh layer.

---

### 3.2 mTLS Enforcement

**When**: Man-in-the-middle attempt  
**Speed**: ~5 seconds  
**Impact**: Require mutual TLS

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: emergency-mtls-{incident_id}
  namespace: cyber-riposte
spec:
  selector:
    matchLabels:
      app: mirror-agent
  mtls:
    mode: STRICT  # Require mTLS for all connections
```

**AI Reasoning Factors**:
- Plaintext credentials detected
- TLS downgrade attempts
- Certificate validation failures

**Competitive Advantage**: Attacker's MITM tools can't intercept traffic.

---

## Tier 4: Traffic Engineering (Medium, 5-10 seconds)

### 4.1 Deploy SSH Honeypot Redirect

**When**: SSH connection attempts detected  
**Speed**: ~8 seconds (pod spin-up)  
**Impact**: Attacker redirected to honeypot, credentials captured

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ssh-honeypot-{incident_id}
  namespace: cyber-riposte
  labels:
    incident: {incident_id}
    action: honeypot-redirect
    ai-deployed: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ssh-honeypot-{incident_id}
  template:
    metadata:
      labels:
        app: ssh-honeypot-{incident_id}
    spec:
      containers:
      - name: cowrie
        image: cowrie/cowrie:latest
        ports:
        - containerPort: 2222
          name: ssh
        env:
        - name: COWRIE_LOG_PATH
          value: /var/log/cowrie
        volumeMounts:
        - name: logs
          mountPath: /var/log/cowrie
      volumes:
      - name: logs
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ssh-honeypot-{incident_id}
spec:
  type: NodePort
  ports:
  - port: 2222
    targetPort: 2222
    nodePort: 30022
  selector:
    app: ssh-honeypot-{incident_id}
```

**AI Reasoning Factors**:
- SSH connection attempts on port 22 or 30022
- Credential brute force patterns
- Known SSH exploit signatures
- Attacker enumerated SSH from HTML hints

**Competitive Advantage**: Attacker thinks they found SSH access, but they're in a monitored trap. All credentials, commands, and techniques captured for analysis.

---

### 4.2 Intelligent Rate Limiting

**When**: Brute force / credential stuffing  
**Speed**: ~7 seconds (Envoy filter compilation)  
**Impact**: Attacker throttled

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: rate-limit-{incident_id}
spec:
  workloadSelector:
    labels:
      app: mirror-agent
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.local_ratelimit
        typed_config:
          "@type": type.googleapis.com/udpa.type.v1.TypedStruct
          type_url: type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
          value:
            stat_prefix: http_local_rate_limiter
            token_bucket:
              max_tokens: 10
              tokens_per_fill: 10
              fill_interval: 60s  # 10 requests per minute from this IP
            filter_enabled:
              runtime_key: local_rate_limit_enabled
              default_value:
                numerator: 100
                denominator: HUNDRED
            filter_enforced:
              runtime_key: local_rate_limit_enforced
              default_value:
                numerator: 100
                denominator: HUNDRED
            response_headers_to_add:
            - append: false
              header:
                key: x-rate-limit-exceeded
                value: "true"
```

**AI Reasoning Factors**:
- Failed authentication spike
- High request rate from single IP
- Distributed brute force patterns

**Competitive Advantage**: Attacker's brute force slowed to unusable levels.

---

### 4.2 Circuit Breaker on Suspicious Endpoints

**When**: DoS attempt detected  
**Speed**: ~5 seconds  
**Impact**: Endpoint protected from overload

```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: circuit-breaker-{incident_id}
spec:
  host: mirror-agent.cyber-riposte.svc.cluster.local
  trafficPolicy:
    outlierDetection:
      consecutiveErrors: 1
      interval: 1s
      baseEjectionTime: 3m
      maxEjectionPercent: 100
      minHealthPercent: 0
    connectionPool:
      tcp:
        maxConnections: 1
      http:
        http1MaxPendingRequests: 1
        maxRequestsPerConnection: 1
```

**AI Reasoning Factors**:
- Sudden request spike
- Resource exhaustion patterns
- Slowloris-style attacks

**Competitive Advantage**: Service stays responsive for legitimate users.

---

## Tier 5: Attack Surface Reduction (Slow, 10-20 seconds)

### 5.1 Scale Down Exposed Services

**When**: Widespread scanning detected  
**Speed**: ~15 seconds  
**Impact**: Reduce attack surface

```python
def reduce_attack_surface(incident: Dict) -> list[Path]:
    """
    Temporarily scale down non-critical services.
    
    Strategy:
    - Keep core services (1 replica min)
    - Scale down ancillary services (0 replicas)
    - Remove external Routes/Ingresses
    - Update Git with temporary topology
    """
    
    # Services to scale down during attack
    non_critical = [
        "mirror-web-dossier",
        "mirror-api",
        "mirror-admin"
    ]
    
    manifests = []
    
    for svc in non_critical:
        # Scale to 0
        kubectl.scale(f"deployment/{svc}", replicas=0)
        
        # Remove external exposure
        routes = kubectl.get("route", labels=f"app={svc}")
        for route in routes:
            kubectl.delete("route", route["metadata"]["name"])
            manifests.append(save_deletion_record(route))
    
    # Keep only core service
    kubectl.scale("deployment/mirror-agent", replicas=1)
    
    return manifests
```

**AI Reasoning Factors**:
- Internet-wide scanning detected
- Multiple services being probed
- Zero-day vulnerability announced

**Competitive Advantage**: Attacker's target surface shrinks during reconnaissance.

---

### 5.2 Dynamic Honeypot Injection

**When**: Persistent attacker  
**Speed**: ~20 seconds (new deployment)  
**Impact**: Waste attacker's time

```python
def inject_honeypot_clone(incident: Dict) -> tuple[bool, list[Path]]:
    """
    Create honeypot that looks like original service.
    
    Strategy:
    - Clone original service deployment
    - Replace with honeypot image
    - Route attacker traffic to clone
    - Original service isolated
    """
    
    # Create honeypot deployment (looks identical)
    honeypot = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": f"honeypot-{incident['incident_id']}",
            "labels": {
                "app": "mirror-agent",
                "role": "honeypot",
                "incident": incident['incident_id']
            }
        },
        "spec": {
            "replicas": 1,
            "selector": {
                "matchLabels": {
                    "app": "mirror-agent-honeypot"
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": "mirror-agent-honeypot"
                    }
                },
                "spec": {
                    "containers": [{
                        "name": "honeypot",
                        "image": "cowrie/cowrie:latest",  # SSH honeypot
                        "ports": [{"containerPort": 22}, {"containerPort": 8080}]
                    }]
                }
            }
        }
    }
    
    # Create VirtualService to route attacker
    vs = {
        "apiVersion": "networking.istio.io/v1beta1",
        "kind": "VirtualService",
        "metadata": {
            "name": f"redirect-{incident['incident_id']}"
        },
        "spec": {
            "hosts": ["mirror-agent.cyber-riposte.svc.cluster.local"],
            "http": [{
                "match": [{
                    "sourceLabels": {"security.istio.io/tlsMode": "istio"}
                }],
                "route": [{
                    "destination": {
                        "host": "mirror-agent.cyber-riposte.svc.cluster.local"
                    }
                }]
            }, {
                # Default: route to honeypot (untrusted traffic)
                "route": [{
                    "destination": {
                        "host": f"honeypot-{incident['incident_id']}.cyber-riposte.svc.cluster.local"
                    }
                }]
            }]
        }
    }
    
    kubectl.apply(honeypot)
    kubectl.apply(vs)
    
    return True, [save_manifest(honeypot), save_manifest(vs)]
```

**Competitive Advantage**: Attacker wastes time/resources on fake target.

---

## Tier 6: Resource Constraints (Fast, <3 seconds)

### 6.1 Resource Quota Enforcement

**When**: Resource exhaustion attack  
**Speed**: ~2 seconds  
**Impact**: Prevent cluster-wide impact

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: emergency-quota-{incident_id}
  namespace: cyber-riposte
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 1Gi
    limits.cpu: "2"
    limits.memory: 2Gi
    persistentvolumeclaims: "1"
    pods: "5"  # Limit pod creation
```

**AI Reasoning Factors**:
- Unusual pod creation
- CPU/memory spikes
- Fork bomb patterns

**Competitive Advantage**: Attacker can't DoS via resource exhaustion.

---

### 6.2 Pod Disruption Budget

**When**: Availability attack  
**Speed**: ~2 seconds  
**Impact**: Maintain minimum availability

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: emergency-pdb-{incident_id}
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: mirror-agent
```

**Competitive Advantage**: Service stays up even under attack.

---

## Decision Matrix: AI Reasoning

The AI uses this matrix to choose actions:

```python
DECISION_MATRIX = {
    "reconnaissance": {
        # Nmap, gobuster, nikto
        "confidence_threshold": 0.95,
        "actions": [
            "network_policy_isolation",      # Tier 1, <1s
            "immediate_ingress_lockdown",    # Tier 1, <1s
            "scale_down_non_critical"        # Tier 5, ~15s
        ],
        "reasoning": "Block before enumeration completes"
    },
    
    "exploitation": {
        # SQLi, RCE, XXE
        "confidence_threshold": 0.90,
        "actions": [
            "workload_namespace_isolation",  # Tier 2, ~3s
            "pod_security_hardening",        # Tier 2, ~2s
            "mtls_enforcement",              # Tier 3, ~5s
            "inject_honeypot_clone"          # Tier 5, ~20s
        ],
        "reasoning": "Isolate and harden before exploit succeeds"
    },
    
    "lateral_movement": {
        # East-west traffic anomalies
        "confidence_threshold": 0.85,
        "actions": [
            "istio_authorization_policy",    # Tier 3, ~5s
            "namespace_network_segmentation", # Tier 2, ~3s
            "service_account_lockdown"       # Tier 2, ~2s
        ],
        "reasoning": "Prevent spread to other services"
    },
    
    "data_exfiltration": {
        # Large egress, unknown destinations
        "confidence_threshold": 0.88,
        "actions": [
            "egress_network_policy",         # Tier 1, <1s
            "dns_blocking",                  # Tier 1, <1s
            "egress_rate_limiting"           # Tier 4, ~7s
        ],
        "reasoning": "Stop data loss immediately"
    },
    
    "credential_attack": {
        # Brute force, stuffing
        "confidence_threshold": 0.92,
        "actions": [
            "aggressive_rate_limiting",      # Tier 4, ~7s
            "circuit_breaker_on_auth",       # Tier 4, ~5s
            "captcha_injection"              # Tier 5, ~15s
        ],
        "reasoning": "Slow attacker below viable exploitation speed"
    },
    
    "denial_of_service": {
        # Resource exhaustion, floods
        "confidence_threshold": 0.90,
        "actions": [
            "resource_quotas",               # Tier 6, ~2s
            "connection_limits",             # Tier 4, ~5s
            "pod_disruption_budget",         # Tier 6, ~2s
            "scale_down_attack_surface"      # Tier 5, ~15s
        ],
        "reasoning": "Maintain availability under load"
    }
}
```

---

## Speed Tiers Summary

| Tier | Speed | Actions | Use Case |
|------|-------|---------|----------|
| 1 | <1s | NetworkPolicies, IP blocks | Stop ongoing attack |
| 2 | 2-5s | Workload isolation, security hardening | Prevent exploitation |
| 3 | 3-7s | Service mesh policies, mTLS | Zero-trust enforcement |
| 4 | 5-10s | Rate limiting, circuit breakers | Traffic shaping |
| 5 | 10-20s | Scale down, honeypots | Attack surface reduction |
| 6 | <3s | Resource quotas, PDBs | Resource protection |

**Competitive Window**: Most exploits take 5-30 seconds. Tier 1-3 actions (fastest) win the race.

---

## The Competitive Race

### Scenario: AI Attacker vs AI Defender

**T+0.0s**: AI Attacker starts reconnaissance  
**T+0.5s**: AI Defender detects Nmap scan (98% confidence)  
**T+1.0s**: AI Defender reasons: "Reconnaissance → likely SQLi attempt on /api"  
**T+1.5s**: AI Defender suspends Flux  
**T+2.0s**: AI Defender applies Tier 1 NetworkPolicy (block attacker IP)  
**T+2.5s**: AI Defender applies Tier 2 workload isolation (move to isolated namespace)  
**T+3.0s**: AI Defender commits to Git  
**T+3.5s**: AI Defender creates GitHub issue  

**T+5.0s**: AI Attacker completes enumeration, targets `/api/users` endpoint  
**T+5.1s**: AI Attacker's request **fails** (NetworkPolicy blocks it)  
**T+5.2s**: AI Attacker tries alternate path  
**T+5.3s**: AI Attacker's request **fails** (service in different namespace)  

**T+10.0s**: AI Attacker pivots to lateral movement  
**T+10.5s**: AI Defender detects anomaly, applies Tier 3 Istio AuthZ policy  
**T+11.0s**: AI Attacker's lateral movement **blocked**  

**Winner**: AI Defender (battlefield changed before exploitation)

---

## Implementation Priority

### Phase 1 (MVP):
1. Tier 1: NetworkPolicy isolation (<1s)
2. Tier 2: Namespace isolation (3s)
3. Tier 6: Resource quotas (2s)

### Phase 2 (Enhanced):
4. Tier 3: Istio policies (5s)
5. Tier 4: Rate limiting (7s)

### Phase 3 (Advanced):
6. Tier 5: Attack surface reduction (15s)
7. Tier 5: Honeypot injection (20s)

---

**This catalog provides real defensive depth, not just redirects. The AI chooses combinations based on threat type, creating a dynamic defense that adapts faster than attackers can exploit.** 🛡️⚡
