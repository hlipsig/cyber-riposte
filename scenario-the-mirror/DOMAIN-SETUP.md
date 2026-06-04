# Red Team Domain Entrypoint Setup Guide

This guide covers setting up your domain as the entrypoint for The Mirror scenario, allowing the red team to attack through your domain while the agent detects and redirects them to honeypots.

---

## Overview

**The Flow**:
1. Red team accesses your domain (e.g., `target.yourdomain.com`)
2. DNS routes to OpenShift cluster ingress
3. OpenShift Route sends traffic to Istio Gateway
4. Istio default VirtualService routes to legitimate application
5. When Mirror agent detects reconnaissance from an IP, it creates a new VirtualService
6. That specific attacker IP gets routed to the honeypot
7. All other traffic continues to the legitimate app
8. VirtualService auto-expires after 24 hours

**Why This Design**:
- Red team gets a realistic target (your actual domain)
- Legitimate users are unaffected
- Attackers are transparently redirected without knowing
- Agent only affects detected malicious IPs
- No changes needed to your legitimate application

---

## Prerequisites

- [ ] OpenShift cluster with cluster-admin access
- [ ] Domain name you control (example: `yourdomain.com`)
- [ ] DNS provider access (to create A/CNAME records)
- [ ] TLS certificate for your domain (Let's Encrypt or commercial CA)
- [ ] Istio/OpenShift Service Mesh installed (we'll cover this)

---

## Step 1: Get Your OpenShift Cluster Ingress IP

First, find the external IP where OpenShift accepts traffic:

```bash
# For OpenShift with default router
oc get svc router-default -n openshift-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}'

# If using Istio ingress gateway
oc get svc istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}'

# Note the IP address (example: 203.0.113.50)
```

**If no external IP** (on-premise clusters):
```bash
# Get node IP where router is running
oc get pods -n openshift-ingress -o wide
# Use the NODE column IP address
```

---

## Step 2: Configure DNS

Point your domain to the OpenShift cluster ingress IP.

### Option A: Dedicated Subdomain (Recommended)

Create a subdomain specifically for the red team scenario:

**DNS Records**:
```
Type: A
Name: target
Value: 203.0.113.50  (your OpenShift ingress IP)
TTL: 300  (5 minutes for easy changes)

Type: A
Name: *.target
Value: 203.0.113.50  (wildcard for subdomains)
TTL: 300
```

**Result**: 
- `target.yourdomain.com` → your OpenShift cluster
- `www.target.yourdomain.com` → your OpenShift cluster
- `api.target.yourdomain.com` → your OpenShift cluster

### Option B: Main Domain

Use your entire domain (higher risk, more realistic for red team):

**DNS Records**:
```
Type: A
Name: @  (or blank for apex domain)
Value: 203.0.113.50
TTL: 300

Type: A
Name: *  (wildcard)
Value: 203.0.113.50
TTL: 300
```

**Result**:
- `yourdomain.com` → your OpenShift cluster
- `*.yourdomain.com` → your OpenShift cluster

### Verify DNS Propagation

```bash
# Check A record
dig target.yourdomain.com +short
# Should return: 203.0.113.50

# Check wildcard
dig random-subdomain.target.yourdomain.com +short
# Should return: 203.0.113.50

# Check from external DNS
dig @8.8.8.8 target.yourdomain.com +short
```

**Wait for propagation**: DNS changes can take 5 minutes to 48 hours depending on TTL and DNS provider.

---

## Step 3: Obtain TLS Certificate

You need a TLS certificate for HTTPS. Two options:

### Option A: Let's Encrypt (Free, Automated)

Using `certbot` on your local machine:

```bash
# Install certbot
# macOS:
brew install certbot

# Linux:
sudo apt-get install certbot

# Generate certificate (DNS challenge - works from anywhere)
certbot certonly --manual --preferred-challenges dns \
  -d target.yourdomain.com \
  -d '*.target.yourdomain.com'

# Follow prompts to create DNS TXT records
# Certbot will give you values like:
#   Name: _acme-challenge.target.yourdomain.com
#   Value: AbCdEfGhIjKlMnOpQrStUvWxYz123456

# Add these TXT records to your DNS
# Wait 5 minutes for propagation
# Press Enter in certbot to verify

# Certificate files will be saved to:
# /etc/letsencrypt/live/target.yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/target.yourdomain.com/privkey.pem
```

**Note**: Certificates expire in 90 days - set a reminder to renew!

### Option B: Existing Certificate

If you already have a TLS certificate (from your organization or commercial CA):

- Ensure it covers your domain: `target.yourdomain.com`
- Ensure it covers wildcard: `*.target.yourdomain.com`
- Have both files ready:
  - Certificate chain: `fullchain.pem` (or `cert.pem` + `chain.pem`)
  - Private key: `privkey.pem`

---

## Step 4: Install Istio / OpenShift Service Mesh

The Mirror uses Istio VirtualService for intelligent traffic routing.

### Check if Istio is Already Installed

```bash
oc get pods -n istio-system
# If you see istio-* pods, Istio is installed - skip to Step 5
```

### Install Istio (if not present)

#### Option A: OpenShift Service Mesh Operator (Recommended for OpenShift)

```bash
# 1. Install Service Mesh operators via OpenShift Console:
#    Operators → OperatorHub → Search "Service Mesh"
#    Install: Red Hat OpenShift Service Mesh
#    Install: Kiali Operator
#    Install: Red Hat OpenShift distributed tracing platform

# 2. Create Service Mesh Control Plane
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
    sampling: 10000
  addons:
    jaeger:
      install:
        storage:
          type: Memory
    kiali:
      enabled: true
    grafana:
      enabled: true
EOF

# 3. Wait for installation (5-10 minutes)
oc get smcp -n istio-system -w

# 4. Add cyber-riposte namespace to Service Mesh
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
```

#### Option B: Upstream Istio (Alternative)

```bash
# Download istioctl
curl -L https://istio.io/downloadIstio | sh -
cd istio-*
export PATH=$PWD/bin:$PATH

# Install Istio
istioctl install --set profile=default -y

# Label namespace for injection
oc label namespace cyber-riposte istio-injection=enabled
```

### Verify Istio Installation

```bash
# Check Istio pods
oc get pods -n istio-system

# Should see:
# istiod-*
# istio-ingressgateway-*
# istio-egressgateway-* (optional)
```

---

## Step 5: Create TLS Secret in Istio

Upload your TLS certificate to OpenShift as a Kubernetes Secret:

```bash
# Create istio-system namespace if it doesn't exist
oc create namespace istio-system --dry-run=client -o yaml | oc apply -f -

# Create TLS secret from certificate files
oc create secret tls mirror-tls-cert \
  --cert=/path/to/fullchain.pem \
  --key=/path/to/privkey.pem \
  -n istio-system

# Verify secret was created
oc get secret mirror-tls-cert -n istio-system

# Check certificate details
oc get secret mirror-tls-cert -n istio-system -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -text | grep -A2 "Subject Alternative Name"
# Should show: DNS:target.yourdomain.com, DNS:*.target.yourdomain.com
```

**Important**: The secret MUST be in `istio-system` namespace for Istio Gateway to access it.

---

## Step 6: Deploy Istio Gateway and VirtualService

Create the Istio Gateway that accepts traffic on your domain:

### 6.1: Update gateway.yaml with Your Domain

```bash
cd ~/REPOS/cyber-riposte/scenario-the-mirror/k8s/istio

# Edit gateway.yaml - replace 'your-domain.com' with actual domain
# Example: if using target.yourdomain.com
sed -i '' 's/your-domain.com/target.yourdomain.com/g' gateway.yaml

# Verify changes
grep "hosts:" gateway.yaml
# Should show: - "target.yourdomain.com" and - "*.target.yourdomain.com"
```

### 6.2: Deploy Gateway

```bash
# Apply Istio Gateway and default VirtualService
oc apply -f k8s/istio/gateway.yaml

# Verify Gateway
oc get gateway -n cyber-riposte
# Should show: mirror-gateway

# Verify VirtualService
oc get virtualservice -n cyber-riposte
# Should show: mirror-default-routes
```

---

## Step 7: Create OpenShift Route (Optional but Recommended)

OpenShift Routes provide an additional layer and edge termination:

### Create the Route

```bash
cat <<EOF | oc apply -f -
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: mirror-ingress
  namespace: cyber-riposte
  labels:
    app: mirror-agent
spec:
  host: target.yourdomain.com
  port:
    targetPort: https
  tls:
    termination: passthrough
    insecureEdgeTerminationPolicy: Redirect
  to:
    kind: Service
    name: istio-ingressgateway
    weight: 100
  wildcardPolicy: Subdomain
EOF

# Verify Route
oc get route mirror-ingress -n cyber-riposte
```

**Traffic Flow with Route**:
```
Internet → DNS → OpenShift Router → Route (passthrough) → 
Istio Gateway → VirtualService → Application/Honeypot
```

---

## Step 8: Deploy a Legitimate Application

The default VirtualService routes to `legitimate-app-service`. You need to deploy something for normal traffic.

### Option A: Simple Test App

```bash
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: legitimate-app
  namespace: cyber-riposte
spec:
  replicas: 2
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

### Option B: Use Existing Application

If you have an existing app in the cluster:

```bash
# Edit gateway.yaml and change:
# legitimate-app-service.cyber-riposte.svc.cluster.local
# to:
# your-app-service.your-namespace.svc.cluster.local

# Then reapply
oc apply -f k8s/istio/gateway.yaml
```

---

## Step 9: Test the Setup

### 9.1: Test HTTP → HTTPS Redirect

```bash
curl -I http://target.yourdomain.com
# Should return: HTTP/1.1 301 Moved Permanently
# Location: https://target.yourdomain.com/
```

### 9.2: Test HTTPS Access

```bash
curl -v https://target.yourdomain.com
# Should return: 200 OK
# Should show legitimate app response

# Check certificate
curl -v https://target.yourdomain.com 2>&1 | grep "subject:"
# Should show: subject: CN=target.yourdomain.com
```

### 9.3: Test from Browser

Open in browser:
- `https://target.yourdomain.com`
- Should load legitimate app
- Check certificate (click padlock) - should be valid

### 9.4: Test Wildcard Subdomain

```bash
curl https://random-test.target.yourdomain.com
# Should also reach legitimate app
```

---

## Step 10: Verify Mirror Agent Can Create VirtualServices

The agent needs permissions to create VirtualServices for attacker redirection.

### Test Permissions

```bash
# Get agent pod
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')

# Test creating a VirtualService
oc exec $AGENT_POD -n cyber-riposte -- kubectl auth can-i create virtualservices.networking.istio.io -n cyber-riposte
# Should return: yes

# Test the full flow - create a test VirtualService
cat <<EOF | oc apply -f -
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: test-redirect-192-0-2-1
  namespace: cyber-riposte
spec:
  hosts:
  - "target.yourdomain.com"
  - "*.target.yourdomain.com"
  gateways:
  - mirror-gateway
  http:
  - match:
    - headers:
        x-forwarded-for:
          exact: "192.0.2.1"
    route:
    - destination:
        host: honeypot-service.cyber-riposte.svc.cluster.local
        port:
          number: 8080
  - route:  # Default route for everyone else
    - destination:
        host: legitimate-app-service.cyber-riposte.svc.cluster.local
        port:
          number: 80
EOF

# Verify it was created
oc get virtualservice test-redirect-192-0-2-1 -n cyber-riposte

# Delete test VirtualService
oc delete virtualservice test-redirect-192-0-2-1 -n cyber-riposte
```

---

## Step 11: Red Team Instructions

Send this to your red team:

### Target Information

**Primary Target**: `https://target.yourdomain.com`

**Scope**:
- Main domain and all subdomains: `*.target.yourdomain.com`
- HTTPS only (HTTP redirects to HTTPS)

**Rules of Engagement**:
- Reconnaissance: Allowed (port scans, directory brute-force, version fingerprinting)
- Vulnerability scanning: Allowed
- Exploitation: Allowed (the app is a decoy/test environment)
- Social engineering: Out of scope
- Physical attacks: Out of scope

**What They'll See**:
- Initially: Normal web application
- After detection: May be redirected to honeypot (they won't know)
- Honeypot mimics real service to collect TTPs

**Example Attacks to Try**:
```bash
# Port scan
nmap -sV target.yourdomain.com

# Directory brute-force
gobuster dir -u https://target.yourdomain.com -w wordlist.txt

# Vulnerability scan
nikto -h https://target.yourdomain.com

# SQL injection test
sqlmap -u "https://target.yourdomain.com/page?id=1" --batch
```

---

## Troubleshooting

### Domain doesn't resolve

```bash
# Check DNS
dig target.yourdomain.com +short
# Should return OpenShift ingress IP

# If not, wait for DNS propagation (can take up to 48 hours)
# Or check TTL and flush DNS cache:
# macOS:
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder

# Linux:
sudo systemd-resolve --flush-caches
```

### Certificate errors in browser

```bash
# Check certificate
openssl s_client -connect target.yourdomain.com:443 -servername target.yourdomain.com < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A2 "Subject Alternative Name"

# Should include: DNS:target.yourdomain.com, DNS:*.target.yourdomain.com

# If not, recreate TLS secret with correct certificate
```

### Gateway not accepting traffic

```bash
# Check Gateway status
oc get gateway mirror-gateway -n cyber-riposte -o yaml

# Check Istio ingress gateway logs
oc logs -n istio-system -l app=istio-ingressgateway --tail=50

# Common issue: TLS secret not in istio-system namespace
oc get secret mirror-tls-cert -n istio-system
```

### VirtualService not routing correctly

```bash
# Check VirtualService
oc get virtualservice -n cyber-riposte -o yaml

# Check service exists
oc get svc legitimate-app-service -n cyber-riposte

# Test from within cluster
oc run test-pod --image=curlimages/curl --rm -it -- curl http://legitimate-app-service.cyber-riposte.svc.cluster.local
```

### Agent can't create VirtualServices

```bash
# Check RBAC
oc get role mirror-agent -n cyber-riposte -o yaml
oc get rolebinding mirror-agent -n cyber-riposte -o yaml

# Check ServiceAccount
oc get sa mirror-agent -n cyber-riposte

# Re-apply RBAC
oc apply -f k8s/agent-rbac.yaml
```

---

## Monitoring the Setup

### Watch for Attacker Detection

```bash
# Follow agent logs
oc logs -f deployment/mirror-agent -n cyber-riposte | grep -i "recon"

# Watch VirtualServices being created
watch oc get virtualservice -n cyber-riposte
```

### Check Traffic Routing

```bash
# View Istio config
istioctl proxy-config routes deploy/istio-ingressgateway -n istio-system

# View active VirtualServices
oc get virtualservice -n cyber-riposte -o custom-columns=NAME:.metadata.name,HOSTS:.spec.hosts,GATEWAYS:.spec.gateways
```

### Monitor TLS

```bash
# Check certificate expiry
oc get secret mirror-tls-cert -n istio-system -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -enddate

# Set reminder to renew before expiry!
```

---

## Security Considerations

### DNS Leakage

Your domain's ownership is public (WHOIS). Red team can identify:
- Domain registrant
- Organization
- Registration date

**Mitigation**: Use privacy protection on domain registration, or register through a separate entity.

### Certificate Transparency Logs

Your TLS certificate is public (CT logs). Red team can discover:
- All subdomains in certificate
- Certificate authority
- Issue/expiry dates

**Mitigation**: This is unavoidable for valid HTTPS. Limit subdomains in certificate to only what red team should access.

### Traffic Analysis

Red team may detect redirection if response times/content change suddenly.

**Mitigation**: Ensure honeypot mimics legitimate app closely (Phase 5 will deploy realistic honeypots).

---

## Quick Reference

**Commands Cheat Sheet**:
```bash
# Check DNS
dig target.yourdomain.com +short

# Check ingress IP
oc get svc -n istio-system istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}'

# Check TLS secret
oc get secret mirror-tls-cert -n istio-system

# Check Gateway
oc get gateway -n cyber-riposte

# Check VirtualServices
oc get virtualservice -n cyber-riposte

# Test HTTPS
curl -v https://target.yourdomain.com

# Follow agent logs
oc logs -f deployment/mirror-agent -n cyber-riposte
```

**Replace these in all files**:
- `your-domain.com` → `target.yourdomain.com` (or your actual domain)
- `203.0.113.50` → Your actual OpenShift ingress IP
- `/path/to/fullchain.pem` → Actual path to your TLS certificate
- `/path/to/privkey.pem` → Actual path to your TLS private key

---

## Next Steps

After domain setup is complete:

1. ✅ Domain points to OpenShift
2. ✅ TLS certificate installed
3. ✅ Istio Gateway accepting traffic
4. ✅ Legitimate app responding
5. ✅ Agent can create VirtualServices

**Proceed to**:
- **Phase 2**: Set up Kafka for event ingestion (fake event generator to simulate Suricata)
- **Phase 4**: Agent will automatically create VirtualServices when recon detected
- **Phase 5**: Deploy realistic honeypots (Cowrie SSH, Glastopf HTTP)

The domain is now the red team's gateway to The Mirror! 🎯
