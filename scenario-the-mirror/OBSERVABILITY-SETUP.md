# Phase 7: Observability Setup Guide

This guide covers Prometheus metrics and Grafana dashboards for monitoring The Mirror in production.

---

## Why Observability?

**Phase 1-6** had limited visibility:
- ❌ No metrics (event rate, detection latency, action success)
- ❌ No dashboards (can't visualize trends)
- ❌ No alerting (don't know when agent is struggling)
- ❌ Hard to debug performance issues
- ❌ Can't measure cache hit rate, rate limit impact

**Phase 7 (Observability)** solves this:
- ✅ Prometheus metrics export (/metrics endpoint)
- ✅ ServiceMonitor for automatic scraping
- ✅ Grafana dashboard (events, incidents, actions, OSINT cache)
- ✅ Metrics for every component (detection, OSINT, DB, VirtualServices)
- ✅ Alerting-ready (can set alerts on metric thresholds)

---

## Quick Start

```bash
# 1. Install Prometheus Operator (if not already installed)
# OpenShift has this built-in with monitoring stack

# 2. Deploy ServiceMonitor
oc apply -f k8s/servicemonitor.yaml

# 3. Verify metrics endpoint
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')
oc exec $AGENT_POD -n cyber-riposte -- curl -s localhost:8080/metrics | head -20

# 4. Import Grafana dashboard
# OpenShift Console → Observe → Dashboards → Import
# Upload: dashboards/mirror-agent-grafana.json

# 5. View dashboard
# Grafana → Dashboards → "The Mirror Agent"
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Mirror Agent Pods (3 replicas)                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  /metrics endpoint (port 8080)                             │
│  ├─ mirror_events_total                                     │
│  ├─ mirror_detections_total                                 │
│  ├─ mirror_actions_total                                    │
│  ├─ mirror_osint_cache_hits_total                          │
│  ├─ mirror_virtualservices_active                          │
│  └─ ... 20+ metrics                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ (scrape every 30s)
                    ┌──────────────────┐
                    │  Prometheus      │
                    │  (via Service    │
                    │   Monitor)       │
                    └──────────────────┘
                              │
                              ▼ (query)
                    ┌──────────────────┐
                    │  Grafana         │
                    │  Dashboard       │
                    │                  │
                    │  - Event rate    │
                    │  - Incidents     │
                    │  - Cache hit %   │
                    │  - Latency       │
                    └──────────────────┘
```

---

## Metrics Exported

### Event Metrics

- `mirror_events_total` (counter) - Events processed
  - Labels: `event_type`, `source`
  
- `mirror_detections_total` (counter) - Detections
  - Labels: `detection_type`, `confidence_level`
  
- `mirror_detection_latency_seconds` (histogram) - Detection time
  - Labels: `detection_method`

### Action Metrics

- `mirror_actions_total` (counter) - Actions executed
  - Labels: `action_id`, `result`
  
- `mirror_action_latency_seconds` (histogram) - Action execution time
  - Labels: `action_id`

### OSINT Metrics

- `mirror_osint_cache_hits_total` (counter) - Cache hits
  - Labels: `module`
  
- `mirror_osint_cache_misses_total` (counter) - Cache misses
  - Labels: `module`
  
- `mirror_osint_rate_limited_total` (counter) - Rate limited calls
  - Labels: `module`
  
- `mirror_osint_api_latency_seconds` (histogram) - API call time
  - Labels: `module`

### VirtualService Metrics

- `mirror_virtualservices_created_total` (counter) - VS created
- `mirror_virtualservices_active` (gauge) - Currently active VS
- `mirror_virtualservices_expired_total` (counter) - VS expired

### LLM Metrics

- `mirror_llm_consultations_total` (counter) - LLM calls
  - Labels: `model`, `backend`
  
- `mirror_llm_latency_seconds` (histogram) - LLM API time
  - Labels: `model`
  
- `mirror_llm_confidence` (histogram) - LLM confidence scores
  - Labels: `model`

### Database Metrics

- `mirror_db_operations_total` (counter) - DB operations
  - Labels: `operation`, `result`
  
- `mirror_db_latency_seconds` (histogram) - Query time
  - Labels: `operation`

### Incident Metrics

- `mirror_incidents_created_total` (counter) - Incidents created
  - Labels: `severity`
  
- `mirror_incidents_active` (gauge) - Active incidents

### Health Metrics

- `mirror_agent_info` (info) - Agent version and config
- `mirror_kafka_consumer_lag` (gauge) - Kafka lag
  - Labels: `partition`

---

## Deployment

### 1. Verify Prometheus Client Installed

```bash
# Check if prometheus-client is in requirements.txt
grep prometheus-client ~/REPOS/cyber-riposte/scenario-the-mirror/requirements.txt

# If not, add it
echo "prometheus-client>=0.19.0" >> requirements.txt
```

### 2. Deploy ServiceMonitor

```bash
# Deploy ServiceMonitor
oc apply -f k8s/servicemonitor.yaml

# Verify ServiceMonitor created
oc get servicemonitor mirror-agent -n cyber-riposte

# Verify service exists
oc get svc mirror-agent-metrics -n cyber-riposte
```

### 3. Test Metrics Endpoint

```bash
# Port-forward to agent
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')
oc port-forward $AGENT_POD 8080:8080 -n cyber-riposte &

# Curl metrics endpoint
curl -s http://localhost:8080/metrics | head -50

# Should see Prometheus format:
# # HELP mirror_events_total Total events processed from Kafka
# # TYPE mirror_events_total counter
# mirror_events_total{event_type="alert",source="kafka"} 42.0
```

### 4. Verify Prometheus Scraping

```bash
# Check Prometheus targets (OpenShift console)
# Observe → Metrics → Targets
# Should see: cyber-riposte/mirror-agent/0 (UP)

# Or via API
oc port-forward -n openshift-monitoring prometheus-k8s-0 9090:9090 &
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job=="mirror-agent")'
```

### 5. Import Grafana Dashboard

```bash
# OpenShift Console method:
# 1. Navigate to: Observe → Dashboards
# 2. Click "Import"
# 3. Upload: dashboards/mirror-agent-grafana.json
# 4. Dashboard appears as "The Mirror Agent"

# Or via ConfigMap (auto-loaded):
oc create configmap grafana-dashboard-mirror \
  --from-file=mirror-agent.json=dashboards/mirror-agent-grafana.json \
  -n openshift-monitoring

# Label for auto-discovery
oc label configmap grafana-dashboard-mirror \
  grafana_dashboard=1 \
  -n openshift-monitoring
```

---

## Grafana Dashboard

The dashboard includes 4 panels:

### 1. Event Rate (Time Series)
- Metric: `rate(mirror_events_total[5m])`
- Shows events/second by type
- Useful for: Detecting traffic spikes, event source health

### 2. Active Incidents (Gauge)
- Metric: `mirror_incidents_active`
- Current number of active incidents
- Thresholds: green (<10), yellow (10-50), red (>50)

### 3. Actions by Type (Pie Chart)
- Metric: `sum by (action_id) (mirror_actions_total)`
- Distribution of actions executed
- Useful for: Understanding agent behavior

### 4. OSINT Cache Hit Rate (Table)
- Metric: `100 * hits / (hits + misses)` per module
- Cache efficiency by OSINT module
- Useful for: Tuning cache TTL

---

## Query Examples

### Event Rate

```promql
# Events per second (5-minute average)
rate(mirror_events_total[5m])

# Events per second by type
rate(mirror_events_total{event_type="alert"}[5m])
```

### Detection Rate

```promql
# Detections per minute
rate(mirror_detections_total[1m]) * 60

# High-confidence detections
rate(mirror_detections_total{confidence_level="high"}[5m])
```

### Action Success Rate

```promql
# Success rate by action
sum by (action_id) (rate(mirror_actions_total{result="success"}[5m]))
/ sum by (action_id) (rate(mirror_actions_total[5m]))

# Failed actions
sum(rate(mirror_actions_total{result="failed"}[5m]))
```

### OSINT Cache Performance

```promql
# Cache hit rate (overall)
100 * sum(mirror_osint_cache_hits_total)
/ (sum(mirror_osint_cache_hits_total) + sum(mirror_osint_cache_misses_total))

# Cache hit rate by module
100 * sum by (module) (mirror_osint_cache_hits_total)
/ (sum by (module) (mirror_osint_cache_hits_total) + sum by (module) (mirror_osint_cache_misses_total))

# Rate limited calls
sum by (module) (rate(mirror_osint_rate_limited_total[5m]))
```

### Latency Percentiles

```promql
# 95th percentile detection latency
histogram_quantile(0.95, rate(mirror_detection_latency_seconds_bucket[5m]))

# 99th percentile OSINT API latency by module
histogram_quantile(0.99, sum by (module, le) (rate(mirror_osint_api_latency_seconds_bucket[5m])))
```

### VirtualService Metrics

```promql
# Active VirtualServices
mirror_virtualservices_active

# VirtualService creation rate
rate(mirror_virtualservices_created_total[5m])

# VirtualService expiration rate
rate(mirror_virtualservices_expired_total[5m])
```

### Kafka Consumer Lag

```promql
# Lag by partition
mirror_kafka_consumer_lag

# Total lag across all partitions
sum(mirror_kafka_consumer_lag)
```

---

## Alerting

### Recommended Alerts

#### High Consumer Lag

```yaml
alert: MirrorKafkaConsumerLagHigh
expr: sum(mirror_kafka_consumer_lag) > 1000
for: 5m
labels:
  severity: warning
annotations:
  summary: "Mirror agent falling behind on Kafka"
  description: "Consumer lag is {{ $value }}, agent may be overloaded"
```

#### Low Cache Hit Rate

```yaml
alert: MirrorOSINTCacheHitRateLow
expr: |
  100 * sum(mirror_osint_cache_hits_total)
  / (sum(mirror_osint_cache_hits_total) + sum(mirror_osint_cache_misses_total))
  < 30
for: 10m
labels:
  severity: info
annotations:
  summary: "OSINT cache hit rate low"
  description: "Hit rate is {{ $value }}%, consider increasing TTL"
```

#### High Rate Limiting

```yaml
alert: MirrorOSINTRateLimitedHigh
expr: rate(mirror_osint_rate_limited_total[5m]) > 0.1
for: 5m
labels:
  severity: warning
annotations:
  summary: "OSINT modules being rate limited"
  description: "Rate: {{ $value }} calls/sec, increase limits or cache TTL"
```

#### Agent Down

```yaml
alert: MirrorAgentDown
expr: up{job="mirror-agent"} == 0
for: 2m
labels:
  severity: critical
annotations:
  summary: "Mirror agent is down"
  description: "Agent pod not responding to metrics scrape"
```

---

## Troubleshooting

### Metrics Not Appearing

```bash
# Check prometheus-client installed
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "import prometheus_client; print('OK')"

# Check /metrics endpoint responding
oc exec $AGENT_POD -n cyber-riposte -- curl -s localhost:8080/metrics

# Check agent logs for errors
oc logs $AGENT_POD -n cyber-riposte | grep -i metric
```

### Prometheus Not Scraping

```bash
# Check ServiceMonitor exists
oc get servicemonitor mirror-agent -n cyber-riposte

# Check service selector matches pods
oc get svc mirror-agent-metrics -n cyber-riposte -o yaml | grep -A5 selector

# Check Prometheus targets
oc port-forward -n openshift-monitoring prometheus-k8s-0 9090:9090 &
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job=="mirror-agent")'
```

### Dashboard Not Loading

```bash
# Check dashboard JSON is valid
cat dashboards/mirror-agent-grafana.json | jq '.'

# Check Prometheus data source configured
# Grafana → Configuration → Data Sources → Prometheus

# Check queries have data
# Grafana → Explore → Run: mirror_events_total
```

---

## Next Steps

After Phase 7 is working:

- **Phase 8**: GitHub integration (include metrics in incident issues)
- **Phase 9**: Hot-reload (reload config without losing metrics)
- **Phase 10**: Testing (unit tests for metrics recording)

---

## Summary

**Phase 7 Complete** when:

✅ Prometheus client installed  
✅ /metrics endpoint responding  
✅ ServiceMonitor deployed  
✅ Prometheus scraping successfully  
✅ Metrics appearing in Prometheus  
✅ Grafana dashboard imported  
✅ Dashboard panels showing data  
✅ Alerts configured (optional)

The Mirror now has **full observability** with metrics and dashboards! 📊
