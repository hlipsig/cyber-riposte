# Grafana Dashboards for The Mirror

Pre-built dashboards for monitoring The Mirror autonomous security system.

## Dashboards

### 1. Incident Overview (`mirror-incidents.json`)
- **Incidents Detected (24h)**: Total incidents count
- **Actions Executed (24h)**: Autonomous actions taken
- **OSINT Lookups (24h)**: Intelligence gathering operations
- **Detection Confidence (Avg)**: Average confidence score
- **Incidents Over Time**: Time series of incident rate
- **Actions by Type**: Pie chart of action distribution
- **Top Attacker IPs**: Table of most active attackers
- **Attack Types**: Bar chart of detection signatures

**Metrics Used**:
- `mirror_incidents_total`
- `mirror_actions_total`
- `mirror_osint_lookups_total`
- `mirror_detection_confidence`

### 2. OSINT Intelligence (`mirror-osint.json`)
- **OSINT Modules Success Rate**: Percentage of successful lookups
- **OSINT Cache Hit Rate**: Efficiency of caching layer
- **Attacker Countries**: World map of geographic distribution
- **OSINT Module Performance**: Average lookup duration
- **Top ASNs**: Most common autonomous systems

**Metrics Used**:
- `mirror_osint_success_total`
- `mirror_osint_cache_hits_total`
- `mirror_osint_duration_seconds`
- `mirror_attackers_by_country`
- `mirror_attackers_by_asn`

## Installation

### Import Dashboards

**Via Grafana UI:**
1. Navigate to Dashboards → Import
2. Upload JSON file or paste content
3. Select Prometheus data source
4. Click Import

**Via API:**
```bash
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GRAFANA_API_KEY" \
  -d @dashboards/mirror-incidents.json
```

**Via ConfigMap (Kubernetes):**
```bash
oc create configmap grafana-dashboards \
  --from-file=dashboards/ \
  -n the-mirror

# Add to Grafana deployment:
volumeMounts:
- name: dashboards
  mountPath: /etc/grafana/provisioning/dashboards

volumes:
- name: dashboards
  configMap:
    name: grafana-dashboards
```

### Configure Data Source

Add Prometheus data source in Grafana:

```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
```

## Metrics Reference

The Mirror exposes metrics on port 8080 at `/metrics`:

```
# Incidents
mirror_incidents_total{attacker_ip, signature, severity}
mirror_detection_confidence{incident_id}

# Actions
mirror_actions_total{action, tier, result}

# OSINT
mirror_osint_lookups_total{module}
mirror_osint_success_total{module}
mirror_osint_cache_hits_total
mirror_osint_duration_seconds{module}

# Geographic
mirror_attackers_by_country{country}
mirror_attackers_by_asn{asn}
```

## Dashboard Screenshots

### Incident Overview
Shows real-time security posture:
- Current attack volume
- Autonomous response effectiveness
- Detection confidence levels
- Attack patterns and trends

### OSINT Intelligence
Shows threat intelligence gathering:
- OSINT module health and performance
- Geographic attack origins
- Infrastructure patterns (ASNs, hosting providers)
- Cache efficiency

## Customization

Edit JSON files to:
- Adjust time ranges (default: 24h for incidents, 6h for OSINT)
- Change refresh rates (default: 30s for incidents, 1m for OSINT)
- Add custom panels
- Modify thresholds and colors
- Add alerting rules

## Alerts

Create alerts in Grafana based on metrics:

**High Incident Rate:**
```promql
rate(mirror_incidents_total[5m]) > 0.1
```

**Low Detection Confidence:**
```promql
avg(mirror_detection_confidence) < 0.7
```

**OSINT Module Failures:**
```promql
rate(mirror_osint_success_total[5m]) / rate(mirror_osint_lookups_total[5m]) < 0.5
```

## Troubleshooting

**Dashboards showing "No Data":**
1. Verify Prometheus is scraping Mirror metrics: `curl http://mirror-agent:8080/metrics`
2. Check Prometheus targets: Prometheus UI → Status → Targets
3. Verify data source configuration in Grafana

**Metrics not appearing:**
1. Ensure Mirror agent has processed incidents (metrics only appear after activity)
2. Check Prometheus scrape interval (should be 15-30s)
3. Verify label selectors match your deployment

**World map not working:**
1. Install Grafana World Map panel plugin
2. Or replace with pie chart: `sum by (country) (mirror_attackers_by_country)`
