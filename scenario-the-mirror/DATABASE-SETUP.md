# Phase 3: PostgreSQL Database Setup Guide

This guide covers setting up PostgreSQL for persistent audit log storage, replacing file-based logging with queryable database.

---

## Why PostgreSQL?

**Phase 1-2 (file-based)** had limitations:
- ❌ No queries - can't search by IP, time range, action type
- ❌ No aggregation - can't get incident counts, average confidence
- ❌ No relational data - OSINT results disconnected from incidents
- ❌ File rotation issues - logs split across multiple files
- ❌ No concurrent access - multiple agents writing to same file

**Phase 3 (PostgreSQL)** solves these:
- ✅ SQL queries for incident investigation
- ✅ Aggregation views (recent_incidents, action_stats, llm_stats)
- ✅ Relational integrity (incidents → audit_log → evidence)
- ✅ Connection pooling for multiple agent replicas
- ✅ JSONB columns for flexible schema (parameters, context, OSINT data)

---

## Quick Start

### Option 1: Development (Simple PostgreSQL)

```bash
# 1. Deploy PostgreSQL
oc apply -f k8s/postgres-deployment.yaml

# 2. Wait for PostgreSQL to be ready
oc wait --for=condition=ready pod -l app=postgres -n cyber-riposte --timeout=300s

# 3. Initialize schema
oc apply -f k8s/postgres-init-job.yaml

# 4. Verify schema created
oc exec -it postgres-0 -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c "\dt"

# 5. Create agent secret with DATABASE_URL
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: mirror-agent-secrets
  namespace: cyber-riposte
type: Opaque
stringData:
  DATABASE_URL: "postgresql://mirror_agent:changeme@postgres:5432/mirror_audit"
EOF

# 6. Deploy/update agent with database connection
oc apply -f k8s/agent-deployment-kafka.yaml
```

### Option 2: Production (CrunchyData Postgres Operator)

See "Production Deployment" section below.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Mirror Agent Replicas (3 pods)                             │
├─────────────────────────────────────────────────────────────┤
│ - Event processing                                          │
│ - Detection logic                                           │
│ - Action execution                                          │
│ - Audit logging                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ (connection pool)
                    ┌──────────────────┐
                    │  PostgreSQL      │
                    │  StatefulSet     │
                    │                  │
                    │  Database:       │
                    │  mirror_audit    │
                    │                  │
                    │  PVC: 50GB       │
                    └──────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│ audit_log   │       │ incidents   │       │ evidence    │
│ (all        │       │ (incident   │       │ (OSINT,     │
│ actions)    │       │ summary)    │       │ PCAP)       │
└─────────────┘       └─────────────┘       └─────────────┘
```

**Key Points**:
- **Connection pooling**: 2-10 connections per agent pod (configurable)
- **Dual persistence**: Writes to BOTH database + stdout (OpenShift logs)
- **File fallback**: Audit still writes to file if database unavailable
- **JSONB columns**: Flexible schema for parameters, context, OSINT results

---

## Database Schema

### Tables

#### audit_log (main audit trail)
Every action the agent takes is recorded here.

**Key columns**:
- `id` (UUID): Unique audit entry ID
- `incident_id` (VARCHAR): Links to incidents table
- `timestamp` (TIMESTAMPTZ): When action occurred
- `action_id`, `action_name`, `action_tier`, `action_result`
- `parameters` (JSONB): Action parameters (IP, duration, etc.)
- `detection_confidence`, `detection_method` (rule_based, llm, hybrid)
- `llm_consulted`, `llm_model`, `llm_reasoning`: LLM usage tracking
- `context` (JSONB): Event context (HTTP headers, IDS alert, etc.)

**Indexes**:
- `incident_id`, `timestamp`, `action_id`, `action_result`
- GIN indexes on JSONB columns for fast searches

#### incidents (incident summary)
One row per detected incident. Denormalized for fast queries.

**Key columns**:
- `incident_id` (VARCHAR): Primary key (format: INC-YYYY-MMDD-HHMM)
- `attacker_ip` (INET): PostgreSQL native IP type
- `detection_signature`, `detection_confidence`, `detection_signals` (JSONB)
- `attacker_info` (JSONB): OSINT dossier (WHOIS, Shodan, CT)
- `actions_count`: Number of actions taken
- `status`: active, resolved, false_positive
- `severity`: 1=high, 2=medium, 3=low
- `postmortem_generated`, `github_issue_url`: Phase 8 integration

**Indexes**:
- `attacker_ip`, `first_seen`, `status`, `severity`

#### evidence
OSINT data, PCAP files, honeypot logs linked to incidents.

**Key columns**:
- `incident_id` (FK to incidents)
- `evidence_type`: whois, shodan, pcap, honeypot_log, ct_log
- `data` (JSONB): Small evidence stored inline
- `file_path`: Large files referenced by path

#### virtualservices (Phase 4)
Tracks Istio VirtualServices created for traffic redirection.

**Key columns**:
- `incident_id` (FK to incidents)
- `vs_name`, `vs_namespace`: Kubernetes resource
- `attacker_ip` (INET), `honeypot_destination`
- `expires_at`, `status`: active, expired, deleted

#### metrics
Time-series metrics for dashboard queries.

**Key columns**:
- `metric_name`: detection_latency, osint_lookup_time, etc.
- `metric_value` (DECIMAL)
- `tags` (JSONB): {ip: "...", action: "..."}

### Views

#### recent_incidents
Last 7 days of incidents with audit entry counts.

```sql
SELECT * FROM recent_incidents LIMIT 10;
```

#### action_stats
Action usage statistics (how often each action is used).

```sql
SELECT * FROM action_stats WHERE action_result = 'success';
```

#### llm_stats
LLM usage over time (consultations per day, avg confidence).

```sql
SELECT * FROM llm_stats ORDER BY date DESC LIMIT 30;
```

---

## Development Setup

### 1. Deploy PostgreSQL

```bash
cd ~/REPOS/cyber-riposte/scenario-the-mirror

# Deploy PostgreSQL StatefulSet
oc apply -f k8s/postgres-deployment.yaml

# Check pod status
oc get pods -n cyber-riposte -l app=postgres

# Wait for ready
oc wait --for=condition=ready pod -l app=postgres -n cyber-riposte --timeout=300s
```

**What this deploys**:
- PostgreSQL 15 (Red Hat UBI image)
- StatefulSet with 50GB PVC
- Secret with credentials (user: mirror_agent, db: mirror_audit)

### 2. Initialize Schema

```bash
# Deploy schema initialization job
oc apply -f k8s/postgres-init-job.yaml

# Watch job progress
oc logs -f job/postgres-init-schema -n cyber-riposte

# Verify schema created
POSTGRES_POD=$(oc get pod -n cyber-riposte -l app=postgres -o jsonpath='{.items[0].metadata.name}')
oc exec -it $POSTGRES_POD -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c "\dt"

# Expected output: audit_log, incidents, evidence, virtualservices, metrics
```

### 3. Create Agent Secret

```bash
# Create secret with DATABASE_URL
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: mirror-agent-secrets
  namespace: cyber-riposte
type: Opaque
stringData:
  DATABASE_URL: "postgresql://mirror_agent:changeme@postgres:5432/mirror_audit"
  SHODAN_API_KEY: ""  # Optional
EOF

# Verify secret created
oc get secret mirror-agent-secrets -n cyber-riposte
```

### 4. Deploy Agent with Database Connection

```bash
# Agent deployment already references DATABASE_URL from secret
oc apply -f k8s/agent-deployment-kafka.yaml

# Check agent logs for database connection
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep -i database
# Should see: "Database connection pool initialized"
```

### 5. Test Database Persistence

```bash
# Port-forward Kafka
oc port-forward svc/kafka 9092:9092 -n cyber-riposte &

# Generate test event
python3 event-producer-sim.py --kafka localhost:9092 --scenario single --count 1

# Check agent logs
oc logs deployment/mirror-agent-kafka -n cyber-riposte | tail -20
# Should see: "database_persisted": true

# Query database directly
oc exec -it $POSTGRES_POD -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT incident_id, action_name, action_result, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT 5;"
```

---

## Production Deployment (CrunchyData Operator)

For production, use **CrunchyData PostgreSQL Operator** for HA, backups, monitoring.

### 1. Install CrunchyData Operator

```bash
# Via OpenShift Console:
# Operators → OperatorHub → Search "Crunchy Postgres"
# Install "Crunchy Postgres for Kubernetes"

# Or via CLI:
cat <<EOF | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: postgresql
  namespace: openshift-operators
spec:
  channel: v5
  name: postgresql
  source: certified-operators
  sourceNamespace: openshift-marketplace
EOF

# Wait for operator
oc get csv -n openshift-operators | grep postgresoperator
```

### 2. Create PostgreSQL Cluster

```bash
cat <<EOF | oc apply -f -
apiVersion: postgres-operator.crunchydata.com/v1beta1
kind: PostgresCluster
metadata:
  name: mirror-postgres
  namespace: cyber-riposte
spec:
  image: registry.developers.crunchydata.com/crunchydata/crunchy-postgres:ubi8-15.5-1
  postgresVersion: 15
  instances:
    - name: instance1
      replicas: 3  # HA: 1 primary + 2 replicas
      dataVolumeClaimSpec:
        accessModes:
        - "ReadWriteOnce"
        resources:
          requests:
            storage: 100Gi
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 1
            podAffinityTerm:
              topologyKey: kubernetes.io/hostname
              labelSelector:
                matchLabels:
                  postgres-operator.crunchydata.com/cluster: mirror-postgres
                  postgres-operator.crunchydata.com/instance-set: instance1
  backups:
    pgbackrest:
      image: registry.developers.crunchydata.com/crunchydata/crunchy-pgbackrest:ubi8-2.47-2
      repos:
      - name: repo1
        volume:
          volumeClaimSpec:
            accessModes:
            - "ReadWriteOnce"
            resources:
              requests:
                storage: 50Gi
  users:
    - name: mirror_agent
      databases:
        - mirror_audit
EOF

# Wait for cluster ready
oc wait postgrescluster/mirror-postgres --for=condition=PostgresClusterInitialized --timeout=300s -n cyber-riposte
```

### 3. Get Connection String

```bash
# Operator creates secret with connection details
oc get secret mirror-postgres-pguser-mirror-agent -n cyber-riposte -o jsonpath='{.data.uri}' | base64 -d

# Update agent secret with production DATABASE_URL
oc patch secret mirror-agent-secrets -n cyber-riposte -p \
  '{"stringData":{"DATABASE_URL":"postgresql://mirror_agent:PASSWORD@mirror-postgres-primary:5432/mirror_audit"}}'
```

---

## Querying the Database

### Connect to PostgreSQL

```bash
# Get postgres pod
POSTGRES_POD=$(oc get pod -n cyber-riposte -l app=postgres -o jsonpath='{.items[0].metadata.name}')

# Connect with psql
oc exec -it $POSTGRES_POD -n cyber-riposte -- psql -U mirror_agent -d mirror_audit
```

### Example Queries

#### Recent incidents
```sql
SELECT
  incident_id,
  attacker_ip,
  detection_signature,
  detection_confidence,
  actions_count,
  status
FROM recent_incidents
LIMIT 10;
```

#### Audit trail for specific incident
```sql
SELECT
  timestamp,
  action_name,
  action_result,
  detection_method,
  llm_consulted
FROM audit_log
WHERE incident_id = 'INC-2024-0615-0314'
ORDER BY timestamp;
```

#### LLM usage over last 7 days
```sql
SELECT
  date,
  detection_method,
  total_detections,
  llm_consultations,
  ROUND(avg_confidence::numeric, 2) as avg_confidence
FROM llm_stats
ORDER BY date DESC
LIMIT 7;
```

#### Top attackers by incident count
```sql
SELECT
  attacker_ip,
  COUNT(*) as incident_count,
  MAX(detection_confidence) as max_confidence,
  MAX(first_seen) as last_seen
FROM incidents
WHERE first_seen >= NOW() - INTERVAL '30 days'
GROUP BY attacker_ip
ORDER BY incident_count DESC
LIMIT 10;
```

#### Actions taken per IP
```sql
SELECT
  i.attacker_ip,
  a.action_name,
  COUNT(*) as action_count,
  SUM(CASE WHEN a.action_result = 'success' THEN 1 ELSE 0 END) as success_count
FROM incidents i
JOIN audit_log a ON i.incident_id = a.incident_id
GROUP BY i.attacker_ip, a.action_name
ORDER BY action_count DESC;
```

#### Search OSINT data
```sql
SELECT
  i.incident_id,
  i.attacker_ip,
  e.evidence_type,
  e.data->>'org' as organization,
  e.data->>'country' as country
FROM incidents i
JOIN evidence e ON i.incident_id = e.incident_id
WHERE e.evidence_type = 'whois'
  AND e.data->>'country' = 'CN';
```

---

## Connection Pooling

The agent uses **psycopg2 ThreadedConnectionPool** for efficient connection reuse.

**Default settings**:
- `DATABASE_POOL_MIN=2`: Minimum connections per agent pod
- `DATABASE_POOL_MAX=10`: Maximum connections per agent pod

**With 3 agent replicas**: 6-30 total connections to PostgreSQL.

**Tuning**:
```bash
# Increase pool for high load
oc set env deployment/mirror-agent-kafka DATABASE_POOL_MAX=20 -n cyber-riposte

# Check PostgreSQL connection count
oc exec $POSTGRES_POD -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT count(*) FROM pg_stat_activity WHERE datname='mirror_audit';"
```

---

## Dual Persistence

Phase 3 maintains **backward compatibility** by writing to BOTH database and file:

1. **PostgreSQL database**: Primary storage, queryable
2. **Audit file**: `/var/log/cyber-riposte/audit.jsonl` (backward compat)
3. **Stdout logs**: JSON structured logs (OpenShift log aggregation)

**Fallback behavior**:
- If `DATABASE_URL` not set → file + stdout only (Phase 1-2 mode)
- If database connection fails → logs error, continues with file + stdout
- Stdout always includes `"database_persisted": true/false` flag

---

## Monitoring

### Check Database Connection

```bash
# Agent logs
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "Database connection pool"
# Should see: "Database connection pool initialized (min=2, max=10)"

# Connection pool stats
oc exec $POSTGRES_POD -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT pid, usename, application_name, state, query_start
   FROM pg_stat_activity
   WHERE datname = 'mirror_audit';"
```

### Database Size

```bash
# Database size
oc exec $POSTGRES_POD -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT pg_size_pretty(pg_database_size('mirror_audit'));"

# Table sizes
oc exec $POSTGRES_POD -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
   FROM pg_tables
   WHERE schemaname = 'public'
   ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;"
```

### Row Counts

```bash
oc exec $POSTGRES_POD -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT
    'audit_log' as table, COUNT(*) as rows FROM audit_log
   UNION ALL
   SELECT 'incidents', COUNT(*) FROM incidents
   UNION ALL
   SELECT 'evidence', COUNT(*) FROM evidence;"
```

---

## Backup and Restore

### Manual Backup

```bash
# Create backup
oc exec $POSTGRES_POD -n cyber-riposte -- pg_dump -U mirror_agent mirror_audit > backup-$(date +%Y%m%d).sql

# Restore from backup
cat backup-20240615.sql | oc exec -i $POSTGRES_POD -n cyber-riposte -- psql -U mirror_agent -d mirror_audit
```

### CrunchyData Automatic Backups

With CrunchyData operator, backups are automatic:

```bash
# List backups
oc get pgbackrestbackup -n cyber-riposte

# Trigger manual backup
cat <<EOF | oc apply -f -
apiVersion: postgres-operator.crunchydata.com/v1beta1
kind: PGBackRestBackup
metadata:
  name: manual-backup-$(date +%Y%m%d)
  namespace: cyber-riposte
spec:
  cluster: mirror-postgres
  repoName: repo1
EOF
```

---

## Troubleshooting

### Agent Can't Connect to Database

```bash
# Check DATABASE_URL in secret
oc get secret mirror-agent-secrets -n cyber-riposte -o jsonpath='{.data.DATABASE_URL}' | base64 -d

# Test connection from agent pod
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')
oc exec -it $AGENT_POD -n cyber-riposte -- python3 -c "
import psycopg2
import os
conn = psycopg2.connect(os.environ['DATABASE_URL'])
print('Connection successful!')
conn.close()
"

# Check agent logs
oc logs $AGENT_POD -n cyber-riposte | grep -i database
```

### Schema Not Initialized

```bash
# Check if init job completed
oc get job postgres-init-schema -n cyber-riposte

# Check job logs
oc logs job/postgres-init-schema -n cyber-riposte

# Re-run init job
oc delete job postgres-init-schema -n cyber-riposte
oc apply -f k8s/postgres-init-job.yaml
```

### Database Persisted = False

If audit logs show `"database_persisted": false`:

```bash
# Check agent logs for error
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep -A5 "Failed to log audit entry"

# Common causes:
# 1. DATABASE_URL not set or invalid
# 2. PostgreSQL not running
# 3. Network policy blocking connection
# 4. Wrong credentials

# Test database reachability
oc exec $AGENT_POD -n cyber-riposte -- nc -zv postgres 5432
```

---

## Migration from File-Based

Phase 3 maintains backward compatibility, so migration is **optional**:

### Option 1: Dual Mode (Recommended)
Keep both file and database. No migration needed.

### Option 2: Import Historical Data

```bash
# Export audit.jsonl to SQL inserts
python3 <<EOF
import json
import sys

with open('/var/log/cyber-riposte/audit.jsonl') as f:
    for line in f:
        entry = json.loads(line)
        # Generate INSERT statements
        # (script would be more complex in practice)
        print(f"INSERT INTO audit_log (...) VALUES (...);"  )
EOF
```

---

## Next Steps

After Phase 3 is working:

- **Phase 4**: Istio VirtualService (traffic redirection) - writes to `virtualservices` table
- **Phase 5**: Honeypot deployment - writes to `evidence` table
- **Phase 8**: GitHub integration - updates `github_issue_url` column

---

## Summary

**Phase 3 Complete** when:

✅ PostgreSQL StatefulSet running  
✅ Schema initialized (tables, indexes, views)  
✅ Agent secret contains DATABASE_URL  
✅ Agent connects to database (connection pool initialized)  
✅ Audit entries written to database (`database_persisted: true`)  
✅ Incidents tracked in `incidents` table  
✅ SQL queries work (recent_incidents, action_stats views)  
✅ Dual persistence: database + file + stdout  
✅ Documentation complete

The Mirror now has queryable, persistent audit storage! 🎯
