# Phase 2: Kafka Integration Guide

This guide covers setting up Kafka message queue for The Mirror agent, replacing stdin with distributed event ingestion.

---

## Why Kafka?

**Phase 1 (stdin)** works for single-instance testing but has limitations:
- ❌ Single point of failure
- ❌ No event replay capability
- ❌ Can't scale horizontally
- ❌ Events lost if agent crashes
- ❌ No backpressure handling

**Phase 2 (Kafka)** solves these:
- ✅ Multiple agent replicas (consumer group)
- ✅ Events persist in topic (replay capability)
- ✅ Horizontal scaling (add more agents)
- ✅ At-least-once delivery guarantee
- ✅ Backpressure via consumer lag

---

## Quick Start

### Option 1: Development (Simple Kafka)

```bash
# 1. Deploy Kafka + Zookeeper
oc apply -f k8s/kafka-deployment.yaml

# 2. Wait for Kafka to be ready
oc wait --for=condition=ready pod -l app=kafka -n cyber-riposte --timeout=300s

# 3. Deploy agent in Kafka mode
oc apply -f k8s/agent-deployment-kafka.yaml

# 4. Generate fake events
python3 event-producer-sim.py --kafka kafka:9092 --scenario sequence --count 5
```

### Option 2: Production (Red Hat AMQ Streams)

See "Production Deployment" section below.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Event Sources                                               │
├─────────────────────────────────────────────────────────────┤
│ - Suricata IDS (filebeat → Kafka)                          │
│ - Web server logs (fluentd → Kafka)                        │
│ - Fake event generator (testing)                           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Kafka Topic:    │
                    │  suricata-eve-   │
                    │  events          │
                    │                  │
                    │  Partitions: 3   │
                    │  Retention: 7d   │
                    └──────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │ Mirror      │   │ Mirror      │   │ Mirror      │
    │ Agent #1    │   │ Agent #2    │   │ Agent #3    │
    │             │   │             │   │             │
    │ Consumer    │   │ Consumer    │   │ Consumer    │
    │ Group:      │   │ Group:      │   │ Group:      │
    │ mirror-     │   │ mirror-     │   │ mirror-     │
    │ agent       │   │ agent       │   │ agent       │
    └─────────────┘   └─────────────┘   └─────────────┘
```

**Key Points**:
- **Consumer Group**: All agents share `mirror-agent` group → each event processed once
- **Partitions**: 3 partitions → up to 3 agents can consume in parallel
- **Retention**: 7 days → events can be replayed for debugging
- **At-least-once**: Offsets committed after successful processing

---

## Development Setup

### 1. Deploy Simple Kafka

```bash
cd ~/REPOS/cyber-riposte/scenario-the-mirror

# Deploy Kafka + Zookeeper
oc apply -f k8s/kafka-deployment.yaml

# Check status
oc get pods -n cyber-riposte -l app=zookeeper
oc get pods -n cyber-riposte -l app=kafka

# Wait for ready
oc wait --for=condition=ready pod -l app=kafka -n cyber-riposte --timeout=300s
```

**What this deploys**:
- Zookeeper StatefulSet (1 replica, 10GB storage)
- Kafka StatefulSet (1 replica, 20GB storage)
- Services for both

### 2. Create Kafka Topic

```bash
# Exec into Kafka pod
KAFKA_POD=$(oc get pod -n cyber-riposte -l app=kafka -o jsonpath='{.items[0].metadata.name}')

# Create topic
oc exec -it $KAFKA_POD -n cyber-riposte -- kafka-topics \
  --create \
  --topic suricata-eve-events \
  --bootstrap-server localhost:9092 \
  --partitions 3 \
  --replication-factor 1

# Verify topic
oc exec $KAFKA_POD -n cyber-riposte -- kafka-topics \
  --list \
  --bootstrap-server localhost:9092
```

### 3. Deploy Agent in Kafka Mode

```bash
# Deploy agent (3 replicas with consumer group)
oc apply -f k8s/agent-deployment-kafka.yaml

# Check replicas
oc get pods -n cyber-riposte -l app=mirror-agent,mode=kafka

# Check logs
oc logs -f deployment/mirror-agent-kafka -n cyber-riposte
# Should see: "Starting Mirror agent in Kafka mode..."
```

### 4. Test with Fake Events

```bash
# Port-forward Kafka for local access
oc port-forward svc/kafka 9092:9092 -n cyber-riposte &

# Generate single event
python3 event-producer-sim.py \
  --kafka localhost:9092 \
  --scenario single \
  --count 1

# Generate attack sequence
python3 event-producer-sim.py \
  --kafka localhost:9092 \
  --scenario sequence \
  --count 3

# Generate continuous events (1 per second)
python3 event-producer-sim.py \
  --kafka localhost:9092 \
  --scenario continuous \
  --rate 1.0
# Press Ctrl+C to stop

# Check agent logs for detections
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep -i "recon"
```

---

## Production Deployment (AMQ Streams)

For production, use **Red Hat AMQ Streams** (Kafka operator).

### 1. Install AMQ Streams Operator

```bash
# Via OpenShift Console:
# Operators → OperatorHub → Search "AMQ Streams"
# Install "Red Hat Integration - AMQ Streams"

# Or via CLI:
cat <<EOF | oc apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: amq-streams
  namespace: openshift-operators
spec:
  channel: stable
  name: amq-streams
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

# Wait for operator to be ready
oc get csv -n openshift-operators | grep amq-streams
```

### 2. Create Kafka Cluster

```bash
cat <<EOF | oc apply -f -
apiVersion: kafka.strimzi.io/v1beta2
kind: Kafka
metadata:
  name: mirror-kafka
  namespace: cyber-riposte
spec:
  kafka:
    version: 3.5.1
    replicas: 3
    listeners:
      - name: plain
        port: 9092
        type: internal
        tls: false
      - name: tls
        port: 9093
        type: internal
        tls: true
    config:
      offsets.topic.replication.factor: 3
      transaction.state.log.replication.factor: 3
      transaction.state.log.min.isr: 2
      default.replication.factor: 3
      min.insync.replicas: 2
      log.retention.hours: 168  # 7 days
    storage:
      type: persistent-claim
      size: 100Gi
      deleteClaim: false
  zookeeper:
    replicas: 3
    storage:
      type: persistent-claim
      size: 10Gi
      deleteClaim: false
  entityOperator:
    topicOperator: {}
    userOperator: {}
EOF

# Wait for Kafka cluster
oc wait kafka/mirror-kafka --for=condition=Ready --timeout=300s -n cyber-riposte
```

### 3. Create Topic via Operator

```bash
cat <<EOF | oc apply -f -
apiVersion: kafka.strimzi.io/v1beta2
kind: KafkaTopic
metadata:
  name: suricata-eve-events
  namespace: cyber-riposte
  labels:
    strimzi.io/cluster: mirror-kafka
spec:
  partitions: 6  # More partitions for higher throughput
  replicas: 3    # High availability
  config:
    retention.ms: 604800000  # 7 days
    segment.bytes: 1073741824  # 1GB
    compression.type: lz4
EOF
```

### 4. Deploy Agent with AMQ Streams

```bash
# Edit deployment to point to AMQ Streams
oc edit deployment mirror-agent-kafka -n cyber-riposte

# Change:
#   KAFKA_BOOTSTRAP_SERVERS: "mirror-kafka-kafka-bootstrap:9092"

# Or apply with sed
sed 's/kafka:9092/mirror-kafka-kafka-bootstrap:9092/' \
  k8s/agent-deployment-kafka.yaml | oc apply -f -
```

---

## Event Generator Usage

### Command Line Options

```bash
python3 event-producer-sim.py --help

Options:
  --kafka BOOTSTRAP    Kafka servers (default: localhost:9092)
  --topic TOPIC        Kafka topic (default: suricata-eve-events)
  --scenario TYPE      single|sequence|mixed|continuous
  --count N            Number of events/sequences
  --rate FLOAT         Events per second (continuous mode)
```

### Scenarios

#### Single Events

Generate standalone reconnaissance events:
```bash
python3 event-producer-sim.py \
  --scenario single \
  --count 10
```

#### Attack Sequences

Generate realistic attack progressions (5 events each):
```bash
python3 event-producer-sim.py \
  --scenario sequence \
  --count 5

# Sequence: reconnaissance → scanning → enumeration → exploitation
```

#### Mixed Traffic

80% attacks, 20% benign (tests false positives):
```bash
python3 event-producer-sim.py \
  --scenario mixed \
  --count 100
```

#### Continuous Generation

For load testing or demos:
```bash
python3 event-producer-sim.py \
  --scenario continuous \
  --rate 5.0  # 5 events/second
```

---

## Monitoring

### Check Kafka Topic

```bash
# List topics
oc exec -it $KAFKA_POD -n cyber-riposte -- kafka-topics \
  --list \
  --bootstrap-server localhost:9092

# Describe topic
oc exec -it $KAFKA_POD -n cyber-riposte -- kafka-topics \
  --describe \
  --topic suricata-eve-events \
  --bootstrap-server localhost:9092

# Check consumer groups
oc exec -it $KAFKA_POD -n cyber-riposte -- kafka-consumer-groups \
  --list \
  --bootstrap-server localhost:9092

# Describe consumer group (see lag)
oc exec -it $KAFKA_POD -n cyber-riposte -- kafka-consumer-groups \
  --describe \
  --group mirror-agent \
  --bootstrap-server localhost:9092
```

### Monitor Agent Logs

```bash
# All replicas
oc logs -f deployment/mirror-agent-kafka -n cyber-riposte

# Specific replica
oc logs -f mirror-agent-kafka-<pod-id> -n cyber-riposte

# Filter for detections
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "Recon from"

# Filter for Kafka messages
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "Kafka"
```

### Check Consumer Lag

```bash
# Via Kafka command
oc exec $KAFKA_POD -n cyber-riposte -- kafka-consumer-groups \
  --describe \
  --group mirror-agent \
  --bootstrap-server localhost:9092 \
  --offsets

# Output shows: CURRENT-OFFSET, LOG-END-OFFSET, LAG per partition
# LAG = 0 means agent is keeping up
# LAG > 100 means agent is falling behind
```

---

## Integrating Real Suricata

To feed real Suricata EVE logs into Kafka:

### Option 1: Filebeat

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true
  json.add_error_key: true

output.kafka:
  hosts: ["kafka:9092"]
  topic: "suricata-eve-events"
  partition.round_robin:
    reachable_only: false
  required_acks: 1
  compression: lz4
```

### Option 2: Logstash

```ruby
# logstash.conf
input {
  file {
    path => "/var/log/suricata/eve.json"
    codec => "json"
  }
}

output {
  kafka {
    bootstrap_servers => "kafka:9092"
    topic_id => "suricata-eve-events"
    compression_type => "lz4"
  }
}
```

### Option 3: Fluentd

```ruby
# fluent.conf
<source>
  @type tail
  path /var/log/suricata/eve.json
  pos_file /var/log/td-agent/suricata-eve.pos
  tag suricata.eve
  format json
</source>

<match suricata.eve>
  @type kafka2
  brokers kafka:9092
  default_topic suricata-eve-events
  compression_codec lz4
</match>
```

---

## Troubleshooting

### Kafka Not Starting

```bash
# Check Zookeeper
oc get pods -l app=zookeeper -n cyber-riposte
oc logs -l app=zookeeper -n cyber-riposte

# Check Kafka logs
oc logs -l app=kafka -n cyber-riposte --tail=100

# Common issue: Zookeeper not ready
# Wait for Zookeeper first, then restart Kafka
```

### Agent Can't Connect to Kafka

```bash
# Check Kafka service
oc get svc kafka -n cyber-riposte

# Test connectivity from agent pod
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')
oc exec -it $AGENT_POD -n cyber-riposte -- nc -zv kafka 9092

# Check agent logs
oc logs $AGENT_POD -n cyber-riposte | grep -i kafka
```

### Events Not Being Consumed

```bash
# Check if topic has messages
oc exec $KAFKA_POD -n cyber-riposte -- kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic suricata-eve-events \
  --from-beginning \
  --max-messages 5

# Check consumer group lag
oc exec $KAFKA_POD -n cyber-riposte -- kafka-consumer-groups \
  --describe \
  --group mirror-agent \
  --bootstrap-server localhost:9092

# Check agent readiness
oc get pods -l app=mirror-agent -n cyber-riposte
```

### High Consumer Lag

If LAG is growing:

```bash
# Scale up agents (more replicas)
oc scale deployment mirror-agent-kafka --replicas=6 -n cyber-riposte

# Note: Max replicas = number of partitions
# If topic has 3 partitions, max 3 agents can consume in parallel

# Increase partitions (if needed)
oc exec $KAFKA_POD -n cyber-riposte -- kafka-topics \
  --alter \
  --topic suricata-eve-events \
  --partitions 6 \
  --bootstrap-server localhost:9092
```

---

## Testing

### End-to-End Test

```bash
# 1. Deploy everything
oc apply -f k8s/kafka-deployment.yaml
oc apply -f k8s/agent-deployment-kafka.yaml

# 2. Wait for ready
oc wait --for=condition=ready pod -l app=kafka -n cyber-riposte --timeout=300s
oc wait --for=condition=ready pod -l app=mirror-agent -n cyber-riposte --timeout=300s

# 3. Port-forward Kafka
oc port-forward svc/kafka 9092:9092 -n cyber-riposte &

# 4. Generate test events
python3 event-producer-sim.py --kafka localhost:9092 --scenario sequence --count 3

# 5. Check detection logs
oc logs deployment/mirror-agent-kafka -n cyber-riposte | tail -50

# 6. Should see: "Recon from X.X.X.X: ..."
```

---

## Next Steps

After Phase 2 is working:

- **Phase 3**: PostgreSQL audit logs (replace file-based)
- **Phase 4**: Istio VirtualService (traffic redirection)
- **Phase 5**: Deploy honeypots (Cowrie, Glastopf)

---

## Summary

**Phase 2 Complete** when:

✅ Kafka cluster running (or AMQ Streams)  
✅ Topic created with 3+ partitions  
✅ Agent deployed in Kafka mode (3 replicas)  
✅ Consumer group working (no lag)  
✅ Fake event generator produces events  
✅ Agent detects and processes events  
✅ Multiple replicas share workload

The Mirror is now horizontally scalable with distributed event ingestion! 🚀
