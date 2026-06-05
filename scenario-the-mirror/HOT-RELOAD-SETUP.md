# Phase 9: Hot-Reload Configuration Guide

This guide covers configuration hot-reload for action-pool.yaml without pod restart.

---

## Why Hot-Reload?

**Phase 1-8** required pod restart for config changes:
- ❌ Edit ConfigMap → restart all agent pods
- ❌ Downtime during restart
- ❌ Loss of in-flight events
- ❌ Kafka consumer rebalance
- ❌ Slow iteration on action pool tuning

**Phase 9 (Hot-Reload)** solves this:
- ✅ Edit ConfigMap → automatic reload
- ✅ No pod restart required
- ✅ No downtime
- ✅ In-flight events continue processing
- ✅ Fast iteration on action pool

---

## Quick Start

```bash
# 1. Edit action pool ConfigMap
oc edit configmap mirror-agent-config -n cyber-riposte

# 2. Save changes
# (File watcher detects change automatically)

# 3. Check agent logs for reload message
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "reloaded"
# Should see: "Action pool reloaded: 8 actions"

# 4. Verify new config active
# Trigger test event, check if new actions execute
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ ConfigMap: mirror-agent-config                              │
│ - action-pool.yaml                                          │
│ - suspicious-user-agents.yaml                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ (mounted as volume)
                    ┌──────────────────┐
                    │  /etc/mirror/    │
                    │  config/         │
                    │                  │
                    │  action-pool.    │
                    │  yaml            │
                    └──────────────────┘
                              │
                              ▼ (file watcher - inotify)
                    ┌──────────────────┐
                    │  Config Watcher  │
                    │  (watchdog lib)  │
                    │                  │
                    │  Detects:        │
                    │  - File modified │
                    │  - Debounce 2s   │
                    └──────────────────┘
                              │
                              ▼ (callback)
                    ┌──────────────────┐
                    │  reload_action_  │
                    │  pool()          │
                    │                  │
                    │  1. Load YAML    │
                    │  2. Validate     │
                    │  3. Replace pool │
                    └──────────────────┘
```

**Flow**:
1. User edits ConfigMap via `oc edit`
2. Kubernetes updates mounted file
3. File watcher detects change (inotify)
4. Debounce 2 seconds (ignore rapid changes)
5. Execute reload callback
6. Load new action pool YAML
7. Validate (check for errors)
8. Replace in-memory action pool
9. Log success/failure

---

## Components

### 1. Config Watcher (agent/config_watcher.py)

**Features**:
- File system monitoring (watchdog library)
- Inotify-based change detection
- Debounce (2-second window)
- Callback on file change
- Watch multiple files simultaneously

**Usage**:
```python
from agent.config_watcher import get_config_watcher

watcher = get_config_watcher()

def reload_action_pool():
    global pool
    pool = ActionPool()  # Reload from disk
    logger.info("Action pool reloaded")

watcher.watch("/etc/mirror/config/action-pool.yaml", reload_action_pool)
watcher.start()
```

### 2. Updated Main Loop (agent/main.py)

Both `run_stdin_mode()` and `run_kafka_mode()` now:
1. Create ActionPool instance
2. Setup file watcher for action-pool.yaml
3. Define reload callback with validation
4. Start watcher

**Reload callback**:
```python
def reload_action_pool():
    nonlocal pool
    try:
        new_pool = ActionPool()
        # Validate before replacing
        if new_pool.actions:
            pool = new_pool
            logger.info(f"Reloaded: {len(pool.actions)} actions")
        else:
            logger.error("New pool empty, keeping current")
    except Exception as e:
        logger.error(f"Reload failed: {e}")
```

---

## Deployment

### 1. Install Watchdog Dependency

Watchdog should already be in requirements.txt from Phase 9:

```bash
# Verify
grep watchdog requirements.txt
# Should see: watchdog>=4.0.0
```

### 2. ConfigMap Must Be Mounted as Volume

Agent deployment already mounts ConfigMap:

```yaml
# k8s/agent-deployment-kafka.yaml
volumeMounts:
- name: config
  mountPath: /etc/mirror/config
  readOnly: true  # ← Important: readOnly still allows file updates

volumes:
- name: config
  configMap:
    name: mirror-agent-config
```

**Note**: `readOnly: true` means container can't write, but Kubernetes can still update the mounted files when ConfigMap changes.

### 3. No Additional Configuration Needed

Hot-reload is automatic once watchdog is installed!

---

## Testing

### Test 1: Add New Action

```bash
# 1. Edit ConfigMap
oc edit configmap mirror-agent-config -n cyber-riposte

# 2. Add new action to action-pool.yaml:
# actions:
#   - id: "test-action"
#     name: "Test hot-reload"
#     tier: 1
#     auto_execute: true
#     requires_approval: false
#     parameters:
#       test: true

# 3. Save and exit editor

# 4. Wait 2-5 seconds (Kubernetes propagates change + debounce)

# 5. Check logs
oc logs deployment/mirror-agent-kafka -n cyber-riposte | tail -20
# Should see: "Action pool reloaded: 9 actions" (increased from 8)
```

### Test 2: Modify Existing Action

```bash
# 1. Edit action pool
oc edit configmap mirror-agent-config -n cyber-riposte

# 2. Change expiry for "run-osint":
#   expiry:
#     duration: 2h  # Changed from 1h
#     unit: hours

# 3. Save

# 4. Check logs
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "reloaded"

# 5. Trigger test event to verify new expiry
python3 event-producer-sim.py --scenario single --count 1

# 6. Check audit log for new expiry time
oc exec postgres-0 -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT action_id, expires_at FROM audit_log ORDER BY created_at DESC LIMIT 1;"
```

### Test 3: Invalid YAML (Should Reject)

```bash
# 1. Edit action pool
oc edit configmap mirror-agent-config -n cyber-riposte

# 2. Introduce syntax error:
#   actions:
#     - id: "broken
#       # Missing closing quote

# 3. Save

# 4. Check logs
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "Failed to reload"
# Should see: "Failed to reload action pool: ..."

# 5. Verify old config still active (not replaced)
# Trigger event, should still process with old config

# 6. Fix YAML and save again
# Should see: "Action pool reloaded successfully"
```

---

## How Kubernetes ConfigMap Updates Work

### ConfigMap Update Propagation

When you edit a ConfigMap:
```bash
oc edit configmap mirror-agent-config
```

Kubernetes:
1. Updates ConfigMap in etcd
2. Kubelet on each node polls for ConfigMap changes (default: 60s)
3. Kubelet updates mounted files in pod volumes
4. File watcher in pod detects change

**Propagation time**: 60-90 seconds (kubelet sync period)

### Speeding Up Propagation

Use annotations to force immediate sync:
```bash
# Add annotation to trigger sync
oc annotate configmap mirror-agent-config \
  reload-timestamp="$(date +%s)" \
  --overwrite
```

Or reduce kubelet sync period (cluster-wide):
```yaml
# kubelet config
syncFrequency: 10s  # Default: 60s
```

---

## Limitations

### What Can Be Hot-Reloaded

✅ **action-pool.yaml**:
- Add/remove actions
- Modify action parameters
- Change expiry times
- Update tiers, approval requirements

✅ **suspicious-user-agents.yaml** (if watcher added):
- Add/remove user agent patterns
- Modify detection rules

### What Cannot Be Hot-Reloaded

❌ **Environment variables**:
- `DATABASE_URL`, `REDIS_URL`, etc.
- Requires pod restart

❌ **Code changes**:
- `agent/*.py` files
- Requires image rebuild + pod restart

❌ **OSINT module changes**:
- `osint-modules/*.py`
- Requires pod restart

❌ **Kafka configuration**:
- `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_TOPIC`
- Requires pod restart

---

## Monitoring

### Check Reload Events

```bash
# Recent reloads
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "reloaded"

# Failed reload attempts
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "Failed to reload"

# Watcher status
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "Configuration watcher"
```

### Verify Watcher Running

```bash
# Exec into pod
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')

# Check watcher process
oc exec $AGENT_POD -n cyber-riposte -- ps aux | grep watchdog

# Check if watchdog installed
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "from watchdog.observers import Observer; print('OK')"
```

---

## Troubleshooting

### Config Not Reloading

```bash
# Check watchdog installed
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "import watchdog; print(watchdog.__version__)"

# Check ConfigMap mounted
oc exec $AGENT_POD -n cyber-riposte -- ls -la /etc/mirror/config/

# Check file watcher running
oc logs $AGENT_POD -n cyber-riposte | grep "Configuration watcher started"

# Check ConfigMap update propagated
oc exec $AGENT_POD -n cyber-riposte -- cat /etc/mirror/config/action-pool.yaml | grep "test-action"
```

### Reload Failed

```bash
# Check logs for error
oc logs $AGENT_POD -n cyber-riposte | grep "Failed to reload"

# Common errors:
# 1. YAML syntax error
#    Fix: Validate YAML before saving

# 2. Missing required fields
#    Fix: Check action-pool-schema.yaml

# 3. File permissions
#    Fix: Ensure ConfigMap mounted correctly
```

### Changes Not Detected

```bash
# Check inotify limits (on node)
oc debug node/<node-name>
cat /proc/sys/fs/inotify/max_user_watches
# Should be >= 8192

# Increase if needed (as root on node)
echo 16384 > /proc/sys/fs/inotify/max_user_watches
```

---

## Best Practices

### 1. Test in Dev First

Always test ConfigMap changes in development before production:
```bash
# Dev namespace
oc edit configmap mirror-agent-config -n cyber-riposte-dev

# Verify reload
# Then apply to production
```

### 2. Use Git for Config Changes

Track action pool changes in git:
```bash
# 1. Edit locally
vim action-pool.yaml

# 2. Commit
git add action-pool.yaml
git commit -m "Add test-action to action pool"

# 3. Apply to cluster
oc create configmap mirror-agent-config \
  --from-file=action-pool.yaml \
  --dry-run=client -o yaml | oc apply -f -
```

### 3. Monitor After Changes

After editing ConfigMap:
```bash
# Watch logs for reload
oc logs -f deployment/mirror-agent-kafka -n cyber-riposte | grep -i reload

# Generate test event
python3 event-producer-sim.py --scenario single --count 1

# Verify new config applied
oc logs deployment/mirror-agent-kafka -n cyber-riposte | tail -50
```

---

## Next Steps

After Phase 9 is working:

- **Phase 10**: Testing & CI/CD (unit tests for config reloading)
- **Future**: Extend hot-reload to rate limiter config, LLM prompts

---

## Summary

**Phase 9 Complete** when:

✅ Watchdog library installed  
✅ Config watcher initialized  
✅ action-pool.yaml being watched  
✅ Edit ConfigMap triggers reload  
✅ Reload logs appearing  
✅ New config active without restart  
✅ Invalid YAML rejected  
✅ Old config preserved on failure

The Mirror now has **zero-downtime configuration updates**! 🔄
