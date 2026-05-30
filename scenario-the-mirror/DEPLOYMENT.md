# Deploying the Mirror Agent

A practical guide to how the agent runs, what access it needs, and how it knows what it's allowed to do.

## What the Agent Actually Is

It's a Python process that runs continuously — a long-running service, same as nginx or a database. It starts, watches telemetry for reconnaissance patterns, and acts when it sees something. There's no special AI platform required. It's a script.

## How It Runs

The agent runs as a **systemd service**:

```ini
# /etc/systemd/system/mirror-agent.service

[Unit]
Description=The Mirror — autonomous counter-reconnaissance agent
After=network.target suricata.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/cyber-riposte/scenario-the-mirror/mirror_agent.py
Restart=on-failure
RestartSec=5
WorkingDirectory=/opt/cyber-riposte/scenario-the-mirror

# API keys for OSINT modules
Environment=SHODAN_API_KEY=your-key-here

# Permissions (see "How It Gets Access" below)
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ReadOnlyPaths=/var/log/suricata
ReadWritePaths=/var/log/cyber-riposte

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now mirror-agent
```

When the machine boots, systemd starts the agent. If it crashes, systemd restarts it. It runs 24/7.

### Input: Where Telemetry Comes From

The agent reads a stream of JSON events — specifically, Suricata's EVE log. The simplest version is literally:

```bash
tail -F /var/log/suricata/eve.json | python3 mirror_agent.py
```

The agent reads one JSON line at a time from stdin, checks if it's interesting, and acts if it is. In production you'd use something more robust (a message queue, a log shipper like Filebeat pushing to the agent), but the core mechanic is the same: events come in, the agent processes them one at a time.

## How It Gets Access

The agent needs permission to do four things:

### 1. Read Telemetry

Access to Suricata's EVE log file. The systemd unit grants read-only access:

```ini
ReadOnlyPaths=/var/log/suricata
```

### 2. Apply Firewall Rules

The agent runs `nft` commands to redirect and block traffic. Rather than giving it full root, you grant just the capability it needs:

```ini
CapabilityBoundingSet=CAP_NET_ADMIN
```

This lets it run `nft add rule ...` but not read `/etc/shadow`, install packages, or do anything else that root could do. It gets the minimum privilege required.

### 3. Run OSINT Lookups

The agent makes outbound HTTP requests to public data sources (WHOIS, Shodan API, crt.sh). It needs:
- Outbound network access (standard for any service)
- API keys passed via environment variables

```ini
Environment=SHODAN_API_KEY=your-key-here
```

No special permissions — it's just making HTTP calls to public APIs.

### 4. Write Audit Logs and Evidence

The agent gets a dedicated directory for its output:

```ini
ReadWritePaths=/var/log/cyber-riposte
```

Everything else on the filesystem is read-only (`ProtectSystem=strict`). The agent can only write to its designated log directory. It cannot modify its own code, its own config, or anything outside its sandbox.

## How It Knows the Action Pool

The action pool is a YAML file (`action-pool.yaml`) that sits next to the agent script. When the agent starts, it loads the file into memory:

```python
class ActionPool:
    def __init__(self):
        with open("action-pool.yaml") as f:
            self.config = yaml.safe_load(f)
```

Every time the agent wants to do something, it checks the pool first:

```python
can_execute, reason = pool.can_execute("redirect-to-honeypot")
if not can_execute:
    # Action not authorized — skip and log why
    audit.record(action="redirect-to-honeypot", result="skipped", reason=reason)
    return
```

The pool defines:
- **What actions exist** (redirect, OSINT, block, collect evidence)
- **What tier each action is** (auto-execute, auto-execute+notify, PR-required)
- **What constraints apply** (max IPs/hour, allowlisted ranges, auto-expiry timers)
- **What can never be touched** (allowlisted IPs, internal ranges)

If an action isn't in the pool, the agent cannot execute it — the code path doesn't exist. The agent never improvises.

**The security team controls the pool, not the agent.** Changing what the agent is allowed to do means editing a YAML file and restarting the service. The agent never modifies its own pool.

## The Flow, Step by Step

```
 1. Agent starts, loads action-pool.yaml into memory
 2. Agent opens the Suricata EVE log stream and starts reading
 3. A JSON event arrives:
    {"event_type": "alert", "src_ip": "198.51.100.23", "http": {"http_user_agent": "Nuclei"}, ...}
 4. Agent checks: is this a recon pattern?
    → Yes (Suricata alert: port scan + user-agent: Nuclei)
 5. Agent checks: is this IP allowlisted?
    → No
 6. Agent checks: can I execute "redirect-to-honeypot"?
    → Yes (Tier 1, pre-approved, constraints met)
 7. Agent runs: nft add rule ... dnat to 10.0.0.99
 8. Agent writes audit log entry: what it did, why, evidence ref
 9. Agent checks: can I execute "run-osint"?
    → Yes (Tier 1, pre-approved)
10. Agent runs WHOIS, reverse DNS, Shodan, Certificate Transparency lookups
11. Agent writes evidence files + audit log entries
12. Agent checks: can I execute "temp-block-ip"?
    → Yes (Tier 1, pre-approved)
13. Agent runs: nft add rule ... drop (1 hour expiry)
14. Agent compiles post-mortem report from all audit entries
15. Agent writes report to /var/log/cyber-riposte/postmortems/
16. Security team reads the report at 8am
```

Every step follows the same pattern: **can I do this?** → check pool → **yes** → do it + log it, or **no** → skip + log why it was skipped.

## Phase 1 vs Phase 2

The deployment described above is **Phase 1: rule-based**. The agent uses pattern matching and thresholds — if the Suricata alert category is in a list of recon categories, if the user-agent matches a known tool signature, if the request count exceeds a threshold.

This works well for known patterns. But it has limitations:
- It can only detect patterns you've written rules for
- It can't reason about novel combinations of signals
- It can't explain *why* a pattern is suspicious in natural language

**Phase 2** introduces an LLM at the decision layer. See [PHASE2-LLM.md](PHASE2-LLM.md) for how this works and what value it adds.
