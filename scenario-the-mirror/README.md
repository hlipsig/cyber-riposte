# Scenario: The Mirror — Turn Their Tools Against Them

> *"In fencing, a riposte is the counterattack launched immediately after parrying. You use your opponent's forward momentum against them. The Mirror is a digital riposte."*

## Overview

When an attacker scans your infrastructure, most defenders block the IP and move on. The Mirror does something different: it **redirects the attacker to a honeypot** while simultaneously **running passive OSINT on the attacker's own infrastructure**. The attacker's probe is the opening — every packet they send reveals something about them.

The AI agent orchestrates the entire sequence autonomously: detect the scan, reroute to the honeypot, launch the OSINT collection, log the attacker's behavior, and compile a full intelligence dossier — all without a human in the loop.

This works because the agent only executes actions from a **pre-approved playbook** — a pool of responses the security team has reviewed and authorized in advance. The agent picks from that pool based on what it observes. It can act at 3am with nobody awake, but every decision is logged, justified, and structured into a post-mortem report for the team to review in the morning.

## How the Agent Works

### Phase 1: Detection

The agent monitors telemetry for reconnaissance through two complementary signals:

**IDS Alerts** — Suricata EVE log alerts for:
- Port scan signatures (many ports from one source in short timeframes)
- Directory brute-forcing (high 404 rate from a single source)
- Version fingerprinting (specific probe patterns for known scanners)

**User-Agent Analysis** — HTTP request user-agent strings matched against known offensive tools (see `suspicious-user-agents.yaml`):

| Category | Tools Detected | Threat Level |
|----------|---------------|--------------|
| Recon scanners | Nmap, Masscan, Nuclei, httpx, ZGrab, Censys, Shodan | High/Medium |
| Directory brute-force | Gobuster, Feroxbuster, ffuf, Dirsearch, DirBuster | High |
| Vulnerability scanners | Nikto, WPScan, sqlmap, Acunetix, Nessus, ZAP | High |
| Secret scanners | TruffleHog, Gitleaks | High |
| Exploit frameworks | Metasploit (IE6 default), Cobalt Strike | High |
| Generic automation | python-requests, Go-http-client, curl, wget, axios | Low (elevated at volume on sensitive endpoints) |
| Headless browsers | HeadlessChrome, PhantomJS | Low/Medium |

Either signal alone triggers the agent, but both together increase detection confidence. A Suricata alert from an IP that's also using `sqlmap/1.8` as its user-agent is near-certain hostile.

The agent also applies **composite rules** — a `python-requests` user-agent is low-confidence on its own, but `python-requests` hitting `/admin` 10 times in 5 minutes is elevated to high.

Source: IDS alerts (Suricata EVE log), web server access logs, firewall connection logs.

### Phase 2: Redirect

Once a source is flagged, the agent:
1. Generates an nftables DNAT rule to reroute the attacker to a honeypot
2. The honeypot mimics the real service closely enough to keep the attacker engaged
3. Every interaction is logged with full packet capture

This buys time for Phase 3 and collects TTPs (tools, techniques, procedures).

### Phase 3: Counter-Reconnaissance

While the attacker probes the honeypot, the agent runs passive OSINT against the attacker's source IP using only publicly available data:

| Module | Data Source | What It Reveals |
|--------|------------|-----------------|
| `whois_lookup.py` | WHOIS registries | IP owner, ASN, abuse contact, registration date |
| `reverse_dns.py` | DNS PTR records | Hostname, hosting provider, possible machine role |
| `shodan_lookup.py` | Shodan API | Open ports, service banners, OS, vulnerabilities on attacker's machine |
| `cert_transparency.py` | CT logs (crt.sh) | TLS certificates issued to domains on this IP — reveals other attacker infrastructure |
| `user_agent_detector.py` | HTTP request headers | Offensive tool identification, attacker toolchain profiling |

All lookups are passive — no packets are sent to the attacker's IP. This is public data collection, not active hacking back.

### Phase 4: Autonomous Execution

The agent doesn't wait for a human. It executes from a **pre-approved action pool** — a set of responses the security team has reviewed and authorized in advance (see `action-pool.yaml`).

Actions are organized into tiers:

| Tier | Authorization | Examples | When |
|------|--------------|----------|------|
| **Auto-execute** | Pre-approved, no human needed | Redirect to honeypot, run OSINT, apply temp block, collect evidence | 3am, no one awake |
| **Auto-execute + notify** | Pre-approved, but alert on-call | Block IP range, sinkhole domain, isolate host | High severity events |
| **PR required** | Needs human review before deploy | Permanent firewall changes, new Suricata rules, infrastructure changes | Business hours |

For The Mirror, all actions are tier 1 (auto-execute) — redirect, OSINT, temp block, evidence collection. The agent acts immediately and logs everything.

### Phase 5: Audit Log + Post-Mortem

Every action the agent takes is recorded in a structured audit log (see `audit-log-schema.json`):

- **What** was done (action type, parameters, result)
- **Why** it was done (trigger signal, detection confidence, which playbook rule matched)
- **When** it happened (timestamps for every step)
- **What evidence** supports the decision (telemetry data, OSINT results, honeypot logs)

When the security team arrives in the morning, they don't find a PR to review. They find a **post-mortem report** (see `templates/postmortem-template.md`): here's what happened, here's what the agent did about it, here's the attacker dossier, here's the evidence chain. The team reviews the report, validates the agent's decisions, and adjusts the action pool if needed.

This creates a feedback loop:

```
Agent acts (night) → Team reviews (morning) → Playbook improves → Agent acts better (next night)
```

## Architecture

```
                    ┌──────────────────────────────────────────────────────┐
                    │                  AI Agent                            │
                    │                                                      │
                    │  ┌──────────────────────────────────────────────┐    │
                    │  │           Action Pool (pre-approved)         │    │
                    │  │  ┌─────────┐ ┌────────┐ ┌───────┐ ┌──────┐ │    │
                    │  │  │Redirect │ │  OSINT │ │ Block │ │Collect│ │    │
                    │  │  │to honey │ │  scan  │ │ temp  │ │evid. │ │    │
                    │  │  └─────────┘ └────────┘ └───────┘ └──────┘ │    │
                    │  └──────────────────────────────────────────────┘    │
                    │         ▲                                            │
Telemetry ─────────▶  ┌──────┴───┐   ┌──────────┐   ┌────────────┐       │
(IDS, logs)         │  │ Detector │──▶│ Execute  │──▶│ OSINT      │       │
                    │  │          │   │ from     │   │ Collector  │       │
                    │  └──────────┘   │ pool     │   │            │       │
                    │                 └──────────┘   │ - WHOIS    │       │
                    │                      │         │ - rDNS     │       │
Attacker ───────────┼──────────────────────┘         │ - Shodan   │       │
 (redirected)       │                                │ - CT logs  │       │
                    │                                └─────┬──────┘       │
                    │                                      │              │
Honeypot ◀──────────┼──────────────────────────────────────┘              │
 (logs TTPs)        │                                                      │
                    │  ┌──────────────────────────────────────────────┐    │
                    │  │ Post-Mortem Generator                        │    │
                    │  │  - Compile OSINT + honeypot logs             │    │
                    │  │  - Full audit trail of every action taken    │    │
                    │  │  - Generate dossier + IOCs                   │    │
                    │  │  - Write post-mortem report                  │    │
                    │  │  - Notify team                               │    │
                    │  └──────────────────────────────────────────────┘    │
                    └──────────────────────────────────────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────────────┐
                    │              Morning Review (Human)                  │
                    │  - Read post-mortem report                          │
                    │  - Validate agent decisions                         │
                    │  - Adjust action pool if needed                     │
                    │  - Escalate or close                                │
                    └──────────────────────────────────────────────────────┘
```

## Files

```
scenario-the-mirror/
├── TALK.md                         # 5-minute talk script with fencing metaphor
├── README.md                       # This file — full implementation guide
├── DEPLOYMENT.md                   # How to deploy: systemd, permissions, input, flow
├── PHASE2-LLM.md                   # Phase 2: adding an LLM to the decision layer
├── mirror_agent.py                 # Main agent orchestrator (autonomous mode)
├── action-pool.yaml                # Pre-approved actions the agent can execute
├── audit-log-schema.json           # Schema for structured audit trail
├── suspicious-user-agents.yaml     # User-agent signatures for offensive tool detection
├── osint-modules/
│   ├── whois_lookup.py             # WHOIS registry lookup
│   ├── reverse_dns.py              # Reverse DNS (PTR) lookup
│   ├── shodan_lookup.py            # Shodan API query
│   ├── cert_transparency.py        # Certificate Transparency log search
│   └── user_agent_detector.py      # User-agent classification and tool identification
├── honeypot/
│   ├── docker-compose.yml          # Honeypot stack
│   └── log-format.json             # Expected log schema for TTP extraction
├── templates/
│   ├── dossier-template.md         # Intelligence report template
│   ├── postmortem-template.md      # Post-mortem report template
│   ├── redirect-rule.nft           # nftables DNAT template
│   └── pr-body.md                  # PR body template (for tier 3 actions)
└── examples/
    ├── example-dossier.md          # What a completed dossier looks like
    ├── example-postmortem.md       # What a post-mortem report looks like
    └── example-audit-log.json      # What the audit trail looks like
```

## Deployment & Implementation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** — How to run the agent: systemd service, permissions model, input sources, and the step-by-step flow from telemetry event to autonomous response.
- **[PHASE2-LLM.md](PHASE2-LLM.md)** — How adding an LLM to the decision layer improves novel pattern recognition, weak signal correlation, natural language audit trails, and adaptive confidence scoring — without changing the action pool or permission boundaries.

## Legal & Ethical Notes

- All OSINT (**Open Source Intelligence** — intelligence gathered from publicly available sources) in this scenario uses **publicly available data only** — WHOIS records, DNS, Shodan (which indexes public-facing services), and Certificate Transparency logs (which are public by design)
- **No active scanning** of the attacker's infrastructure is performed
- The honeypot collects data about traffic the attacker **voluntarily sends to your network**
- Always consult legal counsel before implementing active defense measures in production
