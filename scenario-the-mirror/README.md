# Scenario: The Mirror — Turn Their Tools Against Them

> *"In fencing, a riposte is the counterattack launched immediately after parrying. You use your opponent's forward momentum against them. The Mirror is a digital riposte."*

## Overview

When an attacker scans your infrastructure, most defenders block the IP and move on. The Mirror does something different: it **redirects the attacker to a honeypot** while simultaneously **running passive OSINT on the attacker's own infrastructure**. The attacker's probe is the opening — every packet they send reveals something about them.

The AI agent orchestrates the entire sequence: detect the scan, reroute to the honeypot, launch the OSINT collection, log the attacker's behavior, and open a PR that includes both the defensive action *and* a full intelligence dossier on the attacker.

## How the Agent Works

### Phase 1: Detection

The agent monitors telemetry for reconnaissance patterns:
- Port scan signatures (many ports from one source in short timeframes)
- Directory brute-forcing (high 404 rate from a single source)
- Version fingerprinting (specific probe patterns for known scanners like Nmap, Masscan)

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

All lookups are passive — no packets are sent to the attacker's IP. This is public data collection, not active hacking back.

### Phase 4: Dossier + PR

The agent compiles everything into a structured intelligence report and opens a PR:

1. **Block/reroute rule** — nftables rule to permanently handle this source
2. **Honeypot log summary** — what the attacker did, what tools they used, what they were looking for
3. **OSINT dossier** — who owns the IP, what's running on it, what other infrastructure is associated
4. **IOC extract** — IPs, domains, and hashes for ingestion into threat intel platforms

## Architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │                  AI Agent                       │
                    │                                                 │
Telemetry ─────────▶  ┌──────────┐   ┌──────────┐   ┌────────────┐  │
(IDS, logs)         │  │ Detector │──▶│ Redirect │──▶│ OSINT      │  │
                    │  │          │   │ to       │   │ Collector  │  │
                    │  └──────────┘   │ honeypot │   │            │  │
                    │                 └──────────┘   │ - WHOIS    │  │
                    │                      │         │ - rDNS     │  │
Attacker ───────────┼──────────────────────┘         │ - Shodan   │  │
 (redirected)       │                                │ - CT logs  │  │
                    │                                └─────┬──────┘  │
                    │                                      │         │
Honeypot ◀──────────┼──────────────────────────────────────┘         │
 (logs TTPs)        │                                                │
                    │  ┌─────────────────────────────────────────┐   │
                    │  │ Dossier Generator                       │   │
                    │  │  - Compile OSINT + honeypot logs        │   │
                    │  │  - Generate block rule                  │   │
                    │  │  - Extract IOCs                         │   │
                    │  │  - Open PR                              │   │
                    │  └─────────────────────────────────────────┘   │
                    └─────────────────────────────────────────────────┘
```

## Files

```
scenario-the-mirror/
├── TALK.md                         # 5-minute talk script with fencing metaphor
├── README.md                       # This file — full implementation guide
├── mirror_agent.py                 # Main agent orchestrator
├── osint-modules/
│   ├── whois_lookup.py             # WHOIS registry lookup
│   ├── reverse_dns.py              # Reverse DNS (PTR) lookup
│   ├── shodan_lookup.py            # Shodan API query
│   └── cert_transparency.py        # Certificate Transparency log search
├── honeypot/
│   ├── docker-compose.yml          # Honeypot stack
│   └── log-format.json             # Expected log schema for TTP extraction
├── templates/
│   ├── dossier-template.md         # Intelligence report template
│   ├── redirect-rule.nft           # nftables DNAT template
│   └── pr-body.md                  # PR body template
└── examples/
    └── example-dossier.md          # What a completed dossier looks like
```

## Legal & Ethical Notes

- All OSINT in this scenario uses **publicly available data only** — WHOIS records, DNS, Shodan (which indexes public-facing services), and Certificate Transparency logs (which are public by design)
- **No active scanning** of the attacker's infrastructure is performed
- The honeypot collects data about traffic the attacker **voluntarily sends to your network**
- Always consult legal counsel before implementing active defense measures in production
