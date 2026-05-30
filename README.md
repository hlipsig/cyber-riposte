# Cyber Riposte

A sandbox of ideas for AI-agent-driven defensive security response. The concept: an AI agent monitors telemetry data (auth logs, DNS query logs, IDS alerts, cluster events) and, when it detects adversarial activity, **opens a pull request** with the appropriate countermeasure — a firewall rule change, a DNS sinkhole entry, a new NetworkPolicy, etc.

The human stays in the loop via code review. The agent proposes; the operator approves and merges.

> This is an **ideas repo** — templates, sketches, and reference implementations to explore the pattern. Nothing here is production-hardened.

## The Pattern

```
Telemetry Source          AI Agent                     GitOps / PR
┌──────────────┐       ┌──────────────────┐        ┌──────────────────┐
│ Auth logs     │──────▶│                  │        │                  │
│ DNS query log │──────▶│  Observe         │        │  git checkout -b │
│ IDS alerts    │──────▶│  Correlate       │───────▶│  Apply template  │
│ K8s events    │──────▶│  Predict         │        │  Open PR         │
│ Flow data     │──────▶│  Decide response │        │  Assign reviewer │
│ CVE feeds     │──────▶│                  │        │                  │
│ IP reputation │──────▶│                  │        │                  │
└──────────────┘       └──────────────────┘        └──────────────────┘
                                                          │
                                                          ▼
                                                   Human reviews &
                                                   merges to deploy
```

## Playbooks

### Reactive — Respond to observed threats

| # | Directory | Agent Response | Trigger Signal |
|---|-----------|---------------|----------------|
| 1 | [01-auto-block](01-auto-block/) | PR an nftables drop rule for offending IPs | Auth failure spike from a single source |
| 2 | [02-honeypot-reroute](02-honeypot-reroute/) | PR a DNAT rule + honeypot stack | Reconnaissance patterns against prod services |
| 3 | [03-dns-sinkhole](03-dns-sinkhole/) | PR a sinkhole entry for a C2 domain | DNS queries matching threat intel IOCs |
| 4 | [04-canary-tokens](04-canary-tokens/) | PR new tripwire files into sensitive paths | Post-compromise access to decoy credentials |
| 5 | [05-k8s-microsegment](05-k8s-microsegment/) | PR a NetworkPolicy to isolate a compromised pod | Anomalous east-west traffic in a cluster |
| 6 | [06-suricata-response](06-suricata-response/) | PR a custom Suricata rule for a new attack pattern | Novel alert signatures in IDS telemetry |

### Predictive — Act before the attack succeeds

| # | Directory | Agent Response | Trigger Signal |
|---|-----------|---------------|----------------|
| 7 | [07-credential-stuffing-forecast](07-credential-stuffing-forecast/) | PR rate limits + temporary MFA enforcement | Distributed login failures across many IPs targeting common accounts |
| 8 | [08-lateral-movement-prediction](08-lateral-movement-prediction/) | PR preemptive firewall rules to cut predicted pivot paths | Single host compromised — agent maps likely next targets |
| 9 | [09-dns-entropy-detection](09-dns-entropy-detection/) | PR sinkhole for statistically anomalous domains | High-entropy DNS queries (tunneling fingerprint, no threat intel match) |
| 10 | [10-cve-race](10-cve-race/) | PR WAF/IDS rules for predicted exploit pattern | New CVE published, affected services found in inventory, no public exploit yet |
| 11 | [11-egress-baseline](11-egress-baseline/) | PR egress restriction for deviating workload | New destination, off-hours traffic, or volume spike vs. learned baseline |
| 12 | [12-vpn-source-flagging](12-vpn-source-flagging/) | PR graduated response (block/rate-limit/challenge) | Source IP belongs to known VPN/proxy/Tor, hitting sensitive endpoints |

## Why PRs Instead of Direct Action?

- **Auditability** — every defensive change is a reviewed, mergeable diff
- **Reversibility** — revert a bad response with `git revert`, not a firefight
- **Human-in-the-loop** — the agent is fast but the operator has final say
- **GitOps compatibility** — merged changes deploy through existing CI/CD pipelines (ArgoCD, Flux, Ansible, etc.)

## End-to-End Scenario: The Mirror

The [scenario-the-mirror](scenario-the-mirror/) directory contains a fully worked example that ties the playbooks together: an AI agent detects an attacker scanning your infrastructure, silently redirects them to a honeypot, and simultaneously runs passive OSINT on the attacker's own IP. The result is a PR that contains both the block rule *and* a full intelligence dossier on the attacker.

> *"In fencing, a riposte uses your opponent's forward momentum against them. The Mirror is a digital riposte — they scanned us, so we scanned them back."*

See [TALK.md](scenario-the-mirror/TALK.md) for the 5-minute presentation version.

## What This Repo Is (and Isn't)

**Is:** A collection of templates and ideas for how an AI agent could propose defensive responses as code. A starting point for discussion and experimentation.

**Isn't:** A production framework, a deployable agent, or a substitute for a SOC. The scripts and configs here are intentionally simple to fit on a presentation slide and spark conversation.

## Disclaimer

This repository is a **collection of ideas** developed for the *Cyber Riposte* presentation. The techniques and countermeasures described here are largely for **entertainment and educational purposes** — they are meant to spark discussion about what AI-driven defensive security could look like, not to serve as production-ready implementations.

**Do not implement any of these techniques without a thorough review by your organization's legal, compliance, and security teams.** Active defense measures — particularly those involving traffic redirection, honeypots, and counter-reconnaissance — may have legal implications that vary by jurisdiction. Even passive OSINT collection should be reviewed against your organization's policies and applicable regulations before deployment.

This repository is not legal advice. When in doubt, consult appropriate parties before acting on any ideas presented here.
