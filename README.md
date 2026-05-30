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
│ K8s events    │──────▶│  Decide response │        │  Open PR         │
│ Flow data     │──────▶│                  │        │  Assign reviewer │
└──────────────┘       └──────────────────┘        └──────────────────┘
                                                          │
                                                          ▼
                                                   Human reviews &
                                                   merges to deploy
```

## Playbooks

Each directory contains a response template the agent would use when it detects a specific class of threat:

| # | Directory | Agent Response | Trigger Signal |
|---|-----------|---------------|----------------|
| 1 | [01-auto-block](01-auto-block/) | PR an nftables drop rule for offending IPs | Auth failure spike from a single source |
| 2 | [02-honeypot-reroute](02-honeypot-reroute/) | PR a DNAT rule + honeypot stack | Reconnaissance patterns against prod services |
| 3 | [03-dns-sinkhole](03-dns-sinkhole/) | PR a sinkhole entry for a C2 domain | DNS queries matching threat intel IOCs |
| 4 | [04-canary-tokens](04-canary-tokens/) | PR new tripwire files into sensitive paths | Post-compromise access to decoy credentials |
| 5 | [05-k8s-microsegment](05-k8s-microsegment/) | PR a NetworkPolicy to isolate a compromised pod | Anomalous east-west traffic in a cluster |
| 6 | [06-suricata-response](06-suricata-response/) | PR a custom Suricata rule for a new attack pattern | Novel alert signatures in IDS telemetry |

## Why PRs Instead of Direct Action?

- **Auditability** — every defensive change is a reviewed, mergeable diff
- **Reversibility** — revert a bad response with `git revert`, not a firefight
- **Human-in-the-loop** — the agent is fast but the operator has final say
- **GitOps compatibility** — merged changes deploy through existing CI/CD pipelines (ArgoCD, Flux, Ansible, etc.)

## What This Repo Is (and Isn't)

**Is:** A collection of templates and ideas for how an AI agent could propose defensive responses as code. A starting point for discussion and experimentation.

**Isn't:** A production framework, a deployable agent, or a substitute for a SOC. The scripts and configs here are intentionally simple to fit on a presentation slide and spark conversation.

## Disclaimer

For authorized defensive use, security research, and educational purposes only.
