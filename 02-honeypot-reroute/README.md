# 02 — Reroute Suspicious Traffic to a Honeypot

## Trigger Signal

The agent detects reconnaissance patterns — port scans, directory brute-forcing, or repeated probing of non-existent endpoints — from a source IP against production services.

## Agent Response

Instead of simply blocking the attacker (which tells them they've been detected), the agent opens a PR with two changes:

1. An nftables DNAT rule that silently redirects the attacker's traffic to a honeypot
2. A Docker Compose stack for the honeypot services (if not already running)

The attacker keeps "working" against what they think is a real target, while the team collects TTPs.

## Files

- `reroute-rules/` — directory for generated DNAT rules
- `template-dnat.nft` — nftables DNAT template
- `docker-compose.honeypot.yml` — honeypot service stack (Cowrie SSH + HTTP honeypot)
- `filebeat.yml` — log shipper config to forward honeypot logs to SIEM

## Example PR the Agent Would Open

> **Title:** `reroute: redirect 198.51.100.23 to honeypot (port scan detected)`
>
> **Body:** Source `198.51.100.23` scanned 847 ports on `prod-web-01` in 12 seconds. Rather than block (which signals detection), redirecting all traffic from this source to the honeypot stack at `10.0.0.99`. Honeypot logs will forward to the SIEM for TTP collection.
