# 03 — DNS Sinkhole for C2 Domains

## Trigger Signal

The agent correlates DNS query logs against threat intelligence feeds and detects internal hosts resolving domains associated with known command-and-control infrastructure.

## Agent Response

The agent opens a PR that adds a sinkhole entry to the Unbound DNS resolver config, redirecting the C2 domain to localhost (or to an analysis server for payload capture). The PR body includes which internal hosts made the queries and the threat intel source.

## Files

- `sinkhole-entries/` — directory of generated sinkhole configs (one file per domain, GitOps-friendly)
- `template-sinkhole.conf` — Unbound config template
- `update_from_feed.py` — sketch of agent logic to pull IOCs from a threat intel API and generate entries

## Example PR the Agent Would Open

> **Title:** `sinkhole: block C2 callback to malware-c2.example.com`
>
> **Body:** DNS telemetry shows 3 internal hosts (`10.1.2.15`, `10.1.2.22`, `10.1.3.8`) resolving `malware-c2.example.com` over the last 4 hours. This domain is flagged as C2 infrastructure by AlienVault OTX (pulse ID: 64a3f...). Proposing a sinkhole to `127.0.0.1`. Incident response should investigate the querying hosts.
