# 09 — DNS Tunneling Detection via Query Entropy

## Trigger Signal

The agent continuously scores DNS query patterns for statistical anomalies — high Shannon entropy in subdomain labels, abnormal query cadence, unusual TXT record sizes, or base32/base64-encoded subdomains.

## Predictive Angle

Traditional DNS sinkholing (playbook 03) relies on known-bad domains from threat intel feeds. This playbook catches *unknown* C2 and exfiltration channels by detecting the mathematical fingerprint of DNS tunneling — before the domain appears on any blocklist.

## Agent Response

The agent opens a PR with:
1. A sinkhole entry for the suspicious domain
2. A Suricata rule tailored to the specific tunneling pattern observed
3. Evidence: entropy scores, query samples, and the internal hosts involved

## Files

- `entropy_scorer.py` — DNS query entropy analysis (Shannon entropy, character distribution, label length)
- `template-sinkhole-entropy.conf` — Unbound sinkhole template with entropy evidence
- `thresholds.yaml` — configurable detection thresholds

## Example PR the Agent Would Open

> **Title:** `predict: probable DNS tunnel — x7f2a.data.suspicious-domain.example.com (entropy 4.2)`
>
> **Body:** DNS query analysis detected anomalous patterns for `*.suspicious-domain.example.com`:
>
> | Metric | Value | Normal Range |
> |---|---|---|
> | Subdomain entropy | 4.2 bits/char | < 3.0 |
> | Avg label length | 47 chars | < 15 |
> | Query rate | 12/min sustained | < 1/min |
> | Character set | base32-like | alphabetic |
>
> Querying hosts: `10.1.5.30`, `10.1.5.31`. This domain is not on any current threat intel list but matches the statistical fingerprint of DNS tunneling (iodine/dnscat2-style). Proposing sinkhole and custom Suricata rule.
