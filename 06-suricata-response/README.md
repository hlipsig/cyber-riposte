# 06 — Suricata IDS Rules + Auto-Response

## Trigger Signal

The agent analyzes Suricata EVE JSON logs and identifies either:
- High-severity alerts from existing rules (active intrusion, exfiltration)
- Novel attack patterns that don't match any current rule (gap in coverage)

## Agent Response

Two response modes:

1. **Immediate block** — for high-severity alerts, the agent PRs an nftables rule to block the source (same as playbook 01, but triggered by IDS instead of auth logs)
2. **New detection rule** — when the agent identifies a novel pattern, it PRs a custom Suricata rule to detect future occurrences of that attack

## Files

- `custom-rules/` — directory for agent-generated Suricata rules
- `template-rule.rules` — Suricata rule template
- `responder.py` — sketch of agent logic: read EVE log, correlate, open PRs
- `example-rules.rules` — sample detection rules for common patterns

## Example PR the Agent Would Open

> **Title:** `detect: add rule for DNS exfiltration pattern (oversized TXT queries)`
>
> **Body:** EVE log analysis shows 847 DNS TXT queries from `10.1.5.30` to `*.data.attacker.example.com` over 3 minutes, with query names averaging 180 bytes. This matches a DNS tunneling / exfiltration pattern not covered by current rules. Proposing a Suricata rule to detect and alert on oversized TXT query bursts. Also proposing a block rule for `10.1.5.30` pending investigation.
