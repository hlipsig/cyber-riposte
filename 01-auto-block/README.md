# 01 — Auto-Block Offending IPs

## Trigger Signal

The agent observes a spike in authentication failures from a single source IP in auth log telemetry — consistent with brute-force or credential stuffing.

## Agent Response

The agent generates an nftables rule to drop traffic from the offending IP, commits it to a branch, and opens a PR. The PR body includes the telemetry evidence (failure count, time window, targeted service).

## Files

- `block-rules/` — directory where the agent would commit generated rules (GitOps tools pick these up on merge)
- `template.nft` — the nftables rule template the agent fills in
- `agent_example.py` — sketch of the agent logic: read telemetry, decide, open PR
- `auto_block_config.yaml` — configurable thresholds and allowlists

## Example PR the Agent Would Open

> **Title:** `block: drop traffic from 203.0.113.47 (142 auth failures in 60s)`
>
> **Body:** Telemetry shows 142 failed SSH password attempts from `203.0.113.47` targeting `prod-bastion-01` between 14:32:07Z and 14:33:01Z. This exceeds the threshold of 5 failures/60s. Proposing a drop rule. Auto-expires in 1 hour.
