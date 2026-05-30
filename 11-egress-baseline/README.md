# 11 — Anomalous Egress Baseline Deviation

## Trigger Signal

The agent maintains per-workload egress baselines — normal destinations, traffic volume, timing patterns. It detects when a workload begins making requests that deviate from its established baseline.

## Predictive Angle

Data exfiltration and C2 callbacks often manifest as egress anomalies before any other indicator fires. By learning what "normal" looks like for each workload, the agent can flag the first signs of compromise — a new destination, an unusual hour, a volume spike — before data actually leaves the network.

## Agent Response

The agent opens a PR with:
1. An egress restriction (NetworkPolicy or firewall rule) scoped to the anomalous workload
2. Baseline comparison data showing what changed
3. A recommendation: investigate vs. auto-block based on deviation severity

## Files

- `baseline_monitor.py` — sketch of egress baseline learning and deviation scoring
- `template-restrict-egress.nft` — nftables egress restriction template
- `baseline-example.yaml` — example learned baseline for a workload

## Example PR the Agent Would Open

> **Title:** `predict: anomalous egress from prod-api-01 — new destination 45.33.x.x at 03:00 UTC`
>
> **Body:** Workload `prod-api-01` deviated from its egress baseline:
>
> | Metric | Baseline | Observed | Deviation |
> |---|---|---|---|
> | Destinations | 3 known IPs | +1 unknown (45.33.x.x) | New destination |
> | Time of day | 08:00-22:00 UTC | 03:14 UTC | Off-hours |
> | Volume (1h) | ~50 MB | 340 MB | 6.8x baseline |
> | Protocol | HTTPS only | HTTPS + DNS-over-HTTPS | New protocol |
>
> Severity score: **8.2/10**. Recommending egress restriction pending investigation. The new destination `45.33.x.x` resolves to a Linode VPS with no prior association to this workload.
