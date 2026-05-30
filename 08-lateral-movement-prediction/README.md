# 08 — Lateral Movement Prediction

## Trigger Signal

A canary triggers, an IDS alert fires, or a single host is confirmed compromised. The agent now has a known point of compromise.

## Predictive Angle

Instead of waiting for the attacker to pivot, the agent maps the network topology from the compromised host's perspective — same subnet, shared credentials, similar services, trust relationships — and predicts the most likely next targets. It preemptively locks down those paths.

## Agent Response

The agent opens a PR with:
1. Firewall rules to cut the compromised host off from predicted pivot targets
2. NetworkPolicies (if K8s) to isolate the blast radius
3. A topology map showing the predicted lateral movement paths and which ones are now blocked

## Files

- `predictor.py` — sketch of lateral movement path prediction
- `template-isolate-host.nft` — nftables rules to sever predicted pivot paths
- `topology-example.yaml` — example network topology the agent would reason over

## Example PR the Agent Would Open

> **Title:** `predict: preemptive isolation — 4 likely pivot targets from compromised prod-web-03`
>
> **Body:** Host `prod-web-03` (10.1.2.30) confirmed compromised via canary trigger at 03:14Z. Based on network topology analysis:
>
> | Predicted target | Reason | Action |
> |---|---|---|
> | `prod-web-04` (10.1.2.31) | Same subnet, same SSH key | Block 10.1.2.30 → 10.1.2.31 |
> | `prod-db-01` (10.1.3.10) | Direct DB access via app credentials | Block 10.1.2.30 → 10.1.3.10 |
> | `jenkins-01` (10.1.4.5) | SSH trust relationship | Block 10.1.2.30 → 10.1.4.5 |
> | `nfs-01` (10.1.3.50) | Mounted shared filesystem | Block 10.1.2.30 → 10.1.3.50 |
>
> Proposing preemptive firewall rules to cut these paths before lateral movement occurs.
