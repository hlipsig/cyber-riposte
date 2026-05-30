# 05 — Kubernetes NetworkPolicy for Microsegmentation

## Trigger Signal

The agent detects anomalous east-west traffic inside a Kubernetes cluster — a pod in the `frontend` namespace making direct connections to the database, a workload scanning internal service IPs, or unexpected egress to external hosts.

## Agent Response

The agent opens a PR with a Kubernetes NetworkPolicy that isolates the suspicious workload or tightens the allowed communication paths. If no default-deny policy exists yet, the agent proposes one as the first step.

## Files

- `policies/` — directory for generated NetworkPolicy manifests
- `default-deny.yaml` — baseline deny-all policy (agent proposes this first if missing)
- `template-isolate-pod.yaml` — template to isolate a specific compromised pod
- `template-restrict-egress.yaml` — template to cut off unauthorized external access

## Example PR the Agent Would Open

> **Title:** `netpol: isolate pod frontend-7b4d9 (anomalous DB connections)`
>
> **Body:** Cluster telemetry shows pod `frontend-7b4d9` in namespace `production` making direct TCP connections to `database:5432`, bypassing the `api` service. This violates the expected `frontend → api → database` traffic flow. Proposing a NetworkPolicy to restrict `frontend` pods to only reach `api` on port 8080. Also including a default-deny baseline if not already applied.
