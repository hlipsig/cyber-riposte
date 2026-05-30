# 07 — Credential Stuffing Forecast

## Trigger Signal

The agent detects a pattern of failed logins distributed across many source IPs but targeting the same set of accounts — or the same credentials appearing across multiple services. Each individual source stays below the per-IP block threshold, but the aggregate pattern reveals a coordinated credential stuffing campaign.

## Predictive Angle

Rather than waiting for a successful account compromise, the agent recognizes the campaign early from the statistical pattern and acts preemptively: rate-limiting the targeted accounts, enforcing temporary MFA, or blocking the credential sets across all services.

## Agent Response

The agent opens a PR with:
1. A rate-limit config for the targeted accounts/endpoints
2. A temporary MFA enforcement policy for accounts under attack
3. An alert with the campaign fingerprint (common user-agent, timing pattern, credential overlap)

## Files

- `detector.py` — sketch of the distributed stuffing detector (sliding window correlation)
- `template-rate-limit.yaml` — nginx/HAProxy rate-limit template for targeted endpoints
- `template-mfa-enforcement.yaml` — temporary MFA policy template

## Example PR the Agent Would Open

> **Title:** `predict: credential stuffing campaign targeting 23 accounts across 140 sources`
>
> **Body:** Over the last 30 minutes, 140 unique source IPs have attempted logins against a common set of 23 accounts on `auth.example.com`. No single IP exceeds 3 attempts, but the aggregate pattern (shared user-agent `python-requests/2.28`, uniform 2-3s spacing, credential reuse across accounts) indicates a coordinated campaign. Proposing rate limits on the targeted accounts and temporary MFA enforcement. No accounts have been compromised yet.
