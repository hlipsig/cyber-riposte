# 04 — Canary Tokens / Tripwire Files

## Trigger Signal

A canary file (decoy credentials, fake API keys, dummy database exports) is accessed. The inotify watcher fires an alert, indicating an attacker has gained access and is harvesting credentials or sensitive data.

## Agent Response

When a canary triggers, the agent can respond in two ways:

1. **Immediate alert** — fire a webhook to Slack/PagerDuty with access details
2. **Deploy more canaries** — open a PR to plant additional tripwire files in paths the attacker is likely to explore next, expanding the detection surface

## Files

- `canary_watcher.py` — inotify-based watcher that alerts on canary access
- `canaries/` — example decoy files (fake credentials, API keys, env files)
- `deploy_canaries.yaml` — config defining where canaries should be planted
- `canary_watcher.service` — systemd unit for running the watcher

## Example PR the Agent Would Open

> **Title:** `canary: deploy additional tripwires after trigger on prod-web-02`
>
> **Body:** Canary file `/opt/backup/db_credentials.csv` was accessed on `prod-web-02` at 03:14:22Z. Process: `cat` (PID 48291, user `www-data`). Deploying additional canaries in adjacent paths to track lateral movement. Alert sent to #security-incidents.
