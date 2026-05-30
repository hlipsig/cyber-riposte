# Post-Mortem Report: Incident {{ incident_id }}

**Generated:** {{ timestamp }}
**Agent:** The Mirror (cyber-riposte)
**Status:** Autonomous response completed — awaiting human review

---

## Executive Summary

{{ summary }}

## Timeline

| Time (UTC) | Action | Tier | Result |
|------------|--------|------|--------|
{{ timeline_rows }}

## What Triggered This

- **Signal:** {{ trigger_signal }}
- **Source IP:** {{ attacker_ip }}
- **Detection confidence:** {{ confidence }}
- **First seen:** {{ first_seen }}

## What the Agent Did

### Actions Taken (from pre-approved pool)

{{ action_details }}

### Actions NOT Taken (and why)

{{ actions_skipped }}

## Attacker Dossier

{{ dossier_summary }}

*Full dossier: [dossier-{{ attacker_ip_dashed }}.md]()*

## Honeypot Interaction Summary

- **Session duration:** {{ session_duration }}
- **Commands entered:** {{ command_count }}
- **Credentials attempted:** {{ cred_count }}
- **Files downloaded:** {{ files_downloaded }}
- **Tools identified:** {{ tools_identified }}

## Evidence Chain

Every action references its supporting evidence:

{{ evidence_chain }}

## IOCs Extracted

```json
{{ ioc_json }}
```

## Recommendations for Human Review

{{ recommendations }}

## Action Pool Feedback

Based on this incident, the agent suggests the following changes to the action pool:

{{ pool_feedback }}

---

*This report was generated autonomously. All actions were executed from the pre-approved action pool. No actions outside the pool were taken. Review the audit log for the complete trail: `{{ audit_log_path }}`*
