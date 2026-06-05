# Phase 8: GitHub Issues Integration - DEFERRED

**Status**: ⏸️ Deferred  
**Reason**: Requires separate repository for incident tracking  
**Date Deferred**: 2026-06-04

---

## Why Deferred

Phase 8 would auto-create GitHub Issues for each incident, but:
- Current repo (cyber-riposte) is for the Mirror implementation itself
- Need separate repository for incident tracking (e.g., `cyber-riposte-incidents`)
- Don't want to clutter implementation repo with incident issues

---

## What Phase 8 Would Include

### Auto-Create GitHub Issues

When incident detected:
1. Create GitHub issue in incidents repository
2. Issue title: `[INC-YYYY-MMDD-HHMM] Reconnaissance from {IP}`
3. Issue body includes:
   - Attacker IP and OSINT dossier
   - Detection confidence and signals
   - Actions taken (VirtualService, OSINT, block)
   - Audit trail excerpt
   - Evidence links (WHOIS, Shodan, honeypot logs)
   - Metrics snapshot (cache hit rate, detection latency)

### Issue Labels

Auto-apply labels:
- Severity: `high`, `medium`, `low`
- Detection type: `reconnaissance`, `enumeration`, `exploitation`
- Tool detected: `nmap`, `nuclei`, `sqlmap`, etc.
- Status: `active`, `investigating`, `resolved`, `false-positive`

### Issue Milestones

Group incidents by time period:
- Week: `2024-W24` (incidents from that week)
- Month: `2024-06` (incidents from that month)

### Evidence as Gists

Upload evidence to GitHub Gists:
- OSINT dossier (Markdown)
- Audit log excerpt (JSON)
- Honeypot session logs (text)
- Link gists in issue body

### Slack Notification

Post to `#security-incidents` Slack channel:
```
🚨 New incident: INC-2024-0615-0314
Attacker: 203.0.113.42 (AS12345, Example Corp)
Detection: Nuclei reconnaissance (confidence: 0.97)
Actions: Redirected to honeypot, OSINT collected, temp block
Issue: https://github.com/hlipsig/cyber-riposte-incidents/issues/42
```

### Feedback Loop

When issue closed:
- Check for `lessons-learned` label
- Parse post-mortem notes
- Suggest action pool updates
- Update detection rules if false positive

---

## Implementation Plan (When Ready)

### Prerequisites

1. **Create incidents repository**:
   ```bash
   # On GitHub: Create new repo "cyber-riposte-incidents"
   # Settings:
   # - Private repository
   # - Issues enabled
   # - Disable: Wikis, Projects, Discussions
   # - Labels: high, medium, low, reconnaissance, enumeration, etc.
   # - Milestones: Create weekly/monthly milestones
   ```

2. **GitHub App or Personal Access Token**:
   ```bash
   # Create GitHub App with permissions:
   # - Issues: Read/Write
   # - Contents: Read (for gists)
   # OR
   # Create PAT with scopes: repo, gist
   ```

3. **Slack Webhook** (optional):
   ```bash
   # Create Incoming Webhook for #security-incidents
   # https://api.slack.com/messaging/webhooks
   ```

### Files to Create

1. **agent/github_integration.py**:
   - GitHubIssueManager class
   - create_incident_issue() method
   - upload_evidence_gist() method
   - apply_labels() method
   - set_milestone() method

2. **agent/slack_integration.py**:
   - SlackNotifier class
   - post_incident_notification() method
   - Format message with incident details

3. **templates/github-issue.md**:
   - Template for issue body
   - Sections: Summary, Dossier, Actions Taken, Evidence, Next Steps

4. **k8s/agent-secret.yaml** (update):
   ```yaml
   stringData:
     GITHUB_TOKEN: "ghp_..."
     GITHUB_INCIDENTS_REPO: "hlipsig/cyber-riposte-incidents"
     SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/..."
   ```

5. **Update agent/executor.py**:
   ```python
   # After generate_postmortem()
   if Config.GITHUB_TOKEN:
       from agent.github_integration import create_incident_issue
       issue_url = create_incident_issue(incident_id, attacker_ip, detection, osint_data, audit)
       logger.info(f"GitHub issue created: {issue_url}")
   ```

### Testing

```bash
# 1. Set up test incident repo
# 2. Generate fake event
python3 event-producer-sim.py --scenario single --count 1

# 3. Verify issue created
# GitHub → Issues → Should see new issue

# 4. Verify Slack notification
# Check #security-incidents channel
```

---

## Dependencies to Add (When Implementing)

```txt
# requirements.txt
PyGithub>=2.1.1
slack-sdk>=3.26.0
```

---

## Estimated Effort

**Time**: 1-2 days  
**Complexity**: Medium  
**Dependencies**: New GitHub repository, GitHub token, Slack webhook (optional)

---

## Alternatives Considered

### Option 1: Use Current Repo Issues
- ❌ Clutters implementation repo
- ❌ Mixes code issues with incident issues
- ❌ Hard to separate concerns

### Option 2: Jira/Linear/GitHub Projects
- ✅ More structured incident tracking
- ❌ Requires different API integration
- ❌ May require paid tier

### Option 3: Database Only (No External Issue Tracker)
- ✅ Simplest (already done in Phase 3)
- ❌ Less visibility for team
- ❌ No notifications
- ❌ No collaboration features

**Decision**: Defer until dedicated incidents repo is created.

---

## When to Resume Phase 8

Resume when:
1. ✅ Created `cyber-riposte-incidents` repository
2. ✅ Configured GitHub App or PAT
3. ✅ Defined issue labels and milestones
4. ✅ Optional: Slack webhook configured
5. ✅ Ready to integrate with agent

---

## Current Workaround

Until Phase 8 is implemented:
- Incidents tracked in PostgreSQL database (`incidents` table)
- Post-mortem reports generated as Markdown files
- Evidence stored in database (`evidence` table)
- Query database for incident investigation:
  ```sql
  SELECT * FROM recent_incidents ORDER BY first_seen DESC LIMIT 10;
  ```

This is sufficient for MVP and testing. Phase 8 adds collaboration and visibility for team.

---

**Next**: Phase 9 (Hot-Reload Configuration)
