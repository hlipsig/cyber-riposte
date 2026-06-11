# The Mirror - Full Autonomous Implementation Plan

## Current State (Post-CTF)

✅ **Working Components:**
- PostgreSQL database with incidents table
- Web dossier interface with authentication
- Simple HTTP honeypot (nginx)
- Log detection patterns (Nmap, gobuster, etc.)
- AI narrator (Hugging Face integration)
- Manual incident creation workflow
- RBAC for Kubernetes API access

❌ **Missing Components:**
- Suricata IDS integration
- Automatic Istio traffic redirection
- OSINT modules (Shodan, WHOIS, reverse DNS, etc.)
- GitHub issue creation
- Autonomous action execution
- Evidence collection and storage
- Post-mortem report generation

---

## Implementation Phases

### Phase 1: Suricata Integration (IDS Detection)
**Goal**: Replace manual log watching with real Suricata EVE JSON alerts

**Tasks:**
1. Deploy Suricata as DaemonSet on OpenShift
2. Configure EVE JSON output to shared volume or Redis
3. Update `detector.py` to consume Suricata alerts
4. Add signature-based detection rules
5. Combine IDS alerts with HTTP log analysis

**Files to Create/Update:**
- `k8s/suricata-daemonset.yaml`
- `agent/suricata_consumer.py`
- `agent/detector.py` (enhance)
- `suricata/rules/*.rules`

**Validation:**
- Nmap scan triggers Suricata alert
- Alert flows into detection system
- Confidence score combines IDS + user-agent

---

### Phase 2: Istio Traffic Redirection
**Goal**: Automatically redirect detected attackers to honeypot

**Tasks:**
1. Configure Istio service mesh for namespace
2. Create VirtualService redirect logic
3. Implement dynamic route manipulation in executor
4. Add attacker IP to destination rules
5. Verify traffic flows to honeypot seamlessly

**Files to Create/Update:**
- `k8s/istio-config.yaml`
- `agent/istio_manager.py`
- `agent/executor.py` (add redirect_to_honeypot)
- `templates/virtual-service-template.yaml`

**Validation:**
- Detected attacker's requests go to honeypot
- Real users unaffected
- Redirect happens in <3 seconds

---

### Phase 3: OSINT Collection Modules
**Goal**: Gather intelligence on attacker infrastructure

**Tasks:**
1. Implement Shodan lookup module
2. Implement WHOIS lookup module
3. Implement reverse DNS module
4. Implement certificate transparency lookup
5. Add OSINT caching (24hr TTL)
6. Store results in database

**Files to Create:**
- `osint-modules/shodan_lookup.py`
- `osint-modules/whois_lookup.py`
- `osint-modules/reverse_dns.py`
- `osint-modules/cert_transparency.py`
- `osint-modules/geoip_lookup.py`

**Database Updates:**
- `attacker_info` JSON field in incidents table
- Evidence table for raw OSINT data

**Validation:**
- Shodan returns open ports on attacker IP
- WHOIS returns ASN and abuse contact
- Data cached to avoid rate limits

---

### Phase 4: GitHub Issue Creation
**Goal**: Automatically create incident reports as GitHub issues

**Tasks:**
1. Implement GitHub API integration
2. Create issue template with incident data
3. Add OSINT findings to issue body
4. Include evidence links and timeline
5. Tag issues with labels (severity, type)

**Files to Create:**
- `agent/github_reporter.py`
- `templates/github-issue-template.md`
- Add GITHUB_TOKEN to secrets

**Issue Format:**
```markdown
## Incident: INC-YYYYMMDD-XXXXXX

**Attacker IP**: 1.2.3.4  
**Detection Time**: 2026-06-11 18:40:14 UTC  
**Confidence**: 0.98  

### Attack Timeline
- 18:40:14 - Nmap scan detected (Suricata alert)
- 18:40:15 - Redirected to honeypot
- 18:40:30 - OSINT collection completed

### Attacker Intelligence
- **ASN**: AS12345 (Evil Corp)
- **Shodan**: 5 open ports (22, 80, 443, 3389, 8080)
- **GeoIP**: Moscow, Russia

### Actions Taken
1. ✅ Redirected to honeypot
2. ✅ Collected OSINT
3. ✅ Applied 1-hour IP block
4. ✅ Evidence archived

### Evidence
- Suricata alert: [link]
- Honeypot logs: [link]
- OSINT data: [link]
```

**Validation:**
- Issue created within 30 seconds of detection
- Contains all relevant data
- Properly tagged and formatted

---

### Phase 5: Evidence Collection & Storage
**Goal**: Archive all evidence for forensic analysis

**Tasks:**
1. Create evidence storage structure
2. Archive Suricata alerts (JSON)
3. Archive honeypot logs
4. Archive OSINT results
5. Store packet captures (optional)
6. Link evidence to incidents

**Database Updates:**
```sql
CREATE TABLE evidence (
  id SERIAL PRIMARY KEY,
  incident_id VARCHAR(50) REFERENCES incidents(incident_id),
  evidence_type VARCHAR(50),  -- 'suricata_alert', 'honeypot_log', 'osint', 'pcap'
  data JSONB,
  file_path TEXT,
  collected_at TIMESTAMP DEFAULT NOW()
);
```

**Files to Create:**
- `agent/evidence_collector.py`
- `k8s/evidence-pvc.yaml`

**Validation:**
- All evidence linked to incident
- Queryable from database
- Downloadable from web dossier

---

### Phase 6: Autonomous Action Execution
**Goal**: Execute actions without human intervention

**Tasks:**
1. Implement action tier system
2. Add confidence threshold checks
3. Execute Tier 1 actions automatically
4. Log all decisions and rationale
5. Create audit trail

**Action Tiers:**
- **Tier 1 (Auto-execute)**: Honeypot redirect, OSINT, temp block (<1hr)
- **Tier 2 (Auto + notify)**: Extended block (>1hr), IP range blocks
- **Tier 3 (PR required)**: Permanent rules, infrastructure changes

**Files to Update:**
- `agent/executor.py` (autonomous execution)
- `action-pool.yaml` (tier definitions)
- `agent/audit.py` (enhanced logging)

**Validation:**
- High-confidence detection triggers auto-redirect
- All actions logged with rationale
- Audit log queryable

---

### Phase 7: Post-Mortem Report Generation
**Goal**: Generate human-readable incident reports

**Tasks:**
1. Create report template
2. Aggregate incident data
3. Include timeline visualization
4. Add OSINT summary
5. Provide action recommendations

**Files to Create:**
- `agent/postmortem_generator.py`
- `templates/postmortem-template.md`

**Report Sections:**
1. Executive Summary
2. Attack Timeline
3. Attacker Profile (OSINT)
4. Actions Taken
5. Evidence Chain
6. Recommendations
7. Lessons Learned

**Validation:**
- Report generated automatically
- Readable by non-technical stakeholders
- Includes all relevant context

---

### Phase 8: Integration & Testing
**Goal**: End-to-end autonomous operation

**Tasks:**
1. Wire all components together
2. Test full detection → redirect → OSINT → GitHub flow
3. Performance tuning (must complete in <30 seconds)
4. Error handling and resilience
5. Monitoring and alerting

**Test Scenarios:**
1. Nmap scan → auto-redirect → OSINT → GitHub issue
2. Gobuster scan → detection → honeypot engagement
3. SQL injection attempt → block + evidence collection
4. Multiple attackers simultaneously
5. False positive handling

**Success Criteria:**
- ✅ Detection within 5 seconds
- ✅ Redirect within 10 seconds
- ✅ OSINT completed within 30 seconds
- ✅ GitHub issue created within 60 seconds
- ✅ All evidence archived
- ✅ Zero false positives on test traffic

---

## Architecture Diagram

```
┌─────────────────┐
│   Attacker      │
└────────┬────────┘
         │ HTTP Request
         ▼
┌─────────────────┐      Alerts      ┌──────────────────┐
│   Suricata IDS  │ ────────────────▶│  Mirror Agent    │
│  (DaemonSet)    │                  │  (Autonomous)    │
└─────────────────┘                  └────────┬─────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────┐
                    │                         │                     │
                    ▼                         ▼                     ▼
         ┌─────────────────┐      ┌─────────────────┐   ┌──────────────────┐
         │ Istio Manager   │      │ OSINT Collector │   │ Evidence Storage │
         │ (VirtualService)│      │ (Shodan/WHOIS)  │   │  (PostgreSQL)    │
         └────────┬────────┘      └─────────────────┘   └──────────────────┘
                  │                                                │
                  │ Redirect                                       │
                  ▼                                                ▼
         ┌─────────────────┐                              ┌──────────────────┐
         │   Honeypot      │                              │  GitHub Issues   │
         │   (Cowrie SSH)  │                              │  (Incident RPT)  │
         └─────────────────┘                              └──────────────────┘
```

---

## Timeline Estimate

- **Phase 1**: Suricata Integration - 4 hours
- **Phase 2**: Istio Redirection - 6 hours
- **Phase 3**: OSINT Modules - 8 hours
- **Phase 4**: GitHub Integration - 3 hours
- **Phase 5**: Evidence Collection - 4 hours
- **Phase 6**: Autonomous Execution - 4 hours
- **Phase 7**: Post-Mortem Reports - 3 hours
- **Phase 8**: Integration & Testing - 6 hours

**Total**: ~38 hours (~5 days of focused work)

---

## Next Steps

1. Review this plan
2. Prioritize phases (suggest: 1 → 2 → 3 → 6 → 4 → 5 → 7 → 8)
3. Start with Phase 1 (Suricata) to establish detection foundation
4. Build incrementally, testing each phase

**Question**: Which phase should we start with?
