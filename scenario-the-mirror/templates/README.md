# Incident Report Templates

This directory contains Jinja2 templates for generating incident reports, Slack notifications, executive summaries, and threat actor dossiers.

## Templates

### `incident-report.md.j2`

Comprehensive incident report with full details:
- Incident summary and metadata
- Attacker profile (IP, WHOIS, geolocation)
- Detection signals and confidence
- Actions taken (with success status)
- Evidence links (OSINT, honeypot logs, PCAP)
- Timeline of events
- Recommendations

**Output**: `incidents/{incident_id}.md`

### `slack-notification.md.j2`

Brief Slack-friendly notification:
- Incident ID and attacker info
- Detection signature and confidence
- Top 3 actions taken
- Evidence count
- Link to full report

**Output**: `incidents/slack/{incident_id}.txt`

### `executive-summary.md.j2`

Weekly/monthly summary report:
- Incident breakdown by severity and attack type
- Top attacking countries and ASNs
- Response actions summary
- OSINT cache performance
- Honeypot activity metrics

**Output**: `incidents/summaries/{date_range}.md`

### `dossier-enhanced.md.j2`

Detailed threat actor dossier:
- Network information (IP, WHOIS, geolocation)
- Reconnaissance profile (rDNS, Shodan, Certificate Transparency)
- Attack profile (detection signals, tools detected, timeline)
- Honeypot interactions (SSH sessions, HTTP requests, malware)
- Threat assessment (risk score, IOCs, attribution)
- Recommended actions (immediate, short-term, long-term)
- OSINT references and related incidents

**Output**: `incidents/dossiers/{attacker_ip_slug}.md`

## Usage

### Python API

```python
from agent.template_generator import IncidentReportGenerator

generator = IncidentReportGenerator()

# Generate incident report
incident_data = {
    "incident_id": "INC-2024-0615-0314",
    "attacker_ip": "203.0.113.42",
    "detection_signature": "Reconnaissance Detected",
    "confidence": 0.97,
    # ... more fields
}

report_path = generator.generate_incident_report(incident_data)
# Output: incidents/INC-2024-0615-0314.md

# Generate Slack notification
slack_msg = generator.generate_slack_notification(incident_data)
# Returns: Slack message string (also saved to incidents/slack/INC-*.txt)

# Generate dossier
dossier_path = generator.generate_dossier(dossier_data)
# Output: incidents/dossiers/203-0-113-42.md
```

### Manual GitHub Issue Creation

Once reports are generated, you can manually create GitHub issues:

```bash
# View the generated report
cat incidents/INC-2024-0615-0314.md

# Create issue using gh CLI
gh issue create \
  --title "[INC-2024-0615-0314] Reconnaissance Detected" \
  --body-file incidents/INC-2024-0615-0314.md \
  --label "security,incident,high"

# Or copy/paste to web UI
```

### Manual Slack Posting

```bash
# View Slack notification
cat incidents/slack/INC-2024-0615-0314.txt

# Copy and paste to #security-incidents channel
```

## Template Variables

### Common Variables

All templates support these common variables:

- `incident_id` - Unique incident identifier (e.g., "INC-2024-0615-0314")
- `attacker_ip` - Source IP address
- `attacker_ip_slug` - IP with dots replaced by dashes (for filenames)
- `detection_signature` - Detection rule that triggered (e.g., "Reconnaissance Detected")
- `confidence` - Detection confidence score (0.0-1.0)
- `timestamp` / `first_seen` / `generated_at` - ISO 8601 timestamps
- `agent_version` - The Mirror agent version

### OSINT Data

OSINT data is nested under `osint.*`:

```python
"osint": {
    "whois": {
        "org": "Example Inc",
        "asn": "12345",
        "country": "US",
        "cidr": "203.0.113.0/24",
        "abuse_email": "abuse@example.com"
    },
    "rdns": {
        "hostname": "host.example.com",
        "resolved": True
    },
    "shodan": {
        "ports": [22, 80, 443],
        "services": ["SSH", "HTTP", "HTTPS"],
        "services_detail": [
            {
                "port": 22,
                "product": "OpenSSH",
                "version": "8.2",
                "banner": "SSH-2.0-OpenSSH_8.2"
            }
        ]
    },
    "ct": {
        "certificates": [
            {
                "common_name": "example.com",
                "issuer": "Let's Encrypt",
                "not_before": "2024-01-01",
                "dns_names": ["example.com", "www.example.com"]
            }
        ]
    }
}
```

### Actions and Timeline

Actions taken during incident response:

```python
"actions": [
    {
        "name": "Redirect traffic to honeypot via Istio VirtualService",
        "timestamp": "2024-06-15T03:14:10Z",
        "result": "success",
        "success": True,
        "parameters": {"method": "istio", "virtualservice_name": "redirect-203-0-113-42"}
    }
]

"timeline": [
    {
        "timestamp": "2024-06-15T03:14:07Z",
        "description": "Detection triggered - Reconnaissance Detected"
    }
]
```

### Detection Signals

```python
"detection_signals": [
    {
        "type": "IDS Alert",
        "description": "Multiple port scan attempts detected",
        "confidence": 0.95,
        "evidence": "Suricata EVE log entry"
    }
]
```

## Customization

Templates use Jinja2 syntax. To customize:

1. Edit the `.j2` template files directly
2. Use Jinja2 features:
   - Variables: `{{ variable }}`
   - Conditionals: `{% if condition %}...{% endif %}`
   - Loops: `{% for item in list %}...{% endfor %}`
   - Filters: `{{ list | join(', ') }}`, `{{ ip | replace('.', '-') }}`

Example customization:

```jinja2
## Attacker Profile

{% if osint.whois -%}
- **Organization**: {{ osint.whois.org | default('Unknown') }}
- **Country**: {{ osint.whois.country | default('Unknown') }}
{%- else %}
- WHOIS data not available
{%- endif %}
```

## Testing

Run template generator tests:

```bash
cd scenario-the-mirror
pytest tests/test_template_generator.py -v
```

## Dependencies

- Python 3.11+
- `jinja2>=3.1.0`

Install:

```bash
pip install jinja2
```

## Output Structure

Generated files are organized:

```
incidents/
├── INC-2024-0615-0314.md           # Full incident report
├── INC-2024-0615-0320.md
├── INC-2024-0615-0405.md
├── slack/
│   ├── INC-2024-0615-0314.txt      # Slack message
│   └── INC-2024-0615-0320.txt
├── dossiers/
│   ├── 203-0-113-42.md             # Enhanced dossier
│   └── 198-51-100-15.md
├── summaries/
│   ├── weekly-2024-W24.md          # Executive summary
│   └── monthly-2024-06.md
└── evidence/
    ├── whois-203-0-113-42.json
    ├── shodan-203-0-113-42.json
    └── ...
```

## Future Enhancements

- **PDF generation**: Convert markdown to PDF for formal reports
- **HTML version**: Web-viewable incident reports
- **CSV export**: Incident summary in spreadsheet format
- **Email templates**: Pre-formatted email notifications
- **API integration**: Optional GitHub/Slack posting if credentials provided
