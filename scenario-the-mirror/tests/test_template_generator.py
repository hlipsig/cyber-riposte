"""
Unit tests for template generator (agent/template_generator.py).
"""

import pytest
from pathlib import Path
from agent.template_generator import IncidentReportGenerator


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create temporary output directory for tests."""
    return str(tmp_path / "test_incidents")


@pytest.fixture
def generator(temp_output_dir):
    """Create generator with test output directory."""
    return IncidentReportGenerator(
        template_dir="templates", output_dir=temp_output_dir
    )


@pytest.fixture
def sample_incident_data():
    """Sample incident data for testing."""
    return {
        "incident_id": "INC-TEST-001",
        "attacker_ip": "203.0.113.42",
        "attacker_ip_slug": "203-0-113-42",
        "detection_signature": "Reconnaissance Detected",
        "first_seen": "2024-06-15T03:14:07Z",
        "confidence": 0.97,
        "summary": "Test incident summary",
        "osint": {
            "whois": {"org": "Test Org", "country": "US", "asn": "12345"},
            "rdns": {"hostname": "test.example.com"},
            "shodan": {},
            "ct": {},
        },
        "detection_signals": [
            {"type": "IDS Alert", "description": "Port scan detected", "confidence": 0.9}
        ],
        "actions": [
            {
                "name": "Redirect to honeypot",
                "timestamp": "2024-06-15T03:14:10Z",
                "result": "success",
                "success": True,
                "parameters": {"method": "istio"},
            }
        ],
        "timeline": [
            {
                "timestamp": "2024-06-15T03:14:07Z",
                "description": "Detection triggered",
            },
            {
                "timestamp": "2024-06-15T03:14:10Z",
                "description": "Redirected to honeypot",
            },
        ],
        "recommendations": [
            "Review OSINT data",
            "Check for campaign correlation",
        ],
    }


class TestIncidentReportGenerator:
    """Test incident report generation."""

    def test_generate_incident_report(self, generator, sample_incident_data):
        """Test incident report generation."""
        report_path = generator.generate_incident_report(sample_incident_data)

        assert Path(report_path).exists()
        content = Path(report_path).read_text()

        assert "INC-TEST-001" in content
        assert "203.0.113.42" in content
        assert "Reconnaissance Detected" in content
        assert "0.97" in content
        assert "Test Org" in content

    def test_incident_report_contains_osint(self, generator, sample_incident_data):
        """Test incident report includes OSINT data."""
        report_path = generator.generate_incident_report(sample_incident_data)
        content = Path(report_path).read_text()

        assert "Test Org" in content
        assert "AS12345" in content
        assert "test.example.com" in content

    def test_incident_report_contains_actions(self, generator, sample_incident_data):
        """Test incident report includes actions taken."""
        report_path = generator.generate_incident_report(sample_incident_data)
        content = Path(report_path).read_text()

        assert "Redirect to honeypot" in content
        assert "success" in content

    def test_incident_report_contains_timeline(self, generator, sample_incident_data):
        """Test incident report includes timeline."""
        report_path = generator.generate_incident_report(sample_incident_data)
        content = Path(report_path).read_text()

        assert "Detection triggered" in content
        assert "Redirected to honeypot" in content

    def test_generate_slack_notification(self, generator, sample_incident_data):
        """Test Slack notification generation."""
        slack_msg = generator.generate_slack_notification(sample_incident_data)

        assert "INC-TEST-001" in slack_msg
        assert "203.0.113.42" in slack_msg
        assert "Reconnaissance Detected" in slack_msg
        assert "Test Org" in slack_msg

    def test_slack_notification_saved_to_file(
        self, generator, sample_incident_data, temp_output_dir
    ):
        """Test Slack notification is saved to file."""
        generator.generate_slack_notification(sample_incident_data)

        slack_file = Path(temp_output_dir) / "slack" / "INC-TEST-001.txt"
        assert slack_file.exists()

    def test_generate_executive_summary(self, generator, temp_output_dir):
        """Test executive summary generation."""
        summary_data = {
            "date_range": "2024-W24",
            "start_date": "2024-06-10",
            "end_date": "2024-06-16",
            "total_incidents": 10,
            "unique_ips": 8,
            "high_severity": 3,
            "medium_severity": 5,
            "low_severity": 2,
            "attack_types": [("Port Scan", 5), ("Web Recon", 3), ("Brute Force", 2)],
            "top_countries": [("US", 4), ("CN", 3), ("RU", 2)],
            "top_asns": [("12345", "Test ISP", 4), ("67890", "Other ISP", 3)],
            "total_actions": 25,
            "action_stats": [
                ("Redirect to honeypot", 10),
                ("Run OSINT", 10),
                ("Temp block", 5),
            ],
            "cache_hit_rate": 75.5,
            "api_calls_saved": 150,
            "ssh_sessions": 12,
            "http_requests": 34,
            "malware_downloads": 2,
        }

        summary_path = generator.generate_executive_summary(summary_data)

        assert Path(summary_path).exists()
        content = Path(summary_path).read_text()

        assert "2024-W24" in content
        assert "Total Incidents: 10" in content
        assert "High: 3" in content
        assert "Port Scan: 5" in content

    def test_generate_dossier(self, generator, temp_output_dir):
        """Test dossier generation."""
        dossier_data = {
            "incident_id": "INC-TEST-001",
            "attacker_ip": "203.0.113.42",
            "whois": {"org": "Test Org", "asn": "12345", "country": "US"},
            "rdns": {"hostname": "test.example.com"},
            "shodan": {},
            "ct": {},
            "detection_signals": [
                {
                    "type": "Port Scan",
                    "confidence": 0.9,
                    "description": "Multiple ports scanned",
                    "evidence": "Suricata alert",
                }
            ],
            "detected_tools": [],
            "timeline": [{"timestamp": "2024-06-15T03:14:07Z", "action": "Detection", "details": "Port scan"}],
            "risk_score": 8,
            "risk_factors": [
                {
                    "name": "Detection Confidence",
                    "score": 9,
                    "reasoning": "High confidence detection",
                }
            ],
            "attribution_confidence": "Medium",
            "behavioral_iocs": ["Port scanning activity"],
            "immediate_actions": ["Monitor for continued activity"],
            "shortterm_actions": ["Correlate with other incidents"],
            "longterm_actions": ["Review detection coverage"],
            "related_incidents": [],
            "associated_domains": [],
        }

        dossier_path = generator.generate_dossier(dossier_data)

        assert Path(dossier_path).exists()
        content = Path(dossier_path).read_text()

        assert "203.0.113.42" in content
        assert "Test Org" in content
        assert "AS12345" in content
        assert "Risk Score: 8/10" in content

    def test_custom_output_path(self, generator, sample_incident_data, temp_output_dir):
        """Test custom output path for incident report."""
        custom_path = Path(temp_output_dir) / "custom" / "report.md"

        report_path = generator.generate_incident_report(
            sample_incident_data, output_path=str(custom_path)
        )

        assert Path(report_path).exists()
        assert str(custom_path) == report_path

    def test_missing_template_directory(self):
        """Test error handling for missing template directory."""
        with pytest.raises(FileNotFoundError):
            IncidentReportGenerator(template_dir="nonexistent")

    def test_output_directory_creation(self, temp_output_dir):
        """Test output directory structure is created."""
        generator = IncidentReportGenerator(output_dir=temp_output_dir)

        assert Path(temp_output_dir).exists()
        assert (Path(temp_output_dir) / "slack").exists()
        assert (Path(temp_output_dir) / "dossiers").exists()
        assert (Path(temp_output_dir) / "summaries").exists()
        assert (Path(temp_output_dir) / "evidence").exists()
