"""
Template-based incident report generator.

Generates markdown incident reports, Slack notifications, executive summaries,
and threat actor dossiers using Jinja2 templates. No external API calls required.
"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

logger = logging.getLogger(__name__)


class IncidentReportGenerator:
    """Generate incident reports from templates."""

    def __init__(self, template_dir: str = "templates", output_dir: str = "incidents"):
        """
        Initialize template generator.

        Args:
            template_dir: Directory containing Jinja2 templates
            output_dir: Base directory for output files
        """
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)

        if not self.template_dir.exists():
            raise FileNotFoundError(f"Template directory not found: {template_dir}")

        self.env = Environment(loader=FileSystemLoader(str(self.template_dir)))

        # Create output directory structure
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "slack").mkdir(exist_ok=True)
        (self.output_dir / "dossiers").mkdir(exist_ok=True)
        (self.output_dir / "summaries").mkdir(exist_ok=True)
        (self.output_dir / "evidence").mkdir(exist_ok=True)

    def generate_incident_report(
        self, incident_data: Dict[str, Any], output_path: Optional[str] = None
    ) -> str:
        """
        Generate full incident report.

        Args:
            incident_data: Incident data dictionary
            output_path: Optional custom output path

        Returns:
            Path to generated report file
        """
        try:
            template = self.env.get_template("incident-report.md.j2")

            # Add default values
            incident_data.setdefault("generated_at", datetime.utcnow().isoformat() + "Z")
            incident_data.setdefault("agent_version", "1.0.0")
            incident_data.setdefault("status", "Active")
            incident_data.setdefault("status_emoji", "🔴")

            # Render template
            output = template.render(**incident_data)

            # Write to file
            if output_path:
                report_path = Path(output_path)
            else:
                incident_id = incident_data.get("incident_id", "UNKNOWN")
                report_path = self.output_dir / f"{incident_id}.md"

            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(output)

            logger.info(f"Generated incident report: {report_path}")
            return str(report_path)

        except TemplateNotFound as e:
            logger.error(f"Template not found: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to generate incident report: {e}")
            raise

    def generate_slack_notification(self, incident_data: Dict[str, Any]) -> str:
        """
        Generate Slack notification message.

        Args:
            incident_data: Incident data dictionary

        Returns:
            Rendered Slack message (markdown string)
        """
        try:
            template = self.env.get_template("slack-notification.md.j2")

            # Calculate evidence count
            evidence_count = 0
            if incident_data.get("osint"):
                evidence_count += len(incident_data["osint"])
            if incident_data.get("honeypot_logs"):
                evidence_count += 1
            if incident_data.get("pcap_file"):
                evidence_count += 1

            incident_data.setdefault("evidence_count", evidence_count)

            output = template.render(**incident_data)

            # Optionally write to file
            incident_id = incident_data.get("incident_id", "UNKNOWN")
            slack_path = self.output_dir / "slack" / f"{incident_id}.txt"
            slack_path.write_text(output)

            logger.info(f"Generated Slack notification: {slack_path}")
            return output

        except TemplateNotFound as e:
            logger.error(f"Template not found: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to generate Slack notification: {e}")
            raise

    def generate_executive_summary(
        self, summary_data: Dict[str, Any], output_path: Optional[str] = None
    ) -> str:
        """
        Generate executive summary report.

        Args:
            summary_data: Summary data dictionary
            output_path: Optional custom output path

        Returns:
            Path to generated summary file
        """
        try:
            template = self.env.get_template("executive-summary.md.j2")

            # Add default values
            summary_data.setdefault("generated_at", datetime.utcnow().isoformat() + "Z")

            # Calculate percentages
            total = summary_data.get("total_incidents", 0)
            if total > 0:
                summary_data.setdefault(
                    "high_severity_pct",
                    round(summary_data.get("high_severity", 0) / total * 100, 1),
                )
                summary_data.setdefault(
                    "medium_severity_pct",
                    round(summary_data.get("medium_severity", 0) / total * 100, 1),
                )
                summary_data.setdefault(
                    "low_severity_pct",
                    round(summary_data.get("low_severity", 0) / total * 100, 1),
                )

            output = template.render(**summary_data)

            # Write to file
            if output_path:
                summary_path = Path(output_path)
            else:
                date_range = summary_data.get("date_range", "unknown")
                summary_path = self.output_dir / "summaries" / f"{date_range}.md"

            summary_path.parent.mkdir(parents=True, exist_ok=True)
            summary_path.write_text(output)

            logger.info(f"Generated executive summary: {summary_path}")
            return str(summary_path)

        except TemplateNotFound as e:
            logger.error(f"Template not found: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            raise

    def generate_dossier(
        self, dossier_data: Dict[str, Any], output_path: Optional[str] = None
    ) -> str:
        """
        Generate enhanced threat actor dossier.

        Args:
            dossier_data: Dossier data dictionary
            output_path: Optional custom output path

        Returns:
            Path to generated dossier file
        """
        try:
            template = self.env.get_template("dossier-enhanced.md.j2")

            # Add default values
            dossier_data.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")
            dossier_data.setdefault("agent_version", "1.0.0")

            output = template.render(**dossier_data)

            # Write to file
            if output_path:
                dossier_path = Path(output_path)
            else:
                attacker_ip = dossier_data.get("attacker_ip", "unknown")
                # Convert IP to filename-safe format
                ip_slug = attacker_ip.replace(".", "-")
                dossier_path = self.output_dir / "dossiers" / f"{ip_slug}.md"

            dossier_path.parent.mkdir(parents=True, exist_ok=True)
            dossier_path.write_text(output)

            logger.info(f"Generated threat actor dossier: {dossier_path}")
            return str(dossier_path)

        except TemplateNotFound as e:
            logger.error(f"Template not found: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to generate dossier: {e}")
            raise
