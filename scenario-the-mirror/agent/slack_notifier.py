"""
Slack Notifier - Real-time incident notifications

Sends incident alerts to Slack webhook when attacks detected.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Optional, List

import requests

logger = logging.getLogger(__name__)


class SlackNotifier:
    """
    Sends incident notifications to Slack.

    Features:
    - Rich message formatting with blocks
    - Severity-based color coding
    - Incident summary with attacker info
    - Actions taken and OSINT highlights
    """

    def __init__(self, webhook_url: Optional[str] = None):
        """
        Initialize Slack notifier.

        Args:
            webhook_url: Slack incoming webhook URL
        """
        self.webhook_url = webhook_url or os.getenv('SLACK_WEBHOOK_URL', '')
        self.enabled = bool(self.webhook_url)

        if not self.enabled:
            logger.info("Slack notifications disabled (SLACK_WEBHOOK_URL not set)")
        else:
            logger.info(f"Slack notifications enabled: {self.webhook_url[:30]}...")

    def notify_incident(
        self,
        incident_id: str,
        attacker_ip: str,
        detection: Dict,
        actions_taken: List[Dict],
        osint_data: Optional[Dict] = None,
        github_url: Optional[str] = None
    ) -> bool:
        """
        Send incident notification to Slack.

        Args:
            incident_id: Incident ID (e.g., INC-20260614-1234)
            attacker_ip: Attacker source IP
            detection: Detection data (signature, confidence)
            actions_taken: List of defensive actions
            osint_data: OSINT intelligence (optional)
            github_url: GitHub issue URL (optional)

        Returns:
            True if sent successfully
        """
        if not self.enabled:
            logger.debug("Slack notification skipped (disabled)")
            return False

        try:
            # Build message
            message = self._build_message(
                incident_id=incident_id,
                attacker_ip=attacker_ip,
                detection=detection,
                actions_taken=actions_taken,
                osint_data=osint_data,
                github_url=github_url
            )

            # Send to Slack
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"✅ Slack notification sent: {incident_id}")
                return True
            else:
                logger.error(
                    f"Slack webhook returned {response.status_code}: {response.text}"
                )
                return False

        except requests.exceptions.Timeout:
            logger.error("Slack notification timeout (10s)")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Slack notification failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Error building Slack message: {e}", exc_info=True)
            return False

    def _build_message(
        self,
        incident_id: str,
        attacker_ip: str,
        detection: Dict,
        actions_taken: List[Dict],
        osint_data: Optional[Dict],
        github_url: Optional[str]
    ) -> Dict:
        """
        Build Slack message with blocks formatting.

        Returns dict ready for webhook POST.
        """
        # Determine severity and color
        severity = detection.get('severity', 2)
        confidence = detection.get('confidence', 0.0)

        if severity == 1 or confidence >= 0.95:
            color = "danger"  # Red
            emoji = "🚨"
        elif severity == 2 or confidence >= 0.80:
            color = "warning"  # Orange
            emoji = "⚠️"
        else:
            color = "good"  # Green
            emoji = "ℹ️"

        # Extract OSINT highlights
        osint_summary = self._build_osint_summary(osint_data) if osint_data else "No OSINT data"

        # Build actions summary
        actions_summary = self._build_actions_summary(actions_taken)

        # Build blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Security Incident Detected",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Incident ID:*\n{incident_id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Attacker IP:*\n`{attacker_ip}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Detection:*\n{detection.get('signature', 'Unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence:*\n{confidence:.0%}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔍 Intelligence:*\n{osint_summary}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🛡️ Actions Taken:*\n{actions_summary}"
                }
            }
        ]

        # Add GitHub link if available
        if github_url:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*📋 Full Report:*\n<{github_url}|View GitHub Issue>"
                }
            })

        # Add divider
        blocks.append({"type": "divider"})

        # Add timestamp footer
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🤖 The Mirror · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                }
            ]
        })

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks
                }
            ]
        }

    def _build_osint_summary(self, osint_data: Dict) -> str:
        """Build concise OSINT summary for Slack."""
        parts = []

        # Organization
        org = osint_data.get('organization')
        if org and org != 'unknown':
            parts.append(f"• *Org:* {org}")

        # Country
        country = osint_data.get('country')
        if country and country != 'unknown':
            parts.append(f"• *Country:* {country}")

        # ASN
        asn = osint_data.get('asn')
        if asn and asn != 'unknown':
            parts.append(f"• *ASN:* {asn}")

        # Open ports
        ports = osint_data.get('open_ports', [])
        if ports:
            ports_str = ', '.join(map(str, ports[:5]))
            if len(ports) > 5:
                ports_str += f" (+{len(ports)-5} more)"
            parts.append(f"• *Open Ports:* {ports_str}")

        # Vulnerabilities
        vulns = osint_data.get('vulnerabilities', [])
        if vulns:
            parts.append(f"• *Vulnerabilities:* {len(vulns)} known CVEs")

        if not parts:
            return "_No intelligence gathered_"

        return "\n".join(parts)

    def _build_actions_summary(self, actions_taken: List[Dict]) -> str:
        """Build actions summary for Slack."""
        if not actions_taken:
            return "_No actions taken_"

        parts = []
        for action in actions_taken[:5]:  # Show first 5 actions
            name = action.get('name', 'Unknown')
            result = action.get('result', 'unknown')
            emoji = "✅" if result == "success" else "❌"
            parts.append(f"{emoji} {name}")

        if len(actions_taken) > 5:
            parts.append(f"_+{len(actions_taken)-5} more actions_")

        return "\n".join(parts)

    def notify_test(self) -> bool:
        """
        Send test notification to verify webhook configuration.

        Returns:
            True if test successful
        """
        if not self.enabled:
            logger.error("Cannot send test: SLACK_WEBHOOK_URL not set")
            return False

        try:
            message = {
                "text": "🧪 The Mirror - Test Notification",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🧪 Test Notification",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "The Mirror Slack integration is working correctly!"
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Sent at {datetime.now(timezone.utc).isoformat()}"
                            }
                        ]
                    }
                ]
            }

            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=10
            )

            if response.status_code == 200:
                logger.info("✅ Slack test notification sent successfully")
                return True
            else:
                logger.error(f"Slack test failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Slack test notification failed: {e}")
            return False


# Singleton instance
_slack_notifier = None


def get_slack_notifier() -> SlackNotifier:
    """Get or create global Slack notifier instance."""
    global _slack_notifier
    if _slack_notifier is None:
        _slack_notifier = SlackNotifier()
    return _slack_notifier


# Example usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    notifier = SlackNotifier()

    if notifier.enabled:
        print("Testing Slack notification...")
        success = notifier.notify_test()
        print(f"Result: {'✅ Success' if success else '❌ Failed'}")
    else:
        print("Slack disabled (set SLACK_WEBHOOK_URL to enable)")
