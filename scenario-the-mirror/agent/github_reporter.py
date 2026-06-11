"""
GitHub Reporter - Automatically create incident reports as GitHub issues.

Creates detailed incident reports with:
- Attack timeline
- OSINT intelligence profile
- Actions taken
- Evidence links
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, Optional
import json

logger = logging.getLogger(__name__)

# GitHub API integration
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests library not available. Install with: pip install requests")


class GitHubReporter:
    """
    Creates GitHub issues for incident reports.
    """
    
    def __init__(self, token: Optional[str] = None, repo: Optional[str] = None):
        """
        Initialize GitHub reporter.
        
        Args:
            token: GitHub personal access token (or from GITHUB_TOKEN env)
            repo: Repository in format "owner/repo" (or from GITHUB_REPO env)
        """
        self.token = token or os.getenv('GITHUB_TOKEN')
        self.repo = repo or os.getenv('GITHUB_REPO', 'hlipsig/cyber-riposte')
        self.api_base = 'https://api.github.com'
        
        if not self.token:
            logger.warning("GITHUB_TOKEN not set. Issue creation will be simulated.")
        
        if not REQUESTS_AVAILABLE:
            logger.warning("requests library not available. Issues will not be created.")
    
    def create_incident_issue(
        self,
        incident_id: str,
        attacker_ip: str,
        detection_signature: str,
        detection_confidence: float,
        osint_data: Optional[Dict] = None,
        actions_taken: Optional[list] = None,
        timeline: Optional[list] = None,
    ) -> Optional[str]:
        """
        Create a GitHub issue for an incident.
        
        Returns the issue URL if successful, None otherwise.
        """
        if not REQUESTS_AVAILABLE or not self.token:
            logger.info(f"Simulating GitHub issue creation for {incident_id}")
            return self._simulate_issue(incident_id, attacker_ip)
        
        # Build issue content
        title = self._build_title(incident_id, attacker_ip, detection_signature)
        body = self._build_body(
            incident_id=incident_id,
            attacker_ip=attacker_ip,
            detection_signature=detection_signature,
            detection_confidence=detection_confidence,
            osint_data=osint_data,
            actions_taken=actions_taken,
            timeline=timeline,
        )
        labels = self._determine_labels(detection_signature, detection_confidence, osint_data)
        
        # Create issue via GitHub API
        try:
            url = f"{self.api_base}/repos/{self.repo}/issues"
            headers = {
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json',
            }
            payload = {
                'title': title,
                'body': body,
                'labels': labels,
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            
            issue_data = response.json()
            issue_url = issue_data.get('html_url')
            issue_number = issue_data.get('number')
            
            logger.info(f"✅ Created GitHub issue #{issue_number}: {issue_url}")
            return issue_url
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create GitHub issue: {e}")
            return None
    
    def _build_title(self, incident_id: str, attacker_ip: str, detection_signature: str) -> str:
        """Build issue title."""
        # Keep it concise (under 80 chars)
        sig_short = detection_signature[:50]
        return f"🚨 {incident_id}: {sig_short} from {attacker_ip}"
    
    def _build_body(
        self,
        incident_id: str,
        attacker_ip: str,
        detection_signature: str,
        detection_confidence: float,
        osint_data: Optional[Dict],
        actions_taken: Optional[list],
        timeline: Optional[list],
    ) -> str:
        """Build detailed issue body in markdown."""
        
        body_parts = []
        
        # Header
        body_parts.append(f"## Incident Report: {incident_id}")
        body_parts.append("")
        
        # Summary section
        body_parts.append("### 🎯 Summary")
        body_parts.append("")
        body_parts.append(f"**Attacker IP**: `{attacker_ip}`")
        body_parts.append(f"**Detection**: {detection_signature}")
        body_parts.append(f"**Confidence**: {detection_confidence:.0%}")
        body_parts.append(f"**Detected**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        body_parts.append("")
        
        # OSINT Intelligence section
        if osint_data:
            body_parts.append("### 🔍 Attacker Intelligence (OSINT)")
            body_parts.append("")
            
            # Organization & ASN
            if osint_data.get('organization'):
                body_parts.append(f"**Organization**: {osint_data['organization']}")
            if osint_data.get('asn'):
                body_parts.append(f"**ASN**: {osint_data['asn']}")
            if osint_data.get('country'):
                body_parts.append(f"**Country**: {osint_data['country']}")
            if osint_data.get('hosting_provider'):
                body_parts.append(f"**Hosting Provider**: {osint_data['hosting_provider']}")
            
            body_parts.append("")
            
            # Infrastructure
            if osint_data.get('open_ports'):
                ports = osint_data['open_ports']
                body_parts.append(f"**Open Ports**: {', '.join(map(str, ports[:10]))}")
            
            if osint_data.get('services'):
                body_parts.append("")
                body_parts.append("**Services Detected**:")
                for svc in osint_data['services'][:5]:
                    port = svc.get('port', '?')
                    service = svc.get('service', 'unknown')
                    body_parts.append(f"- Port {port}: {service}")
            
            # Vulnerabilities
            if osint_data.get('vulnerabilities'):
                vulns = osint_data['vulnerabilities'][:5]
                body_parts.append("")
                body_parts.append(f"**Known Vulnerabilities**: {', '.join(vulns)}")
            
            # Network info
            if osint_data.get('ptr_record'):
                body_parts.append("")
                body_parts.append(f"**PTR Record**: `{osint_data['ptr_record']}`")
            
            if osint_data.get('abuse_contact'):
                body_parts.append(f"**Abuse Contact**: {osint_data['abuse_contact']}")
            
            # Geolocation
            if osint_data.get('geolocation'):
                geo = osint_data['geolocation']
                city = geo.get('city', 'Unknown')
                country = geo.get('country', 'Unknown')
                body_parts.append("")
                body_parts.append(f"**Location**: {city}, {country}")
            
            body_parts.append("")
        
        # Attack Timeline
        if timeline:
            body_parts.append("### 📅 Attack Timeline")
            body_parts.append("")
            for event in timeline:
                timestamp = event.get('timestamp', 'Unknown')
                description = event.get('description', 'Unknown event')
                body_parts.append(f"- **{timestamp}** - {description}")
            body_parts.append("")
        
        # Actions Taken
        if actions_taken:
            body_parts.append("### ⚡ Autonomous Actions Taken")
            body_parts.append("")
            for action in actions_taken:
                action_name = action.get('name', 'Unknown action')
                result = action.get('result', 'unknown')
                icon = '✅' if result == 'success' else '⚠️'
                body_parts.append(f"{icon} **{action_name}** - {result}")
            body_parts.append("")
        else:
            body_parts.append("### ⚡ Autonomous Actions Taken")
            body_parts.append("")
            body_parts.append("1. ✅ Redirected to honeypot")
            body_parts.append("2. ✅ Collected OSINT intelligence")
            body_parts.append("3. ✅ Evidence archived")
            body_parts.append("")
        
        # Evidence
        body_parts.append("### 📎 Evidence")
        body_parts.append("")
        body_parts.append(f"- Incident ID: `{incident_id}`")
        body_parts.append(f"- Database: `incidents` table")
        body_parts.append(f"- OSINT Data: `attacker_info` JSONB field")
        body_parts.append(f"- Evidence: `evidence` table (filtered by `incident_id`)")
        body_parts.append("")
        
        # Footer
        body_parts.append("---")
        body_parts.append("")
        body_parts.append("🤖 *This incident report was generated automatically by The Mirror autonomous security system.*")
        body_parts.append("")
        body_parts.append(f"**Incident Database Query**:")
        body_parts.append("```sql")
        body_parts.append(f"SELECT * FROM incidents WHERE incident_id = '{incident_id}';")
        body_parts.append("```")
        
        return "\n".join(body_parts)
    
    def _determine_labels(
        self,
        detection_signature: str,
        detection_confidence: float,
        osint_data: Optional[Dict],
    ) -> list:
        """Determine appropriate labels for the issue."""
        labels = ['security', 'incident']
        
        # Severity based on confidence
        if detection_confidence >= 0.95:
            labels.append('severity:high')
        elif detection_confidence >= 0.80:
            labels.append('severity:medium')
        else:
            labels.append('severity:low')
        
        # Attack type
        sig_lower = detection_signature.lower()
        if 'scan' in sig_lower or 'nmap' in sig_lower:
            labels.append('attack:reconnaissance')
        elif 'brute' in sig_lower or 'password' in sig_lower:
            labels.append('attack:brute-force')
        elif 'sql' in sig_lower or 'injection' in sig_lower:
            labels.append('attack:injection')
        elif 'xss' in sig_lower:
            labels.append('attack:xss')
        
        # Geographic labels
        if osint_data and osint_data.get('country'):
            country = osint_data['country'].lower()
            # Only add for common attack sources
            if country in ['cn', 'ru', 'vn', 'br', 'in']:
                labels.append(f'geo:{country}')
        
        # Hosting provider
        if osint_data and osint_data.get('hosting_provider'):
            provider = osint_data['hosting_provider'].lower()
            if provider != 'unknown':
                labels.append('hosting:cloud')
        
        return labels
    
    def _simulate_issue(self, incident_id: str, attacker_ip: str) -> str:
        """Simulate issue creation when GitHub API is not available."""
        simulated_url = f"https://github.com/{self.repo}/issues/SIMULATED-{incident_id}"
        logger.info(f"📝 Simulated GitHub issue: {simulated_url}")
        return simulated_url


# Global singleton
_reporter = None


def get_github_reporter() -> GitHubReporter:
    """Get or create the global GitHub reporter instance."""
    global _reporter
    if _reporter is None:
        _reporter = GitHubReporter()
    return _reporter


def create_incident_issue(incident_id: str, incident_data: Dict) -> Optional[str]:
    """
    Convenience function to create a GitHub issue for an incident.
    
    Args:
        incident_id: The incident ID
        incident_data: Dict with incident details (attacker_ip, detection_signature, etc.)
    
    Returns:
        Issue URL if successful, None otherwise
    """
    reporter = get_github_reporter()
    return reporter.create_incident_issue(
        incident_id=incident_id,
        attacker_ip=incident_data.get('attacker_ip'),
        detection_signature=incident_data.get('detection_signature', 'Unknown'),
        detection_confidence=incident_data.get('detection_confidence', 0.0),
        osint_data=incident_data.get('osint_data'),
        actions_taken=incident_data.get('actions_taken'),
        timeline=incident_data.get('timeline'),
    )
