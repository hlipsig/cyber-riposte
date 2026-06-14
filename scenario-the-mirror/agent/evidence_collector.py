"""
Evidence Collector - Archive all evidence for forensic analysis

Phase 5: Archive Suricata alerts, honeypot logs, OSINT results, and PCAP files.
Links evidence to incidents in the database.
"""

import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, List

from agent.config import Config

logger = logging.getLogger(__name__)


class EvidenceCollector:
    """
    Collects and archives forensic evidence for incidents.

    Evidence types:
    - Suricata IDS alerts (JSON)
    - Honeypot interaction logs
    - OSINT results
    - Packet captures (PCAP)
    - Screenshots/artifacts
    """

    def __init__(self, evidence_dir: Optional[str] = None):
        """
        Initialize evidence collector.

        Args:
            evidence_dir: Base directory for evidence storage
        """
        self.evidence_dir = Path(evidence_dir or Config.EVIDENCE_DIR)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Evidence collector initialized: {self.evidence_dir}")

    def collect_suricata_alert(
        self,
        incident_id: str,
        alert_data: Dict
    ) -> Optional[str]:
        """
        Archive a Suricata alert.

        Args:
            incident_id: Incident ID
            alert_data: Suricata EVE alert JSON

        Returns:
            Path to archived alert file
        """
        try:
            # Create incident directory
            incident_dir = self.evidence_dir / incident_id
            incident_dir.mkdir(parents=True, exist_ok=True)

            # Save alert as JSON
            alert_file = incident_dir / "suricata-alert.json"
            alert_file.write_text(json.dumps(alert_data, indent=2, default=str))

            logger.info(f"✅ Archived Suricata alert: {alert_file}")

            # Store in database
            self._store_evidence_db(
                incident_id=incident_id,
                evidence_type="suricata_alert",
                file_path=str(alert_file),
                data=alert_data
            )

            return str(alert_file)

        except Exception as e:
            logger.error(f"Failed to collect Suricata alert: {e}")
            return None

    def collect_osint_results(
        self,
        incident_id: str,
        osint_data: Dict
    ) -> Optional[str]:
        """
        Archive OSINT results.

        Args:
            incident_id: Incident ID
            osint_data: OSINT intelligence data

        Returns:
            Path to archived OSINT file
        """
        try:
            # Create incident directory
            incident_dir = self.evidence_dir / incident_id
            incident_dir.mkdir(parents=True, exist_ok=True)

            # Save OSINT as JSON
            osint_file = incident_dir / "osint-results.json"
            osint_file.write_text(json.dumps(osint_data, indent=2, default=str))

            logger.info(f"✅ Archived OSINT results: {osint_file}")

            # Store in database
            self._store_evidence_db(
                incident_id=incident_id,
                evidence_type="osint",
                file_path=str(osint_file),
                data=osint_data
            )

            return str(osint_file)

        except Exception as e:
            logger.error(f"Failed to collect OSINT results: {e}")
            return None

    def collect_honeypot_logs(
        self,
        incident_id: str,
        attacker_ip: str,
        log_source: str = "cowrie"
    ) -> Optional[str]:
        """
        Archive honeypot interaction logs for a specific attacker.

        Args:
            incident_id: Incident ID
            attacker_ip: Attacker IP address
            log_source: Honeypot type (cowrie, glastopf, etc.)

        Returns:
            Path to archived log file
        """
        try:
            # Create incident directory
            incident_dir = self.evidence_dir / incident_id
            incident_dir.mkdir(parents=True, exist_ok=True)

            # Look for honeypot logs
            honeypot_log_paths = self._find_honeypot_logs(attacker_ip, log_source)

            if not honeypot_log_paths:
                logger.warning(f"No {log_source} logs found for {attacker_ip}")
                return None

            # Copy logs to evidence directory
            archive_file = incident_dir / f"{log_source}-logs.txt"
            with archive_file.open('w') as out:
                for log_path in honeypot_log_paths:
                    try:
                        with open(log_path, 'r') as f:
                            out.write(f"=== {log_path} ===\n")
                            out.write(f.read())
                            out.write("\n\n")
                    except Exception as e:
                        logger.warning(f"Failed to read {log_path}: {e}")

            logger.info(f"✅ Archived {log_source} logs: {archive_file}")

            # Store in database
            self._store_evidence_db(
                incident_id=incident_id,
                evidence_type=f"{log_source}_logs",
                file_path=str(archive_file),
                data={"attacker_ip": attacker_ip, "log_source": log_source}
            )

            return str(archive_file)

        except Exception as e:
            logger.error(f"Failed to collect honeypot logs: {e}")
            return None

    def collect_pcap(
        self,
        incident_id: str,
        pcap_source: Optional[str] = None
    ) -> Optional[str]:
        """
        Archive packet capture for incident.

        Args:
            incident_id: Incident ID
            pcap_source: Path to PCAP file (or auto-discover from Suricata)

        Returns:
            Path to archived PCAP file
        """
        try:
            # Create incident directory
            incident_dir = self.evidence_dir / incident_id
            incident_dir.mkdir(parents=True, exist_ok=True)

            # Find PCAP file
            if not pcap_source:
                pcap_source = self._find_suricata_pcap(incident_id)

            if not pcap_source or not Path(pcap_source).exists():
                logger.warning(f"No PCAP file found for {incident_id}")
                return None

            # Copy PCAP to evidence directory
            pcap_dest = incident_dir / "capture.pcap"
            shutil.copy2(pcap_source, pcap_dest)

            logger.info(f"✅ Archived PCAP: {pcap_dest}")

            # Store in database
            self._store_evidence_db(
                incident_id=incident_id,
                evidence_type="pcap",
                file_path=str(pcap_dest),
                data={"source": pcap_source}
            )

            return str(pcap_dest)

        except Exception as e:
            logger.error(f"Failed to collect PCAP: {e}")
            return None

    def _find_honeypot_logs(self, attacker_ip: str, log_source: str) -> List[str]:
        """Find honeypot logs containing attacker IP."""
        log_paths = []

        # Common honeypot log locations
        search_paths = [
            f"/var/log/{log_source}",
            f"/var/log/cyber-riposte/{log_source}",
            f"/honeypot/{log_source}/log",
        ]

        for base_path in search_paths:
            if not Path(base_path).exists():
                continue

            # Search for logs with attacker IP
            try:
                for log_file in Path(base_path).rglob("*.log"):
                    try:
                        with open(log_file, 'r') as f:
                            content = f.read()
                            if attacker_ip in content:
                                log_paths.append(str(log_file))
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Error searching {base_path}: {e}")

        return log_paths

    def _find_suricata_pcap(self, incident_id: str) -> Optional[str]:
        """Find Suricata PCAP file for incident."""
        # Suricata PCAP log directory
        pcap_dir = Path("/var/log/suricata/pcap")

        if not pcap_dir.exists():
            return None

        # Look for recent PCAP files (match by timestamp in incident_id)
        # incident_id format: INC-YYYYMMDD-HHMM
        try:
            incident_time = incident_id.split('-')[1:3]  # ['YYYYMMDD', 'HHMM']
            date_prefix = incident_time[0]  # YYYYMMDD

            for pcap_file in pcap_dir.glob(f"*{date_prefix}*.pcap"):
                return str(pcap_file)

        except Exception as e:
            logger.debug(f"Error finding PCAP: {e}")

        return None

    def _store_evidence_db(
        self,
        incident_id: str,
        evidence_type: str,
        file_path: str,
        data: Optional[Dict] = None
    ):
        """Store evidence metadata in database."""
        try:
            from agent.db import get_db_manager
            from psycopg2.extras import Json

            db = get_db_manager()

            with db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO evidence (incident_id, evidence_type, file_path, data, collected_at)
                        VALUES (%s, %s, %s, %s, NOW())
                    """, (incident_id, evidence_type, file_path, Json(data) if data else None))
                    conn.commit()

            logger.debug(f"Stored evidence in DB: {evidence_type} -> {file_path}")

        except Exception as e:
            logger.warning(f"Failed to store evidence in database: {e}")

    def get_evidence_list(self, incident_id: str) -> List[Dict]:
        """
        Get list of all evidence for an incident.

        Returns:
            List of evidence dicts with type, path, timestamp
        """
        try:
            from agent.db import get_db_manager

            db = get_db_manager()

            with db.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT evidence_type, file_path, collected_at, data
                        FROM evidence
                        WHERE incident_id = %s
                        ORDER BY collected_at ASC
                    """, (incident_id,))

                    results = cur.fetchall()

                    return [
                        {
                            'type': row[0],
                            'path': row[1],
                            'collected_at': row[2].isoformat() if row[2] else None,
                            'data': row[3]
                        }
                        for row in results
                    ]

        except Exception as e:
            logger.error(f"Failed to get evidence list: {e}")
            return []


# Singleton instance
_evidence_collector = None


def get_evidence_collector() -> EvidenceCollector:
    """Get or create global evidence collector instance."""
    global _evidence_collector
    if _evidence_collector is None:
        _evidence_collector = EvidenceCollector()
    return _evidence_collector


# Convenience functions
def collect_incident_evidence(
    incident_id: str,
    alert_data: Optional[Dict] = None,
    osint_data: Optional[Dict] = None,
    attacker_ip: Optional[str] = None
) -> Dict[str, str]:
    """
    Collect all available evidence for an incident.

    Returns:
        Dict mapping evidence type to file path
    """
    collector = get_evidence_collector()
    evidence_files = {}

    # Suricata alert
    if alert_data:
        path = collector.collect_suricata_alert(incident_id, alert_data)
        if path:
            evidence_files['suricata_alert'] = path

    # OSINT results
    if osint_data:
        path = collector.collect_osint_results(incident_id, osint_data)
        if path:
            evidence_files['osint'] = path

    # Honeypot logs
    if attacker_ip:
        for log_source in ['cowrie', 'glastopf']:
            path = collector.collect_honeypot_logs(incident_id, attacker_ip, log_source)
            if path:
                evidence_files[f'{log_source}_logs'] = path

    # PCAP
    path = collector.collect_pcap(incident_id)
    if path:
        evidence_files['pcap'] = path

    return evidence_files
