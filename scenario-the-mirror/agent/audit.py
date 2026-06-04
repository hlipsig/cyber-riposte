"""
Audit logging for The Mirror agent.
Phase 1: Logs to file and stdout (JSON structured logs)
Phase 3: Will be refactored to write to PostgreSQL
"""
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


logger = logging.getLogger(__name__)


class AuditLog:
    """Structured audit trail — every action the agent takes is recorded."""

    def __init__(self, log_path="/var/log/cyber-riposte/audit.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.entries = []

    def record(self, incident_id, action_id, action_name, tier, parameters,
               result, justification, context, rollback_handle=None, expires_at=None):
        """
        Record an audit entry.

        Returns the audit entry ID.
        """
        entry = {
            "id": f"aud-{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": {
                "id": action_id,
                "name": action_name,
                "tier": tier,
                "parameters": parameters,
                "result": result,
            },
            "justification": justification,
            "context": context,
        }
        if rollback_handle:
            entry["action"]["rollback_handle"] = rollback_handle
        if expires_at:
            entry["action"]["expires_at"] = expires_at

        self.entries.append(entry)

        # Write to file (Phase 1)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit entry to file: {e}")

        # Also log to stdout as structured JSON (for OpenShift log aggregation)
        log_entry = {
            "level": "INFO",
            "logger": "audit",
            "message": f"Action {action_id} {result}",
            "audit_entry": entry,
        }
        print(json.dumps(log_entry), file=sys.stdout, flush=True)

        return entry["id"]
