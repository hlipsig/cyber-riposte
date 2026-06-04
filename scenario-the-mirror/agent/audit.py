"""
Audit logging for The Mirror agent.
Phase 1-2: Logs to file and stdout (JSON structured logs)
Phase 3: Writes to PostgreSQL database + stdout (dual persistence)
"""
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from agent.db import get_db_manager


logger = logging.getLogger(__name__)


class AuditLog:
    """
    Structured audit trail — every action the agent takes is recorded.

    Phase 3: Records to BOTH file (backward compat) and PostgreSQL database.
    Stdout logging remains for OpenShift log aggregation.
    """

    def __init__(self, log_path="/var/log/cyber-riposte/audit.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.entries = []
        self.db = get_db_manager()

    def record(
        self,
        incident_id: str,
        action_id: str,
        action_name: str,
        tier: int,
        parameters: Dict[str, Any],
        result: str,
        justification: Dict[str, Any],
        context: Dict[str, Any],
        rollback_handle: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> str:
        """
        Record an audit entry.

        Returns the audit entry ID (database UUID or local ID).
        """
        entry_id = f"aud-{uuid.uuid4().hex[:8]}"

        entry = {
            "id": entry_id,
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
            entry["action"]["expires_at"] = expires_at.isoformat() if isinstance(expires_at, datetime) else expires_at

        self.entries.append(entry)

        # Phase 3: Write to PostgreSQL database
        db_entry_id = self.db.log_audit_entry(
            incident_id=incident_id,
            action_id=action_id,
            action_name=action_name,
            action_result=result,
            action_tier=tier,
            parameters=parameters,
            rollback_handle=rollback_handle,
            expires_at=expires_at,
            detection_confidence=justification.get("detection_confidence"),
            detection_method=justification.get("detection_method"),
            evidence_refs=justification.get("evidence_refs"),
            playbook_rule=justification.get("playbook_rule"),
            reasoning=justification.get("reasoning"),
            context=context,
            llm_consulted=justification.get("llm_consulted", False),
            llm_model=justification.get("llm_model"),
            llm_reasoning=justification.get("llm_reasoning"),
        )

        # If database write succeeded, use that ID
        if db_entry_id:
            entry["id"] = db_entry_id
            entry_id = db_entry_id

        # Phase 1-2: Write to file (backward compatibility)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit entry to file: {e}")

        # Always log to stdout as structured JSON (for OpenShift log aggregation)
        log_entry = {
            "level": "INFO",
            "logger": "audit",
            "message": f"Action {action_id} {result}",
            "audit_entry": entry,
            "database_persisted": db_entry_id is not None,
        }
        print(json.dumps(log_entry), file=sys.stdout, flush=True)

        return entry_id
