"""
Database module for PostgreSQL audit log persistence.
Replaces file-based audit.jsonl with queryable database storage.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from contextlib import contextmanager

try:
    import psycopg2
    from psycopg2.extras import Json, RealDictCursor
    from psycopg2.pool import ThreadedConnectionPool
except ImportError:
    print("ERROR: psycopg2 not installed. Run: pip install psycopg2-binary", file=sys.stderr)
    sys.exit(1)

from agent.config import (
    DATABASE_URL,
    DATABASE_POOL_MIN,
    DATABASE_POOL_MAX,
)

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Manages PostgreSQL connection pool and provides methods for audit log persistence.
    """

    def __init__(self):
        self.pool: Optional[ThreadedConnectionPool] = None
        self._init_pool()

    def _init_pool(self):
        """Initialize connection pool."""
        if not DATABASE_URL:
            logger.warning("DATABASE_URL not set. Audit logs will NOT be persisted to database.")
            return

        try:
            self.pool = ThreadedConnectionPool(
                DATABASE_POOL_MIN,
                DATABASE_POOL_MAX,
                DATABASE_URL
            )
            logger.info(f"Database connection pool initialized (min={DATABASE_POOL_MIN}, max={DATABASE_POOL_MAX})")
        except Exception as e:
            logger.error(f"Failed to initialize database connection pool: {e}")
            self.pool = None

    @contextmanager
    def get_conn(self):
        """
        Context manager for database connections.
        Automatically returns connection to pool after use.
        """
        if not self.pool:
            raise RuntimeError("Database pool not initialized")

        conn = self.pool.getconn()
        try:
            yield conn
        finally:
            self.pool.putconn(conn)

    def log_audit_entry(
        self,
        incident_id: str,
        action_id: str,
        action_name: str,
        action_result: str,
        action_tier: Optional[int] = None,
        parameters: Optional[Dict[str, Any]] = None,
        rollback_handle: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        detection_confidence: Optional[float] = None,
        detection_method: Optional[str] = None,
        evidence_refs: Optional[List[str]] = None,
        playbook_rule: Optional[str] = None,
        reasoning: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        llm_consulted: bool = False,
        llm_model: Optional[Dict[str, Any]] = None,
        llm_reasoning: Optional[str] = None,
    ) -> Optional[str]:
        """
        Log an audit entry to the database.

        Returns the audit entry UUID if successful, None otherwise.
        """
        if not self.pool:
            logger.debug("Database pool not available. Skipping database audit log.")
            return None

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    query = """
                    INSERT INTO audit_log (
                        incident_id, timestamp, action_id, action_name, action_tier, action_result,
                        parameters, rollback_handle, expires_at,
                        detection_confidence, detection_method, evidence_refs, playbook_rule, reasoning,
                        context, llm_consulted, llm_model, llm_reasoning
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """

                    cur.execute(query, (
                        incident_id,
                        datetime.utcnow(),
                        action_id,
                        action_name,
                        action_tier,
                        action_result,
                        Json(parameters) if parameters else None,
                        rollback_handle,
                        expires_at,
                        detection_confidence,
                        detection_method,
                        Json(evidence_refs) if evidence_refs else None,
                        playbook_rule,
                        reasoning,
                        Json(context) if context else None,
                        llm_consulted,
                        Json(llm_model) if llm_model else None,
                        llm_reasoning,
                    ))

                    audit_id = cur.fetchone()[0]
                    conn.commit()

                    logger.debug(f"Audit entry logged to database: {audit_id}")
                    return str(audit_id)

        except Exception as e:
            logger.error(f"Failed to log audit entry to database: {e}")
            return None

    def upsert_incident(
        self,
        incident_id: str,
        attacker_ip: str,
        detection_signature: str,
        detection_confidence: float,
        detection_signals: Dict[str, Any],
        attacker_info: Optional[Dict[str, Any]] = None,
        severity: int = 2,  # Default to medium
        status: str = "active",
    ) -> bool:
        """
        Create or update an incident record.
        Returns True if successful, False otherwise.
        """
        if not self.pool:
            return False

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    # Check if incident exists
                    cur.execute("SELECT incident_id FROM incidents WHERE incident_id = %s", (incident_id,))
                    exists = cur.fetchone() is not None

                    if exists:
                        # Update existing incident
                        query = """
                        UPDATE incidents
                        SET last_updated = %s,
                            detection_confidence = %s,
                            detection_signals = %s,
                            attacker_info = %s,
                            actions_count = actions_count + 1,
                            status = %s
                        WHERE incident_id = %s
                        """
                        cur.execute(query, (
                            datetime.utcnow(),
                            detection_confidence,
                            Json(detection_signals),
                            Json(attacker_info) if attacker_info else None,
                            status,
                            incident_id,
                        ))
                    else:
                        # Insert new incident
                        query = """
                        INSERT INTO incidents (
                            incident_id, first_seen, last_updated,
                            attacker_ip, attacker_info,
                            detection_signature, detection_confidence, detection_signals,
                            actions_count, status, severity
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        """
                        now = datetime.utcnow()
                        cur.execute(query, (
                            incident_id,
                            now,
                            now,
                            attacker_ip,
                            Json(attacker_info) if attacker_info else None,
                            detection_signature,
                            detection_confidence,
                            Json(detection_signals),
                            1,  # First action
                            status,
                            severity,
                        ))

                    conn.commit()
                    logger.debug(f"Incident {'updated' if exists else 'created'}: {incident_id}")
                    return True

        except Exception as e:
            logger.error(f"Failed to upsert incident: {e}")
            return False

    def add_evidence(
        self,
        incident_id: str,
        evidence_type: str,
        data: Optional[Dict[str, Any]] = None,
        file_path: Optional[str] = None,
        file_size: Optional[int] = None,
    ) -> Optional[str]:
        """
        Add evidence to an incident.
        Returns evidence UUID if successful, None otherwise.
        """
        if not self.pool:
            return None

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    query = """
                    INSERT INTO evidence (
                        incident_id, evidence_type, file_path, file_size, data, collected_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """

                    cur.execute(query, (
                        incident_id,
                        evidence_type,
                        file_path,
                        file_size,
                        Json(data) if data else None,
                        datetime.utcnow(),
                    ))

                    evidence_id = cur.fetchone()[0]
                    conn.commit()

                    logger.debug(f"Evidence added: {evidence_id} (type={evidence_type})")
                    return str(evidence_id)

        except Exception as e:
            logger.error(f"Failed to add evidence: {e}")
            return None

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve incident record.
        Returns incident dict if found, None otherwise.
        """
        if not self.pool:
            return None

        try:
            with self.get_conn() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT * FROM incidents WHERE incident_id = %s", (incident_id,))
                    row = cur.fetchone()
                    return dict(row) if row else None

        except Exception as e:
            logger.error(f"Failed to get incident: {e}")
            return None

    def get_audit_log(
        self,
        incident_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Query audit log entries.
        Returns list of audit log dicts.
        """
        if not self.pool:
            return []

        try:
            with self.get_conn() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    if incident_id:
                        query = """
                        SELECT * FROM audit_log
                        WHERE incident_id = %s
                        ORDER BY timestamp DESC
                        LIMIT %s OFFSET %s
                        """
                        cur.execute(query, (incident_id, limit, offset))
                    else:
                        query = """
                        SELECT * FROM audit_log
                        ORDER BY timestamp DESC
                        LIMIT %s OFFSET %s
                        """
                        cur.execute(query, (limit, offset))

                    rows = cur.fetchall()
                    return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to query audit log: {e}")
            return []

    def get_recent_incidents(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get recent incidents from last N days.
        Returns list of incident dicts.
        """
        if not self.pool:
            return []

        try:
            with self.get_conn() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    query = """
                    SELECT * FROM recent_incidents
                    WHERE first_seen >= %s
                    ORDER BY first_seen DESC
                    """
                    cutoff = datetime.utcnow() - timedelta(days=days)
                    cur.execute(query, (cutoff,))

                    rows = cur.fetchall()
                    return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get recent incidents: {e}")
            return []

    def mark_postmortem_generated(self, incident_id: str) -> bool:
        """Mark incident as having post-mortem generated."""
        if not self.pool:
            return False

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    query = """
                    UPDATE incidents
                    SET postmortem_generated = TRUE
                    WHERE incident_id = %s
                    """
                    cur.execute(query, (incident_id,))
                    conn.commit()
                    return True

        except Exception as e:
            logger.error(f"Failed to mark postmortem generated: {e}")
            return False

    def create_virtualservice(
        self,
        incident_id: str,
        vs_name: str,
        vs_namespace: str,
        attacker_ip: str,
        honeypot_destination: str,
        expires_at: datetime,
    ) -> Optional[str]:
        """
        Record VirtualService creation (Phase 4).
        Returns virtualservice UUID if successful, None otherwise.
        """
        if not self.pool:
            return None

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    query = """
                    INSERT INTO virtualservices (
                        incident_id, vs_name, vs_namespace,
                        attacker_ip, honeypot_destination, expires_at, status
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING id;
                    """

                    cur.execute(query, (
                        incident_id,
                        vs_name,
                        vs_namespace,
                        attacker_ip,
                        honeypot_destination,
                        expires_at,
                        'active',
                    ))

                    vs_id = cur.fetchone()[0]
                    conn.commit()

                    logger.debug(f"VirtualService recorded: {vs_id} ({vs_name})")
                    return str(vs_id)

        except Exception as e:
            logger.error(f"Failed to record VirtualService: {e}")
            return None

    def get_expired_virtualservices(self) -> List[Dict[str, Any]]:
        """
        Get VirtualServices that have expired but not yet deleted.
        Returns list of VS dicts with id, vs_name, vs_namespace, attacker_ip.
        """
        if not self.pool:
            return []

        try:
            with self.get_conn() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    query = """
                    SELECT id, incident_id, vs_name, vs_namespace, attacker_ip
                    FROM virtualservices
                    WHERE status = 'active'
                      AND expires_at <= NOW()
                    ORDER BY expires_at ASC
                    """
                    cur.execute(query)

                    rows = cur.fetchall()
                    return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get expired VirtualServices: {e}")
            return []

    def mark_virtualservice_deleted(self, vs_id: str) -> bool:
        """Mark VirtualService as deleted."""
        if not self.pool:
            return False

        try:
            with self.get_conn() as conn:
                with conn.cursor() as cur:
                    query = """
                    UPDATE virtualservices
                    SET status = 'deleted', deleted_at = NOW()
                    WHERE id = %s
                    """
                    cur.execute(query, (vs_id,))
                    conn.commit()
                    return True

        except Exception as e:
            logger.error(f"Failed to mark VirtualService deleted: {e}")
            return False

    def close(self):
        """Close connection pool."""
        if self.pool:
            self.pool.closeall()
            logger.info("Database connection pool closed")


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager() -> DatabaseManager:
    """
    Get singleton database manager instance.
    Creates it if it doesn't exist.
    """
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager
