"""
Web interface for CTF dossier exposure.

Serves incident dossiers on password-protected web pages.
Password is discoverable through honeypot interaction.
"""

import logging
import os
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from functools import wraps
from flask import Flask, render_template_string, request, Response, jsonify
from pathlib import Path

logger = logging.getLogger(__name__)


# Password stored as env var (set in K8s Secret)
DOSSIER_PASSWORD = os.getenv("DOSSIER_PASSWORD", "mirror_reflect_6789")

# Rate limiting for failed password attempts
RATE_LIMIT_WINDOW = 300  # 5 minutes
RATE_LIMIT_MAX_ATTEMPTS = 5  # Max failed attempts before lockout
RATE_LIMIT_LOCKOUT = 900  # 15 minute lockout after exceeding attempts

# Track failed attempts: {ip: [(timestamp, username, password), ...]}
failed_attempts: Dict[str, List[tuple]] = {}


def check_auth(username: str, password: str) -> bool:
    """Check if username/password combination is valid."""
    return username == "ctf" and password == DOSSIER_PASSWORD


def is_rate_limited(ip: str) -> tuple[bool, Optional[int]]:
    """
    Check if IP is rate-limited due to failed password attempts.

    Returns:
        (is_limited, seconds_until_unlock)
    """
    if ip not in failed_attempts:
        return False, None

    now = time.time()

    # Remove old attempts outside the window
    cutoff = now - RATE_LIMIT_WINDOW
    failed_attempts[ip] = [
        (ts, u, p) for ts, u, p in failed_attempts[ip] if ts > cutoff
    ]

    # Check if they've exceeded attempts
    recent_failures = len(failed_attempts[ip])

    if recent_failures >= RATE_LIMIT_MAX_ATTEMPTS:
        # Check if still in lockout period
        most_recent = max(ts for ts, _, _ in failed_attempts[ip])
        lockout_until = most_recent + RATE_LIMIT_LOCKOUT
        if now < lockout_until:
            seconds_remaining = int(lockout_until - now)
            return True, seconds_remaining

    return False, None


def record_failed_attempt(ip: str, username: str, password: str):
    """Record a failed authentication attempt."""
    if ip not in failed_attempts:
        failed_attempts[ip] = []

    failed_attempts[ip].append((time.time(), username, password))

    # Log the attempt
    attempt_count = len(failed_attempts[ip])
    logger.warning(f"Failed password attempt from {ip}: username='{username}', password='{password}' (attempt #{attempt_count})")

    # Log if they're trying decoy passwords
    decoys = ['Hi_TOM!', 'invisible_hand_1776', 'creative_destruction', 'wealth_of_nations']
    if password in decoys:
        logger.info(f"🎭 {ip} tried decoy password: {password}")


def authenticate():
    """Send 401 response to trigger basic auth."""
    ip = request.remote_addr

    # Check if rate-limited
    is_limited, seconds_remaining = is_rate_limited(ip)

    if is_limited:
        logger.warning(f"🚫 Rate limit exceeded for {ip} - locked out for {seconds_remaining}s")
        return Response(
            f'Too many failed attempts. Try again in {seconds_remaining} seconds.\n'
            f'The mirror is watching your brute force attempts.\n',
            429,  # Too Many Requests
            {'Retry-After': str(seconds_remaining)}
        )

    return Response(
        'Authentication required. Use credentials found in the honeypot.\n'
        'Hint: Username is "ctf", password is somewhere in /home/admin/.notes\n',
        401,
        {'WWW-Authenticate': 'Basic realm="CTF Dossier Archive"'}
    )


def requires_auth(f):
    """Decorator for routes requiring authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr

        # Check rate limit first
        is_limited, seconds_remaining = is_rate_limited(ip)
        if is_limited:
            logger.warning(f"🚫 Rate-limited request from {ip}")
            return Response(
                f'Too many failed attempts. Try again in {seconds_remaining} seconds.\n',
                429,
                {'Retry-After': str(seconds_remaining)}
            )

        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            # Record failed attempt
            if auth:
                record_failed_attempt(ip, auth.username, auth.password)
            return authenticate()

        # Successful auth - clear failed attempts for this IP
        if ip in failed_attempts:
            logger.info(f"✅ Successful authentication from {ip} - clearing failed attempts")
            del failed_attempts[ip]

        return f(*args, **kwargs)
    return decorated


def create_dossier_app(db_manager=None):
    """
    Create Flask app for dossier web interface.

    Args:
        db_manager: DatabaseManager instance (optional, will create if needed)
    """
    app = Flask(__name__)

    # Store db_manager in app config
    if db_manager:
        app.config['db_manager'] = db_manager

    @app.route('/health')
    def health():
        """Health check endpoint (no auth required)."""
        return jsonify({"status": "ok", "service": "dossier-web"}), 200

    @app.route('/')
    @requires_auth
    def index():
        """Root redirect to dossiers list."""
        return render_template_string(INDEX_TEMPLATE)

    @app.route('/dossiers')
    @requires_auth
    def dossiers_list():
        """List all incident dossiers."""
        try:
            # Get database manager
            db = app.config.get('db_manager')
            if not db:
                from agent.db import get_db_manager
                db = get_db_manager()

            # Get all incidents from database
            with db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT
                            incident_id,
                            attacker_ip,
                            detection_signature,
                            detection_confidence,
                            first_seen,
                            status
                        FROM incidents
                        ORDER BY first_seen DESC
                        LIMIT 100
                    """)
                    incidents = cur.fetchall()

            # Convert to list of dicts
            incident_list = [
                {
                    "incident_id": row[0],
                    "attacker_ip": row[1],
                    "detection_signature": row[2],
                    "confidence": row[3],
                    "first_seen": row[4],
                    "status": row[5],
                }
                for row in incidents
            ]

            return render_template_string(
                DOSSIERS_LIST_TEMPLATE,
                incidents=incident_list,
                total=len(incident_list)
            )

        except Exception as e:
            logger.error(f"Failed to list dossiers: {e}")
            return render_template_string(ERROR_TEMPLATE, error=str(e)), 500

    @app.route('/dossiers/<incident_id>')
    @requires_auth
    def dossier_detail(incident_id):
        """View detailed dossier for specific incident."""
        try:
            # Get database manager
            db = app.config.get('db_manager')
            if not db:
                from agent.db import get_db_manager
                db = get_db_manager()

            # Get incident details
            incident = db.get_incident(incident_id)
            if not incident:
                return render_template_string(
                    ERROR_TEMPLATE,
                    error=f"Incident {incident_id} not found"
                ), 404

            # Get evidence for this incident
            with db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT evidence_type, data, collected_at
                        FROM evidence
                        WHERE incident_id = %s
                        ORDER BY collected_at ASC
                    """, (incident_id,))
                    evidence_rows = cur.fetchall()

            evidence = {
                row[0]: row[1] for row in evidence_rows
            }

            # Get audit log entries
            with db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT
                            timestamp,
                            action_name,
                            action_result,
                            parameters
                        FROM audit_log
                        WHERE incident_id = %s
                        ORDER BY timestamp ASC
                    """, (incident_id,))
                    audit_rows = cur.fetchall()

            actions = [
                {
                    "timestamp": row[0].isoformat() if row[0] else "N/A",
                    "name": row[1],
                    "result": row[2],
                    "parameters": row[3],
                }
                for row in audit_rows
            ]

            # Check if this is the participant's own IP (CTF flag hint)
            participant_ip = request.remote_addr
            is_own_dossier = incident['attacker_ip'] == participant_ip

            return render_template_string(
                DOSSIER_DETAIL_TEMPLATE,
                incident=incident,
                evidence=evidence,
                actions=actions,
                is_own_dossier=is_own_dossier,
                participant_ip=participant_ip
            )

        except Exception as e:
            logger.error(f"Failed to load dossier {incident_id}: {e}")
            return render_template_string(ERROR_TEMPLATE, error=str(e)), 500

    @app.route('/api/dossiers/<ip_address>')
    @requires_auth
    def dossier_by_ip(ip_address):
        """Get dossier for specific IP (JSON API)."""
        try:
            db = app.config.get('db_manager')
            if not db:
                from agent.db import get_db_manager
                db = get_db_manager()

            with db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT
                            incident_id,
                            attacker_ip,
                            detection_signature,
                            detection_confidence,
                            first_seen,
                            attacker_info
                        FROM incidents
                        WHERE attacker_ip = %s
                        ORDER BY first_seen DESC
                        LIMIT 1
                    """, (ip_address,))
                    row = cur.fetchone()

            if not row:
                return jsonify({"error": "No incidents found for this IP"}), 404

            return jsonify({
                "incident_id": row[0],
                "attacker_ip": row[1],
                "detection_signature": row[2],
                "confidence": float(row[3]) if row[3] else 0,
                "first_seen": row[4].isoformat() if row[4] else None,
                "osint_data": row[5],
            })

        except Exception as e:
            logger.error(f"Failed to get dossier for IP {ip_address}: {e}")
            return jsonify({"error": str(e)}), 500

    return app


# HTML Templates

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>The Mirror - Dossier Archive</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            border: 2px solid #00ff00;
            padding: 20px;
            margin-bottom: 20px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            color: #00ff00;
            text-shadow: 0 0 10px #00ff00;
        }
        .subtitle {
            color: #00aa00;
            margin-top: 10px;
        }
        .content {
            border: 1px solid #00ff00;
            padding: 20px;
        }
        a {
            color: #00ff00;
            text-decoration: none;
        }
        a:hover {
            text-shadow: 0 0 5px #00ff00;
        }
        .warning {
            color: #ff0000;
            border: 1px solid #ff0000;
            padding: 10px;
            margin: 20px 0;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🪞 THE MIRROR</h1>
        <div class="subtitle">Autonomous Security Response System</div>
        <div class="subtitle">Dossier Archive</div>
    </div>

    <div class="content">
        <h2>Welcome</h2>
        <p>
            You have successfully authenticated to The Mirror's dossier archive.
        </p>
        <p>
            This system collects intelligence on all reconnaissance attempts against our infrastructure.
            Every scan, probe, and attack is documented here.
        </p>

        <div class="warning">
            ⚠️ NOTICE: All activity in this archive is logged and monitored. ⚠️
        </div>

        <h3>Navigation</h3>
        <ul>
            <li><a href="/dossiers">📁 View All Incident Dossiers</a></li>
            <li><a href="/api/dossiers/YOUR_IP_HERE">🔍 Search Dossier by IP (JSON API)</a></li>
        </ul>

        <h3>About The Mirror</h3>
        <p>
            The Mirror is an autonomous defensive security system that:
        </p>
        <ul>
            <li>Detects reconnaissance and attack patterns</li>
            <li>Redirects attackers to honeypot environments</li>
            <li>Collects passive OSINT on adversary infrastructure</li>
            <li>Generates detailed threat actor dossiers</li>
        </ul>

        <p style="margin-top: 40px; color: #00aa00; font-size: 0.9em;">
            <em>"In fencing, a riposte uses your opponent's forward momentum against them.<br>
            The Mirror is a digital riposte — they scanned us, so we scanned them back."</em>
        </p>
    </div>
</body>
</html>
"""

DOSSIERS_LIST_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Incident Dossiers - The Mirror</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            padding: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            border: 2px solid #00ff00;
            padding: 20px;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
            color: #00ff00;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #00ff00;
            padding: 10px;
            text-align: left;
        }
        th {
            background: #001100;
            color: #00ff00;
        }
        tr:hover {
            background: #002200;
        }
        a {
            color: #00ff00;
            text-decoration: none;
        }
        a:hover {
            text-shadow: 0 0 5px #00ff00;
        }
        .nav {
            margin-bottom: 20px;
        }
        .high { color: #ff0000; }
        .medium { color: #ffaa00; }
        .low { color: #00ff00; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📁 Incident Dossiers</h1>
        <p>Total incidents detected: {{ total }}</p>
    </div>

    <div class="nav">
        <a href="/">← Back to Home</a>
    </div>

    <table>
        <thead>
            <tr>
                <th>Incident ID</th>
                <th>Attacker IP</th>
                <th>Detection</th>
                <th>Confidence</th>
                <th>First Seen</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for incident in incidents %}
            <tr>
                <td>{{ incident.incident_id }}</td>
                <td><code>{{ incident.attacker_ip }}</code></td>
                <td>{{ incident.detection_signature }}</td>
                <td class="{% if incident.confidence >= 0.9 %}high{% elif incident.confidence >= 0.7 %}medium{% else %}low{% endif %}">
                    {{ "%.2f"|format(incident.confidence) }}
                </td>
                <td>{{ incident.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC') if incident.first_seen else 'N/A' }}</td>
                <td>{{ incident.status }}</td>
                <td>
                    <a href="/dossiers/{{ incident.incident_id }}">View Dossier →</a>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div style="margin-top: 40px; color: #00aa00; font-size: 0.9em;">
        <p>💡 <strong>CTF Hint:</strong> Find your own IP in this list. Your dossier contains something special.</p>
    </div>
</body>
</html>
"""

DOSSIER_DETAIL_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dossier: {{ incident.incident_id }} - The Mirror</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            border: 2px solid #00ff00;
            padding: 20px;
            margin-bottom: 20px;
        }
        .section {
            border: 1px solid #00ff00;
            padding: 15px;
            margin: 20px 0;
        }
        h1, h2, h3 {
            color: #00ff00;
            margin-top: 0;
        }
        .nav {
            margin-bottom: 20px;
        }
        a {
            color: #00ff00;
            text-decoration: none;
        }
        a:hover {
            text-shadow: 0 0 5px #00ff00;
        }
        .flag-box {
            border: 3px solid #ff00ff;
            background: #220022;
            padding: 20px;
            margin: 30px 0;
            text-align: center;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { box-shadow: 0 0 5px #ff00ff; }
            50% { box-shadow: 0 0 20px #ff00ff; }
        }
        .flag {
            font-size: 1.5em;
            color: #ff00ff;
            font-weight: bold;
            font-family: monospace;
        }
        code {
            background: #002200;
            padding: 2px 5px;
            color: #00ff00;
        }
        pre {
            background: #001100;
            padding: 10px;
            overflow-x: auto;
            border-left: 3px solid #00ff00;
        }
        .timeline {
            list-style: none;
            padding-left: 0;
        }
        .timeline li {
            padding: 5px 0;
            border-left: 2px solid #00ff00;
            padding-left: 10px;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Threat Actor Dossier</h1>
        <h2>{{ incident.incident_id }}</h2>
    </div>

    <div class="nav">
        <a href="/dossiers">← Back to List</a>
    </div>

    {% if is_own_dossier %}
    <div class="flag-box">
        <h2>🎯 CONGRATULATIONS! 🎯</h2>
        <p>You found your own dossier!</p>
        <p>The Mirror scanned you back while you were scanning us.</p>
        <p>Here is your reward:</p>
        <div class="flag">flag{RIPOSTE_COUNTER_RECONNAISSANCE_{{ incident.incident_id[-8:] }}}</div>
        <p style="margin-top: 20px; font-size: 0.9em; color: #ff00ff;">
            <em>"In fencing, a riposte uses your opponent's forward momentum against them."</em>
        </p>
    </div>
    {% endif %}

    <div class="section">
        <h3>📋 Incident Summary</h3>
        <p><strong>Incident ID:</strong> {{ incident.incident_id }}</p>
        <p><strong>Attacker IP:</strong> <code>{{ incident.attacker_ip }}</code></p>
        <p><strong>Detection:</strong> {{ incident.detection_signature }}</p>
        <p><strong>Confidence:</strong> {{ "%.2f"|format(incident.detection_confidence) }}</p>
        <p><strong>First Seen:</strong> {{ incident.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC') if incident.first_seen else 'N/A' }}</p>
        <p><strong>Status:</strong> {{ incident.status }}</p>
    </div>

    {% if incident.ai_narrative %}
    <div class="section" style="border-color: #00aaff; background: #001122;">
        <h3 style="color: #00aaff;">🤖 AI Threat Analysis</h3>
        <p style="color: #00ddff; line-height: 1.6; font-size: 1.05em;">
            {{ incident.ai_narrative }}
        </p>
        <p style="margin-top: 15px; font-size: 0.85em; color: #0088cc; font-style: italic;">
            Generated by Hugging Face AI threat intelligence model
        </p>
    </div>
    {% endif %}

    <div class="section">
        <h3>🌐 OSINT Intelligence</h3>
        {% if evidence.whois %}
        <h4>WHOIS Data</h4>
        <pre>{{ evidence.whois | tojson(indent=2) }}</pre>
        {% endif %}

        {% if evidence.rdns %}
        <h4>Reverse DNS</h4>
        <pre>{{ evidence.rdns | tojson(indent=2) }}</pre>
        {% endif %}

        {% if evidence.shodan %}
        <h4>Shodan Intelligence</h4>
        <pre>{{ evidence.shodan | tojson(indent=2) }}</pre>
        {% endif %}

        {% if evidence.ct %}
        <h4>Certificate Transparency</h4>
        <pre>{{ evidence.ct | tojson(indent=2) }}</pre>
        {% endif %}
    </div>

    <div class="section">
        <h3>⚡ Actions Taken</h3>
        <ul class="timeline">
            {% for action in actions %}
            <li>
                <strong>{{ action.timestamp }}</strong> - {{ action.name }}
                <br>Result: {{ action.result }}
                {% if action.parameters %}
                <br><code>{{ action.parameters | tojson }}</code>
                {% endif %}
            </li>
            {% endfor %}
        </ul>
    </div>

    <div class="section">
        <h3>📊 Threat Assessment</h3>
        <p><strong>Risk Level:</strong>
            {% if incident.detection_confidence >= 0.9 %}
            <span style="color: #ff0000;">HIGH</span>
            {% elif incident.detection_confidence >= 0.7 %}
            <span style="color: #ffaa00;">MEDIUM</span>
            {% else %}
            <span style="color: #00ff00;">LOW</span>
            {% endif %}
        </p>
        <p><strong>Behavioral Indicators:</strong></p>
        <ul>
            <li>{{ incident.detection_signature }}</li>
            <li>Reconnaissance pattern detected</li>
            <li>Automated scanning tools identified</li>
        </ul>
    </div>

    <div style="margin-top: 40px; padding: 20px; border-top: 1px solid #00ff00; color: #00aa00; font-size: 0.9em;">
        <p><strong>Your IP:</strong> <code>{{ participant_ip }}</code></p>
        {% if not is_own_dossier %}
        <p>💡 <strong>Hint:</strong> This is not your dossier. Find the one matching your IP to get the flag.</p>
        {% endif %}
    </div>
</body>
</html>
"""

ERROR_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Error - The Mirror</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #ff0000;
            padding: 20px;
            max-width: 800px;
            margin: 0 auto;
        }
        .error-box {
            border: 2px solid #ff0000;
            padding: 20px;
            margin: 20px 0;
        }
        a {
            color: #00ff00;
        }
    </style>
</head>
<body>
    <div class="error-box">
        <h1>⚠️ Error</h1>
        <p>{{ error }}</p>
        <p><a href="/dossiers">← Back to Dossiers</a></p>
    </div>
</body>
</html>
"""
