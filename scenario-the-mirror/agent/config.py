"""
Configuration management for The Mirror agent.
All configuration comes from environment variables with sensible defaults.
"""
import os
from pathlib import Path


class Config:
    """Agent configuration from environment variables."""

    # Base paths
    BASE_DIR = Path(__file__).parent.parent
    TEMPLATE_DIR = BASE_DIR / "templates"

    # Honeypot configuration
    HONEYPOT_IP = os.getenv("HONEYPOT_IP", "honeypot-service.cyber-riposte.svc.cluster.local")

    # Action pool and signatures
    ACTION_POOL_PATH = os.getenv("ACTION_POOL_PATH", str(BASE_DIR / "action-pool.yaml"))
    USER_AGENTS_PATH = os.getenv("USER_AGENTS_PATH", str(BASE_DIR / "suspicious-user-agents.yaml"))

    # Audit log (Phase 1: file-based, Phase 3: will be PostgreSQL)
    AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/var/log/cyber-riposte/audit.jsonl")

    # Evidence storage
    EVIDENCE_DIR = os.getenv("EVIDENCE_DIR", "/var/log/cyber-riposte/evidence")
    POSTMORTEM_DIR = os.getenv("POSTMORTEM_DIR", "/var/log/cyber-riposte/postmortems")

    # Health check
    HEALTH_PORT = int(os.getenv("HEALTH_PORT", "8080"))

    # Event source (Phase 1: stdin/suricata, Phase 2: kafka)
    EVENT_SOURCE = os.getenv("EVENT_SOURCE", "stdin")  # stdin, suricata, or kafka

    # Suricata configuration (Phase 1)
    SURICATA_EVE_LOG = os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json")
    SURICATA_MODE = os.getenv("SURICATA_MODE", "file")  # file or redis

    # Kafka configuration (Phase 2)
    KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "suricata-eve-events")
    KAFKA_CONSUMER_GROUP = os.getenv("KAFKA_CONSUMER_GROUP", "mirror-agent")

    # Database configuration (Phase 3)
    DATABASE_URL = os.getenv("DATABASE_URL", "")
    DATABASE_POOL_MIN = int(os.getenv("DATABASE_POOL_MIN", "2"))
    DATABASE_POOL_MAX = int(os.getenv("DATABASE_POOL_MAX", "10"))

    # OSINT API keys
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

    # Redis configuration (Phase 6)
    REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

    # GitHub integration (Phase 8)
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
    GITHUB_REPO = os.getenv("GITHUB_REPO", "")  # e.g., "hlipsig/cyber-riposte-incidents"

    # Slack integration (Phase 8)
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = os.getenv("LOG_FORMAT", "json")  # json or text

    # LLM Configuration
    LLM_BACKEND = os.getenv("LLM_BACKEND", "rules")  # rules, claude, huggingface, hybrid, auto

    # Claude API
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")

    # Hugging Face
    HF_MODEL = os.getenv("HF_MODEL", "meta-llama/Llama-3.1-8B-Instruct")
    HF_DEVICE = os.getenv("HF_DEVICE", "cpu")  # cpu, cuda, mps
    HF_USE_API = os.getenv("HF_USE_API", "false").lower() == "true"
    HF_API_TOKEN = os.getenv("HF_API_TOKEN", "")

    @classmethod
    def validate(cls):
        """Validate critical configuration and warn about missing values."""
        warnings = []

        if not cls.SHODAN_API_KEY:
            warnings.append("SHODAN_API_KEY not set - Shodan lookups will return placeholder data")

        if cls.EVENT_SOURCE == "kafka" and not cls.KAFKA_BOOTSTRAP_SERVERS:
            warnings.append("KAFKA_BOOTSTRAP_SERVERS not set but EVENT_SOURCE=kafka")

        if cls.DATABASE_URL and not cls.DATABASE_URL.startswith("postgresql"):
            warnings.append(f"DATABASE_URL should start with postgresql:// but got: {cls.DATABASE_URL[:20]}")

        # LLM validation
        if cls.LLM_BACKEND in ["claude", "hybrid", "auto"]:
            if not cls.ANTHROPIC_API_KEY:
                warnings.append("LLM_BACKEND includes Claude but ANTHROPIC_API_KEY not set")

        if cls.LLM_BACKEND in ["huggingface", "hybrid", "auto"]:
            if not cls.HF_USE_API and cls.HF_DEVICE == "cuda":
                warnings.append("HF_DEVICE=cuda but GPU may not be available - will fall back to CPU")

        return warnings


# Export config values as module-level constants for easy import
HONEYPOT_IP = Config.HONEYPOT_IP
ACTION_POOL_PATH = Config.ACTION_POOL_PATH
USER_AGENTS_PATH = Config.USER_AGENTS_PATH
AUDIT_LOG_PATH = Config.AUDIT_LOG_PATH
EVIDENCE_DIR = Config.EVIDENCE_DIR
POSTMORTEM_DIR = Config.POSTMORTEM_DIR
HEALTH_PORT = Config.HEALTH_PORT
EVENT_SOURCE = Config.EVENT_SOURCE
KAFKA_BOOTSTRAP_SERVERS = Config.KAFKA_BOOTSTRAP_SERVERS
KAFKA_TOPIC = Config.KAFKA_TOPIC
KAFKA_CONSUMER_GROUP = Config.KAFKA_CONSUMER_GROUP
DATABASE_URL = Config.DATABASE_URL
DATABASE_POOL_MIN = Config.DATABASE_POOL_MIN
DATABASE_POOL_MAX = Config.DATABASE_POOL_MAX
SHODAN_API_KEY = Config.SHODAN_API_KEY
REDIS_URL = Config.REDIS_URL
GITHUB_TOKEN = Config.GITHUB_TOKEN
GITHUB_REPO = Config.GITHUB_REPO
SLACK_WEBHOOK_URL = Config.SLACK_WEBHOOK_URL
LOG_LEVEL = Config.LOG_LEVEL
LOG_FORMAT = Config.LOG_FORMAT
LLM_BACKEND = Config.LLM_BACKEND
ANTHROPIC_API_KEY = Config.ANTHROPIC_API_KEY
CLAUDE_MODEL = Config.CLAUDE_MODEL
HF_MODEL = Config.HF_MODEL
HF_DEVICE = Config.HF_DEVICE
HF_USE_API = Config.HF_USE_API
HF_API_TOKEN = Config.HF_API_TOKEN
