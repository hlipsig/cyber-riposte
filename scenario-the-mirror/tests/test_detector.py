"""
Unit tests for detection logic (agent/detector.py).
"""

import pytest
from agent.detector import detect_recon


class TestDetectRecon:
    """Test reconnaissance detection."""

    def test_ids_alert_detection(self):
        """Test IDS alert triggers detection."""
        event = {
            "event_type": "alert",
            "src_ip": "203.0.113.42",
            "alert": {
                "category": "Attempted Recon",
                "signature": "Nmap scan detected",
            },
            "timestamp": "2024-06-15T03:14:07.123Z",
        }

        detection = detect_recon(event)

        assert detection is not None
        assert detection["src_ip"] == "203.0.113.42"
        assert detection["signature"] == "Nmap scan detected"
        assert detection["confidence"] >= 0.95  # IDS alerts are high confidence
        assert len(detection["signals"]) > 0

    def test_suspicious_user_agent(self):
        """Test suspicious user agent detection."""
        event = {
            "event_type": "http",
            "src_ip": "198.51.100.15",
            "http": {
                "http_user_agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
                "hostname": "example.com",
                "url": "/",
                "http_method": "GET",
            },
            "timestamp": "2024-06-15T03:15:00.000Z",
        }

        detection = detect_recon(event)

        assert detection is not None
        assert detection["src_ip"] == "198.51.100.15"
        assert "Nuclei" in detection["signature"]
        assert detection["confidence"] >= 0.85

    def test_multiple_signals(self):
        """Test event with multiple detection signals."""
        event = {
            "event_type": "alert",
            "src_ip": "192.0.2.100",
            "alert": {
                "category": "Attempted Recon",
                "signature": "Port scan detected",
            },
            "http": {
                "http_user_agent": "sqlmap/1.7.2",
                "url": "/admin/login.php",
            },
            "timestamp": "2024-06-15T03:16:00.000Z",
        }

        detection = detect_recon(event)

        assert detection is not None
        assert detection["src_ip"] == "192.0.2.100"
        assert len(detection["signals"]) >= 2  # IDS + user agent
        assert detection["confidence"] >= 0.95  # Multiple signals boost confidence

    def test_benign_event(self):
        """Test benign event doesn't trigger detection."""
        event = {
            "event_type": "http",
            "src_ip": "10.0.0.1",
            "http": {
                "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "hostname": "example.com",
                "url": "/index.html",
                "http_method": "GET",
            },
            "timestamp": "2024-06-15T03:17:00.000Z",
        }

        detection = detect_recon(event)

        assert detection is None

    def test_missing_src_ip(self):
        """Test event without src_ip doesn't crash."""
        event = {
            "event_type": "alert",
            "alert": {
                "category": "Attempted Recon",
            },
        }

        detection = detect_recon(event)

        assert detection is None

    def test_confidence_calculation(self):
        """Test confidence scores are in valid range."""
        events = [
            # High confidence (IDS alert)
            {
                "event_type": "alert",
                "src_ip": "1.2.3.4",
                "alert": {"category": "Attempted Recon"},
            },
            # Medium confidence (suspicious UA)
            {
                "event_type": "http",
                "src_ip": "1.2.3.5",
                "http": {"http_user_agent": "nmap"},
            },
        ]

        for event in events:
            detection = detect_recon(event)
            if detection:
                assert 0.0 <= detection["confidence"] <= 1.0
