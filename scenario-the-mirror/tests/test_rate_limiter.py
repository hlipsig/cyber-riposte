"""
Unit tests for rate limiter (agent/rate_limiter.py).
"""

import pytest
import time
from agent.rate_limiter import RateLimiter, OSINTRateLimiter


class TestRateLimiter:
    """Test token bucket rate limiter."""

    def test_allow_within_limit(self):
        """Test requests within limit are allowed."""
        limiter = RateLimiter(rate=10, per=60)  # 10 per minute

        # First 10 requests should be allowed
        for i in range(10):
            assert limiter.allow("test") is True

    def test_rate_limit_exceeded(self):
        """Test requests beyond limit are rejected."""
        limiter = RateLimiter(rate=5, per=60)

        # Use up all tokens
        for i in range(5):
            limiter.allow("test")

        # Next request should be rate limited
        assert limiter.allow("test") is False

    def test_token_refill(self):
        """Test tokens refill over time."""
        limiter = RateLimiter(rate=10, per=1)  # 10 per second

        # Use all tokens
        for i in range(10):
            limiter.allow("test")

        # Should be rate limited
        assert limiter.allow("test") is False

        # Wait for refill (0.2 seconds = 2 tokens)
        time.sleep(0.2)

        # Should have refilled 2 tokens
        assert limiter.allow("test") is True
        assert limiter.allow("test") is True
        assert limiter.allow("test") is False  # Third should fail

    def test_wait_time_calculation(self):
        """Test wait time until next token."""
        limiter = RateLimiter(rate=10, per=1)  # 10 per second

        # Use all tokens
        for i in range(10):
            limiter.allow("test")

        # Should need to wait ~0.1 seconds for next token
        wait = limiter.wait_time("test")
        assert 0.05 <= wait <= 0.15  # Allow some tolerance

    def test_reset(self):
        """Test resetting rate limit."""
        limiter = RateLimiter(rate=5, per=60)

        # Use all tokens
        for i in range(5):
            limiter.allow("test")

        # Reset
        limiter.reset("test")

        # Should be allowed again
        assert limiter.allow("test") is True

    def test_get_stats(self):
        """Test statistics retrieval."""
        limiter = RateLimiter(rate=10, per=60)

        # Use some tokens
        for i in range(3):
            limiter.allow("test")

        stats = limiter.get_stats("test")

        assert stats is not None
        assert stats["rate"] == 10
        assert stats["per"] == 60
        assert 6.5 <= stats["tokens"] <= 7.5  # Used 3, should have ~7 left


class TestOSINTRateLimiter:
    """Test OSINT-specific rate limiter."""

    def test_module_limits(self):
        """Test per-module rate limits."""
        limiter = OSINTRateLimiter()

        # Shodan has lower limit (6 per minute)
        # Use up Shodan tokens
        for i in range(6):
            assert limiter.allow("shodan") is True

        # Shodan should be rate limited
        assert limiter.allow("shodan") is False

        # But WHOIS should still work (10 per minute)
        assert limiter.allow("whois") is True

    def test_unknown_module(self):
        """Test unknown module is allowed."""
        limiter = OSINTRateLimiter()

        # Unknown module should be allowed (no limit)
        assert limiter.allow("unknown_module") is True

    def test_all_modules_configured(self):
        """Test all expected modules are configured."""
        limiter = OSINTRateLimiter()

        expected_modules = ["shodan", "whois", "rdns", "ct"]

        for module in expected_modules:
            stats = limiter.get_stats(module)
            assert stats is not None
            assert "rate" in stats
            assert "per" in stats
