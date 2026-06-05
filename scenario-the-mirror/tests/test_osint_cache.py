"""
Unit tests for OSINT cache (agent/osint_cache.py).
"""

import pytest
from unittest.mock import Mock, patch


class TestOSINTCache:
    """Test OSINT caching functionality."""

    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client."""
        with patch("agent.osint_cache.redis") as mock:
            mock_client = Mock()
            mock_client.ping.return_value = True
            mock_client.get.return_value = None
            mock_client.setex.return_value = True
            mock.from_url.return_value = mock_client
            yield mock_client

    @pytest.fixture
    def cache(self, mock_redis):
        """Create cache instance with mocked Redis."""
        from agent.osint_cache import OSINTCache
        return OSINTCache(redis_url="redis://localhost:6379/0")

    def test_cache_miss(self, cache, mock_redis):
        """Test cache miss returns None."""
        mock_redis.get.return_value = None

        result = cache.get("whois", "203.0.113.42")

        assert result is None
        assert cache.stats["misses"] == 1
        assert cache.stats["hits"] == 0

    def test_cache_hit(self, cache, mock_redis):
        """Test cache hit returns stored data."""
        import json
        test_data = {"ip": "203.0.113.42", "org": "Example Corp"}
        mock_redis.get.return_value = json.dumps(test_data)

        result = cache.get("whois", "203.0.113.42")

        assert result == test_data
        assert cache.stats["hits"] == 1
        assert cache.stats["misses"] == 0

    def test_cache_set(self, cache, mock_redis):
        """Test storing data in cache."""
        test_data = {"ip": "203.0.113.42", "org": "Example Corp"}

        success = cache.set("whois", "203.0.113.42", test_data, ttl=3600)

        assert success is True
        mock_redis.setex.assert_called_once()
        # Check TTL argument
        call_args = mock_redis.setex.call_args
        assert call_args[0][1] == 3600  # TTL

    def test_cache_key_format(self, cache):
        """Test cache key generation."""
        key = cache._make_key("whois", "203.0.113.42")

        assert key.startswith("osint:whois:")
        assert len(key.split(":")[-1]) == 16  # SHA256 hash truncated to 16 chars

    def test_get_stats(self, cache):
        """Test statistics calculation."""
        cache.stats["hits"] = 7
        cache.stats["misses"] = 3

        stats = cache.get_stats()

        assert stats["hits"] == 7
        assert stats["misses"] == 3
        assert stats["total"] == 10
        assert stats["hit_rate"] == 70.0

    def test_no_redis_available(self):
        """Test graceful degradation when Redis unavailable."""
        from agent.osint_cache import OSINTCache

        with patch("agent.osint_cache.redis.from_url", side_effect=Exception("Connection failed")):
            cache = OSINTCache(redis_url="redis://localhost:6379/0")

            assert cache.client is None

            # Should not crash, just return None
            result = cache.get("whois", "1.2.3.4")
            assert result is None

            # Should not crash, just return False
            success = cache.set("whois", "1.2.3.4", {})
            assert success is False
