"""
OSINT caching layer with Redis (Phase 6).
Reduces API calls and improves performance by caching OSINT results.
"""

import json
import logging
import hashlib
from typing import Optional, Dict, Any, Callable
from functools import wraps

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("Redis client not available. Install with: pip install redis")

from agent.config import Config


logger = logging.getLogger(__name__)


class OSINTCache:
    """
    Redis-backed cache for OSINT lookups.

    Features:
    - TTL-based expiration (default 7 days)
    - Key namespacing by module (whois, rdns, shodan, ct)
    - Automatic serialization/deserialization
    - Cache hit/miss statistics
    """

    def __init__(self, redis_url: str = None, default_ttl: int = 604800):
        """
        Initialize OSINT cache.

        Args:
            redis_url: Redis connection URL (default: from Config.REDIS_URL)
            default_ttl: Default TTL in seconds (default: 7 days)
        """
        self.redis_url = redis_url or Config.REDIS_URL
        self.default_ttl = default_ttl
        self.client: Optional[redis.Redis] = None
        self.stats = {
            "hits": 0,
            "misses": 0,
            "errors": 0,
        }

        self._connect()

    def _connect(self):
        """Connect to Redis."""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available. OSINT caching disabled.")
            return

        if not self.redis_url:
            logger.warning("REDIS_URL not set. OSINT caching disabled.")
            return

        try:
            self.client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            # Test connection
            self.client.ping()
            logger.info(f"Connected to Redis at {self.redis_url}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.client = None

    def _make_key(self, module: str, target: str) -> str:
        """
        Generate cache key.

        Format: osint:{module}:{target_hash}

        Args:
            module: OSINT module name (whois, rdns, shodan, ct)
            target: Target IP/domain

        Returns:
            Cache key string
        """
        # Hash target to handle long/special characters
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
        return f"osint:{module}:{target_hash}"

    def get(self, module: str, target: str) -> Optional[Dict[str, Any]]:
        """
        Get cached OSINT result.

        Args:
            module: OSINT module name
            target: Target IP/domain

        Returns:
            Cached result dict, or None if not found
        """
        if not self.client:
            return None

        key = self._make_key(module, target)

        try:
            data = self.client.get(key)
            if data:
                self.stats["hits"] += 1
                logger.debug(f"Cache HIT: {module}:{target}")
                return json.loads(data)
            else:
                self.stats["misses"] += 1
                logger.debug(f"Cache MISS: {module}:{target}")
                return None
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Cache GET error: {e}")
            return None

    def set(
        self,
        module: str,
        target: str,
        result: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> bool:
        """
        Store OSINT result in cache.

        Args:
            module: OSINT module name
            target: Target IP/domain
            result: OSINT result dict
            ttl: TTL in seconds (default: self.default_ttl)

        Returns:
            True if cached successfully, False otherwise
        """
        if not self.client:
            return False

        key = self._make_key(module, target)
        ttl = ttl or self.default_ttl

        try:
            data = json.dumps(result)
            self.client.setex(key, ttl, data)
            logger.debug(f"Cached: {module}:{target} (TTL: {ttl}s)")
            return True
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Cache SET error: {e}")
            return False

    def delete(self, module: str, target: str) -> bool:
        """
        Delete cached result.

        Args:
            module: OSINT module name
            target: Target IP/domain

        Returns:
            True if deleted, False otherwise
        """
        if not self.client:
            return False

        key = self._make_key(module, target)

        try:
            self.client.delete(key)
            logger.debug(f"Deleted cache: {module}:{target}")
            return True
        except Exception as e:
            logger.error(f"Cache DELETE error: {e}")
            return False

    def get_stats(self) -> Dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dict with hits, misses, errors, hit_rate
        """
        total = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total * 100) if total > 0 else 0.0

        return {
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "errors": self.stats["errors"],
            "total": total,
            "hit_rate": round(hit_rate, 2),
        }

    def clear_stats(self):
        """Reset statistics counters."""
        self.stats = {"hits": 0, "misses": 0, "errors": 0}

    def flush_all(self) -> bool:
        """
        Flush all OSINT cache keys.

        WARNING: Only flushes keys matching osint:* pattern.

        Returns:
            True if successful, False otherwise
        """
        if not self.client:
            return False

        try:
            cursor = 0
            count = 0
            while True:
                cursor, keys = self.client.scan(cursor, match="osint:*", count=100)
                if keys:
                    self.client.delete(*keys)
                    count += len(keys)
                if cursor == 0:
                    break

            logger.info(f"Flushed {count} OSINT cache keys")
            return True
        except Exception as e:
            logger.error(f"Cache FLUSH error: {e}")
            return False


# Global cache instance
_cache: Optional[OSINTCache] = None


def get_osint_cache() -> OSINTCache:
    """
    Get singleton OSINT cache instance.

    Returns:
        OSINTCache instance
    """
    global _cache
    if _cache is None:
        _cache = OSINTCache()
    return _cache


def cached_osint(module: str, ttl: int = 604800):
    """
    Decorator for caching OSINT lookup functions.

    Usage:
        @cached_osint("whois", ttl=86400)
        def whois_lookup(ip: str) -> dict:
            # Expensive API call
            return result

    Args:
        module: OSINT module name (whois, rdns, shodan, ct)
        ttl: Cache TTL in seconds (default: 7 days)

    Returns:
        Decorated function with caching
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(target: str, *args, **kwargs) -> Dict[str, Any]:
            cache = get_osint_cache()

            # Try cache first
            cached_result = cache.get(module, target)
            if cached_result is not None:
                return cached_result

            # Cache miss - call actual function
            result = func(target, *args, **kwargs)

            # Store in cache
            if result:
                cache.set(module, target, result, ttl=ttl)

            return result

        return wrapper

    return decorator
