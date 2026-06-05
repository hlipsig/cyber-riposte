"""
Rate limiter for OSINT API calls (Phase 6).
Implements token bucket algorithm to prevent quota exhaustion.
"""

import time
import logging
from typing import Dict, Optional
from threading import Lock


logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Token bucket rate limiter.

    Limits API calls per time window to prevent quota exhaustion.
    Each OSINT module has its own bucket.

    Example:
        limiter = RateLimiter(rate=10, per=60)  # 10 calls per minute
        if limiter.allow("shodan"):
            result = shodan_api_call()
        else:
            # Rate limited - wait or skip
    """

    def __init__(self, rate: int, per: int = 60):
        """
        Initialize rate limiter.

        Args:
            rate: Number of allowed calls
            per: Time window in seconds
        """
        self.rate = rate
        self.per = per
        self.buckets: Dict[str, Dict[str, float]] = {}
        self.lock = Lock()

        logger.info(f"Rate limiter initialized: {rate} calls per {per}s")

    def allow(self, key: str) -> bool:
        """
        Check if request is allowed.

        Uses token bucket algorithm:
        - Bucket starts with 'rate' tokens
        - Each call consumes 1 token
        - Tokens refill at constant rate

        Args:
            key: Rate limit key (e.g., "shodan", "whois")

        Returns:
            True if allowed, False if rate limited
        """
        with self.lock:
            now = time.time()

            # Initialize bucket if doesn't exist
            if key not in self.buckets:
                self.buckets[key] = {
                    "tokens": float(self.rate),
                    "last_update": now,
                }

            bucket = self.buckets[key]

            # Refill tokens based on elapsed time
            elapsed = now - bucket["last_update"]
            refill_rate = self.rate / self.per  # tokens per second
            bucket["tokens"] = min(
                self.rate,
                bucket["tokens"] + (elapsed * refill_rate)
            )
            bucket["last_update"] = now

            # Check if token available
            if bucket["tokens"] >= 1.0:
                bucket["tokens"] -= 1.0
                return True
            else:
                logger.warning(f"Rate limited: {key} (tokens: {bucket['tokens']:.2f})")
                return False

    def wait_time(self, key: str) -> float:
        """
        Get wait time until next token available.

        Args:
            key: Rate limit key

        Returns:
            Wait time in seconds (0 if token available now)
        """
        with self.lock:
            now = time.time()

            if key not in self.buckets:
                return 0.0

            bucket = self.buckets[key]

            # Refill tokens
            elapsed = now - bucket["last_update"]
            refill_rate = self.rate / self.per
            bucket["tokens"] = min(
                self.rate,
                bucket["tokens"] + (elapsed * refill_rate)
            )

            # If token available, no wait
            if bucket["tokens"] >= 1.0:
                return 0.0

            # Calculate wait time for next token
            tokens_needed = 1.0 - bucket["tokens"]
            wait_seconds = tokens_needed / refill_rate

            return wait_seconds

    def reset(self, key: str):
        """
        Reset rate limit for a key.

        Args:
            key: Rate limit key
        """
        with self.lock:
            if key in self.buckets:
                self.buckets[key] = {
                    "tokens": float(self.rate),
                    "last_update": time.time(),
                }
                logger.info(f"Rate limit reset: {key}")

    def get_stats(self, key: str) -> Optional[Dict[str, float]]:
        """
        Get rate limit statistics for a key.

        Args:
            key: Rate limit key

        Returns:
            Dict with tokens, rate, per, wait_time
        """
        with self.lock:
            if key not in self.buckets:
                return None

            bucket = self.buckets[key]
            wait = self.wait_time(key)

            return {
                "tokens": round(bucket["tokens"], 2),
                "rate": self.rate,
                "per": self.per,
                "wait_time": round(wait, 2),
            }


class OSINTRateLimiter:
    """
    Pre-configured rate limiters for OSINT modules.

    Limits:
    - Shodan: 1 call per 10 seconds (free tier: 1/s max, conservative)
    - WHOIS: 10 calls per minute (most WHOIS servers allow ~60/min)
    - rDNS: 30 calls per minute (local DNS, no strict limit)
    - CT: 10 calls per minute (crt.sh API)
    """

    def __init__(self):
        self.limiters = {
            "shodan": RateLimiter(rate=6, per=60),     # 6 per minute
            "whois": RateLimiter(rate=10, per=60),     # 10 per minute
            "rdns": RateLimiter(rate=30, per=60),      # 30 per minute
            "ct": RateLimiter(rate=10, per=60),        # 10 per minute
        }

        logger.info("OSINT rate limiters initialized")

    def allow(self, module: str) -> bool:
        """
        Check if OSINT call is allowed.

        Args:
            module: OSINT module name (shodan, whois, rdns, ct)

        Returns:
            True if allowed, False if rate limited
        """
        if module not in self.limiters:
            logger.warning(f"Unknown OSINT module: {module}")
            return True  # Allow unknown modules

        return self.limiters[module].allow(module)

    def wait_time(self, module: str) -> float:
        """
        Get wait time for OSINT module.

        Args:
            module: OSINT module name

        Returns:
            Wait time in seconds
        """
        if module not in self.limiters:
            return 0.0

        return self.limiters[module].wait_time(module)

    def get_stats(self, module: str) -> Optional[Dict[str, float]]:
        """
        Get rate limit stats for module.

        Args:
            module: OSINT module name

        Returns:
            Stats dict or None
        """
        if module not in self.limiters:
            return None

        return self.limiters[module].get_stats(module)

    def reset(self, module: str):
        """
        Reset rate limit for module.

        Args:
            module: OSINT module name
        """
        if module in self.limiters:
            self.limiters[module].reset(module)


# Global rate limiter instance
_rate_limiter: Optional[OSINTRateLimiter] = None


def get_osint_rate_limiter() -> OSINTRateLimiter:
    """
    Get singleton OSINT rate limiter instance.

    Returns:
        OSINTRateLimiter instance
    """
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = OSINTRateLimiter()
    return _rate_limiter
