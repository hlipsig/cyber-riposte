"""
Resilience and Error Handling

Provides retry logic, circuit breakers, and graceful degradation for external services.
"""

import functools
import logging
import time
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """
    Circuit breaker pattern for external service calls.

    States:
    - CLOSED: Normal operation, calls pass through
    - OPEN: Service is down, calls fail immediately
    - HALF_OPEN: Testing if service recovered
    """

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function through circuit breaker.

        Args:
            func: Function to call
            *args, **kwargs: Function arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerOpen: If circuit is open
        """
        if self.state == "OPEN":
            # Check if enough time has passed to try recovery
            if self.last_failure_time and \
               time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "HALF_OPEN"
                logger.info(f"Circuit breaker HALF_OPEN: {func.__name__}")
            else:
                raise CircuitBreakerOpen(f"Circuit breaker is OPEN for {func.__name__}")

        try:
            result = func(*args, **kwargs)

            # Success - reset if in HALF_OPEN
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
                self.failure_count = 0
                logger.info(f"Circuit breaker CLOSED: {func.__name__}")

            return result

        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
                logger.error(
                    f"Circuit breaker OPEN: {func.__name__} "
                    f"(failures: {self.failure_count})"
                )

            raise


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker is open."""
    pass


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """
    Decorator for retrying functions with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds
        backoff_factor: Multiplier for delay after each retry
        exceptions: Tuple of exceptions to catch and retry

    Example:
        @retry_with_backoff(max_retries=3, initial_delay=1.0)
        def unreliable_api_call():
            ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)

                except exceptions as e:
                    if attempt == max_retries:
                        logger.error(
                            f"{func.__name__} failed after {max_retries} retries: {e}"
                        )
                        raise

                    logger.warning(
                        f"{func.__name__} failed (attempt {attempt + 1}/{max_retries}), "
                        f"retrying in {delay:.1f}s: {e}"
                    )

                    time.sleep(delay)
                    delay *= backoff_factor

        return wrapper
    return decorator


def fallback_on_error(fallback_value: Any = None, log_level: str = "warning"):
    """
    Decorator to return fallback value on exception.

    Args:
        fallback_value: Value to return if function raises exception
        log_level: Logging level for errors ("debug", "info", "warning", "error")

    Example:
        @fallback_on_error(fallback_value={})
        def get_osint_data(ip):
            ...  # Returns {} if fails
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log_func = getattr(logger, log_level, logger.warning)
                log_func(f"{func.__name__} failed, using fallback: {e}")
                return fallback_value
        return wrapper
    return decorator


# Global circuit breakers for external services
_circuit_breakers = {}


def get_circuit_breaker(service_name: str) -> CircuitBreaker:
    """Get or create circuit breaker for a service."""
    if service_name not in _circuit_breakers:
        _circuit_breakers[service_name] = CircuitBreaker()
    return _circuit_breakers[service_name]
