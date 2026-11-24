"""Login rate limiter (brute-force protection).

A brute-force attack tries many passwords quickly. We count FAILED logins per
username and per client IP. Once either key reaches the limit inside the time
window, further attempts are refused (HTTP 429) until old failures expire.

Limitation (documented on purpose): counts live in memory, so they reset
when the server restarts and are not shared between multiple server
processes. That is fine for a single-instance lab app; a production system
would keep them in Redis or the database.
"""

import time
from collections import defaultdict, deque
from threading import Lock


class LoginRateLimiter:
    def __init__(self, max_failures: int, window_seconds: int) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()  # requests can run in parallel threads

    def _prune(self, key: str, now: float) -> deque[float]:
        attempts = self._failures[key]
        while attempts and now - attempts[0] > self.window_seconds:
            attempts.popleft()
        return attempts

    def retry_after(self, *keys: str) -> int:
        """Seconds until a blocked key may try again, or 0 if not blocked."""
        now = time.monotonic()
        with self._lock:
            wait = 0
            for key in keys:
                attempts = self._prune(key, now)
                if len(attempts) >= self.max_failures:
                    wait = max(wait, int(self.window_seconds - (now - attempts[0])) + 1)
            return wait

    def record_failure(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                self._prune(key, now).append(now)

    def reset(self, *keys: str) -> None:
        """Clear failures after a successful login."""
        with self._lock:
            for key in keys:
                self._failures.pop(key, None)
