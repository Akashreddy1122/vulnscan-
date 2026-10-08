"""Global asynchronous request pacing."""

import asyncio
import secrets


_RNG = secrets.SystemRandom()


class RateLimiter:
    """Serialize request starts with an upper rate and optional jitter."""

    def __init__(self, rate: float, jitter: float = 0) -> None:
        """Initialize timing state."""
        self.interval = 1.0 / rate
        self.jitter = jitter
        self.next_at = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Reserve the next request slot without blocking the event loop."""
        async with self.lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            start = max(now, self.next_at)
            self.next_at = start + self.interval + _RNG.uniform(0, self.jitter)
            await asyncio.sleep(max(0, start - now))
