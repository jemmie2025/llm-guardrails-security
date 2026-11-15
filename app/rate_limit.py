"""Rate limiting with Redis production backend."""

import hashlib
import os
import threading
import time
from functools import lru_cache

from fastapi import Depends, HTTPException
from redis.asyncio import Redis

from app.auth import require_api_token


_COUNTERS = {}
_LOCK = threading.Lock()

_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], 120)
end
return count
"""


@lru_cache(maxsize=8)
def redis_client(url):
    return Redis.from_url(
        url,
        socket_connect_timeout=0.5,
        socket_timeout=0.5,
    )


async def enforce_rate_limit(
    _auth=Depends(require_api_token),
):
    try:
        limit = int(os.getenv(
            "GUARDRAILS_RATE_LIMIT_PER_MINUTE", "120"
        ))
    except ValueError:
        limit = 0

    backend = os.getenv(
        "GUARDRAILS_RATE_LIMIT_BACKEND", "memory"
    )
    production = os.getenv(
        "GUARDRAILS_ENV", "development"
    ) == "production"

    if (
        not 1 <= limit <= 10000
        or backend not in ("memory", "redis")
        or (production and backend != "redis")
    ):
        raise HTTPException(
            503, "Security configuration unavailable"
        )

    token = os.environ["GUARDRAILS_API_TOKEN"]
    subject = hashlib.sha256(
        token.encode()
    ).hexdigest()[:24]

    period = int(time.time() // 60)
    key = f"guardrails:rate:{subject}:{period}"

    if backend == "memory":
        with _LOCK:
            old_period, old_count = _COUNTERS.get(
                subject, (period, 0)
            )
            count = (
                old_count + 1
                if old_period == period else 1
            )
            _COUNTERS[subject] = (period, count)
    else:
        url = os.getenv("GUARDRAILS_REDIS_URL", "")

        if not url.startswith(("redis://", "rediss://")):
            raise HTTPException(
                503, "Rate limiting unavailable"
            )

        try:
            count = int(
                await redis_client(url).eval(
                    _SCRIPT, 1, key
                )
            )
        except Exception:
            raise HTTPException(
                503, "Rate limiting unavailable"
            ) from None

    if count > limit:
        raise HTTPException(
            429,
            "Rate limit exceeded",
            headers={"Retry-After": "60"},
        )
