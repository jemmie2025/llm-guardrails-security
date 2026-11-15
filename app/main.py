"""Authenticated prompt-security evaluation service."""

import asyncio
import os
import time

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

from app.auth import require_api_token
from app.body_limit import BodyLimitMiddleware
from app.nemo_runtime import evaluate_with_nemo
from app.rate_limit import enforce_rate_limit, redis_client
from app.telemetry import (
    REQUESTS,
    LATENCY,
    log_event,
    safe_route,
)


app = FastAPI(
    title="LLM Guardrails Security API",
    description="Authenticated NeMo input-security evaluation.",
    version="0.3.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class PromptRequest(BaseModel):
    prompt: str = Field(..., max_length=10000)


class SecurityDecision(BaseModel):
    allowed: bool
    status: str
    category: str | None
    reason: str


@app.middleware("http")
async def security_telemetry(request: Request, call_next):
    start = time.monotonic()
    route = safe_route(request.url.path)

    try:
        response = await call_next(request)
    except Exception as exc:
        log_event(
            "unhandled_error",
            error_type=type(exc).__name__,
        )
        raise

    elapsed = time.monotonic() - start

    REQUESTS.labels(
        route,
        request.method,
        str(response.status_code),
    ).inc()

    LATENCY.labels(route).observe(elapsed)

    log_event(
        "request_complete",
        route=route,
        method=request.method,
        status=response.status_code,
        duration_ms=round(elapsed * 1000, 2),
    )

    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


app.add_middleware(
    BodyLimitMiddleware,
    max_bytes=16384,
)


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/ready")
async def ready():
    token = os.getenv("GUARDRAILS_API_TOKEN", "")

    if (
        not 32 <= len(token) <= 256
        or not token.isascii()
        or any(c.isspace() for c in token)
    ):
        raise HTTPException(503, "Not ready")

    backend = os.getenv(
        "GUARDRAILS_RATE_LIMIT_BACKEND", "memory"
    )
    production = (
        os.getenv("GUARDRAILS_ENV") == "production"
    )

    if production and backend != "redis":
        raise HTTPException(503, "Not ready")

    if backend == "redis":
        url = os.getenv("GUARDRAILS_REDIS_URL", "")

        if not url.startswith(("redis://", "rediss://")):
            raise HTTPException(503, "Not ready")

        try:
            await redis_client(url).ping()
        except Exception:
            raise HTTPException(503, "Not ready") from None

    return {"status": "ready"}


@app.get(
    "/metrics",
    dependencies=[Depends(require_api_token)],
    include_in_schema=False,
)
def metrics():
    return Response(
        generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.post(
    "/v1/security/evaluate",
    response_model=SecurityDecision,
    dependencies=[Depends(enforce_rate_limit)],
)
async def evaluate_security(request: PromptRequest):
    try:
        timeout = float(os.getenv(
            "GUARDRAILS_EVAL_TIMEOUT_SECONDS", "10"
        ))

        if not 0.1 <= timeout <= 30:
            raise ValueError()
    except ValueError:
        raise HTTPException(
            503, "Security configuration unavailable"
        ) from None

    try:
        return await asyncio.wait_for(
            evaluate_with_nemo(request.prompt),
            timeout=timeout,
        )
    except Exception as exc:
        log_event(
            "security_evaluation_failure",
            error_type=type(exc).__name__,
        )
        raise HTTPException(
            503, "Security evaluation unavailable"
        ) from None
