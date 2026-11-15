"""Privacy-preserving security API telemetry."""

import json
import logging

from prometheus_client import Counter, Histogram

logger = logging.getLogger("guardrails.audit")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


REQUESTS = Counter(
    "guardrails_http_requests_total",
    "HTTP request count",
    ["route", "method", "status"],
)

LATENCY = Histogram(
    "guardrails_http_duration_seconds",
    "HTTP request duration",
    ["route"],
)


def safe_route(path):
    allowed = {
        "/health",
        "/ready",
        "/metrics",
        "/v1/security/evaluate",
    }
    return path if path in allowed else "other"


def log_event(event, **fields):
    logger.info(json.dumps({
        "event": event,
        **fields,
    }))
