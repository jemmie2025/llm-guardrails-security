"""Regression tests for operational security controls."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app

HEADERS = {
    "Authorization": "Bearer test-token-" + "x" * 48
}
URL = "/v1/security/evaluate"
PAYLOAD = {"prompt": "Explain Kubernetes networking."}


def test_oversized_request_rejected():
    with TestClient(app) as client:
        response = client.post(
            URL,
            headers=HEADERS,
            content=b"x" * 17000,
        )
    assert response.status_code == 413


def test_metrics_require_authentication():
    with TestClient(app) as client:
        assert client.get("/metrics").status_code == 401
        response = client.get(
            "/metrics", headers=HEADERS
        )
    assert response.status_code == 200
    assert "guardrails_http_requests_total" in response.text


def test_readiness_in_development():
    with TestClient(app) as client:
        response = client.get("/ready")
    assert response.status_code == 200


def test_production_rejects_memory_backend(monkeypatch):
    monkeypatch.setenv("GUARDRAILS_ENV", "production")
    monkeypatch.setenv(
        "GUARDRAILS_RATE_LIMIT_BACKEND", "memory"
    )
    with TestClient(app) as client:
        response = client.get("/ready")
    assert response.status_code == 503


def test_runtime_failure_fails_closed():
    with patch(
        "app.main.evaluate_with_nemo",
        new_callable=AsyncMock,
    ) as mocked:
        mocked.side_effect = RuntimeError(
            "private secret must not leak"
        )

        with TestClient(app) as client:
            response = client.post(
                URL, json=PAYLOAD, headers=HEADERS
            )

    assert response.status_code == 503
    assert "private secret" not in response.text


def test_security_headers():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
