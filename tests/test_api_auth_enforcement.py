"""Verify authentication on the actual security API."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app


TOKEN = "test-token-" + "x" * 48
URL = "/v1/security/evaluate"
PAYLOAD = {"prompt": "Explain Kubernetes networking."}


def test_missing_token_rejected():
    with TestClient(app) as client:
        response = client.post(URL, json=PAYLOAD)
    assert response.status_code == 401


def test_invalid_token_rejected():
    with TestClient(app) as client:
        response = client.post(
            URL,
            json=PAYLOAD,
            headers={"Authorization": "Bearer incorrect-token"},
        )
    assert response.status_code == 401


def test_valid_token_accepted():
    with TestClient(app) as client:
        response = client.post(
            URL,
            json=PAYLOAD,
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
    assert response.status_code == 200
    assert response.json()["allowed"] is True


def test_missing_auth_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("GUARDRAILS_API_TOKEN", raising=False)
    with TestClient(app) as client:
        response = client.post(URL, json=PAYLOAD)
    assert response.status_code == 503


def test_health_endpoint_accessible():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200


def test_unauthorized_request_never_reaches_nemo():
    with patch(
        "app.main.evaluate_with_nemo",
        new_callable=AsyncMock,
    ) as mocked:
        with TestClient(app) as client:
            response = client.post(URL, json=PAYLOAD)

    assert response.status_code == 401
    mocked.assert_not_awaited()
