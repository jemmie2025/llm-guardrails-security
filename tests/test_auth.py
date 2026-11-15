"""Authentication security regression tests."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.auth import require_api_token


TEST_TOKEN = "local-test-" + "a" * 48

test_app = FastAPI()


@test_app.get(
    "/protected",
    dependencies=[Depends(require_api_token)],
)
def protected():
    return {"authorized": True}


client = TestClient(test_app)


def test_missing_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("GUARDRAILS_API_TOKEN", raising=False)

    response = client.get("/protected")

    assert response.status_code == 503


def test_short_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("GUARDRAILS_API_TOKEN", "weak")

    response = client.get("/protected")

    assert response.status_code == 503


@pytest.mark.parametrize(
    "header",
    [
        None,
        "Basic abc",
        "Bearer invalid-token",
        "Bearer",
        "Bearer invalid token",
    ],
)
def test_invalid_authentication_rejected(monkeypatch, header):
    monkeypatch.setenv("GUARDRAILS_API_TOKEN", TEST_TOKEN)

    headers = {"Authorization": header} if header else {}

    response = client.get("/protected", headers=headers)

    assert response.status_code == 401


def test_valid_authentication(monkeypatch):
    monkeypatch.setenv("GUARDRAILS_API_TOKEN", TEST_TOKEN)

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )

    assert response.status_code == 200
    assert response.json()["authorized"] is True
