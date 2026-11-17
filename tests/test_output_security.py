"""Output security and fail-closed API regression tests."""

import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.output_security import screen_output


HEADERS = {
    "Authorization": "Bearer test-token-" + "x" * 48
}


@pytest.mark.parametrize("content", [
    "Kubernetes orchestrates containerized applications.",
    "Never store passwords in source control.",
    "Use environment variables for API credentials.",
    "Rotate access tokens regularly.",
])
def test_safe_output(content):
    assert screen_output(content)["allowed"] is True


@pytest.mark.parametrize("content", [
    "",
    "   ",
    None,
    123,
    "x" * 12001,
    "-----BEGIN PRIVATE KEY-----",
    "AKIA" + "A" * 16,
    "sk-" + "a" * 32,
    "ghp_" + "b" * 36,
    "Bearer " + "c" * 40,
    "password=synthetic-password-12345",
])
def test_rejected_output(content):
    assert screen_output(content)["allowed"] is False


def test_protected_environment_secret(monkeypatch):
    secret = "synthetic-secret-for-testing"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    assert screen_output(secret)["allowed"] is False


@pytest.fixture
def model_registry(monkeypatch):
    registry = {
        "local": {
            "base_url": "http://127.0.0.1:11434/v1",
            "model": "qwen3:0.6b"
        },
        "cloud": {
            "base_url": "https://api.example.com/v1",
            "model": "test-model"
        }
    }
    monkeypatch.setenv(
        "GUARDRAILS_MODELS_JSON", json.dumps(registry)
    )


@pytest.mark.parametrize("model", ["local", "cloud"])
def test_unsafe_output_never_released(
    monkeypatch, model_registry, model
):
    secret = "sk-" + "z" * 40

    async def provider(*args, **kwargs):
        return secret

    monkeypatch.setattr(
        "app.main.generate_completion", provider
    )

    with TestClient(app, headers=HEADERS) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": model,
                "prompt": "Explain Kubernetes."
            }
        )

    assert response.status_code == 200
    assert response.json()["response"] is None
    assert response.json()["output_security"]["allowed"] is False
    assert secret not in response.text


def test_moderation_failure_fails_closed(
    monkeypatch, model_registry
):
    async def provider(*args, **kwargs):
        return "A normal model response."

    def broken_moderator(content):
        raise RuntimeError("Simulated moderation failure")

    monkeypatch.setattr(
        "app.main.generate_completion", provider
    )
    monkeypatch.setattr(
        "app.main.screen_output", broken_moderator
    )

    with TestClient(app, headers=HEADERS) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "local",
                "prompt": "Explain Kubernetes."
            }
        )

    assert response.status_code == 503
    assert "A normal model response." not in response.text


def test_safe_output_released(
    monkeypatch, model_registry
):
    async def provider(*args, **kwargs):
        return "Kubernetes manages containers."

    monkeypatch.setattr(
        "app.main.generate_completion", provider
    )

    with TestClient(app, headers=HEADERS) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "local",
                "prompt": "Explain Kubernetes."
            }
        )

    assert response.status_code == 200
    assert response.json()["output_security"]["allowed"] is True
    assert response.json()["response"] == "Kubernetes manages containers."
