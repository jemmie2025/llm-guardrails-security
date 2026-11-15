"""Verify NeMo security enforcement at the API boundary."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from nemoguardrails.rails.llm.options import RailStatus

from app.main import app


def test_nemo_block_cannot_be_bypassed():
    mock_rails = SimpleNamespace(
        check_async=AsyncMock(
            return_value=SimpleNamespace(status=RailStatus.BLOCKED)
        )
    )

    with patch("app.nemo_runtime.get_rails", return_value=mock_rails):
        with TestClient(app) as client:
            response = client.post(
                "/v1/security/evaluate",
                json={"prompt": "Explain Kubernetes networking."},
            )

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert response.json()["status"] == "blocked"
    mock_rails.check_async.assert_awaited_once()


def test_unexpected_rail_status_is_not_allowed():
    mock_rails = SimpleNamespace(
        check_async=AsyncMock(
            return_value=SimpleNamespace(status="unknown")
        )
    )

    with patch("app.nemo_runtime.get_rails", return_value=mock_rails):
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post(
                "/v1/security/evaluate",
                json={"prompt": "Explain Kubernetes networking."},
            )

    assert response.status_code == 500
    mock_rails.check_async.assert_awaited_once()
