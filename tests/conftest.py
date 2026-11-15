"""Test-only API authentication configuration."""

import pytest

TEST_TOKEN = "test-token-" + "x" * 48


@pytest.fixture(autouse=True)
def configure_test_auth(monkeypatch):
    monkeypatch.setenv("GUARDRAILS_API_TOKEN", TEST_TOKEN)
