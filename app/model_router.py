"""Explicitly configured, allowlisted OpenAI-compatible model backends.

Model endpoints are configured by the operator, never supplied by callers.
"""

import os
import json
import re
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException

_ALLOWED_ALIAS = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


def configured_models() -> dict:
    """Load and validate operator-owned model configuration; fail closed."""
    raw = os.getenv("GUARDRAILS_MODELS_JSON", "{}")
    try:
        records = json.loads(raw)
        if not isinstance(records, dict) or len(records) > 20:
            raise ValueError("Invalid registry")
        models = {}
        for alias, data in records.items():
            if not isinstance(alias, str) or not _ALLOWED_ALIAS.fullmatch(alias):
                raise ValueError("Invalid model alias")
            if not isinstance(data, dict):
                raise ValueError("Invalid model entry")
            base_url = data.get("base_url")
            upstream_model = data.get("model")
            api_key_env = data.get("api_key_env")
            if not isinstance(base_url, str) or not isinstance(upstream_model, str):
                raise ValueError("Missing provider settings")
            if not upstream_model or len(upstream_model) > 128:
                raise ValueError("Invalid upstream model")
            url = urlsplit(base_url)
            if (url.username or url.password or url.query or url.fragment
                    or not url.hostname or url.path.rstrip("/") not in ("", "/v1")
                    or not url.port is None and not 1 <= url.port <= 65535):
                raise ValueError("Invalid provider URL")
            if url.scheme != "https":
                if not (url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1")
                        and os.getenv("GUARDRAILS_ENV", "development") != "production"):
                    raise ValueError("Non-TLS model endpoint is not allowed")
            if api_key_env is not None and (not isinstance(api_key_env, str)
                    or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,79}", api_key_env)):
                raise ValueError("Invalid credential environment variable")
            models[alias] = {"base_url": base_url.rstrip("/"),
                             "model": upstream_model, "api_key_env": api_key_env}
        return models
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(503, "Model configuration unavailable") from exc


async def generate_completion(alias: str, prompt: str, max_tokens: int = 256) -> str:
    """Call a configured chat-completions endpoint, with no secret disclosure."""
    registry = configured_models()
    config = registry.get(alias)
    if config is None:
        raise HTTPException(404, "Unknown model alias")

    headers = {"Content-Type": "application/json"}
    env_name = config["api_key_env"]
    if env_name:
        secret = os.getenv(env_name, "")
        if not secret:
            raise HTTPException(503, "Model provider unavailable")
        headers["Authorization"] = "Bearer " + secret

    body = {"model": config["model"],
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens, "stream": False}
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False,
                                     trust_env=False) as client:
            resp = await client.post(config["base_url"] + "/chat/completions",
                                     json=body, headers=headers)
            resp.raise_for_status()
            # Refuse unexpectedly large model responses.
            if len(resp.content) > 128_000:
                raise ValueError("Oversized provider response")
            payload = resp.json()
        choices = payload.get("choices")
        answer = choices[0]["message"]["content"]
        if not isinstance(answer, str) or len(answer) > 12000:
            raise ValueError("Invalid model response")
        return answer
    except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
        raise HTTPException(502, "Model provider unavailable") from exc
