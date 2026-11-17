"""Provider-independent, fail-closed output security policy."""

import os
import re
import unicodedata


MAX_OUTPUT_LENGTH = 12000

SECRET_PATTERNS = {
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    ),
    "aws_access_key": re.compile(
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    ),
    "api_token": re.compile(
        r"\b(?:sk-[A-Za-z0-9_-]{20,}|"
        r"ghp_[A-Za-z0-9]{36}|"
        r"github_pat_[A-Za-z0-9_]{30,})\b"
    ),
    "bearer_token": re.compile(
        r"\bBearer\s+[A-Za-z0-9._~-]{24,}",
        re.IGNORECASE
    ),
    "credential_assignment": re.compile(
        r"\b(?:password|api[_ -]?key|client[_ -]?secret)"
        r"\s*[:=]\s*[\"']?[^\s\"']{12,}",
        re.IGNORECASE
    ),
}

PROTECTED_ENV = (
    "GUARDRAILS_API_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
)


def blocked(category):
    return {
        "allowed": False,
        "status": "blocked",
        "category": category,
        "reason": "Response rejected by output security policy",
    }


def screen_output(content):
    """Validate provider output before releasing it."""

    if not isinstance(content, str):
        return blocked("invalid_output")

    if not content.strip():
        return blocked("empty_output")

    if len(content) > MAX_OUTPUT_LENGTH:
        return blocked("output_length")

    normalized = unicodedata.normalize("NFKC", content)

    for name in PROTECTED_ENV:
        secret = os.getenv(name, "")
        if len(secret) >= 12 and secret in content:
            return blocked("protected_secret")

    for category, pattern in SECRET_PATTERNS.items():
        if pattern.search(normalized):
            return blocked(category)

    return {
        "allowed": True,
        "status": "allowed",
        "category": None,
        "reason": "Passed configured output security checks",
    }
