"""API authentication with fail-closed configuration."""

import os
import secrets

from fastapi import Header, HTTPException


def require_api_token(
    authorization: str | None = Header(default=None),
) -> None:
    expected = os.getenv("GUARDRAILS_API_TOKEN")

    if (
        not expected
        or not 32 <= len(expected) <= 256
        or not expected.isascii()
        or any(c.isspace() for c in expected)
    ):
        raise HTTPException(
            status_code=503,
            detail="Security configuration unavailable",
        )

    scheme, separator, supplied = (
        authorization or ""
    ).partition(" ")

    if (
        not separator
        or scheme.lower() != "bearer"
        or not supplied
        or len(supplied) > 256
        or not supplied.isascii()
        or any(c.isspace() for c in supplied)
        or not secrets.compare_digest(supplied, expected)
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
