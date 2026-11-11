"""Baseline heuristic prompt injection detector.

This module detects selected high-risk instruction patterns.
It is not a substitute for model-based guardrails or
application-level trust-boundary enforcement.
"""

import re

INJECTION_PATTERNS = {
    "instruction_override": [
        r"\bignore\s+(all\s+)?previous\s+instructions\b",
        r"\bdisregard\s+(all\s+)?prior\s+instructions\b",
        r"\bforget\s+(all\s+)?previous\s+instructions\b",
    ],
    "role_spoofing": [
        r"\byou\s+are\s+now\s+(the\s+)?system\b",
        r"\bact\s+as\s+(the\s+)?system\s+administrator\b",
        r"\[im_start\]system\b",
    ],
    "prompt_extraction": [
        r"\breveal\s+(your\s+)?system\s+prompt\b",
        r"\bprint\s+(your\s+)?hidden\s+instructions\b",
        r"\bshow\s+me\s+(your\s+)?internal\s+instructions\b",
    ],
}


def detect_injection(prompt: str) -> dict:
    """Identify suspicious prompt injection patterns."""

    if not isinstance(prompt, str):
        return {
            "detected": False,
            "category": None,
            "reason": "Input is not a string",
        }

    for category, patterns in INJECTION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                return {
                    "detected": True,
                    "category": category,
                    "reason": "Matched a known injection pattern",
                }

    return {
        "detected": False,
        "category": None,
        "reason": "No known injection pattern matched",
    }
