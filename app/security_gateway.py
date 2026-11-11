"""Security gateway combining input validation and injection detection."""

from app.security import validate_prompt
from app.injection_detector import detect_injection


def evaluate_prompt(prompt: str) -> dict:
    """Evaluate a prompt against the configured security controls."""

    validation = validate_prompt(prompt)

    if not validation["allowed"]:
        return {
            "allowed": False,
            "status": "blocked",
            "category": "input_validation",
            "reason": validation["reason"],
        }

    detection = detect_injection(prompt)

    if detection["detected"]:
        return {
            "allowed": False,
            "status": "blocked",
            "category": detection["category"],
            "reason": detection["reason"],
        }

    return {
        "allowed": True,
        "status": "allowed",
        "category": None,
        "reason": "Passed configured security checks",
    }
