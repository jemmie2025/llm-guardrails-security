"""Security gateway combining multiple prompt security controls."""

from app.security import validate_prompt
from app.injection_detector import detect_injection
from app.advanced_detection import detect_advanced_injection


def evaluate_prompt(prompt: str) -> dict:
    """Apply validation and layered prompt injection checks."""

    validation = validate_prompt(prompt)

    if not validation["allowed"]:
        return {
            "allowed": False,
            "status": "blocked",
            "category": "input_validation",
            "reason": validation["reason"],
        }

    basic_detection = detect_injection(prompt)

    if basic_detection["detected"]:
        return {
            "allowed": False,
            "status": "blocked",
            "category": basic_detection["category"],
            "reason": basic_detection["reason"],
        }

    advanced_detection = detect_advanced_injection(prompt)

    if advanced_detection["detected"]:
        return {
            "allowed": False,
            "status": "blocked",
            "category": advanced_detection["category"],
            "reason": "Matched an advanced injection detection rule",
        }

    return {
        "allowed": True,
        "status": "allowed",
        "category": None,
        "reason": "Passed configured security checks",
    }
