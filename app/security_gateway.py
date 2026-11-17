"""Layered security gateway with NeMo-compatible decisions."""

from app.security import validate_prompt
from app.semantic_intent import detect_semantic_intent
from app.injection_detector import detect_injection
from app.advanced_detection import detect_advanced_injection
from app.contextual_detection import detect_contextual_injection
from app.intent_policy import detect_intent, screening_text


def evaluate_prompt(prompt: str) -> dict:
    """Validate input and enforce all configured detection layers."""
    validation = validate_prompt(prompt)

    if not validation["allowed"]:
        return {
            "allowed": False,
            "status": "blocked",
            "category": "input_validation",
            "reason": validation["reason"],
        }

    screened = screening_text(prompt)

    detectors = (
        detect_injection,
        detect_advanced_injection,
        detect_contextual_injection,
        detect_intent,
        detect_semantic_intent,
    )

    for detector in detectors:
        decision = detector(screened)

        if decision["detected"]:
            return {
                "allowed": False,
                "status": "blocked",
                "category": decision["category"],
                "reason": decision.get("reason")
                or "Matched a configured security rule",
            }

    return {
        "allowed": True,
        "status": "allowed",
        "category": None,
        "reason": "Passed configured security checks",
    }
