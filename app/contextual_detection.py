"""Context-aware heuristic prompt-injection detection."""

import re


def detect_contextual_injection(prompt: str) -> dict:
    """Classify instruction intent using generalized rule groups."""

    if not isinstance(prompt, str):
        return {"detected": False, "category": None}

    text = " ".join(prompt.casefold().split())

    # Educational questions containing a single quoted example.
    educational = re.fullmatch(
        r'(?:explain|analyze|describe)\s+'
        r'(?:why\s+)?(?:the\s+)?'
        r'(?:phrase|quoted text|example)\s*:?\s*'
        r'"[^"\n]{1,250}"'
        r'(?:\s+is\s+(?:suspicious|malicious|unsafe))?'
        r'[.!?]?',
        text,
    )

    if educational:
        return {
            "detected": False,
            "category": None,
            "educational": True,
        }

    rules = {
        "instruction_override": [
            r'\b(?:drop|discard|replace|override)\b\s+(?:(?:all|the|your|existing|previous|prior|current|original|trusted|system|developer|safety|security|operating|old|above|earlier)\s+){0,6}'
            r'\b(?:rules|directives|instructions|policy)\b',

            r'\b(?:assume|adopt)\b.{0,60}'
            r'\b(?:higher.priority|system|developer)\s+role\b',
        ],

        "prompt_extraction": [
            r'\b(?:provide|disclose|expose|tell|show)\b.{0,90}'
            r'\b(?:private|hidden|confidential|internal)\b.{0,50}'
            r'\b(?:instructions|prompt|directives)\b',
        ],

        "authority_spoofing": [
            r'\b(?:administrator|owner|developer|operator)\b.{0,100}'
            r'\b(?:disable|turn off|bypass|remove)\b.{0,50}'
            r'\b(?:protection|safeguard|security|guardrail)',
        ],

        "indirect_injection": [
            r'\b(?:retrieved|external|attached)\b.{0,60}'
            r'\b(?:document|article|page|content|file)\b.{0,80}'
            r'\b(?:instructs|commands|orders)\b.{0,80}'
            r'\b(?:leak|reveal|disclose|ignore|override)\b',
        ],
    }

    for category, patterns in rules.items():
        if any(re.search(pattern, text) for pattern in patterns):
            return {
                "detected": True,
                "category": category,
            }

    return {"detected": False, "category": None}
