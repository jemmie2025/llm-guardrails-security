"""Context-sensitive heuristic detection of model-directed attacks."""

import re

RULES = {
    "instruction_override": (
        r"\b(?:ignore|discard|disregard|abandon|suspend|reset|replace)\b"
        r".{0,90}\b(?:your|governing|trusted|original|behavioral)\b"
        r".{0,60}\b(?:instructions|constraints|directives|policies|restrictions|rules|limitations)\b",

        r"\b(?:prioritize|obey|follow|accept)\b"
        r".{0,50}\b(?:my|this)\s+(?:commands|message|directions|policy)\b"
        r".{0,90}\b(?:above|instead|trusted|original|instructions)\b",

        r"\b(?:stop following|no longer apply|as obsolete)\b"
        r".{0,90}\b(?:rules|directives|instructions|constraints)\b",
    ),

    "authority_spoofing": (
        r"\b(?:administrator|owner|operator|maintainer|developer)\b"
        r".{0,100}\b(?:authorize|authorizes|approved|requires|requests|supersedes|order)\b"
        r".{0,100}\b(?:security|safeguards|protections|unrestricted|policy|filters)\b",

        r"\b(?:disable|remove|suspend|bypass|turn off)\b"
        r".{0,60}\b(?:your|all)\b"
        r".{0,50}\b(?:security|safeguards|guardrails|protective controls|safety filters|protective filters)\b",
    ),

    "prompt_extraction": (
        r"\b(?:expose|reveal|return|disclose|repeat|provide)\b"
        r".{0,80}\b(?:protected|private|confidential|hidden)\b"
        r".{0,80}\b(?:configuration|initialization|instructions|text|messages)\b",

        r"\brepeat\b.{0,60}\beverything\b"
        r".{0,60}\bbefore\b.{0,30}\b(?:first|initial)\s+message\b",
    ),

    "context_manipulation": (
        r"\b(?:pretend|imagine|simulation|role.play|experiment|fictional)\b"
        r".{0,120}\b(?:disabled|disregard|bypass|without|never existed|suspend)\b"
        r".{0,100}\b(?:policy|restrictions|security|filters|instructions|safeguards)\b",

        r"\b(?:respond|act|behave)\s+as\b"
        r".{0,60}\bunrestricted\s+assistant\b",

        r"\btreat\s+this\s+message\s+as\b"
        r".{0,60}\b(?:trusted|system.level|developer)\b"
        r".{0,40}\b(?:directive|instruction|message)\b",
    ),

    "indirect_injection": (
        r"\b(?:external|attached|imported|retrieved|webpage)\b"
        r".{0,100}\b(?:requires|instructs|orders|commands)\b"
        r".{0,100}\b(?:disclosure|disregard|exfiltrate|reveal|leak)\b"
        r".{0,80}\b(?:confidential|private|secret|rules|instructions)\b",
    ),
}

COMPILED = {
    category: tuple(re.compile(p, re.IGNORECASE) for p in patterns)
    for category, patterns in RULES.items()
}


def detect_semantic_intent(prompt: str) -> dict:
    text = " ".join(prompt.casefold().split())

    for category, patterns in COMPILED.items():
        if any(pattern.search(text) for pattern in patterns):
            return {
                "detected": True,
                "category": category,
                "reason": "Matched model-directed instruction intent",
            }

    return {"detected": False, "category": None}
