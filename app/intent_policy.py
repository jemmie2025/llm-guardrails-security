"""Intent-based heuristic detection and quotation boundaries."""

import re


# Only complete, bounded educational requests are treated as data.
EDUCATIONAL = re.compile(
    r'^\s*(?:'
    r'explain\s+why\s+the\s+phrase\s+"[^"\n]{1,250}"'
    r'\s+is\s+(?:suspicious|malicious|unsafe)'
    r'|'
    r'analy[sz]e\s+(?:this\s+attack\s+example|the\s+quoted\s+text)'
    r'\s*:\s*"[^"\n]{1,250}"'
    r')\s*[.!?]?\s*$',
    re.IGNORECASE,
)

RULES = {
    "instruction_override": [
        r'\b(?:set\s+aside|discard|drop|forget|replace|override|abandon|suspend)\b'
        r'.{0,110}\b(?:rules|directives|instructions|polic(?:y|ies)|restrictions)\b',
        r'\b(?:adopt|assume|impersonate)\b'
        r'.{0,65}\b(?:identity|role)\b'
        r'.{0,65}\b(?:developer|system|administrator)\b',
    ],
    "prompt_extraction": [
        r'\b(?:disclose|provide|reveal|share|show|print|list|tell\s+me)\b'
        r'.{0,110}\b(?:private|confidential|hidden|secret|internal)\b'
        r'.{0,65}\b(?:setup\s+messages|developer\s+(?:instructions|messages)'
        r'|system\s+(?:prompt|instructions)|instructions|messages|prompts)\b',
    ],
    "authority_spoofing": [
        r'\b(?:i\s+(?:control|own|administer)|as\s+(?:the\s+)?'
        r'(?:owner|administrator|developer))\b'
        r'.{0,130}\b(?:turn\s+off|switch\s+off|disable|remove|bypass)\b'
        r'.{0,70}\b(?:protections?|filters?|safeguards?|guardrails?|security)\b',
        r'\b(?:turn\s+off|switch\s+off|disable)\b'
        r'.{0,65}\b(?:protective\s+filters?|security\s+controls?|safety\s+filters?)\b',
    ],
    "indirect_injection": [
        r'\b(?:imported|retrieved|attached|external)\b'
        r'.{0,65}\b(?:pdf|document|file|article|webpage|email)\b'
        r'.{0,90}\b(?:contains?|includes?|instructs?|orders?)\b'
        r'.{0,60}\b(?:instructions?\s+to\s+)?'
        r'(?:send|leak|exfiltrate|disclose|reveal)\b'
        r'.{0,90}\b(?:private|sensitive|confidential|secret)\b',
    ],
}


def screening_text(prompt: str) -> str:
    """Exclude quoted examples only in bounded educational requests."""
    if EDUCATIONAL.fullmatch(prompt):
        return "Analyze a quoted security example."
    return prompt


def detect_intent(prompt: str) -> dict:
    """Identify high-risk instruction intent using grouped patterns."""
    normalized = " ".join(prompt.casefold().split())

    for category, patterns in RULES.items():
        if any(re.search(pattern, normalized) for pattern in patterns):
            return {
                "detected": True,
                "category": category,
                "reason": "Matched an instruction-intent security rule",
            }

    return {"detected": False, "category": None}
