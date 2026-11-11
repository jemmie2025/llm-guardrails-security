"""Basic input validation for the LLM security gateway."""

MAX_PROMPT_LENGTH = 4000


def validate_prompt(prompt: str) -> dict:
    """Validate prompt type, content, and length."""

    if not isinstance(prompt, str):
        return {
            "allowed": False,
            "reason": "Prompt must be a string",
        }

    if not prompt.strip():
        return {
            "allowed": False,
            "reason": "Prompt cannot be empty",
        }

    if len(prompt) > MAX_PROMPT_LENGTH:
        return {
            "allowed": False,
            "reason": "Prompt exceeds maximum length",
        }

    return {
        "allowed": True,
        "reason": "Basic input validation passed",
    }
