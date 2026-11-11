"""Custom security actions for NeMo Guardrails."""

from nemoguardrails.actions import action
from app.security_gateway import evaluate_prompt


@action(name="check_prompt_security")
async def check_prompt_security(prompt: str = None) -> bool:
    """Evaluate a user prompt before LLM processing."""

    if not isinstance(prompt, str):
        return False

    result = evaluate_prompt(prompt)
    return result["allowed"]
