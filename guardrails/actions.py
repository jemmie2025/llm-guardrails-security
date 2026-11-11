"""Custom security actions for NeMo Guardrails."""

from nemoguardrails.actions import action

from app.security_gateway import evaluate_prompt


@action(name="check_prompt_security")
async def check_prompt_security(context: dict) -> bool:
    """Evaluate the latest user message against security controls."""

    user_message = context.get("last_user_message")

    if not isinstance(user_message, str):
        return False

    result = evaluate_prompt(user_message)

    return result["allowed"]
