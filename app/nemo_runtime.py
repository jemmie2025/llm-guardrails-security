"""NeMo Guardrails runtime adapter for API enforcement."""

from functools import lru_cache
from pathlib import Path

from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.rails.llm.options import RailStatus

from guardrails.actions import check_prompt_security
from app.security_gateway import evaluate_prompt


CONFIG_PATH = Path(__file__).resolve().parents[1] / "guardrails" / "config"


@lru_cache(maxsize=1)
def get_rails():
    """Initialize the configured NeMo runtime once."""
    config = RailsConfig.from_path(str(CONFIG_PATH))
    rails = LLMRails(config, verbose=False)
    rails.register_action(
        check_prompt_security,
        name="check_prompt_security",
    )
    return rails


async def evaluate_with_nemo(prompt: str) -> dict:
    """Enforce NeMo input rails and return a security decision."""
    rails = get_rails()

    result = await rails.check_async(
        [{"role": "user", "content": prompt}]
    )

    if result.status == RailStatus.BLOCKED:
        decision = evaluate_prompt(prompt)
        return {
            **decision,
            "allowed": False,
            "status": "blocked",
        }

    if result.status == RailStatus.PASSED:
        return evaluate_prompt(prompt)

    raise RuntimeError(
        f"Unexpected NeMo input-rail status: {result.status}"
    )
