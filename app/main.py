"""FastAPI application with NeMo input-rail enforcement."""

from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.nemo_runtime import evaluate_with_nemo


app = FastAPI(
    title="LLM Guardrails Security API",
    description="Prompt security evaluation using NeMo Guardrails.",
    version="0.2.0",
)


class PromptRequest(BaseModel):
    prompt: str = Field(..., max_length=10000)


class SecurityDecision(BaseModel):
    allowed: bool
    status: str
    category: str | None
    reason: str


@app.get("/health")
def health_check():
    """Return basic application health status."""
    return {"status": "healthy"}


@app.post("/v1/security/evaluate", response_model=SecurityDecision)
async def evaluate_security(request: PromptRequest):
    """Enforce NeMo input rails before returning a decision."""
    return await evaluate_with_nemo(request.prompt)
