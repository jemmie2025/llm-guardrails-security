"""FastAPI application for LLM prompt security checks."""

from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.security_gateway import evaluate_prompt


app = FastAPI(
    title="LLM Guardrails Security API",
    description="Prompt validation and baseline injection detection.",
    version="0.1.0",
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
def evaluate_security(request: PromptRequest):
    """Evaluate a prompt before it reaches an LLM."""
    return evaluate_prompt(request.prompt)
