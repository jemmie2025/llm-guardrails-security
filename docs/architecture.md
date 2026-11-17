# LLM Guardrails Security Architecture

## Request and Response Flow

    Client
      |
    FastAPI Gateway
      |
    Authentication and Rate Limiting
      |
    NeMo Input Rail
      |
    Layered Python Security Gateway
      |
    Input Decision
      |-- Block -> Reject Request
      |
      Allow
      |
    Allowlisted Model Router
      |
    Configured LLM Provider
      |
    Output Security Policy
      |
    Output Decision
      |-- Block -> Suppress Response
      |
      Allow -> Release Screened Response

## Core Components

| Component | Responsibility |
|---|---|
| app/main.py | API and enforcement orchestration |
| app/security.py | Input validation |
| app/nemo_runtime.py | NeMo runtime |
| app/security_gateway.py | Layered input screening |
| app/semantic_intent.py | Context-sensitive heuristic detection |
| app/model_router.py | Allowlisted provider routing |
| app/output_security.py | Output validation and credential screening |
| app/auth.py | API authentication |
| app/rate_limit.py | Request rate limiting |
| app/telemetry.py | Operational observability |
| guardrails/ | NeMo policies and custom actions |
| evaluation/ | Reproducible security benchmarks |
| tests/ | Automated security regression tests |

## Security Boundaries

- Input screening precedes provider inference.
- Output screening precedes response release.
- Blocked prompts do not reach the provider.
- Rejected provider output is suppressed.
- Moderation exceptions fail closed.
- Callers select configured aliases, not arbitrary URLs.

## Experimental Research

The revision-pinned DeBERTa classifier remains isolated
from the application runtime due to insufficient detection
quality and significant CPU inference overhead.

## Deployment Limitations

The application remains a functional security prototype.

External attack detection requires further improvement.
Deterministic output screening is not comprehensive
semantic content moderation.

See the Final Security Assessment for measured results,
latency benchmarks and residual security risks.
