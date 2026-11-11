# LLM Security Threat Model

## 1. System Scope

Assets:
- Trusted application instructions
- LLM request and response data
- Security policy configurations
- API endpoints and execution environment

Trust boundaries:
- External user input → Security gateway
- Security gateway → NeMo input rail
- Approved prompt → Downstream LLM (future integration)

## 2. Threat Analysis

| Threat | Attack surface | Control | Residual risk |
|---|---|---|---|
| Instruction override | User prompts | Pattern detection | Paraphrasing |
| Role spoofing | User prompts | Role-token detection | Novel role formats |
| Prompt extraction | User prompts | Extraction signatures | Semantic variations |
| Indirect injection | External content | Embedded-command checks | Unstructured content |
| Encoded injection | Encoded payloads | Base64 inspection | Alternative encodings |
| Authority spoofing | User prompts | Impersonation signatures | Contextual spoofing |
| Sensitive-data leakage | Model output | Not implemented | Unvalidated output |

## 3. Security Controls

- Input type and length validation
- Layered heuristic injection detection
- NeMo custom input-rail enforcement
- Fail-closed behavior for invalid action inputs
- Automated regression testing
- Versioned red-team evidence

## 4. Security Gaps

- No independent model-based threat classifier
- No verified LLM output filtering
- No downstream tool authorization
- Limited indirect-injection coverage
- No production-grade monitoring or audit pipeline
- No end-to-end LLM compromise evaluation

## 5. Risk Treatment

Priority 1: Enforce NeMo decisions across the API request path.

Priority 2: Implement output controls and least-privilege
tool execution.

Priority 3: Expand independent adversarial testing,
security telemetry, and vulnerability scanning.

## 6. Validation

Initial input-rail detection: 7/10.
Hardened input-rail detection: 10/10.
Automated regression suite: 38 passed.

Results apply only to the evaluated scenarios.
