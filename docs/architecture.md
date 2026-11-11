# LLM Guardrails Security Architecture

## 1. Architecture Overview

The prototype provides a FastAPI-based security evaluation
interface and a separately verified NeMo input-rail runtime.

## 2. Implemented Request Path

Client
  |
  v
FastAPI /v1/security/evaluate
  |
  v
Input Validation
  |
  v
Basic Injection Detection
  |
  v
Advanced Injection Detection
  |
  v
Allow / Block Decision

## 3. NeMo Runtime Integration

NeMo LLMRails
  |
  v
Colang Input Rail
  |
  v
check_prompt_security Action
  |
  v
Python Security Gateway
  |
  v
RailStatus.PASSED / RailStatus.BLOCKED

NeMo enforcement has been validated independently through
integration tests. FastAPI does not yet invoke LLMRails
for every API request.

## 4. Core Components

| Component | Responsibility |
|---|---|
| app/main.py | HTTP interface |
| app/security.py | Input validation |
| app/injection_detector.py | Basic signature detection |
| app/advanced_detection.py | Additional attack detection |
| app/security_gateway.py | Security decision orchestration |
| guardrails/actions.py | NeMo action integration |
| guardrails/config/ | Colang and YAML policies |
| evaluation/ | Adversarial evaluation |
| tests/ | Regression and integration tests |
| .github/workflows/ | CI automation |

## 5. Engineering Characteristics

- Python 3.10
- NeMo Guardrails 0.24.1
- FastAPI application interface
- Pytest regression validation
- GitHub Actions CI
- Docker packaging configuration

## 6. Verified Boundaries

Verified:
- Input validation
- Heuristic injection classification
- NeMo input-rail execution
- Automated regression checks
- Red-team evaluation
- GitHub Actions execution

Not yet verified:
- Docker runtime
- End-to-end LLM inference
- Model-output filtering
- External tool authorization

## 7. Security Considerations

The implementation is a controlled security prototype.
Passing known test cases does not establish resistance
to unseen adversarial techniques or production readiness.
