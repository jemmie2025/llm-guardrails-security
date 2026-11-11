# LLM Guardrail Frameworks — Technical Assessment

## 1. Objective

Evaluate three LLM security frameworks for prompt-injection
mitigation, runtime policy enforcement, and integration
with Python-based AI applications.

## 2. Framework Comparison

| Criterion | NeMo Guardrails | Llama Guard 4 | Rebuff |
|---|---|---|---|
| Architecture | Programmable policy engine | 12B safety classifier | Multi-layer injection detector |
| Primary function | Runtime guardrail orchestration | Input/output content classification | Prompt-injection detection |
| Detection approach | Custom actions and configurable rails | Model inference | Heuristics, LLM, vector search |
| Input enforcement | Supported | Requires application integration | Requires application integration |
| Output evaluation | Supported | Supported | Canary-token leakage detection |
| Python integration | Native | Inference/API integration | Python SDK |
| Maintenance | Maintained | Meta model release | Archived May 2025 |

## 3. Technical Findings

### NeMo Guardrails

Supports input, retrieval, dialog, execution, and output
rails through configurable policies and custom actions.

Selected for this prototype because it supports
deterministic input enforcement and Python integration.

Implemented version: 0.24.1.

### Llama Guard 4

A 12-billion-parameter multimodal safety classifier
supporting input and output moderation.

Requires model inference infrastructure and application-
level handling of classifier decisions.

Evaluated through documentation only; not deployed.

### Rebuff

Combines heuristic detection, LLM-based analysis,
vector similarity, and canary-token leakage detection.

Its repository was archived on May 16, 2025.
Not selected as a production dependency.

Evaluated through documentation only; not deployed.

## 4. Implementation Results

The selected NeMo implementation combines custom Python
validation with heuristic prompt-injection detection.

Verified evaluation:
- Initial detection: 7/10 predefined attacks
- Hardened detection: 10/10 predefined attacks
- Observed improvement: +30 percentage points
- Hardened evaluation: 0/3 benign prompts blocked
- Automated tests: 38 passed
- GitHub Actions: Successful

These are input-rail classification results, not
measurements of downstream LLM compromise.

## 5. Engineering Decision

NeMo Guardrails was selected for programmable policy
enforcement and compatibility with the Python application.

Llama Guard is a candidate for future independent
model-based safety classification.

Rebuff is retained as a reference architecture but is
not recommended as an actively maintained dependency.

## 6. Residual Risks

- Signature evasion and adversarial paraphrasing
- Incomplete encoded-payload coverage
- False positives on unseen legitimate inputs
- Unvalidated model outputs and downstream tool calls
- Limited adversarial corpus and no model-level testing

## 7. References

- NVIDIA NeMo Guardrails:
  https://docs.nvidia.com/nemo/guardrails/v0.24.1/

- Meta Llama Guard 4:
  https://dev.meta.ai/llama/docs/model-cards-and-prompt-formats/llama-guard-4

- Protect AI Rebuff:
  https://github.com/protectai/rebuff
