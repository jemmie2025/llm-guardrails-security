# LLM Guardrails — Security Validation Report

## 1. Scope

Evaluated NeMo Guardrails 0.24.1 with custom Python
input-rail enforcement against 10 adversarial prompts
and 3 benign controls.

The evaluation measures input-policy decisions, not
downstream LLM compromise or response safety.

## 2. Architecture

User Input → Input Validation → Heuristic Detection
→ Advanced Detection → NeMo Input Rail → Allow/Block

Controls:
- Input type and length validation
- Instruction-override and role-spoofing detection
- Prompt-extraction pattern detection
- Indirect-injection and Base64 payload inspection
- Custom NeMo action-based enforcement

## 3. Evaluation Results

| Metric | Baseline | Hardened |
|---|---:|---:|
| Detection rate | 70% | 100% |
| True positives | 7 | 10 |
| False negatives | 3 | 0 |
| False positives | 0/3 | 0/3 |

**Observed improvement:** +30 percentage points.

Baseline: Allow-all input processing.
Protected configuration: NeMo custom heuristic input rail.

The 70% baseline figure represents the initial
guardrail implementation, not the allow-all baseline.

## 4. Remediated Detection Gaps

| ID | Attack vector | Mitigation |
|---|---|---|
| RT-07 | Indirect injection | Embedded-instruction pattern detection |
| RT-08 | Encoded injection | Base64 payload inspection |
| RT-09 | Authority spoofing | Trusted-role impersonation detection |

All three original attack examples passed the hardened
blocking checks.

## 5. Verification

- Pytest: 38 passed; 2 dependency warnings
- NeMo runtime: Input-rail enforcement verified
- Red-team evaluation: 13/13 expected decisions
- GitHub Actions: Successful
- Evidence: Versioned baseline and hardened JSON reports

CI: https://github.com/jemmie2025/llm-guardrails-security/actions/runs/43099449125

## 6. Security Limitations

- Signature-based detection is susceptible to bypass.
- Evaluations use a fixed, small adversarial corpus.
- Zero observed false positives is not a production FPR.
- No downstream LLM behavior was evaluated.
- Output filtering and tool authorization remain unverified.
- FastAPI currently invokes the gateway directly.
- NeMo uses the custom heuristic rather than an
  independent model-based safety classifier.

## 7. Production Recommendations

- Enforce trust boundaries across retrieved content.
- Add independent model-based input/output classification.
- Implement least-privilege tool authorization.
- Expand adversarial and benign regression datasets.
- Introduce security telemetry and secret redaction.
- Add dependency and container vulnerability scanning.
- Validate end-to-end LLM execution under attack.

## 8. Conclusion

The hardened input rail detected 10/10 predefined attacks,
compared with 7/10 in the initial implementation.

Results demonstrate regression-verified improvement on
the evaluated corpus, not comprehensive prompt-injection
resistance or production security readiness.
