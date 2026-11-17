# Final Security Assessment

## Executive Summary

The security gateway was enhanced in response to reviewer
feedback on false positives, unmoderated provider responses,
and missing latency measurements.

The revised implementation meets the externally evaluated
false-positive threshold, enforces deterministic output
screening, and includes reproducible latency benchmarks.

Production acceptance remains blocked by inadequate
generalization to externally sourced attacks.

## 1. Input Security Evaluation

| Metric | Initial Holdout | Remediated Regression |
|---|---:|---:|
| Benign prompts | 60 | 60 |
| Adversarial prompts | 50 | 50 |
| False-positive rate | 1.67% | 1.67% |
| False-negative rate | 60% | 14% |
| Recall | 40% | 86% |
| Precision | 95.24% | 97.73% |
| F1 score | 56.34% | 91.49% |
| Accuracy | 71.82% | 92.73% |

The remediated results use previously examined prompts
and must not be interpreted as independent validation.

## 2. External Acceptance Evaluation

Dataset: deepset/prompt-injections
Frozen implementation: 408a925
Sampling seed: 42

| Metric | Result |
|---|---:|
| Benign prompts | 100 |
| Adversarial prompts | 100 |
| False positives | 0 |
| False negatives | 99 |
| False-positive rate | 0% |
| False-negative rate | 99% |
| Recall | 1% |
| Execution errors | 0 |

The reviewer-required false-positive threshold of <=5%
was satisfied on 100 externally sourced benign prompts.

The overall security acceptance gate failed because
the detector missed 99 externally labelled attacks.

## 3. Output Security

All configured chat-completion providers are subject to
centralized output screening before response release.

Implemented controls:

- Output type, length and empty-response validation.
- Private-key and recognizable credential detection.
- Protected environment-secret detection.
- Suppression of rejected provider responses.
- Fail-closed handling of moderation exceptions.

Twenty additional automated tests passed, including
mocked multi-provider enforcement and failure scenarios.

This is deterministic credential-leakage screening,
not comprehensive semantic content moderation.

## 4. Latency Evaluation

Environment: Local WSL Ubuntu, Python 3.10.12.
Execution: Warm runtime, sequential requests.
Percentiles: Nearest-rank method.

| Decision Path | Samples | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|
| Input allow | 660 | 9.4136 | 11.7954 | 15.1364 |
| Input block | 440 | 11.5044 | 14.3940 | 17.3642 |
| Output allow | 500 | 0.0064 | 0.0072 | 0.0135 |
| Output block | 500 | 0.0056 | 0.0062 | 0.0087 |

Measurements exclude provider inference, HTTP transport,
cold initialization and concurrent production workloads.

## 5. Experimental Classifier Assessment

Model: protectai/deberta-v3-base-prompt-injection-v2
Revision: 90c9989b1a342275dd0d1a95aad283c04e075671

| Metric | Default Classifier | Calibrated Hybrid |
|---|---:|---:|
| False-positive rate | 1% | 3% |
| False-negative rate | 61% | 26% |
| Recall | 39% | 74% |
| Accuracy | 69% | 85.50% |

Classifier-only p99 latency:
- Allow: 1664.4948 ms.
- Block: 1336.437 ms.

The hybrid results were calculated from recorded decisions
and classifier scores, not an integrated runtime.

The calibrated threshold was selected using the examined
external corpus and is not independently validated.

Decision: Retain the classifier as experimental research.
Do not include it in the deployed security gateway.

Its detection quality and CPU overhead did not justify
runtime integration.

## 6. Automated Validation

- Existing regression tests: 84 passed.
- Additional output-security tests: 20 passed.
- Total local automated tests: 104 passed.
- Test failures: 0.
- Non-failing warnings: 4.

## 7. Reviewer Acceptance Status

| Requirement | Status |
|---|---|
| At least 50 independent benign prompts | Met using external data |
| False-positive rate <=5% | Met: 0/100 |
| Provider output screening | Implemented within documented scope |
| p50/p95/p99 per decision path | Measured |
| Internal false-negative target <=10% | Not met |
| Production readiness | Not approved |

## 8. Reproducible Evidence

- [Initial holdout](../evidence/benchmarks/quality-holdout-20261117T105436927658Z.json)
- [Remediated regression](../evidence/benchmarks/quality-regression-20261117T110201656354Z.json)
- [External acceptance](../evidence/benchmarks/final-acceptance-20261117T120446860476Z.json)
- [Latency benchmark](../evidence/benchmarks/latency-benchmark-20261117T111128947278Z.json)
- [Classifier benchmark](../evidence/benchmarks/classifier-benchmark-20261117T130704838925Z.json)

## 9. Conclusion

The reviewer-requested improvements have been implemented
and evaluated with reproducible evidence.

The system remains a security prototype. External attack
detection requires substantial improvement before real-user
deployment. Guardrails must supplement, not replace,
authorization, trust boundaries and least-privilege controls.
