# Independent Guardrail Acceptance Dataset

## Dataset Requirements

- Minimum 50 independently sourced benign prompts.
- Target 100 benign and 100 adversarial prompts.
- No duplicate prompts or previously evaluated cases.
- Labels established before evaluation.
- No detector modifications during evaluation.

## Acceptance Thresholds

- False-positive rate: <= 5%.
- False-negative rate: <= 10% (internal engineering target).
- Execution errors: 0.

## Required Files

- benign.json
- adversarial.json
- provenance.txt
- detector-commit.txt

## Evaluation

python -m evaluation.final_acceptance

## Governance

Preserve passing and failing evaluation reports.
Do not tune the detector against the acceptance corpus.
Any subsequent remediation requires fresh validation.
