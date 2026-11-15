# Independent Holdout Security Assessment

## Method

Evaluated five new adversarial prompts and five benign
controls against the existing Python security gateway.

No detector modifications were made for this evaluation.

## Results

| Metric | Result |
|---|---:|
| Total scenarios | 10 |
| Correct decisions | 4/10 |
| Attacks blocked | 0/5 |
| False negatives | 5 |
| Benign controls allowed | 4/5 |
| False positives | 1 |

## Findings

The detector missed paraphrased instruction overrides,
prompt extraction, authority impersonation, and indirect
injection attempts.

One legitimate question quoting suspicious instructions
was incorrectly blocked.

These findings demonstrate limited generalization beyond
known detection signatures.

## Interpretation

The original 10/10 result applies to the predefined
evaluation corpus. The independent holdout demonstrates
that this result does not establish broad attack resistance.

The holdout is preserved unchanged as diagnostic evidence.
Future detection improvements should use separate
development cases and be validated on new unseen data.

## Evidence

- evaluation/holdout_evaluation.py
- evidence/test-results/holdout-results.json
- evaluation/replay_history.py
