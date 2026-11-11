# LLM Guardrails Security

**NeMo Guardrails | Prompt Injection Defense | FastAPI | Docker | DevSecOps**

A containerized LLM security prototype integrating NeMo input rails, layered prompt-injection detection, and automated adversarial evaluation.

## Architecture

```mermaid
flowchart LR
    A[Client] --> B[FastAPI]
    B --> C[NeMo Input Rails]
    C --> D[Python Security Gateway]
    D --> E{Allow / Block}
```

**Stack:** Python 3.10 · NeMo Guardrails · Colang · FastAPI · Pytest · Docker · GitHub Actions

## Verified Results

| Metric | Initial | Hardened |
|---|---:|---:|
| Attacks blocked | 7/10 | 10/10 |
| Detection rate | 70% | 100% |
| False positives | 0/3 | 0/3 |

- **38 automated tests passed**
- **4/4 containerized API checks passed**
- **GitHub Actions CI passed**

Results apply to a fixed test corpus, not unseen attacks or downstream LLM behavior.

## Evidence

**Automated Tests**

![Pytest Results](evidence/screenshots/01-automated-security-tests.png)

**Red-Team Evaluation**

![Red-Team Results](evidence/screenshots/02-red-team-before-after.png)

## Run

```bash
pip install -r requirements.txt
python -m pytest -q
python -m evaluation.run_evaluation
```

**Docker**

```bash
docker build -t llm-guardrails-security:1.1 .
docker run --rm -p 127.0.0.1:8000:8000 llm-guardrails-security:1.1
```

## Documentation

[Architecture](docs/architecture.md) · [Security Validation](docs/security-validation.md) · [Threat Model](docs/threat-model.md) · [Research](docs/research-report.md)

**Scope:** Input-rail security evaluation; no downstream LLM inference or output filtering.
