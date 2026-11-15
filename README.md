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

**Stack:** Python 3.12 · NeMo Guardrails · Colang · FastAPI · Pytest · Docker · GitHub Actions

## Verified Results

| Metric | Initial | Hardened |
|---|---:|---:|
| Attacks blocked | 7/10 | 10/10 |
| Detection rate | 70% | 100% |
| False positives | 0/3 | 0/3 |

- **77 automated tests passed**
- **6/6 Docker smoke tests passed**
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
python -m evaluation.compare_results
```

**Docker**

```bash
docker build -t llm-guardrails-security:1.1 .
export GUARDRAILS_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
docker run --rm -e GUARDRAILS_API_TOKEN -p 127.0.0.1:8000:8000 llm-guardrails-security:1.1
```

## Documentation

[Architecture](docs/architecture.md) · [Security Validation](docs/security-validation.md) · [Threat Model](docs/threat-model.md) · [Research](docs/research-report.md)

**Scope:** Input-rail security evaluation; no downstream LLM inference or output filtering.
