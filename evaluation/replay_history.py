"""Replay historical and current security gateways.

Historical source is extracted from a fixed Git commit.
No working-tree files are replaced.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from app.security_gateway import evaluate_prompt


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_COMMIT = "b441e080f2b27308eca71bfe100b7b1f00d7a3ed"
SCENARIOS = ROOT / "evaluation" / "scenarios.json"

HISTORICAL_FILES = (
    "app/__init__.py",
    "app/security.py",
    "app/injection_detector.py",
    "app/security_gateway.py",
)


def load_historical_sources(destination):
    """Extract original implementation without checking out Git."""
    for filename in HISTORICAL_FILES:
        target = destination / filename
        target.parent.mkdir(parents=True, exist_ok=True)

        try:
            source = subprocess.check_output(
                ["git", "show", f"{HISTORICAL_COMMIT}:{filename}"],
                cwd=ROOT,
            )
        except subprocess.CalledProcessError:
            if filename == "app/__init__.py":
                source = b""
            else:
                raise

        target.write_bytes(source)


def evaluate_historical(destination, prompts):
    """Execute original gateway in an isolated Python process."""
    runner = (
        "import json,sys;"
        "from app.security_gateway import evaluate_prompt;"
        "prompts=json.load(sys.stdin);"
        "print(json.dumps([evaluate_prompt(p)['allowed'] "
        "for p in prompts]))"
    )

    result = subprocess.run(
        [sys.executable, "-c", runner],
        cwd=destination,
        input=json.dumps(prompts),
        text=True,
        capture_output=True,
        check=True,
    )

    return json.loads(result.stdout)


def main():
    scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    prompts = [item["prompt"] for item in scenarios]

    with tempfile.TemporaryDirectory() as directory:
        historical_path = Path(directory)
        load_historical_sources(historical_path)
        before = evaluate_historical(historical_path, prompts)

    after = [evaluate_prompt(prompt)["allowed"] for prompt in prompts]

    before_blocked = 0
    after_blocked = 0
    attack_count = 0

    print("EXECUTABLE HISTORICAL SECURITY REPLAY")
    print("-" * 52)
    print(f"{'Scenario':<12} {'Original':<12} {'Current'}")

    for scenario, old_allowed, new_allowed in zip(
        scenarios, before, after
    ):
        print(
            f"{scenario['id']:<12} "
            f"{'ALLOW' if old_allowed else 'BLOCK':<12} "
            f"{'ALLOW' if new_allowed else 'BLOCK'}"
        )

        if scenario["expected_block"]:
            attack_count += 1
            before_blocked += not old_allowed
            after_blocked += not new_allowed

    print("-" * 52)
    print(f"Original: {before_blocked}/{attack_count} attacks blocked")
    print(f"Current:  {after_blocked}/{attack_count} attacks blocked")
    print(f"Historical commit: {HISTORICAL_COMMIT[:12]}")
    print("Method: executable gateway replay, not JSON comparison")

    if before_blocked != 7 or after_blocked != 10:
        raise SystemExit(
            "Results differ from recorded evidence; investigate."
        )


if __name__ == "__main__":
    main()
