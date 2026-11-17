"""Measure baseline guardrail quality without modifying detection rules."""

import asyncio
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from app.nemo_runtime import evaluate_with_nemo


async def main():
    benign = json.loads(
        Path("evaluation/datasets/development-benign.json").read_text()
    )

    known = json.loads(
        Path("evaluation/scenarios.json").read_text()
    )

    attacks = [
        {
            "id": case["id"],
            "prompt": case["prompt"],
            "expected_allowed": False
        }
        for case in known
        if case["expected_block"]
    ]

    results = []

    for case in benign + attacks:
        decision = await evaluate_with_nemo(case["prompt"])
        actual = decision["allowed"]

        result = {
            **case,
            "actual_allowed": actual,
            "category": decision["category"],
            "correct": actual == case["expected_allowed"]
        }

        results.append(result)

        print(
            f"{case['id']} | "
            f"Expected={'ALLOW' if case['expected_allowed'] else 'BLOCK'} | "
            f"Actual={'ALLOW' if actual else 'BLOCK'} | "
            f"{'PASS' if result['correct'] else 'FAIL'}"
        )

    fp = sum(
        r["expected_allowed"] and not r["actual_allowed"]
        for r in results
    )

    fn = sum(
        not r["expected_allowed"] and r["actual_allowed"]
        for r in results
    )

    summary = {
        "dataset_type": "development_baseline",
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "benign_cases": len(benign),
        "attack_cases": len(attacks),
        "false_positives": fp,
        "false_negatives": fn,
        "false_positive_rate": fp / len(benign),
        "false_negative_rate": fn / len(attacks),
        "results": results
    }

    folder = Path("evidence/benchmarks")
    folder.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )

    output = folder / f"quality-baseline-{stamp}.json"

    with output.open("x") as file:
        json.dump(summary, file, indent=2)

    print("\nBASELINE QUALITY RESULTS")
    print(f"Benign cases: {len(benign)}")
    print(f"Attack cases: {len(attacks)}")
    print(f"False positives: {fp}/{len(benign)}")
    print(f"False-positive rate: {fp / len(benign):.2%}")
    print(f"False-negative rate: {fn / len(attacks):.2%}")
    print(f"Evidence saved: {output}")


if __name__ == "__main__":
    asyncio.run(main())
