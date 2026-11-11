"""Evaluate baseline and NeMo input-rail security decisions."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.rails.llm.options import RailStatus

from guardrails.actions import check_prompt_security


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "evaluation" / "scenarios.json"
REPORT = ROOT / "evidence" / "test-results" / "red-team-results.json"


async def main():
    scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))

    config = RailsConfig.from_path(str(ROOT / "guardrails" / "config"))
    rails = LLMRails(config, verbose=False)
    rails.register_action(
        check_prompt_security,
        name="check_prompt_security",
    )

    results = []

    for scenario in scenarios:
        prompt = scenario["prompt"]

        # An unprotected baseline allows all inputs.
        baseline_blocked = False

        response = await rails.check_async(
            [{"role": "user", "content": prompt}]
        )

        if response.status not in (
            RailStatus.PASSED,
            RailStatus.BLOCKED,
        ):
            raise RuntimeError(
                f"Unexpected rail status for {scenario['id']}: "
                f"{response.status}"
            )

        protected_blocked = response.status == RailStatus.BLOCKED
        expected_block = scenario["expected_block"]

        record = {
            "id": scenario["id"],
            "category": scenario["category"],
            "expected_block": expected_block,
            "baseline_blocked": baseline_blocked,
            "protected_blocked": protected_blocked,
            "correct": protected_blocked == expected_block,
            "triggered_rail": str(response.rail) if response.rail else None,
        }

        results.append(record)

        verdict = "PASS" if record["correct"] else "FAIL"
        print(
            f"{scenario['id']:<10} "
            f"Expected={'BLOCK' if expected_block else 'ALLOW':<6} "
            f"Baseline=ALLOW "
            f"NeMo={'BLOCK' if protected_blocked else 'ALLOW':<6} "
            f"{verdict}"
        )

    attacks = [r for r in results if r["expected_block"]]
    benign = [r for r in results if not r["expected_block"]]

    true_positives = sum(r["protected_blocked"] for r in attacks)
    false_negatives = len(attacks) - true_positives
    false_positives = sum(r["protected_blocked"] for r in benign)
    true_negatives = len(benign) - false_positives

    summary = {
        "attack_detection_rate": true_positives / len(attacks),
        "false_negative_rate": false_negatives / len(attacks),
        "false_positive_rate": false_positives / len(benign),
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
    }

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "evaluation_type": "input_rail_decision_only",
        "baseline": "allow_all",
        "protected": "nemo_custom_heuristic_input_rail",
        "summary": summary,
        "results": results,
    }

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print("\n--- SECURITY EVALUATION SUMMARY ---")
    print(f"Attacks blocked: {true_positives}/{len(attacks)}")
    print(f"Attack bypasses: {false_negatives}")
    print(f"False positives: {false_positives}/{len(benign)}")
    print(f"Attack detection rate: {summary['attack_detection_rate']:.1%}")
    print(f"False-negative rate: {summary['false_negative_rate']:.1%}")
    print(f"False-positive rate: {summary['false_positive_rate']:.1%}")
    print(f"Report saved: {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    asyncio.run(main())
