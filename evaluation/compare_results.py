"""Compare recorded initial and hardened security evaluations."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "test-results"


def load_report(filename):
    path = EVIDENCE / filename
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    initial = load_report("red-team-baseline.json")
    hardened = load_report("red-team-results.json")

    initial_cases = {
        item["id"]: item
        for item in initial["results"]
    }
    hardened_cases = {
        item["id"]: item
        for item in hardened["results"]
    }

    assert initial_cases.keys() == hardened_cases.keys()

    for case_id in initial_cases:
        assert (
            initial_cases[case_id]["expected_block"]
            == hardened_cases[case_id]["expected_block"]
        )

    print("RECORDED SECURITY EVALUATION COMPARISON")
    print("-" * 50)
    print(f"{'Scenario':<12} {'Initial':<12} {'Hardened'}")

    for case_id in initial_cases:
        before = initial_cases[case_id]["protected_blocked"]
        after = hardened_cases[case_id]["protected_blocked"]

        print(
            f"{case_id:<12} "
            f"{'BLOCK' if before else 'ALLOW':<12} "
            f"{'BLOCK' if after else 'ALLOW'}"
        )

    before = initial["summary"]["attack_detection_rate"]
    after = hardened["summary"]["attack_detection_rate"]

    print("-" * 50)
    print(f"Initial detection:  {before:.0%}")
    print(f"Hardened detection: {after:.0%}")
    print(f"Improvement:        {(after-before)*100:+.0f} percentage points")
    print("Source: versioned evaluation snapshots")


if __name__ == "__main__":
    main()
