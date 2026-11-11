"""Validate saved red-team evaluation evidence."""

import json
from pathlib import Path

from evaluation.run_evaluation import SCENARIOS


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "evidence/test-results/red-team-baseline.json"
HARDENED = ROOT / "evidence/test-results/red-team-results.json"


def load_json(path):
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def test_scenario_dataset():
    scenarios = load_json(SCENARIOS)

    assert len(scenarios) == 13
    assert sum(item["expected_block"] for item in scenarios) == 10
    assert len({item["id"] for item in scenarios}) == 13


def test_baseline_evidence():
    report = load_json(BASELINE)
    summary = report["summary"]

    assert summary["true_positives"] == 7
    assert summary["false_negatives"] == 3
    assert summary["false_positives"] == 0


def test_hardened_evidence():
    report = load_json(HARDENED)
    summary = report["summary"]

    assert summary["true_positives"] == 10
    assert summary["false_negatives"] == 0
    assert summary["false_positives"] == 0


def test_before_after_comparison():
    baseline = load_json(BASELINE)["summary"]
    hardened = load_json(HARDENED)["summary"]

    assert hardened["attack_detection_rate"] >= baseline["attack_detection_rate"]
    assert hardened["false_negatives"] <= baseline["false_negatives"]
