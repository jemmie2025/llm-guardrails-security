"""Reproducible guardrail latency benchmark."""

import asyncio
import hashlib
import json
import math
import platform
import random
import statistics
import subprocess
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from time import perf_counter_ns

from app.nemo_runtime import evaluate_with_nemo
from app.output_security import screen_output

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "evaluation/datasets"
OUTPUT = ROOT / "evidence/benchmarks"

ROUNDS = 10
SEED = 42


def summarize(samples):
    values = sorted(samples)

    if not values:
        raise ValueError("No latency samples recorded")

    def percentile(p):
        index = math.ceil(p * len(values)) - 1
        return round(values[index], 4)

    return {
        "samples": len(values),
        "p50_ms": percentile(0.50),
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "mean_ms": round(statistics.mean(values), 4),
        "max_ms": round(max(values), 4),
    }


async def main():
    cases = []
    hashes = {}

    for filename in (
        "holdout-benign.json",
        "holdout-adversarial.json",
    ):
        raw = (DATA / filename).read_bytes()
        hashes[filename] = hashlib.sha256(raw).hexdigest()
        cases.extend(json.loads(raw))

    assert len(cases) == 110

    print("Warming up NeMo runtime...")

    for case in cases:
        await evaluate_with_nemo(case["prompt"])

    samples = {"allow": [], "block": []}
    records = []
    rng = random.Random(SEED)

    print("Measuring input guardrail latency...")

    for iteration in range(ROUNDS):
        batch = cases.copy()
        rng.shuffle(batch)

        for case in batch:
            start = perf_counter_ns()

            decision = await evaluate_with_nemo(
                case["prompt"]
            )

            elapsed = (perf_counter_ns() - start) / 1e6

            path = "allow" if decision["allowed"] else "block"
            samples[path].append(elapsed)

            records.append({
                "id": case["id"],
                "round": iteration + 1,
                "decision": path,
                "correct": (
                    decision["allowed"]
                    == case["expected_allowed"]
                ),
                "latency_ms": elapsed,
            })

    output_cases = [
        "Kubernetes orchestrates containers.",
        "Use secure environment variables.",
        "-----BEGIN PRIVATE KEY-----",
        "sk-" + "x" * 40,
    ]

    output_samples = {"allow": [], "block": []}

    for content in output_cases:
        screen_output(content)

    for _ in range(250):
        for content in output_cases:
            start = perf_counter_ns()
            decision = screen_output(content)
            elapsed = (perf_counter_ns() - start) / 1e6

            path = "allow" if decision["allowed"] else "block"
            output_samples[path].append(elapsed)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
        ).strip(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "nemoguardrails": version("nemoguardrails"),
        },
        "methodology": {
            "warmup_requests": len(cases),
            "rounds": ROUNDS,
            "random_seed": SEED,
            "concurrency": 1,
            "percentile_method": "nearest_rank",
            "model_inference_included": False,
            "dataset_provenance": "previously examined corpus",
        },
        "dataset_hashes": hashes,
        "input_guardrails": {
            key: summarize(values)
            for key, values in samples.items()
        },
        "output_guardrails": {
            key: summarize(values)
            for key, values in output_samples.items()
        },
        "input_raw_measurements": records,
        "output_raw_measurements": output_samples,
    }

    OUTPUT.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )

    path = OUTPUT / f"latency-benchmark-{stamp}.json"

    with path.open("x") as file:
        json.dump(report, file, indent=2)

    print("\nGUARDRAIL LATENCY REPORT")
    print("-" * 60)

    for layer in ("input_guardrails", "output_guardrails"):
        print(f"\n{layer.upper()}")

        for decision, metrics in report[layer].items():
            print(f"\nDecision: {decision.upper()}")

            for key, value in metrics.items():
                print(f"{key}: {value}")

    print(f"\nEvidence saved: {path.relative_to(ROOT)}")


if __name__ == "__main__":
    asyncio.run(main())
