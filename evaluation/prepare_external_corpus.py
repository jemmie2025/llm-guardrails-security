"""Prepare reproducible external security evaluation datasets."""

import hashlib
import json
import random
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen

ROOT = Path("evaluation/datasets")
FINAL = ROOT / "final"

DATASET = "deepset/prompt-injections"
SEED = 42
TARGET = 100

API = "https://datasets-server.huggingface.co/rows"


def normalize(text):
    return " ".join(text.casefold().split())


def fetch_split(split):
    records = []
    offset = 0

    while True:
        params = urlencode({
            "dataset": DATASET,
            "config": "default",
            "split": split,
            "offset": offset,
            "length": 100,
        })

        with urlopen(f"{API}?{params}", timeout=60) as response:
            page = json.load(response)

        rows = page["rows"]

        if not rows:
            break

        for item in rows:
            records.append({
                **item["row"],
                "source_id": f"{split}-{item['row_idx']}",
            })

        offset += len(rows)

        if offset >= page["num_rows_total"]:
            break

    return records


def main():
    FINAL.mkdir(parents=True, exist_ok=True)

    destinations = [
        FINAL / name for name in (
            "benign.json",
            "adversarial.json",
            "provenance.txt",
        )
    ]

    if any(p.exists() for p in destinations):
        raise RuntimeError(
            "Final dataset already exists; refusing overwrite"
        )

    previous = set()

    for path in ROOT.glob("*.json"):
        for case in json.loads(path.read_text()):
            previous.add(normalize(case["prompt"]))

    records = fetch_split("train") + fetch_split("test")

    print("External records downloaded:", len(records))

    digest = hashlib.sha256(
        json.dumps(records, sort_keys=True).encode()
    ).hexdigest()

    pools = {0: [], 1: []}
    seen = set(previous)

    for row in records:
        text = row["text"]
        label = row["label"]

        if not isinstance(text, str) or label not in (0, 1):
            continue

        key = normalize(text)

        if not key or key in seen or len(text) > 4000:
            continue

        seen.add(key)
        pools[label].append(row)

    rng = random.Random(SEED)

    for label in (0, 1):
        if len(pools[label]) < TARGET:
            raise RuntimeError(
                f"Insufficient unique records for label {label}"
            )

    for label, filename, prefix in (
        (0, "benign.json", "EXT-B"),
        (1, "adversarial.json", "EXT-A"),
    ):
        selected = rng.sample(pools[label], TARGET)

        cases = [
            {
                "id": f"{prefix}-{index:03d}",
                "prompt": row["text"],
                "expected_allowed": label == 0,
                "category": (
                    "benign" if label == 0
                    else "prompt_injection"
                ),
                "source_id": row["source_id"],
            }
            for index, row in enumerate(selected, 1)
        ]

        with (FINAL / filename).open("x") as file:
            json.dump(cases, file, indent=2)

        print(f"{filename}: {len(cases)} prompts")

    provenance = (
        f"External dataset: {DATASET}\n"
        f"Source: https://huggingface.co/datasets/{DATASET}\n"
        f"Source splits: train, test\n"
        f"Source snapshot SHA256: {digest}\n"
        f"Sampling seed: {SEED}\n"
        "Selection: random sampling without replacement\n"
        "Excluded: empty, oversized and duplicate prompts\n"
        "Labels: original external dataset labels\n"
        "No selection based on detector performance\n"
    )

    with (FINAL / "provenance.txt").open("x") as file:
        file.write(provenance)

    print("PASS: External evaluation corpus prepared")


if __name__ == "__main__":
    main()
