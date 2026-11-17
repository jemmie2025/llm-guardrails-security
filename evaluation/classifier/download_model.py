"""Download an immutable classifier model snapshot."""

import json
from pathlib import Path
from huggingface_hub import HfApi, snapshot_download

MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"

revision = HfApi().model_info(MODEL_ID).sha

if not revision:
    raise RuntimeError("Unable to resolve model revision")

print("Model:", MODEL_ID)
print("Revision:", revision)

snapshot_download(
    repo_id=MODEL_ID,
    revision=revision,
    allow_patterns=[
        "config.json",
        "model.safetensors",
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "added_tokens.json",
        "spm.model",
        "LICENSE",
    ],
    max_workers=2,
)

metadata = {
    "model_id": MODEL_ID,
    "revision": revision,
    "device": "cpu",
    "weights_format": "safetensors",
}

Path("evaluation/classifier/model-lock.json").write_text(
    json.dumps(metadata, indent=2) + "\n"
)

print("PASS: Model downloaded and revision pinned")
