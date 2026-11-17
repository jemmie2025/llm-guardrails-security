"""Revision-pinned local prompt injection classifier."""

import json
from pathlib import Path

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
)

LOCK = Path(__file__).with_name("model-lock.json")


class InjectionClassifier:
    def __init__(self):
        torch.set_num_threads(4)

        metadata = json.loads(LOCK.read_text())

        options = {
            "revision": metadata["revision"],
            "local_files_only": True,
            "trust_remote_code": False,
        }

        self.tokenizer = AutoTokenizer.from_pretrained(
            metadata["model_id"], **options
        )

        self.model = (
            AutoModelForSequenceClassification.from_pretrained(
                metadata["model_id"],
                use_safetensors=True,
                **options
            )
        )

        self.model.eval()

        labels = {
            str(label).upper(): int(index)
            for index, label in self.model.config.id2label.items()
        }

        if set(labels) != {"SAFE", "INJECTION"}:
            raise ValueError(f"Unexpected label mapping: {labels}")

        self.injection_id = labels["INJECTION"]

    def classify(self, prompt):
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Invalid classifier input")

        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            stride=64,
            return_overflowing_tokens=True,
        )

        inputs.pop("overflow_to_sample_mapping", None)

        with torch.inference_mode():
            logits = self.model(**inputs).logits
            probabilities = logits.softmax(dim=-1)

        score = probabilities[:, self.injection_id].max().item()

        return {
            "allowed": score < 0.5,
            "injection_score": score,
        }
