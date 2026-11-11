"""Automated tests for basic prompt validation."""

import pytest

from app.security import MAX_PROMPT_LENGTH, validate_prompt


@pytest.mark.parametrize(
    "prompt",
    [
        "Hello, how are you?",
        "Explain cloud computing.",
        "What is Kubernetes?",
    ],
)
def test_valid_prompts(prompt):
    result = validate_prompt(prompt)
    assert result["allowed"] is True


@pytest.mark.parametrize(
    "prompt",
    ["", " ", "\n\t"],
)
def test_empty_prompts_are_blocked(prompt):
    result = validate_prompt(prompt)
    assert result["allowed"] is False
    assert result["reason"] == "Prompt cannot be empty"


def test_oversized_prompt_is_blocked():
    result = validate_prompt("A" * (MAX_PROMPT_LENGTH + 1))
    assert result["allowed"] is False
    assert result["reason"] == "Prompt exceeds maximum length"


def test_maximum_allowed_length():
    result = validate_prompt("A" * MAX_PROMPT_LENGTH)
    assert result["allowed"] is True


@pytest.mark.parametrize(
    "prompt",
    [None, 123, [], {}],
)
def test_non_string_input_is_blocked(prompt):
    result = validate_prompt(prompt)
    assert result["allowed"] is False
    assert result["reason"] == "Prompt must be a string"
