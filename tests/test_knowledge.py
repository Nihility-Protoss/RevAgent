"""Tests for workers.knowledge package."""
import os
import tempfile

import pytest


def test_registry_contains_windows_pe():
    from workers.knowledge import KNOWLEDGE_REGISTRY
    assert "windows_pe" in KNOWLEDGE_REGISTRY
    meta = KNOWLEDGE_REGISTRY["windows_pe"]
    assert meta.priority == 10
    assert meta.max_tokens == 1200
    assert "baseline" in meta.applies_to


def test_load_knowledge_success():
    from workers.knowledge import load_knowledge
    result = load_knowledge("windows_pe", "any_project")
    assert result["status"] == "success"
    assert result["name"] == "windows_pe"
    assert "PE" in result["content"]
    assert result["token_estimate"] <= 1200
    assert result.get("truncated") in (None, False)


def test_load_knowledge_unknown_name():
    from workers.knowledge import load_knowledge
    result = load_knowledge("no_such_guide", "any_project")
    assert result["status"] == "error"
    assert "error" in result


def test_all_registered_files_respect_token_budget():
    from tools.blackboard_tools import _estimate_tokens
    from workers.knowledge import KNOWLEDGE_REGISTRY
    for name, meta in KNOWLEDGE_REGISTRY.items():
        text = meta.path.read_text(encoding="utf-8")
        assert _estimate_tokens(text) <= meta.max_tokens, (
            f"knowledge file {name} exceeds token budget"
        )


def test_registry_contains_language_guides():
    from workers.knowledge import KNOWLEDGE_REGISTRY
    for name in ("cpp", "rust"):
        assert name in KNOWLEDGE_REGISTRY
        assert KNOWLEDGE_REGISTRY[name].priority == 90
