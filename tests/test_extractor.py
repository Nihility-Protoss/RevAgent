"""Tests for workers.extractor pure functions (post LangGraph migration).

The ADK LlmAgent `extractor_agent` is gone; extraction is a plain
`llm.ainvoke` inside the graph nodes, driven by build_extraction_prompt.
"""
from workers.extractor import SUMMARY_SCHEMAS, build_extraction_prompt


def test_build_extraction_prompt_returns_string():
    artifact = {"key_findings": ["a", "b", "c"], "confidence": "high"}
    prompt = build_extraction_prompt(artifact, "strings")
    assert isinstance(prompt, str)
    assert "strings" in prompt
    assert "1500" in prompt or "summary" in prompt


def test_build_extraction_prompt_embeds_artifact_json():
    artifact = {"overall_assessment": "疑似 Stealer", "confidence": "high"}
    prompt = build_extraction_prompt(artifact, "behavior")
    assert "疑似 Stealer" in prompt
    assert "behavior" in prompt


def test_build_extraction_prompt_unknown_type_falls_back_to_strings_schema():
    prompt = build_extraction_prompt({"a": 1}, "no_such_type")
    assert "string_artifact_analyst" in prompt


def test_strings_summary_schema_includes_arch_detection():
    assert "arch_detection" in SUMMARY_SCHEMAS["strings"]


def test_all_summary_schemas_declare_confidence():
    for artifact_type, schema in SUMMARY_SCHEMAS.items():
        assert '"confidence"' in schema, artifact_type


def test_worker_summary_schemas_declare_worker_field():
    for artifact_type in ["strings", "api", "exports", "behavior", "functions"]:
        assert '"worker"' in SUMMARY_SCHEMAS[artifact_type], artifact_type
