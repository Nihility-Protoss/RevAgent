import pytest
from google.adk.agents import LlmAgent

from workers.extractor import extractor_agent, build_extraction_prompt


def test_extractor_agent_exists():
    assert isinstance(extractor_agent, LlmAgent)
    assert extractor_agent.name == "summary_extractor"


def test_build_extraction_prompt_returns_string():
    artifact = {"key_findings": ["a", "b", "c"], "confidence": "high"}
    prompt = build_extraction_prompt(artifact, "strings")
    assert isinstance(prompt, str)
    assert "strings" in prompt
    assert "1500" in prompt or "summary" in prompt


def test_extractor_has_tools():
    assert extractor_agent.tools is not None
    assert len(extractor_agent.tools) > 0
