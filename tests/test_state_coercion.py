"""Tests for tools.state_utils — ADK session state parsing helpers."""
import json


def test_coerce_state_dict_passthrough():
    from tools.state_utils import coerce_state_dict
    value = {"a": 1}
    assert coerce_state_dict(value) == value


def test_coerce_state_dict_from_json_string():
    from tools.state_utils import coerce_state_dict
    assert coerce_state_dict('{"a": 1}') == {"a": 1}


def test_coerce_state_dict_non_dict_json_returns_empty():
    from tools.state_utils import coerce_state_dict
    assert coerce_state_dict("[1, 2, 3]") == {}
    assert coerce_state_dict('"just a string"') == {}


def test_coerce_state_dict_garbage_returns_empty():
    from tools.state_utils import coerce_state_dict
    assert coerce_state_dict("not json {") == {}
    assert coerce_state_dict("") == {}


def test_coerce_state_dict_other_types_return_empty():
    from tools.state_utils import coerce_state_dict
    assert coerce_state_dict(None) == {}
    assert coerce_state_dict(123) == {}
    assert coerce_state_dict(["a"]) == {}


def test_extract_arch_detection_from_dict():
    from tools.state_utils import extract_arch_detection
    arch = {"language": "rust", "confidence": "high"}
    assert extract_arch_detection({"arch_detection": arch}) == arch


def test_extract_arch_detection_from_json_string():
    from tools.state_utils import extract_arch_detection
    arch = {"language": "golang", "confidence": "high"}
    result = extract_arch_detection(json.dumps({"arch_detection": arch}))
    assert result == arch


def test_extract_arch_detection_invalid_returns_empty():
    from tools.state_utils import extract_arch_detection
    assert extract_arch_detection("not json") == {}
    assert extract_arch_detection(None) == {}
    assert extract_arch_detection({"no_arch_key": 1}) == {}


def test_build_review_message_handles_json_string_state():
    """Regression: ADK stores output_key as raw JSON string; must not crash."""
    from workers.orchestrator import _build_review_message
    state = {
        "behavior_profile": '{"behavior_profile": {"primary_type": "Stealer", "confidence": "high"}}',
        "string_analysis": '{"suspicious_patterns": [{"risk_level": "high"}, {"risk_level": "high"}]}',
        "api_behavior_analysis": '{"suspicious_apis": [{"threat_category": "进程注入"}]}',
        "function_boundary_analysis": '{"candidates": [], "total_functions": 100}',
    }
    msg = _build_review_message(state)
    assert "Stealer" in msg
    assert "high" in msg
    assert "CONFIRM" in msg


def test_persist_worker_output_coerces_json_string(monkeypatch):
    """Regression: raw JSON string from ADK state must be coerced to dict
    before artifact write and extraction prompt build."""
    import agent

    captured = {}

    def fake_write_artifact(name, data, project):
        captured["artifact"] = data

    def fake_build_prompt(artifact, artifact_type):
        captured["prompt_artifact"] = artifact
        return "prompt"

    class FakeRunner:
        def __init__(self, **kwargs):
            pass

        def run(self, **kwargs):
            return iter([])

    monkeypatch.setattr(agent, "bb_write_artifact", fake_write_artifact)
    monkeypatch.setattr(agent, "build_extraction_prompt", fake_build_prompt)
    monkeypatch.setattr(agent, "Runner", FakeRunner)

    import asyncio
    from tools.token_stats import AnalysisTokenReport

    asyncio.run(agent._persist_worker_output(
        worker=type("W", (), {"name": "w", "output_key": "k"})(),
        raw_output='{"findings": ["a"]}',
        artifact_type="strings",
        project_name="proj",
        token_report=AnalysisTokenReport(sample_project_name="proj"),
    ))
    assert captured["artifact"] == {"findings": ["a"]}
    assert captured["prompt_artifact"] == {"findings": ["a"]}
