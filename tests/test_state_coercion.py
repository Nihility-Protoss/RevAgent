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
