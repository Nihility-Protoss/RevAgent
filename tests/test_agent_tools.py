"""tools/agent_tools.py 测试：命令解析、角色工具数量、full 模式排除特权工具、真实读取与项目隔离。"""
import inspect
import json

import pytest

from tools.agent_tools import parse_command, get_agent_tools


def test_parse_command_fixed_grammar():
    assert parse_command("next", allowed_keys=frozenset()) == {"next": True}
    assert parse_command(" chunk=2 ", allowed_keys={"chunk"}) == {"chunk": "2"}
    assert parse_command("```text\nkeyword=socket\n```", allowed_keys={"keyword"}) == {
        "keyword": "socket"
    }
    with pytest.raises(ValueError):
        parse_command("unknown=1", allowed_keys={"chunk"})


@pytest.mark.parametrize("role,count", [
    ("string_artifact_analyst", 1),
    ("api_behavior_profiler", 2),
    ("export_interface_analyzer", 2),
    ("behavior_profile_synthesizer", 1),
    ("function_boundary_detector", 3),
    ("scheduler", 1),
])
def test_minimal_tool_counts(role, count):
    tools = get_agent_tools(role, "p", "run", "/tmp/export", mode="minimal")
    assert len(tools) == count


def test_full_mode_excludes_privileged_tools():
    tools = get_agent_tools("scheduler", "p", "run", "/tmp/export", mode="full")
    names = {tool.name for tool in tools}
    assert "bb_query_entries" in names
    assert "bb_create_entry" in names
    assert "bb_review_entries" not in names
    assert "bb_flush_store" not in names


def test_minimal_reader_commands_and_project_binding(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for project, value in (("p1", "alpha"), ("p2", "beta")):
        directory = tmp_path / "data" / "output" / project / "extracts"
        directory.mkdir(parents=True)
        (directory / "strings_extract.json").write_text(json.dumps({
            "chunk_size": 100, "by_category": {"urls": [value]}, "by_type": {},
        }), encoding="utf-8")
    tools1 = get_agent_tools("string_artifact_analyst", "p1", "run", "unused", "minimal")
    tools2 = get_agent_tools("string_artifact_analyst", "p2", "run", "unused", "minimal")
    reader1 = next(tool for tool in tools1 if tool.name == "read_strings_data")
    reader2 = next(tool for tool in tools2 if tool.name == "read_strings_data")
    assert reader1.invoke({"command": "chunk=0"})["data"]["by_category"]["urls"] == ["alpha"]
    assert reader2.invoke({"command": "chunk=0"})["data"]["by_category"]["urls"] == ["beta"]
    assert "project_name" not in inspect.signature(reader1.func).parameters
    invalid = reader1.invoke({"command": "unknown"})
    assert invalid["status"] == "error"
    assert invalid["expected_examples"] == ["next", "chunk=0", "keyword=<文本>"]
