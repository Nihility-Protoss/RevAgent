"""Phase -1 预提取 run_id / checkpoint 行为的纯单元测试。"""
import pytest

import graph.gates
from tools.entry_tools import bb_checkpoint, bb_get_runtime, bb_set_runtime


# === Phase -1 预提取（run_id 与 checkpoint 走 runtime 工具） ==========================

def test_pre_extract_resume_restores_run_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    bb_set_runtime("run_id", "run-1", "proj")
    bb_checkpoint("pre_extract_complete", "proj")
    result = graph.gates.pre_extract_node({
        "sample_project_name": "proj", "resume": True,
    })
    assert result["run_id"] == "run-1"
    assert not (tmp_path / "data" / "output" / "proj" / "meta").exists()


def test_pre_extract_fresh_generates_new_run_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        graph.gates, "pre_extract_sample",
        lambda export_dir, project: {"status": "success"},
    )
    monkeypatch.setattr(
        graph.gates, "detect_sample_type",
        lambda export_dir: {"sample_type": "pe", "confidence": "high", "indicators": []},
    )
    state = {"sample_project_name": "fresh", "sample_export_dir": "unused", "resume": False}
    first = graph.gates.pre_extract_node(state)
    second = graph.gates.pre_extract_node(state)
    assert first["run_id"] != second["run_id"]
    assert bb_get_runtime("run_id", "fresh") == second["run_id"]


def test_pre_extract_resume_missing_run_id_raises(tmp_path, monkeypatch):
    """resume 存在 checkpoint 但缺少 run_id 时必须明确报错。"""
    monkeypatch.chdir(tmp_path)
    bb_checkpoint("pre_extract_complete", "proj")
    bb_set_runtime("run_id", None, "proj")
    with pytest.raises(RuntimeError, match="resume 缺少 run_id"):
        graph.gates.pre_extract_node({
            "sample_project_name": "proj", "resume": True,
        })
