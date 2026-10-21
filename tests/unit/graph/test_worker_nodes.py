"""Worker 节点的本地行为：返回空状态并把产物投影为版本化条目。"""
import asyncio

import graph.workers
from tests.fake_llm import ScriptedFakeChatModel, _CALL_COUNTS, _make_export_dir
from tools.entry_tools import bb_query_entries
from workers.specs import ALL_SPECS


def test_worker_nodes_return_empty_and_write_entries(tmp_path, monkeypatch):
    """六个 Worker 节点全部返回 {}，产物投影为版本化条目（无兜底分支）。"""
    monkeypatch.chdir(tmp_path)
    _CALL_COUNTS.clear()
    state = {
        "sample_project_name": "proj",
        "sample_export_dir": _make_export_dir(str(tmp_path)),
        "run_id": "run-1",
    }
    for spec in ALL_SPECS:
        node = graph.workers.make_worker_node(spec, ScriptedFakeChatModel())
        assert asyncio.run(node(state)) == {}
    assert len(bb_query_entries("proj", {"entry_type": "sample"})["data"]) == 1
    assert len(bb_query_entries("proj", {"entry_type": "finding"})["data"]) >= 3
    assert len(bb_query_entries("proj", {"entry_type": "function"})["data"]) == 1
    assert len(bb_query_entries("proj", {"entry_type": "decision"})["data"]) == 1
    assert "unmatched" not in _CALL_COUNTS
