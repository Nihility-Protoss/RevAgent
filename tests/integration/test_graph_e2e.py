"""LangGraph 编排层的端到端集成测试（ADK 迁移之后）。

编排通过 build_graph(llm=fake) 配合脚本化的假聊天模型端到端执行，
不消耗任何真实 API token。
"""
import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, LLMResult

import graph
import graph.gates
import main
from graph import build_graph
from graph.observability import TokenStatsCallback
from tests.fake_llm import ScriptedFakeChatModel, _CALL_COUNTS, _make_export_dir
from tools.entry_tools import bb_get_entry, bb_query_entries


# === TokenStatsCallback（LangGraph callback 可观测性） =====================================

def _llm_result_with_usage(input_tokens=100, output_tokens=50, total_tokens=150) -> LLMResult:
    msg = AIMessage(content="x", usage_metadata={
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    })
    return LLMResult(generations=[[ChatGeneration(message=msg)]])


def test_token_stats_callback_aggregates_usage_metadata():
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_llm_start(
        {}, ["prompt"], run_id=run_id,
        metadata={"langgraph_node": "string_artifact_analyst"},
    )
    cb.on_llm_end(_llm_result_with_usage(100, 50, 150), run_id=run_id)

    assert cb.report.total_llm_calls == 1
    assert cb.report.total_prompt_tokens == 100
    assert cb.report.total_candidate_tokens == 50
    assert cb.report.total_tokens == 150
    stage = cb.report.stages["string_artifact_analyst"]
    assert stage.call_count == 1
    assert stage.prompt_tokens == 100


def test_token_stats_callback_on_chat_model_start():
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_chat_model_start(
        {}, [[AIMessage(content="hi")]], run_id=run_id,
        metadata={"langgraph_node": "aggregator"},
    )
    cb.on_llm_end(_llm_result_with_usage(10, 5, 15), run_id=run_id)
    assert cb.report.stages["aggregator"].total_tokens == 15


def test_token_stats_callback_falls_back_to_llm_output_token_usage():
    """消息上没有 usage_metadata 的模型（例如 OpenAI 的 llm_output）。"""
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_llm_start({}, ["prompt"], run_id=run_id, metadata={"langgraph_node": "scheduler"})
    resp = LLMResult(
        generations=[[ChatGeneration(message=AIMessage(content="y"))]],
        llm_output={"token_usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}},
    )
    cb.on_llm_end(resp, run_id=run_id)

    assert cb.report.total_llm_calls == 1
    stage = cb.report.stages["scheduler"]
    assert stage.prompt_tokens == 8
    assert stage.candidate_tokens == 2
    assert stage.total_tokens == 10


def test_token_stats_callback_ignores_result_without_usage():
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_llm_start({}, ["prompt"], run_id=run_id, metadata={"langgraph_node": "scheduler"})
    resp = LLMResult(generations=[[ChatGeneration(message=AIMessage(content="y"))]])
    cb.on_llm_end(resp, run_id=run_id)

    assert cb.report.total_llm_calls == 0
    assert cb.report.total_tokens == 0


def test_token_stats_callback_defaults_stage_to_unknown():
    cb = TokenStatsCallback(sample_project_name="test")
    run_id = uuid4()
    cb.on_llm_start({}, ["prompt"], run_id=run_id, metadata=None)
    cb.on_llm_end(_llm_result_with_usage(1, 1, 2), run_id=run_id)
    assert "unknown" in cb.report.stages


# === 运行入口退出落盘 ======================================================================

def test_run_analysis_calls_shutdown_on_error(monkeypatch):
    calls = []

    class FailingGraph:
        def get_graph(self):
            return SimpleNamespace(draw_mermaid_png=lambda output_file_path: None)

        async def ainvoke(self, state, config):
            raise RuntimeError("stop")

    monkeypatch.setattr(graph, "build_graph", lambda: FailingGraph())
    monkeypatch.setattr(main, "shutdown_stores", lambda: calls.append(True))
    with pytest.raises(RuntimeError, match="stop"):
        asyncio.run(main.run_analysis_with_blackboard(
            "proj", sample_export_dir="unused",
        ))
    assert calls == [True]


# === 端到端编排冒烟测试 =======================================================================

def test_full_analysis_graph_smoke(tmp_path, monkeypatch):
    _CALL_COUNTS.clear()
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(graph.gates, "prompt_human", lambda message: "CONFIRM")
    final_state = asyncio.run(build_graph(llm=ScriptedFakeChatModel()).ainvoke({
        "sample_project_name": "test_proj",
        "sample_export_dir": export_dir,
        "sample_type": "auto",
    }))
    assert set(final_state) <= {
        "sample_project_name", "sample_export_dir", "sample_type",
        "resume", "run_id", "final_report_entry_id",
    }
    for branch in (
        "string_analyst", "api_profiler", "export_analyzer",
        "behavior_synthesizer", "boundary_detector", "scheduler",
        "phase3", "shard", "aggregator",
    ):
        assert _CALL_COUNTS.get(branch, 0) >= 1, branch
    assert "unmatched" not in _CALL_COUNTS
    report = bb_get_entry(final_state["final_report_entry_id"], "test_proj")["data"]
    assert report["versions"][0]["payload"]["details"]["malware_family"] == "Unknown"
    board = tmp_path / "data" / "output" / "test_proj"
    assert (board / "entries" / "store.pickle").exists()
    assert not (board / "artifacts").exists()
    assert not (board / "summary").exists()
    assert not (board / "meta").exists()


def test_full_analysis_graph_modify_branch(tmp_path, monkeypatch):
    """MODIFY 回复必须把 Phase 3 限制在人工批准的地址范围内（全部走条目黑板）。"""
    _CALL_COUNTS.clear()
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        graph.gates, "prompt_human",
        lambda message: "MODIFY 0x401000,0x409999",
    )

    asyncio.run(build_graph(llm=ScriptedFakeChatModel()).ainvoke({
        "sample_project_name": "test_proj",
        "sample_export_dir": export_dir,
        "sample_type": "auto",
    }))

    decision = bb_query_entries("test_proj", {"entry_type": "decision"})["data"][0]
    selected = decision["versions"][0]["payload"]["selected_function_refs"]
    assert decision["versions"][0]["payload"]["summary"]["unknown_addresses"] == ["0x409999"]
    # 边界候选中只有 0x401000 存在，因此只有它会被深度分析。
    assert len(selected) == 1
    analyzed = bb_get_entry(selected[0]["entry_id"], "test_proj", include_history=True)["data"]
    assert analyzed["subject"]["key"] == "0x401000"
    assert analyzed["versions"][-1]["producer"]["phase"] == "phase3"
    funcs = bb_query_entries("test_proj", {"entry_type": "function"})["data"]
    assert len(funcs) == 1 and funcs[0]["subject"]["key"] == "0x401000"
