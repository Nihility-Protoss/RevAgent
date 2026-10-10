"""Phase 3 Send 并行扇出测试（Step 3）。

用真实的 phase3_dispatch_node / phase3_fanout / make_phase3_function_node
组装最小子图（dispatch →（Send）phase3_function → verification_agent 桩节点），
验证扇出数量、reducer 聚合、幂等跳过、空候选直通与并发上限。
全部使用假模型注入，不消耗真实 API token。
"""
import asyncio
import json
import os

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from graph_nodes import (
    make_phase3_function_node,
    orchestrator_node,
    phase3_dispatch_node,
    phase3_fanout,
)
from state import AnalysisState
from tools.blackboard_tools import bb_write_artifact, board_path


def _candidate(addr: str, priority: int = 9) -> dict:
    return {
        "func_addr": addr, "func_name": f"sub_{addr[2:]}", "size": 128,
        "xrefs": 3, "is_thunk": False, "is_export": False,
        "analysis_priority": priority, "priority_reason": "测试",
    }


def _boundary(*addrs: str, priority: int = 9) -> dict:
    return {
        "status": "success",
        "total_functions": len(addrs),
        "candidates": [_candidate(a, priority) for a in addrs],
    }


def _make_export_dir(base: str, *addrs: str) -> str:
    """最小 IDA 导出目录：每个地址一个反编译文件（load_function_data 可查）。"""
    export_dir = os.path.join(base, "export")
    os.makedirs(os.path.join(export_dir, "decompile"), exist_ok=True)
    for addr in addrs:
        with open(
            os.path.join(export_dir, "decompile", f"{addr[2:]}.c"), "w", encoding="utf-8"
        ) as f:
            f.write(f"int sub_{addr[2:]}() {{ return 0; }}\n")
    return export_dir


class CountingFakeModel:
    """按 prompt 内容区分统计分析/摘要调用次数的假模型。"""

    def __init__(self):
        self.analysis_calls = 0
        self.extractor_calls = 0

    async def ainvoke(self, messages, config=None):
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        if "函数级分析专家" in text:
            self.analysis_calls += 1
            return AIMessage(content=json.dumps({
                "status": "success", "functionality": "test",
                "suspicious_behaviors": ["test_behavior"], "confidence": "low",
            }, ensure_ascii=False))
        # 结构化摘要提取器（extractor）
        self.extractor_calls += 1
        return AIMessage(content=json.dumps({
            "worker": "extractor_function_deep", "key_findings": ["x"],
            "confidence": "low", "suspicious_behaviors": ["test_behavior"],
            "analysis_priority": 9,
        }, ensure_ascii=False))


class ConcurrencyProbeModel(CountingFakeModel):
    """在 CountingFakeModel 基础上记录分析调用的并发峰值。"""

    def __init__(self):
        super().__init__()
        self.current = 0
        self.peak = 0

    async def ainvoke(self, messages, config=None):
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        if "函数级分析专家" in text:
            self.current += 1
            self.peak = max(self.peak, self.current)
            await asyncio.sleep(0.02)  # 让出事件循环，制造并发窗口
            self.current -= 1
        return await super().ainvoke(messages, config)


def _build_mini_graph(llm):
    """dispatch →（Send）phase3_function → orchestrator → verification_agent（桩节点）。"""
    builder = StateGraph(AnalysisState)

    def verification_stub(state):
        return {"final_report_ref": "bb://summary/p4_final_report"}

    builder.add_node("phase3_dispatch", phase3_dispatch_node)
    builder.add_node("phase3_function", make_phase3_function_node(llm))
    builder.add_node("orchestrator", orchestrator_node)
    builder.add_node("verification_agent", verification_stub)
    builder.add_edge(START, "phase3_dispatch")
    builder.add_conditional_edges(
        "phase3_dispatch", phase3_fanout, ["phase3_function", "orchestrator"]
    )
    builder.add_edge("phase3_function", "orchestrator")
    builder.add_edge("orchestrator", "verification_agent")
    builder.add_edge("verification_agent", END)
    return builder.compile()


# === 扇出路由（phase3_fanout） ===========================================================

def test_fanout_send_count_matches_candidates():
    """Send 数量与候选列表一致，载荷携带单函数元数据与项目上下文。"""
    state = {
        "sample_project_name": "p",
        "sample_export_dir": "x",
        "function_boundary_analysis": _boundary("0x401000", "0x402000", "0x403000"),
    }
    sends = phase3_fanout(state)
    assert len(sends) == 3
    assert all(isinstance(s, Send) and s.node == "phase3_function" for s in sends)
    assert [s.arg["phase3_candidate"]["func_addr"] for s in sends] == [
        "0x401000", "0x402000", "0x403000",
    ]
    assert sends[0].arg["sample_project_name"] == "p"
    assert sends[0].arg["sample_export_dir"] == "x"


def test_fanout_prefers_human_approved_functions():
    """MODIFY 人工列表优先于 analysis_priority 过滤。"""
    state = {
        "sample_project_name": "p",
        "sample_export_dir": "x",
        "function_boundary_analysis": _boundary("0x401000", "0x402000"),
        "human_approved_functions": ["0x402000"],
    }
    sends = phase3_fanout(state)
    assert [s.arg["phase3_candidate"]["func_addr"] for s in sends] == ["0x402000"]


def test_fanout_filters_low_priority_and_caps_top20():
    """analysis_priority < 7 的候选被过滤，CONFIRM 路径最多取 Top 20。"""
    boundary = {
        "candidates": [_candidate("0x401000", 9), _candidate("0x402000", 5)],
    }
    state = {
        "sample_project_name": "p", "sample_export_dir": "x",
        "function_boundary_analysis": boundary,
    }
    sends = phase3_fanout(state)
    assert [s.arg["phase3_candidate"]["func_addr"] for s in sends] == ["0x401000"]

    many = {
        "candidates": [_candidate(f"0x{0x401000 + i * 0x1000:x}", 9) for i in range(25)],
    }
    sends = phase3_fanout({
        "sample_project_name": "p", "sample_export_dir": "x",
        "function_boundary_analysis": many,
    })
    assert len(sends) == 20


# === 子图端到端：聚合 / 幂等 / 空候选 ====================================================

def test_parallel_results_aggregated_by_reducer(tmp_path, monkeypatch):
    """并行 phase3_function 的结果经 add reducer 全部聚合到 func_analysis_refs。"""
    monkeypatch.chdir(tmp_path)
    addrs = ["0x401000", "0x402000", "0x403000"]
    export_dir = _make_export_dir(str(tmp_path), *addrs)
    fake = CountingFakeModel()
    graph = _build_mini_graph(fake)

    final = asyncio.run(graph.ainvoke({
        "sample_project_name": "t3",
        "sample_export_dir": export_dir,
        "function_boundary_analysis": _boundary(*addrs),
    }))

    refs = final["func_analysis_refs"]
    assert len(refs) == 3
    assert {r["addr"] for r in refs} == set(addrs)
    assert all("summary" in r for r in refs)
    assert fake.analysis_calls == 3
    assert fake.extractor_calls == 3

    # 黑板产物路径与串行版一致
    for addr in addrs:
        assert os.path.exists(board_path("t3", "artifacts", f"phase3_func_{addr}.json"))
        assert os.path.exists(board_path("t3", "summary", "phase3_funcs", f"func_{addr}.json"))
    # 调度日志记录了扇出计划
    with open(board_path("t3", "meta", "execution_log.jsonl"), encoding="utf-8") as f:
        assert "phase3_dispatch" in f.read()


def test_completed_function_skipped_without_llm_call(tmp_path, monkeypatch):
    """已有 artifact 的函数幂等跳过：返回 skipped 引用，不发起 LLM 调用。"""
    monkeypatch.chdir(tmp_path)
    export_dir = _make_export_dir(str(tmp_path), "0x401000", "0x402000")
    bb_write_artifact("phase3_func_0x401000", {"status": "success"}, "t3")
    fake = CountingFakeModel()
    graph = _build_mini_graph(fake)

    final = asyncio.run(graph.ainvoke({
        "sample_project_name": "t3",
        "sample_export_dir": export_dir,
        "function_boundary_analysis": _boundary("0x401000", "0x402000"),
    }))

    refs = {r["addr"]: r for r in final["func_analysis_refs"]}
    assert refs["0x401000"].get("skipped") is True
    assert "summary" in refs["0x402000"]
    assert fake.analysis_calls == 1
    assert fake.extractor_calls == 1


def test_empty_candidates_go_straight_to_verification(tmp_path, monkeypatch):
    """空候选列表：条件边直通 orchestrator（再进入 verification_agent），不扇出、不调 LLM。

    验证覆盖 Phase 0-2 的 high 置信度发现，因此空候选不再跳过验证节点；
    orchestrator 是纯代码节点（空 manifest 全部计数为 0），不消耗 LLM。
    """
    monkeypatch.chdir(tmp_path)
    state = {
        "sample_project_name": "t3",
        "sample_export_dir": "x",
        "function_boundary_analysis": _boundary(),  # 空候选
    }
    assert phase3_fanout(state) == "orchestrator"

    fake = CountingFakeModel()
    graph = _build_mini_graph(fake)
    final = asyncio.run(graph.ainvoke(state))

    assert final["func_analysis_refs"] == []
    # 桩节点被执行，证明条件边直通成功
    assert final["final_report_ref"] == "bb://summary/p4_final_report"
    assert fake.analysis_calls == 0
    assert fake.extractor_calls == 0
    with open(board_path("t3", "meta", "execution_log.jsonl"), encoding="utf-8") as f:
        assert "phase3_skipped" in f.read()


def test_phase3_max_concurrency_limits_parallel_llm_calls(tmp_path, monkeypatch):
    """analysis.phase3_max_concurrency 限制同时进行的函数分析 LLM 调用数。"""
    monkeypatch.chdir(tmp_path)  # 避开仓库 config.yaml，让环境变量兜底生效
    monkeypatch.setenv("PHASE3_MAX_CONCURRENCY", "2")
    addrs = [f"0x{0x401000 + i * 0x1000:x}" for i in range(5)]
    export_dir = _make_export_dir(str(tmp_path), *addrs)
    probe = ConcurrencyProbeModel()
    # 工厂在 env 设置后调用，读取上限 2
    graph = _build_mini_graph(probe)

    final = asyncio.run(graph.ainvoke({
        "sample_project_name": "t3",
        "sample_export_dir": export_dir,
        "function_boundary_analysis": _boundary(*addrs),
    }))

    assert probe.analysis_calls == 5
    assert probe.peak <= 2
    assert len(final["func_analysis_refs"]) == 5
