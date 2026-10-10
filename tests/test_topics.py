"""Phase 3 双轨制（批次 A2）测试：主题 Worker + TaskManifest + 分波扇出。

覆盖：主题 prompt 五段式、manifest 构建（默认主题映射 / 依赖分波 / 兜底函数任务 /
MODIFY 无条件采纳）、主题节点幂等跳过、迷你子图端到端（dispatch → Send →
topic+function 双轨 → wave2 依赖波 → verification 桩）、空任务直通。
全部使用假模型注入，不消耗真实 API token。
"""
import asyncio
import json
import os

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from graph_nodes import (
    _manifest_waves,
    _select_phase3_candidates,
    build_task_manifest,
    make_phase3_function_node,
    make_topic_node,
    orchestrator_node,
    phase3_dispatch_node,
    phase3_fanout,
    phase3_fanout_wave2,
    phase3_wave2_node,
)
from state import ANALYSIS_TOPIC_VOCABULARY, AnalysisState, TopicAnalysis
from tools.blackboard_tools import bb_write_artifact, board_path
from workers.topics.topic_prompts import TOPIC_METHODOLOGIES, build_topic_prompt


def _candidate(addr: str, priority: int = 9, xrefs: int = 3, size: int = 128,
               is_export: bool = False) -> dict:
    return {
        "func_addr": addr, "func_name": f"sub_{addr[2:]}", "size": size,
        "xrefs": xrefs, "is_thunk": False, "is_export": is_export,
        "analysis_priority": priority, "priority_reason": "测试",
    }


def _boundary(*cands: dict) -> dict:
    return {"status": "success", "total_functions": len(cands), "candidates": list(cands)}


def _state(*cands: dict, topics=None, behavior="Unknown", human=None) -> dict:
    state = {
        "sample_project_name": "t_topic",
        "sample_export_dir": "x",
        "function_boundary_analysis": _boundary(*cands),
    }
    if topics is not None:
        state["scheduler_decision"] = {"status": "success", "proposed_topics": topics}
    if behavior != "Unknown":
        state["behavior_profile"] = {"behavior_profile": {"primary_type": behavior}}
    if human:
        state["human_approved_functions"] = human
    return state


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


class TopicFakeModel:
    """按 prompt 内容区分主题分析/函数分析/摘要调用的假模型，记录调用顺序。"""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []  # (kind, 标识)
        self.topic_prompts: dict[str, str] = {}  # topic -> prompt 原文

    async def ainvoke(self, messages, config=None):
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        if "主题分析专家" in text:
            topic = next(
                (t for t in ANALYSIS_TOPIC_VOCABULARY if f"（{t}）" in text), "unknown"
            )
            self.calls.append(("topic", topic))
            self.topic_prompts[topic] = text
            return AIMessage(content=json.dumps({
                "status": "success", "topic": topic,
                "summary": f"{topic} 主题结论",
                "findings": [{"subject": "cmd 0x06", "conclusion": "截屏", "confidence": "medium"}],
                "evidence": [{"address": "0x401000", "snippet": "switch(cmd)", "source": "decompile"}],
                "confidence": "medium", "unresolved": ["cmd 0x09 待动态验证"],
            }, ensure_ascii=False))
        if "函数级分析专家" in text:
            self.calls.append(("func", text.split("当前分析函数：")[1].split("\n")[0]))
            return AIMessage(content=json.dumps({
                "status": "success", "functionality": "test",
                "suspicious_behaviors": ["b"], "confidence": "low",
            }, ensure_ascii=False))
        # 结构化摘要提取器（extractor）：尽量带上 artifact 的 topic 标识
        topic = next(
            (t for t in ANALYSIS_TOPIC_VOCABULARY if f'"topic": "{t}"' in text), ""
        )
        self.calls.append(("extractor", topic))
        return AIMessage(content=json.dumps({
            "worker": "extractor_topic", "topic": topic,
            "key_findings": ["x"], "confidence": "low",
        }, ensure_ascii=False))


# === 主题 prompt 五段式 =====================================================

def test_topic_prompt_has_five_sections():
    """主题 prompt 必须保持五段式结构，且携带主题词与函数地址。"""
    prompt = build_topic_prompt(
        "command_dispatcher",
        ["0x401000"],
        [{"addr": "0x401000", "name": "sub_401000", "decompile_snippet": "int f(){}", "disassembly_snippet": None}],
        project_name="p",
    )
    for section in ["【角色定义】", "【输入数据】", "【分析维度】", "【输出格式】", "【误差控制】"]:
        assert section in prompt, section
    assert "command_dispatcher" in prompt
    assert "0x401000" in prompt
    # 输出 schema 约束：五要素字段齐全
    for field in ["findings", "evidence", "confidence", "unresolved", "summary"]:
        assert field in prompt, field


def test_topic_prompt_methodology_for_all_topics():
    """8 个主题词各有专属方法论要点注入到分析维度段。"""
    keywords = {
        "init_config_decrypt": "解密算法",
        "command_dispatcher": "逐条还原命令语义",
        "persistence": "注册表 Run 键",
        "injection_loader": "CreateRemoteThread",
        "stealer": "窃取目标",
        "network_stack": "C2",
        "anti_analysis": "反调试",
        "export_interface": "ordinal",
    }
    assert set(TOPIC_METHODOLOGIES) == set(ANALYSIS_TOPIC_VOCABULARY)
    for topic, kw in keywords.items():
        prompt = build_topic_prompt(topic, [], [])
        assert kw in prompt, f"{topic} 缺少方法论关键词 {kw!r}"


def test_topic_prompt_includes_prerequisites():
    """depends_on 前置主题结论注入 prompt，供第二波主题引用。"""
    prompt = build_topic_prompt(
        "network_stack", ["0x401000"],
        [{"addr": "0x401000", "decompile_snippet": "x", "disassembly_snippet": None}],
        prerequisites={"init_config_decrypt": {"summary": "配置含 C2 1.2.3.4"}},
    )
    assert "前置主题结论" in prompt
    assert "配置含 C2 1.2.3.4" in prompt


def test_topic_prompt_includes_special_requirements():
    """USER.md 异步通道内容以"特殊要求"段注入 prompt（缺省时不出现该段）。"""
    prompt = build_topic_prompt(
        "stealer", ["0x401000"],
        [{"addr": "0x401000", "decompile_snippet": "x", "disassembly_snippet": None}],
        special_requirements="【问题 1】加壳确认\n用户回答：已脱壳，直接分析。",
    )
    assert "特殊要求" in prompt
    assert "已脱壳，直接分析。" in prompt

    plain = build_topic_prompt("stealer", [], [])
    assert "特殊要求" not in plain


def test_topic_analysis_model_shape():
    """TopicAnalysis 嵌套 ≤2 层，字段含 findings/evidence/confidence/unresolved。"""
    m = TopicAnalysis.model_validate({
        "topic": "stealer",
        "findings": [{"subject": "浏览器密码", "conclusion": "读取 Login Data", "confidence": "high"}],
        "evidence": [{"address": "0x401000", "snippet": "Login Data", "source": "strings"}],
        "unresolved": ["打包格式未知"],
    })
    assert m.findings[0].confidence == "high"
    assert m.evidence[0].source == "strings"
    assert m.confidence == "low"  # 缺省值
    # 词表外 confidence 必须校验失败
    import pytest
    with pytest.raises(Exception):
        TopicAnalysis.model_validate({"confidence": "exploding"})


# === manifest 构建 ===========================================================

def test_manifest_default_topics_by_behavior():
    """proposed_topics 缺失时按 behavior_profile 默认映射（Stealer→stealer 等）。"""
    state = _state(
        _candidate("0x401000", xrefs=10), _candidate("0x402000", xrefs=8),
        _candidate("0x403000", xrefs=5), _candidate("0x404000", xrefs=2),
        _candidate("0x405000", xrefs=1),
        behavior="Stealer",
    )
    manifest = build_task_manifest(state)
    topics = {t.topic: t for t in manifest.tasks if t.kind == "topic"}
    # Stealer 默认映射 stealer/anti_analysis/command_dispatcher；
    # 强特征 command_dispatcher 先分（xrefs 降序前 3），弱特征 stealer 拿剩余 2 个，
    # anti_analysis 归组为空不立项
    assert set(topics) == {"command_dispatcher", "stealer"}
    assert len(topics["command_dispatcher"].function_addrs) == 3
    assert len(topics["stealer"].function_addrs) == 2
    # 5 个候选全被主题覆盖 → 无函数兜底任务
    assert not [t for t in manifest.tasks if t.kind == "function"]


def test_manifest_proposed_topics_override_default_and_filter_vocabulary():
    """proposed_topics 优先于默认映射；词表外取值与重复项被过滤。"""
    state = _state(
        _candidate("0x401000"),
        topics=["persistence", "not_a_topic", "persistence"],
        behavior="Stealer",  # 默认映射应被 proposed_topics 覆盖
    )
    manifest = build_task_manifest(state)
    assert [t.topic for t in manifest.tasks if t.kind == "topic"] == ["persistence"]


def test_manifest_dependency_waves():
    """network_stack 依赖 init_config_decrypt：depends_on 标注 + 分两波。"""
    state = _state(
        _candidate("0x401000", size=512), _candidate("0x402000", size=256),
        _candidate("0x403000", size=128), _candidate("0x404000", size=64),
        topics=["network_stack", "init_config_decrypt"],
    )
    manifest = build_task_manifest(state)
    by_id = {t.task_id: t for t in manifest.tasks}
    assert by_id["topic_network_stack"].depends_on == ["topic_init_config_decrypt"]
    assert by_id["topic_init_config_decrypt"].depends_on == []

    wave0, wave1 = _manifest_waves({**state, "task_manifest": manifest.model_dump()})
    assert [t["task_id"] for t in wave0] == ["topic_init_config_decrypt"]
    assert [t["task_id"] for t in wave1] == ["topic_network_stack"]


def test_manifest_dependency_dropped_when_target_absent():
    """依赖目标不在本次清单时 depends_on 为空（依赖悬空无意义）→ 任务留在 wave0。"""
    state = _state(_candidate("0x401000"), topics=["network_stack"])
    manifest = build_task_manifest(state)
    task = manifest.tasks[0]
    assert task.depends_on == []
    wave0, wave1 = _manifest_waves({**state, "task_manifest": manifest.model_dump()})
    assert len(wave0) == 1 and not wave1


def test_manifest_fallback_function_tasks():
    """未被任何主题覆盖的护栏后候选 → 逐函数兜底任务。"""
    state = _state(
        _candidate("0x401000", xrefs=10), _candidate("0x402000", xrefs=8),
        _candidate("0x403000", xrefs=5), _candidate("0x404000", xrefs=2),
        topics=["command_dispatcher"],  # 拿 3 个，剩 0x404000 兜底
    )
    manifest = build_task_manifest(state)
    func_tasks = [t for t in manifest.tasks if t.kind == "function"]
    assert [t.function_addrs for t in func_tasks] == [["0x404000"]]
    assert func_tasks[0].task_id == "func_0x404000"


def test_manifest_modify_unconditional_acceptance():
    """MODIFY 人工指定的地址不在 LLM candidates 中也不得丢弃（合成 FuncCandidate），
    且 MODIFY 路径只产函数任务（无主题归组）。"""
    state = _state(
        _candidate("0x401000"),
        topics=["command_dispatcher"],
        human=["0x401000", "0x409999"],
    )
    # 候选选取：0x409999 合成条目补入
    candidates = _select_phase3_candidates(state)
    assert {c["func_addr"] for c in candidates} == {"0x401000", "0x409999"}
    synth = next(c for c in candidates if c["func_addr"] == "0x409999")
    assert synth["priority_reason"].startswith("人工 MODIFY 指定")

    manifest = build_task_manifest(state)
    assert all(t.kind == "function" for t in manifest.tasks)
    assert {t.function_addrs[0] for t in manifest.tasks} == {"0x401000", "0x409999"}


def test_manifest_exclusive_assignment():
    """一个函数只归一个主题（先到先得），同一地址不会出现在两个主题里。"""
    state = _state(
        _candidate("0x401000", size=512, xrefs=10),
        _candidate("0x402000", size=256, xrefs=8),
        topics=["command_dispatcher", "init_config_decrypt"],
    )
    manifest = build_task_manifest(state)
    seen: set = set()
    for t in manifest.tasks:
        for addr in t.function_addrs:
            assert addr not in seen
            seen.add(addr)


# === 迷你子图端到端（双轨 + 依赖分波 + 幂等 + 空任务直通） ==================

def _build_dual_track_graph(llm):
    """dispatch →（Send）topic+function → wave2 →（Send）topic_dep → orchestrator → verification 桩。"""
    builder = StateGraph(AnalysisState)

    def verification_stub(state):
        return {"final_report_ref": "bb://summary/p4_final_report"}

    builder.add_node("phase3_dispatch", phase3_dispatch_node)
    builder.add_node("phase3_topic", make_topic_node(llm))
    builder.add_node("phase3_function", make_phase3_function_node(llm))
    builder.add_node("phase3_wave2", phase3_wave2_node)
    builder.add_node("phase3_topic_dep", make_topic_node(llm))
    # orchestrator 为真实纯代码节点（docs 归档落在 tmp_path 黑板下，不调 LLM）
    builder.add_node("orchestrator", orchestrator_node)
    builder.add_node("verification_agent", verification_stub)
    builder.add_edge(START, "phase3_dispatch")
    builder.add_conditional_edges(
        "phase3_dispatch",
        phase3_fanout,
        ["phase3_topic", "phase3_function", "phase3_wave2", "orchestrator"],
    )
    builder.add_edge("phase3_topic", "phase3_wave2")
    builder.add_edge("phase3_function", "phase3_wave2")
    builder.add_conditional_edges(
        "phase3_wave2", phase3_fanout_wave2, ["phase3_topic_dep", "orchestrator"]
    )
    builder.add_edge("phase3_topic_dep", "orchestrator")
    builder.add_edge("orchestrator", "verification_agent")
    builder.add_edge("verification_agent", END)
    return builder.compile()


def test_dual_track_dependency_waves_end_to_end(tmp_path, monkeypatch):
    """依赖分波端到端：wave1 主题（network_stack）必须在 wave0 主题
    （init_config_decrypt）全部 LLM 调用完成后才开始，且其 prompt 携带前置结论。"""
    monkeypatch.chdir(tmp_path)
    addrs = ["0x401000", "0x402000", "0x403000", "0x404000"]
    export_dir = _make_export_dir(str(tmp_path), *addrs)
    fake = TopicFakeModel()
    graph = _build_dual_track_graph(fake)

    final = asyncio.run(graph.ainvoke(_state(
        _candidate("0x401000", size=512), _candidate("0x402000", size=256),
        _candidate("0x403000", size=128), _candidate("0x404000", size=64),
        topics=["init_config_decrypt", "network_stack"],
    )))

    # 两个主题各分析一次；init 的 extractor 完成后 network 才开始（分波生效）
    topic_calls = [c for c in fake.calls if c[0] == "topic"]
    assert [t for _, t in topic_calls] == ["init_config_decrypt", "network_stack"]
    init_done = max(i for i, c in enumerate(fake.calls)
                    if c[1] == "init_config_decrypt")
    network_start = fake.calls.index(("topic", "network_stack"))
    assert network_start > init_done
    # wave1 主题节点读到了前置主题的 extractor 摘要并注入 prompt
    assert "前置主题结论" in fake.topic_prompts["network_stack"]

    # 双轨聚合：4 个候选全被主题覆盖，无函数兜底
    assert {r["topic"] for r in final["topic_analysis_refs"]} == {
        "init_config_decrypt", "network_stack",
    }
    assert final["func_analysis_refs"] == []
    assert final["final_report_ref"] == "bb://summary/p4_final_report"

    # 黑板产物：主题 artifact + 摘要 + manifest 落盘
    for topic in ("init_config_decrypt", "network_stack"):
        assert os.path.exists(board_path("t_topic", "artifacts", f"topic_{topic}.json"))
        assert os.path.exists(board_path("t_topic", "summary", "topics", f"{topic}.json"))
    with open(board_path("t_topic", "meta", "task_manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    assert len(manifest["tasks"]) == 2


def test_dual_track_topic_and_function_both_fanout(tmp_path, monkeypatch):
    """双轨扇出：主题任务与函数兜底任务同波并行，两条轨的 refs 都聚合到终态。"""
    monkeypatch.chdir(tmp_path)
    addrs = ["0x401000", "0x402000", "0x403000", "0x404000"]
    export_dir = _make_export_dir(str(tmp_path), *addrs)
    fake = TopicFakeModel()
    graph = _build_dual_track_graph(fake)

    final = asyncio.run(graph.ainvoke(_state(
        _candidate("0x401000", xrefs=10), _candidate("0x402000", xrefs=8),
        _candidate("0x403000", xrefs=5), _candidate("0x404000", xrefs=2),
        topics=["command_dispatcher"],
    )))

    assert [r["topic"] for r in final["topic_analysis_refs"]] == ["command_dispatcher"]
    assert [r["addr"] for r in final["func_analysis_refs"]] == ["0x404000"]
    assert ("topic", "command_dispatcher") in fake.calls
    assert any(c[0] == "func" for c in fake.calls)


def test_topic_node_idempotent_skip(tmp_path, monkeypatch):
    """已有 topic artifact 的主题幂等跳过：返回 skipped 引用，不发起主题 LLM 调用。"""
    monkeypatch.chdir(tmp_path)
    addrs = ["0x401000", "0x402000"]
    export_dir = _make_export_dir(str(tmp_path), *addrs)
    bb_write_artifact("topic_command_dispatcher", {"status": "success"}, "t_topic")
    fake = TopicFakeModel()
    graph = _build_dual_track_graph(fake)

    final = asyncio.run(graph.ainvoke(_state(
        _candidate("0x401000"), _candidate("0x402000"),
        topics=["command_dispatcher"],
    )))

    assert final["topic_analysis_refs"][0]["skipped"] is True
    assert not [c for c in fake.calls if c[0] == "topic"]


def test_empty_manifest_goes_straight_to_verification(tmp_path, monkeypatch):
    """空任务（无候选且无主题）：条件边直通 orchestrator（再进 verification 桩），不调 LLM。"""
    monkeypatch.chdir(tmp_path)
    state = _state()  # 空候选、无 scheduler_decision、behavior Unknown
    assert phase3_fanout(state) == "orchestrator"

    fake = TopicFakeModel()
    graph = _build_dual_track_graph(fake)
    final = asyncio.run(graph.ainvoke(state))

    assert final["func_analysis_refs"] == []
    assert final["topic_analysis_refs"] == []
    assert final["final_report_ref"] == "bb://summary/p4_final_report"
    assert fake.calls == []


def test_wave0_empty_but_wave1_non_empty_routes_via_wave2(tmp_path, monkeypatch):
    """wave0 空但 wave1 非空（理论边界：依赖被过滤后残留）：dispatch 直通 wave2。

    注：正常构建下 depends_on 只在依赖目标同波存在时标注，wave1 非空必然
    wave0 非空；这里直接手工构造 manifest 验证条件边的路由分支。
    """
    monkeypatch.chdir(tmp_path)
    state = _state()
    state["task_manifest"] = {"tasks": [{
        "task_id": "topic_network_stack", "kind": "topic", "topic": "network_stack",
        "function_addrs": [], "depends_on": ["topic_init_config_decrypt"],
        "output_doc": "", "status": "pending",
    }]}
    assert phase3_fanout(state) == "phase3_wave2"
    # wave2 条件边把 wave1 扇出到 phase3_topic_dep
    sends = phase3_fanout_wave2(state)
    assert isinstance(sends, list) and len(sends) == 1
    assert sends[0].node == "phase3_topic_dep"
    assert sends[0].arg["analysis_task"]["topic"] == "network_stack"
