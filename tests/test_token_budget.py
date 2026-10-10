"""Token 预算闸门（B1）测试：observability 模块级注册表、
_enforce_token_budget 的 interrupt/resume/步进语义、
invoke_guarded 与 Worker 节点入口的闸门接线。

interrupt 必须在带 checkpointer 的图节点上下文中触发，故用最小 probe 图驱动；
LLM 调用全部用 ScriptedFakeChatModel 假模型，不消耗真实 API。
"""
import asyncio
from typing import TypedDict

import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

import graph_nodes
import observability
from graph_nodes import _enforce_token_budget, invoke_guarded, make_worker_node
from observability import TokenStatsCallback, current_total_tokens, register_callback
from tests.test_integration import ScriptedFakeChatModel, _make_export_dir
from workers.specs import string_artifact_analyst


class _ProbeState(TypedDict, total=False):
    sample_project_name: str
    sample_export_dir: str
    done: bool
    string_analysis: dict


@pytest.fixture(autouse=True)
def _clean_budget_state(tmp_path, monkeypatch):
    """每个用例独立：chdir 到无 config.yaml 的临时目录，清空放行记录与注册表。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TOKEN_BUDGET", raising=False)
    graph_nodes._BUDGET_ALLOWANCE.clear()
    observability._CALLBACK_REGISTRY.clear()
    yield tmp_path
    graph_nodes._BUDGET_ALLOWANCE.clear()
    observability._CALLBACK_REGISTRY.clear()


def _register_used(project: str, used: int) -> TokenStatsCallback:
    """注册一个已累计 used tokens 的 callback（预算闸门的数据源）。"""
    cb = TokenStatsCallback(sample_project_name=project)
    cb.report.add_usage("probe", used, 0, used)
    register_callback(project, cb)
    return cb


def _build_probe_graph(node):
    builder = StateGraph(_ProbeState)
    builder.add_node("probe", node)
    builder.add_edge(START, "probe")
    builder.add_edge("probe", END)
    return builder.compile(checkpointer=MemorySaver())


def _pending_interrupts(graph, config) -> list:
    snapshot = graph.get_state(config)
    return [it for task in snapshot.tasks for it in task.interrupts]


# === 注册表 ===

def test_callback_registry_roundtrip():
    """未注册项目返回 0；注册后返回 report.total_tokens。"""
    assert current_total_tokens("ghost") == 0
    _register_used("proj", 150)
    assert current_total_tokens("proj") == 150


# === 未启用时无操作 ===

def test_budget_disabled_by_default():
    """token_budget 缺省（null/0）不启用：即使用量巨大也直接放行，不触碰 interrupt。"""
    assert graph_nodes.token_budget() == 0
    _register_used("proj", 10 ** 9)
    _enforce_token_budget("proj")  # 裸调不抛即证明未触发 interrupt


# === interrupt / resume / 步进 ===

def _budget_probe(state):
    _enforce_token_budget(state)
    return {"done": True}


def test_budget_gate_interrupts_then_resume_steps_up(monkeypatch):
    """超预算挂起（payload 含用量与预算）；resume 后放行一个步长并跑完。"""
    monkeypatch.setenv("TOKEN_BUDGET", "100")
    _register_used("proj", 150)

    graph = _build_probe_graph(_budget_probe)
    config = {"configurable": {"thread_id": "t1"}}
    asyncio.run(graph.ainvoke({"sample_project_name": "proj"}, config=config))

    pending = _pending_interrupts(graph, config)
    assert len(pending) == 1
    payload = pending[0].value
    assert payload["kind"] == "token_budget"
    assert payload["used_tokens"] == 150
    assert payload["budget"] == 100
    assert payload["effective_budget"] == 100
    assert "150" in payload["message"]

    # resume（任意放行文本）：节点重跑，interrupt 返回后放行记录 +100，节点完成
    result = asyncio.run(graph.ainvoke(Command(resume="CONTINUE"), config=config))
    assert result["done"] is True
    assert graph_nodes._BUDGET_ALLOWANCE["proj"] == 100
    assert not _pending_interrupts(graph, config)


def test_budget_gate_reinterrupts_after_step_consumed(monkeypatch):
    """放行一个步长后，用量再次涨满步长会再次挂起（可反复放行），阈值随步进上移。"""
    monkeypatch.setenv("TOKEN_BUDGET", "100")
    cb = _register_used("proj", 150)

    graph = _build_probe_graph(_budget_probe)
    config = {"configurable": {"thread_id": "t1"}}
    asyncio.run(graph.ainvoke({"sample_project_name": "proj"}, config=config))
    asyncio.run(graph.ainvoke(Command(resume="CONTINUE"), config=config))
    assert graph_nodes._BUDGET_ALLOWANCE["proj"] == 100  # effective=200

    # 用量涨到 250（>=200）：新一轮运行再次挂起，payload 反映步进后的阈值
    cb.report.add_usage("probe", 100, 0, 100)  # used=250
    config2 = {"configurable": {"thread_id": "t2"}}
    asyncio.run(graph.ainvoke({"sample_project_name": "proj"}, config=config2))
    pending = _pending_interrupts(graph, config2)
    assert len(pending) == 1
    assert pending[0].value["effective_budget"] == 200
    assert pending[0].value["used_tokens"] == 250

    asyncio.run(graph.ainvoke(Command(resume="CONTINUE"), config=config2))
    assert graph_nodes._BUDGET_ALLOWANCE["proj"] == 200


def test_budget_gate_passes_when_under_budget(monkeypatch):
    """用量低于预算时直接放行（不挂起）。"""
    monkeypatch.setenv("TOKEN_BUDGET", "100")
    _register_used("proj", 50)

    graph = _build_probe_graph(_budget_probe)
    config = {"configurable": {"thread_id": "t1"}}
    result = asyncio.run(graph.ainvoke({"sample_project_name": "proj"}, config=config))
    assert result["done"] is True
    assert not _pending_interrupts(graph, config)


def test_budget_gate_passes_when_callback_unregistered(monkeypatch):
    """项目未注册 callback（如未挂 TokenStatsCallback 的运行）时用量视为 0，直接放行。"""
    monkeypatch.setenv("TOKEN_BUDGET", "100")
    graph = _build_probe_graph(_budget_probe)
    config = {"configurable": {"thread_id": "t1"}}
    result = asyncio.run(graph.ainvoke({"sample_project_name": "proj"}, config=config))
    assert result["done"] is True


# === invoke_guarded 接线 ===

def test_invoke_guarded_enforces_budget(monkeypatch):
    """invoke_guarded 传 project_name 时先过预算闸门：超预算挂起，resume 后放行跑完。"""
    monkeypatch.setenv("TOKEN_BUDGET", "100")
    _register_used("proj", 150)

    async def probe(state):
        resp = await invoke_guarded(
            ScriptedFakeChatModel(),
            [("user", "你好")],
            project_name=state["sample_project_name"],
        )
        return {"done": bool(getattr(resp, "content", None))}

    graph = _build_probe_graph(probe)
    config = {"configurable": {"thread_id": "t1"}}
    asyncio.run(graph.ainvoke({"sample_project_name": "proj"}, config=config))
    pending = _pending_interrupts(graph, config)
    assert len(pending) == 1
    assert pending[0].value["kind"] == "token_budget"

    result = asyncio.run(graph.ainvoke(Command(resume="CONTINUE"), config=config))
    assert result["done"] is True


# === Worker 节点入口接线（ReAct 内层不走 invoke_guarded，故在 ainvoke 前检查）===

def test_worker_node_enforces_budget(monkeypatch):
    """make_worker_node 在 ReAct 主调用前过预算闸门：超预算时 worker 节点挂起，
    反复 resume 放行足够步长后照常跑完（主调用 + extractor + 结构化输出）。

    节点内有两个闸门调用点（主调用入口 + extractor 的 invoke_guarded）：
    每次 resume 只推进一个挂起点（LangGraph 语义），故循环放行直至跑完。
    """
    monkeypatch.setenv("TOKEN_BUDGET", "100")
    _register_used("proj", 500)

    async def worker_probe(state):
        node = make_worker_node(string_artifact_analyst, llm=ScriptedFakeChatModel())
        return await node(state)

    graph = _build_probe_graph(worker_probe)
    config = {"configurable": {"thread_id": "t1"}}
    state = {"sample_project_name": "proj", "sample_export_dir": _make_export_dir("export_src")}

    result = asyncio.run(graph.ainvoke(state, config=config))
    resumes = 0
    for _ in range(10):
        pending = _pending_interrupts(graph, config)
        if not pending:
            break
        assert all(it.value["kind"] == "token_budget" for it in pending)
        resumes += 1
        result = asyncio.run(graph.ainvoke(Command(resume="CONTINUE"), config=config))
    else:
        pytest.fail("预算闸门反复挂起未收敛")
    assert resumes >= 1  # 确实被闸门拦过
    assert result["string_analysis"]["status"] == "success"
