"""模型分层（B1）测试：WorkerSpec tier 声明、get_llm 双单例缓存与缺省回退、
节点工厂按 tier 取模型、build_graph 显式注入假模型时分层不生效。

不消耗真实 API：init_chat_model 被替换为记录参数的伪构造器，图执行用
ScriptedFakeChatModel 假模型。
"""
import asyncio

import pytest
from langgraph.checkpoint.memory import MemorySaver

import graph_nodes
from graph import build_graph
from graph_nodes import make_worker_node
from tests.test_integration import (
    ScriptedFakeChatModel,
    _make_export_dir,
    _run_graph_with_human_replies,
)
from workers.specs import (
    PHASE0_SPECS,
    PHASE1_SPECS,
    WorkerSpec,
    behavior_profile_synthesizer,
    scheduler,
    string_artifact_analyst,
    verification_agent,
)


class _FakeModel:
    """记录构造参数的伪 chat model（替代 init_chat_model 的真实产物）。"""

    def __init__(self, model, **kwargs):
        self.model = model
        self.kwargs = kwargs


def _fake_init_chat_model(model, **kwargs):
    return _FakeModel(model, **kwargs)


@pytest.fixture
def fresh_llm_cache(tmp_path, monkeypatch):
    """隔离的双单例与配置环境：重置缓存，chdir 到无 config.yaml 的临时目录。"""
    monkeypatch.chdir(tmp_path)
    for var in ("LIGHT_MODEL", "LIGHT_BASE_URL", "LIGHT_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    graph_nodes.set_llm(None)
    yield tmp_path
    graph_nodes.set_llm(None)


# === WorkerSpec tier 声明 ===

def test_workerspec_tier_defaults_strong():
    """不显式声明 tier 的 WorkerSpec 默认 strong（零行为变化）。"""
    spec = WorkerSpec(name="x", instruction="i", tools=(), output_key="k")
    assert spec.tier == "strong"


def test_spec_tier_assignments():
    """分层默认：Phase 0 triage / scheduler / verification 为 light；Phase 1 为 strong。"""
    for spec in (*PHASE0_SPECS, scheduler, verification_agent):
        assert spec.tier == "light", spec.name
    for spec in PHASE1_SPECS:
        assert spec.tier == "strong", spec.name


# === get_llm 双单例与配置回退 ===

def test_light_tier_falls_back_to_strong_when_unconfigured(fresh_llm_cache, monkeypatch):
    """未配置 llm.light_model 时 get_llm("light") 直接返回 strong 单例（零行为变化）。"""
    monkeypatch.setattr(graph_nodes, "init_chat_model", _fake_init_chat_model)
    strong = graph_nodes.get_llm()
    light = graph_nodes.get_llm("light")
    assert light is strong


def test_light_tier_separate_singleton_with_config_fallback(fresh_llm_cache, monkeypatch):
    """配置 light_model 后 light 为独立单例；light_base_url / light_api_key 缺省
    分别回退主模型 base_url / API_KEY；两个 tier 各自只构造一次（双单例缓存）。"""
    with open("config.yaml", "w", encoding="utf-8") as f:
        f.write(
            "llm:\n"
            "  model: main-model\n"
            "  base_url: http://main.example/v1\n"
            "  light_model: light-model\n"
        )
    monkeypatch.setenv("API_KEY", "main-key")
    monkeypatch.setattr(graph_nodes, "init_chat_model", _fake_init_chat_model)

    strong = graph_nodes.get_llm()
    light = graph_nodes.get_llm("light")
    assert light is not strong
    assert light.model == "light-model"
    # 缺省回退：端点用主 base_url，key 用 API_KEY
    assert light.kwargs["base_url"] == "http://main.example/v1"
    assert light.kwargs["api_key"] == "main-key"
    # 双单例缓存：重复获取命中缓存，不重复构造
    assert graph_nodes.get_llm() is strong
    assert graph_nodes.get_llm("light") is light


def test_light_tier_explicit_overrides(fresh_llm_cache, monkeypatch):
    """显式配置 light_base_url / LIGHT_API_KEY 时不回退主模型配置。"""
    with open("config.yaml", "w", encoding="utf-8") as f:
        f.write(
            "llm:\n"
            "  model: main-model\n"
            "  base_url: http://main.example/v1\n"
            "  light_model: light-model\n"
            "  light_base_url: http://light.example/v1\n"
        )
    monkeypatch.setenv("API_KEY", "main-key")
    monkeypatch.setenv("LIGHT_API_KEY", "light-key")
    monkeypatch.setattr(graph_nodes, "init_chat_model", _fake_init_chat_model)

    light = graph_nodes.get_llm("light")
    assert light.kwargs["base_url"] == "http://light.example/v1"
    assert light.kwargs["api_key"] == "light-key"


# === 节点工厂按 tier 取模型 ===

def test_worker_node_model_tiers(tmp_path, monkeypatch):
    """make_worker_node 按 spec.tier 取主调用模型，extractor 摘要固定走 light。

    light spec（string_artifact_analyst）：主调用与 extractor 都请求 light；
    strong spec（behavior_profile_synthesizer）：主调用 strong、extractor light。
    """
    monkeypatch.chdir(tmp_path)
    export_dir = _make_export_dir(str(tmp_path))
    fake = ScriptedFakeChatModel()
    calls = []

    def _recording_get_llm(tier="strong"):
        calls.append(tier)
        return fake

    monkeypatch.setattr(graph_nodes, "get_llm", _recording_get_llm)

    node = make_worker_node(string_artifact_analyst)  # tier=light
    asyncio.run(node({"sample_project_name": "tier_light", "sample_export_dir": export_dir}))
    assert calls and set(calls) == {"light"}

    calls.clear()
    node = make_worker_node(behavior_profile_synthesizer)  # tier=strong
    asyncio.run(node({"sample_project_name": "tier_strong", "sample_export_dir": export_dir}))
    assert "strong" in calls  # 主调用
    assert "light" in calls   # extractor 摘要


def test_build_graph_injected_llm_bypasses_tiering(tmp_path, monkeypatch):
    """build_graph(llm=fake) 显式注入时所有 tier 都用注入模型：get_llm 一次都不应被调用，
    全图冒烟跑完（测试行为与分层落地前一致）。"""
    export_dir = _make_export_dir(str(tmp_path))
    monkeypatch.chdir(tmp_path)

    def _forbidden_get_llm(*args, **kwargs):
        pytest.fail("显式注入假模型时不应调用 get_llm")

    monkeypatch.setattr(graph_nodes, "get_llm", _forbidden_get_llm)
    graph = build_graph(llm=ScriptedFakeChatModel(), checkpointer=MemorySaver())
    final_state, interrupt_count = asyncio.run(_run_graph_with_human_replies(
        graph,
        {
            "sample_project_name": "test_tier_bypass",
            "sample_export_dir": export_dir,
            "sample_type": "auto",
        },
        replies=["CONFIRM"],
    ))
    assert interrupt_count == 1
    assert final_state["final_report_ref"] == "bb://summary/p4_final_report"
