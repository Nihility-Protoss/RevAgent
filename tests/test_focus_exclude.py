"""C2 focus/exclude 用户分析优先级机制的全链路测试。

链路：CLI --focus/--exclude（config.yaml analysis.focus/exclude 兜底，env FOCUS/EXCLUDE）
→ initial_state 的 user_focus/user_exclude → pre_extract 落盘 USER.md focus 段
→ 各 prompt 注入点（Worker / 主题 / 函数 / 报告）经 _load_user_special_requirements
合并两来源（启动参数 + USER.md）并去重。

行为约束对齐金标准：exclude 领域不深入静态过程、不阻塞整体流程、产物标注
"用户指示不深入分析此部分"，结果性数据只提供动态调试提取方案。

全部使用假模型注入与临时目录黑板，不消耗真实 API token。
"""
import asyncio
import json
import os
import shutil

import pytest

import graph_nodes
from graph_nodes import (
    _load_user_special_requirements,
    _sync_user_priority_to_user_md,
    build_user_priority_text,
    make_report_generator_node,
    make_worker_node,
)
from tests.test_integration import (
    ScriptedFakeChatModel,
    _make_export_dir as _make_full_export_dir,
)
from tests.test_topics import (
    TopicFakeModel,
    _build_dual_track_graph,
    _candidate,
    _make_export_dir as _make_funcs_export_dir,
    _state,
)
from tools.docs_tools import user_md_read, user_md_set_focus
from workers.phase3.function_deep_analyzer import build_func_analysis_prompt

FOCUS = "驻留,持久化,二次加载,窃取"
EXCLUDE = "加解密过程"


# === 约束文案（build_user_priority_text）=====================================

def test_priority_text_empty_when_no_args():
    """无 focus/exclude 时返回空字符串（缺省零行为变化）。"""
    assert build_user_priority_text() == ""
    assert build_user_priority_text("", "  ") == ""


def test_priority_text_focus_only():
    text = build_user_priority_text(focus=FOCUS)
    assert FOCUS in text
    assert "优先详细展开" in text
    assert "排除" not in text


def test_priority_text_exclude_constraint_wording():
    """exclude 约束文案对齐金标准：不深入、不阻塞、标注边界、动调替代。"""
    text = build_user_priority_text(exclude=EXCLUDE)
    assert EXCLUDE in text
    assert "用户指示不深入分析此部分" in text
    assert "不阻塞整体分析流程" in text
    assert "动态调试" in text and "断点位置" in text
    assert "不展开静态分析过程" in text


def test_priority_text_both_sections():
    text = build_user_priority_text(FOCUS, EXCLUDE)
    assert "【用户分析重点（启动参数 --focus）】" in text
    assert "【用户排除领域（启动参数 --exclude）】" in text


# === USER.md 落盘（docs_tools.user_md_set_focus + pre_extract 同步）==========

def test_user_md_set_focus_write_idempotent_append(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r1 = user_md_set_focus("p1", "- 重点关注：驻留")
    assert r1["status"] == "success" and r1["changed"] is True
    assert "驻留" in user_md_read("p1")["focus"]

    # 幂等：同文本再次写入不产生重复
    r2 = user_md_set_focus("p1", "- 重点关注：驻留")
    assert r2["status"] == "success" and r2["changed"] is False
    assert user_md_read("p1")["focus"].count("驻留") == 1

    # 追加语义：已有内容保留，新文本追加在后
    r3 = user_md_set_focus("p1", "- 排除领域：加解密")
    assert r3["changed"] is True
    focus_text = user_md_read("p1")["focus"]
    assert "驻留" in focus_text and "加解密" in focus_text

    # 空文本报错；骨架段占位符被正确替换
    assert user_md_set_focus("p1", "  ")["status"] == "error"


def test_sync_user_priority_to_user_md(tmp_path, monkeypatch):
    """pre_extract 的 USER.md 落盘：focus/exclude 写入 focus 段，空参数不动文件。"""
    monkeypatch.chdir(tmp_path)
    state = {"sample_project_name": "p2", "user_focus": FOCUS, "user_exclude": EXCLUDE}
    _sync_user_priority_to_user_md(state)
    focus_text = user_md_read("p2")["focus"]
    assert FOCUS in focus_text and EXCLUDE in focus_text
    assert "--focus" in focus_text and "--exclude" in focus_text

    # 幂等：重复同步不重复落盘
    _sync_user_priority_to_user_md(state)
    assert user_md_read("p2")["focus"].count(FOCUS) == 1

    # 空参数：不创建/不修改 USER.md 段内容
    _sync_user_priority_to_user_md({"sample_project_name": "p3"})
    assert user_md_read("p3")["focus"] == ""


# === 两来源合并与去重（_load_user_special_requirements）======================

def test_special_requirements_dedup_startup_vs_user_md(tmp_path, monkeypatch):
    """启动参数已落盘 USER.md 时不重复注入；未覆盖的来源单独追加。"""
    monkeypatch.chdir(tmp_path)
    _sync_user_priority_to_user_md(
        {"sample_project_name": "p4", "user_focus": FOCUS, "user_exclude": EXCLUDE}
    )
    merged = _load_user_special_requirements("p4", FOCUS, EXCLUDE)
    # 两个来源同一内容：focus/exclude 原文各出现一次（USER.md 段），启动参数段不追加
    assert merged.count(FOCUS) == 1
    assert merged.count(EXCLUDE) == 1
    assert "【用户着重关心的内容（USER.md）】" in merged
    assert "【用户分析重点（启动参数 --focus）】" not in merged

    # USER.md 未覆盖的新 focus：启动参数段追加（两来源合一）
    merged2 = _load_user_special_requirements("p4", "网络通信", EXCLUDE)
    assert "【用户分析重点（启动参数 --focus）】" in merged2
    assert "网络通信" in merged2
    # exclude 已落盘 → 不重复出排除段
    assert merged2.count(EXCLUDE) == 1


def test_special_requirements_cli_only_without_user_md(tmp_path, monkeypatch):
    """USER.md 无内容时（如迷你子图不经 pre_extract），启动参数段照常注入。"""
    monkeypatch.chdir(tmp_path)
    merged = _load_user_special_requirements("p5", FOCUS, EXCLUDE)
    assert FOCUS in merged and EXCLUDE in merged
    assert "用户指示不深入分析此部分" in merged


def test_special_requirements_empty_by_default(tmp_path, monkeypatch):
    """无 USER.md 内容且无启动参数：返回空字符串（缺省零行为变化）。"""
    monkeypatch.chdir(tmp_path)
    assert _load_user_special_requirements("p6") == ""


# === prompt 注入点 ===========================================================

def test_func_analysis_prompt_special_requirements():
    """函数分析 prompt：special_requirements 追加为最高优先级约束段。"""
    prompt = build_func_analysis_prompt(
        "0x401000", "sub_401000",
        {"decompile_snippet": "int a;", "disassembly_snippet": "mov eax, 1"},
        special_requirements=build_user_priority_text(FOCUS, EXCLUDE),
    )
    assert "用户分析重点与排除约束（最高优先级，严格遵守）" in prompt
    assert FOCUS in prompt and "用户指示不深入分析此部分" in prompt
    # 缺省（不传）时无该段
    plain = build_func_analysis_prompt(
        "0x401000", "sub_401000",
        {"decompile_snippet": "int a;", "disassembly_snippet": "mov eax, 1"},
    )
    assert "用户分析重点与排除约束" not in plain


def test_topic_and_function_nodes_inject_focus_exclude(tmp_path, monkeypatch):
    """迷你子图端到端：initial_state 带 user_focus/user_exclude 时，
    主题节点与函数节点的 prompt 都携带用户分析重点与排除约束。"""
    monkeypatch.chdir(tmp_path)
    addrs = ["0x401000", "0x402000", "0x403000", "0x404000"]
    export_dir = _make_funcs_export_dir(str(tmp_path), *addrs)

    class FocusRecordingModel(TopicFakeModel):
        """在 TopicFakeModel 基础上记录函数轨 prompt 原文。"""

        def __init__(self):
            super().__init__()
            self.func_prompts: list[str] = []

        async def ainvoke(self, messages, config=None):
            text = "\n".join(getattr(m, "content", "") or "" for m in messages)
            if "函数级分析专家" in text:
                self.func_prompts.append(text)
            return await super().ainvoke(messages, config)

    fake = FocusRecordingModel()
    graph = _build_dual_track_graph(fake)
    state = _state(
        _candidate("0x401000", xrefs=10), _candidate("0x402000", xrefs=8),
        _candidate("0x403000", xrefs=5), _candidate("0x404000", xrefs=2),
        topics=["command_dispatcher"],
    )
    state["sample_export_dir"] = export_dir
    state["user_focus"] = FOCUS
    state["user_exclude"] = EXCLUDE
    final = asyncio.run(graph.ainvoke(state))

    # 主题轨 prompt 注入（特殊要求段）
    topic_prompt = fake.topic_prompts["command_dispatcher"]
    assert FOCUS in topic_prompt and "用户指示不深入分析此部分" in topic_prompt
    # 函数轨 prompt 注入（最高优先级约束段）
    assert fake.func_prompts, "函数兜底任务应被扇出"
    assert all(FOCUS in p and "用户指示不深入分析此部分" in p for p in fake.func_prompts)
    assert final["func_analysis_refs"], "函数轨应有产出引用"


_SEEN_WORKER_MESSAGES: list[str] = []


class _RecordingWorkerModel(ScriptedFakeChatModel):
    """记录收到的全部消息文本的脚本化假模型（worker ReAct 主调用 + extractor）。

    节点走异步调用路径，因此重写 ``_agenerate`` 记录消息。
    """

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        _SEEN_WORKER_MESSAGES.append(
            "\n".join(getattr(m, "content", "") or "" for m in messages)
        )
        return await super()._agenerate(messages, stop, run_manager, **kwargs)


def test_worker_node_injects_focus_exclude(tmp_path, monkeypatch):
    """Worker 节点统一注入：task 消息携带用户分析重点与排除约束。"""
    monkeypatch.chdir(tmp_path)
    from state import StringAnalysis
    from workers.specs import WorkerSpec

    spec = WorkerSpec(
        name="string_artifact_analyst",
        instruction="你是恶意代码取证分析专家（测试用最小指令）。",
        tools=(),
        output_key="string_analysis",
        output_schema=StringAnalysis,
        tier="light",
    )
    node = make_worker_node(spec, llm=_RecordingWorkerModel())
    _SEEN_WORKER_MESSAGES.clear()
    result = asyncio.run(node({
        "sample_project_name": "w_focus",
        "sample_export_dir": "x",
        "user_focus": FOCUS,
        "user_exclude": EXCLUDE,
    }))
    assert result["string_analysis"]["status"] == "success"
    joined = "\n".join(_SEEN_WORKER_MESSAGES)
    assert "【用户分析重点与排除约束（优先遵循）】" in joined
    assert FOCUS in joined and "用户指示不深入分析此部分" in joined


def test_report_generator_injects_focus_exclude(tmp_path, monkeypatch):
    """报告节点：focus/exclude 约束拼进 user 消息（影响章节详略）。"""
    monkeypatch.chdir(tmp_path)
    seen: list[str] = []

    class _ReportFakeModel:
        async def ainvoke(self, messages, config=None):
            seen.append("\n".join(getattr(m, "content", "") or "" for m in messages))
            from langchain_core.messages import AIMessage
            return AIMessage(content="# 手册\n\n## 1. 样本概览\n\n本章置信度：low\n")

    node = make_report_generator_node(llm=_ReportFakeModel())
    result = asyncio.run(node({
        "sample_project_name": "p4_focus",
        "user_focus": FOCUS,
        "user_exclude": EXCLUDE,
    }))
    assert result["report_md_path"].endswith("final_report.md")
    assert seen, "报告节点应发起 LLM 调用"
    assert FOCUS in seen[0] and "用户指示不深入分析此部分" in seen[0]
    assert "用户特殊要求" in seen[0]


# === 入口：CLI / config.yaml / Web UI ========================================

def test_cli_focus_exclude_forwarded(monkeypatch, tmp_path):
    """CLI --focus/--exclude 经 main() 原样转发给 run_analysis_with_blackboard。"""
    monkeypatch.chdir(tmp_path)  # 隔离 config.yaml（默认值应为 None）
    import main as main_mod

    captured: dict = {}

    async def fake_run(**kwargs):
        captured.update(kwargs)
        return {}, None

    monkeypatch.setattr(main_mod, "run_analysis_with_blackboard", fake_run)
    monkeypatch.setattr("sys.argv", [
        "main.py", "-p", "demo", "--focus", FOCUS, "--exclude", EXCLUDE,
    ])
    main_mod.main()
    assert captured["sample_project_name"] == "demo"
    assert captured["focus"] == FOCUS
    assert captured["exclude"] == EXCLUDE


def test_cli_focus_exclude_default_none(monkeypatch, tmp_path):
    """未传参且无配置时 focus/exclude 默认为 None（缺省零行为变化）。"""
    monkeypatch.chdir(tmp_path)
    import main as main_mod

    captured: dict = {}

    async def fake_run(**kwargs):
        captured.update(kwargs)
        return {}, None

    monkeypatch.setattr(main_mod, "run_analysis_with_blackboard", fake_run)
    monkeypatch.setattr("sys.argv", ["main.py", "-p", "demo"])
    monkeypatch.delenv("FOCUS", raising=False)
    monkeypatch.delenv("EXCLUDE", raising=False)
    main_mod.main()
    assert captured["focus"] is None
    assert captured["exclude"] is None


def test_config_yaml_has_focus_exclude_defaults():
    """仓库 config.yaml 的 analysis 段带 focus/exclude 默认值（null）。"""
    import yaml

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "config.yaml"), encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert "focus" in data["analysis"] and data["analysis"]["focus"] is None
    assert "exclude" in data["analysis"] and data["analysis"]["exclude"] is None


def test_run_analysis_initial_state_carries_focus(tmp_path, monkeypatch):
    """run_analysis_with_blackboard 把 focus/exclude 写入 initial_state（user_focus/user_exclude）。"""
    monkeypatch.chdir(tmp_path)
    import main as main_mod

    captured: dict = {}

    class _FakeSaver:
        async def __aenter__(self):
            return None

        async def __aexit__(self, *a):
            return False

    class _FakeGraph:
        def get_graph(self):
            return self

        def draw_mermaid_png(self, output_file_path=None):
            os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

        async def ainvoke(self, state, config=None):
            captured.update(state)
            return state

        async def aget_state(self, config):
            class _Snap:
                tasks = []
            return _Snap()

    monkeypatch.setattr(main_mod, "resolve_sample_export_dir", lambda *a, **k: "x")
    monkeypatch.setattr(main_mod, "make_saver_cm", lambda *a, **k: _FakeSaver())
    import graph as graph_mod
    monkeypatch.setattr(graph_mod, "build_graph", lambda **k: _FakeGraph())

    asyncio.run(main_mod.run_analysis_with_blackboard(
        "demo", focus=FOCUS, exclude=EXCLUDE,
    ))
    assert captured["user_focus"] == FOCUS
    assert captured["user_exclude"] == EXCLUDE

    captured.clear()
    asyncio.run(main_mod.run_analysis_with_blackboard("demo2"))
    assert "user_focus" not in captured and "user_exclude" not in captured


def test_webui_start_focus_exclude(tmp_path, monkeypatch):
    """Web UI start 端点：请求体 focus/exclude 进入 initial_state；缺省回退 config.yaml。"""
    monkeypatch.chdir(tmp_path)
    staging = _make_full_export_dir(str(tmp_path / "staging"))
    os.makedirs(os.path.join("data", "input"), exist_ok=True)
    shutil.move(staging, os.path.join("data", "input", "fe_case_export_for_ai"))

    import webui.server as server

    captured: dict = {}

    async def fake_advance(project, graph_input):
        captured[project] = graph_input

    monkeypatch.setattr(server, "_advance", fake_advance)
    server.RUNS.clear()

    async def _run():
        resp = await server.start_analysis(server.StartRequest(
            project_name="fe_case", input_name="fe_case",
            focus=FOCUS, exclude=EXCLUDE,
        ))
        await asyncio.sleep(0.05)  # 让 create_task 调度的 fake_advance 执行
        return resp

    resp = asyncio.run(_run())
    assert resp["status"] == "running"
    state = captured["fe_case"]
    assert state["user_focus"] == FOCUS
    assert state["user_exclude"] == EXCLUDE

    # 缺省回退：请求不带 focus 时读 config.yaml 的 analysis.focus
    with open("config.yaml", "w", encoding="utf-8") as f:
        f.write("analysis:\n  focus: 窃取\n")
    # config 模块按 (路径, mtime) 缓存，清缓存确保读到新写入的配置
    import config as config_mod
    monkeypatch.setattr(config_mod, "_cache_key", None)
    server.RUNS.clear()
    captured.clear()

    async def _run2():
        resp = await server.start_analysis(server.StartRequest(
            project_name="fe_case2", input_name="fe_case",
        ))
        await asyncio.sleep(0.05)
        return resp

    asyncio.run(_run2())
    assert captured["fe_case2"]["user_focus"] == "窃取"
    assert "user_exclude" not in captured["fe_case2"]
    server.RUNS.clear()
