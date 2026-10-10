"""Phase 4 综合 prompt 测试（LangGraph 迁移后）。

ADK agents（synthesis_shard / synthesis_aggregator）已移除；Phase 4 现在由
graph 节点（make_shard_synthesis_node / make_aggregator_node / make_report_generator_node）
驱动，使用此处断言的 prompt 常量。
"""
import asyncio
import json
import os

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from graph_nodes import make_report_generator_node
from tools.blackboard_tools import board_base_dir
from workers.phase4.report_generator import REPORT_GENERATOR_PROMPT
from workers.phase4.synthesis_agent import AGGREGATOR_PROMPT, SHARD_SYNTHESIS_PROMPT


def test_shard_synthesis_prompt_is_preserved():
    """Phase 4 Map 步骤需要带局部分析模式的 shard prompt。
    """
    assert "局部分析模式" in SHARD_SYNTHESIS_PROMPT
    assert "shard_id" in SHARD_SYNTHESIS_PROMPT


def test_aggregator_prompt_is_preserved():
    """Phase 4 Reduce 步骤需要带必需字段的 aggregator prompt。
    """
    assert "汇总模式" in AGGREGATOR_PROMPT
    assert "malware_family" in AGGREGATOR_PROMPT
    assert "uncertainties" in AGGREGATOR_PROMPT


def test_aggregator_prompt_requires_uncertainties():
    """Aggregator 必须要求 uncertainties 非空。
    """
    assert "uncertainties 字段必须非空" in AGGREGATOR_PROMPT


def test_aggregator_prompt_family_constraint():
    """Aggregator 仅在 ≥2 个 shard 一致时才可输出家族名。
    """
    assert "≥2 个 shard 一致支持" in AGGREGATOR_PROMPT
    assert "Unknown" in AGGREGATOR_PROMPT


# === 综合报告 Worker（P2 路线图项，2026-10-09 落地） ===================================

def test_report_generator_prompt_is_five_section():
    """报告 Worker 提示词必须是五段式结构。"""
    for section in ["【角色定义】", "【输入数据】", "【分析维度】", "【输出格式】", "【误差控制】"]:
        assert section in REPORT_GENERATOR_PROMPT


def test_report_generator_prompt_targets_markdown_manual():
    """报告面向动态调试参考手册：Markdown 输出 + 三分类验证状态 + 断点建议。"""
    assert "综合参考手册" in REPORT_GENERATOR_PROMPT
    assert "Markdown" in REPORT_GENERATOR_PROMPT
    assert "断点" in REPORT_GENERATOR_PROMPT
    for verdict in ["verified", "disputed", "unverifiable"]:
        assert verdict in REPORT_GENERATOR_PROMPT
    # 反幻觉：禁止编造与保留被反驳发现
    assert "禁止编造" in REPORT_GENERATOR_PROMPT
    assert "不得悄悄丢弃" in REPORT_GENERATOR_PROMPT


class _MarkdownFakeChatModel(BaseChatModel):
    """返回固定文本（默认 Markdown）的假模型，用于报告节点落盘测试。"""

    reply: str = "# 恶意样本综合参考手册：report_proj\n\n## 1. 样本概述\n\n- Stealer [Phase 1]\n"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.reply))])

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.reply))])

    @property
    def _llm_type(self):
        return "markdown-fake-chat-model"


def _run_report_node(tmp_path, monkeypatch, reply):
    monkeypatch.chdir(tmp_path)
    node = make_report_generator_node(llm=_MarkdownFakeChatModel(reply=reply))
    return asyncio.run(node({
        "sample_project_name": "report_proj",
        "shard_reports": [{"shard_id": 1, "status": "success"}],
        "verification_report": {
            "status": "success", "verified": [], "disputed": [], "unverifiable": [],
        },
        "final_report_ref": "bb://summary/p4_final_report",
    }))


def test_report_generator_node_writes_markdown(tmp_path, monkeypatch):
    """手册落盘 final_report.md，bb_write_artifact 存 JSON 元数据，state 写路径。"""
    result = _run_report_node(tmp_path, monkeypatch, _MarkdownFakeChatModel().reply)

    path = result["report_md_path"]
    assert os.path.basename(path) == "final_report.md"
    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert content.startswith("# 恶意样本综合参考手册")

    meta_path = os.path.join(
        board_base_dir(), "report_proj", "artifacts", "p4_final_report_meta.json"
    )
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["status"] == "success"
    assert meta["report_path"] == path
    assert meta["source_refs"]["final_report_ref"] == "bb://summary/p4_final_report"
    assert meta["source_refs"]["shard_report_count"] == 1


def test_report_generator_node_strips_markdown_fence(tmp_path, monkeypatch):
    """模型用代码围栏包裹整篇文档时，落盘前必须剥掉围栏。"""
    reply = "```markdown\n# 恶意样本综合参考手册：report_proj\n\n正文\n```"
    result = _run_report_node(tmp_path, monkeypatch, reply)
    with open(result["report_md_path"], encoding="utf-8") as f:
        content = f.read()
    assert content.startswith("# 恶意样本综合参考手册")
    assert "```" not in content


def test_report_generator_node_empty_output_fallback(tmp_path, monkeypatch):
    """模型返回空内容时落盘占位手册并记录日志，不允许写出空文件。"""
    result = _run_report_node(tmp_path, monkeypatch, "")
    with open(result["report_md_path"], encoding="utf-8") as f:
        content = f.read()
    assert "数据不足" in content
    log_path = os.path.join(
        board_base_dir(), "report_proj", "meta", "execution_log.jsonl"
    )
    with open(log_path, encoding="utf-8") as f:
        assert "report_generator_empty_output" in f.read()


# === 9 章化与主题摘要消费（2026-10-10） =======================================

from pydantic import Field  # noqa: E402

from graph_nodes import (  # noqa: E402
    _collect_global_var_candidates,
    make_aggregator_node,
    make_shard_synthesis_node,
)
from tools.benchmark import compare  # noqa: E402
from tools.blackboard_tools import bb_write_artifact, bb_write_summary  # noqa: E402


def test_shard_prompt_mentions_topic_summaries():
    """Phase 4 Map 的 shard prompt 必须声明主题摘要输入（A2 遗留修复）。"""
    assert "topic_summaries" in SHARD_SYNTHESIS_PROMPT
    assert "主题" in SHARD_SYNTHESIS_PROMPT


def test_aggregator_prompt_mentions_topic_conclusions():
    """Aggregator 输入含主题摘要，输出提炼 topic_conclusions（受 ≤1500 tokens 限制）。"""
    assert "topic_summaries" in AGGREGATOR_PROMPT
    assert "topic_conclusions" in AGGREGATOR_PROMPT
    assert "1500" in AGGREGATOR_PROMPT


def test_report_generator_prompt_nine_chapters():
    """报告 prompt 固定 9 章结构（对齐金标准 ALL_IN_ONE 骨架），章节标题逐字出现。"""
    for chapter in [
        "## 1. 样本概览",
        "## 2. 完整执行流程图",
        "## 3. 操作能力矩阵",
        "## 4. 关键函数速查表",
        "## 5. 动态分析断点指南",
        "## 6. 内存中的关键全局变量",
        "## 7. C2 与配置提取方法",
        "## 8. IoC 指标汇总",
        "## 9. 调试注意事项",
    ]:
        assert chapter in REPORT_GENERATOR_PROMPT, chapter
    # 能力矩阵章必须按行为视角分节；每章末尾标注置信度
    for dim in ["驻留", "持久化", "注入", "窃取", "C2"]:
        assert dim in REPORT_GENERATOR_PROMPT
    assert "本章置信度" in REPORT_GENERATOR_PROMPT
    # 空数据章节保留标题并标注缺口，禁止删章/编造
    assert "未发现" in REPORT_GENERATOR_PROMPT
    assert "禁止删章" in REPORT_GENERATOR_PROMPT


def test_report_generator_prompt_data_source_mapping():
    """prompt 必须写明每章数据源字段名（让模型知道数据从哪来）。"""
    for field in [
        "phase0_summary", "behavior_profile", "breakpoint_matrix",
        "topic_summaries", "orchestrator_report", "phase3_function_summaries",
        "preclassified_iocs", "decompile_failed_functions", "global_var_candidates",
        "verification_report", "final_report", "user_special_requirements",
    ]:
        assert field in REPORT_GENERATOR_PROMPT, field
    # USER.md focus/exclude 规则：exclude 维度只给动调提取方案
    assert "用户特殊要求" in REPORT_GENERATOR_PROMPT
    assert "不展开静态分析过程" in REPORT_GENERATOR_PROMPT


class _RecordingChatModel(BaseChatModel):
    """记录收到的全部消息文本并返回预置回复的假模型（供 Phase 4 节点输入断言）。"""

    reply: str = "{}"
    recorded: list = Field(default_factory=list)

    def _capture(self, messages):
        self.recorded.append(
            "\n".join(str(getattr(m, "content", "") or "") for m in messages)
        )
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.reply))])

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        return self._capture(messages)

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        return self._capture(messages)

    @property
    def _llm_type(self):
        return "recording-fake-chat-model"


def _write_board_summary(project: str, name: str, payload: dict) -> None:
    result = bb_write_summary(name, payload, project)
    assert result["status"] == "success", result


_TOPIC_SUMMARY_PAYLOAD = {
    "worker": "topic_analyzer",
    "topic": "command_dispatcher",
    "summary": "命令分发器：switch-case 逐条分发，已还原 1 条命令语义",
    "key_findings": ["cmd 0x06 截屏回传"],
    "confidence": "medium",
    "unresolved_count": 1,
}

_SHARD_REPLY = json.dumps({
    "shard_id": 1, "status": "success",
    "suspicious_functions_summary": ["0x401000: C2 connect"],
    "key_iocs": {"urls": [], "files": [], "registry": []},
    "behavior_pattern": "网络通信", "confidence": "medium",
    "uncertainties": ["样本量小"],
}, ensure_ascii=False)


def test_shard_synthesis_node_consumes_topic_summaries(tmp_path, monkeypatch):
    """shard_synthesis 的输入收集必须包含 summary/topics/ 全部摘要。"""
    monkeypatch.chdir(tmp_path)
    project = "shard_proj"
    _write_board_summary(project, "phase3_funcs/func_0x401000", {
        "func_addr": "0x401000", "suspicious_behaviors": ["C2 connect"],
        "analysis_priority": 9,
    })
    _write_board_summary(project, "topics/command_dispatcher", _TOPIC_SUMMARY_PAYLOAD)

    model = _RecordingChatModel(reply=_SHARD_REPLY)
    node = make_shard_synthesis_node(llm=model)
    result = asyncio.run(node({"sample_project_name": project}))

    assert len(result["shard_reports"]) == 1
    assert model.recorded, "shard 节点未发起 LLM 调用"
    joined = "\n".join(model.recorded)
    assert '"topic_summaries"' in joined
    assert "命令分发器：switch-case 逐条分发" in joined
    assert "cmd 0x06 截屏回传" in joined


_AGG_REPLY = json.dumps({
    "status": "success", "malware_family": "Unknown", "confidence": "medium",
    "behavior_summary": "Stealer 行为",
    "key_iocs": {"urls": [], "files": [], "registry": []},
    "analyzed_functions": {"total": 1, "suspicious": 1, "key_functions": ["0x401000"]},
    "breakpoint_recommendations": {"P0": [], "P1": [], "P2": []},
    "topic_conclusions": ["command_dispatcher: switch-case 分发，已还原 1 条命令"],
    "uncertainties": ["样本量小"], "recommendations": ["动态调试确认"],
}, ensure_ascii=False)


def test_aggregator_node_consumes_topics_and_writes_topic_conclusions(tmp_path, monkeypatch):
    """aggregator 输入含主题摘要；p4_final_report 摘要结构携带主题结论要点。"""
    monkeypatch.chdir(tmp_path)
    project = "agg_proj"
    _write_board_summary(project, "topics/init_config_decrypt", {
        "worker": "topic_analyzer", "topic": "init_config_decrypt",
        "summary": "配置经单字节异或解密，密钥 0x5A",
        "key_findings": ["异或密钥 0x5A 解出 C2 域名"],
        "confidence": "high", "unresolved_count": 0,
    })

    model = _RecordingChatModel(reply=_AGG_REPLY)
    node = make_aggregator_node(llm=model)
    result = asyncio.run(node({"sample_project_name": project, "shard_reports": []}))

    assert result["final_report_ref"] == "bb://summary/p4_final_report"
    assert '"topic_summaries"' in model.recorded[0]
    assert "异或密钥 0x5A" in model.recorded[0]
    with open(
        os.path.join(board_base_dir(), project, "summary", "p4_final_report.json"),
        encoding="utf-8",
    ) as f:
        final = json.load(f)
    assert final["topic_conclusions"] == [
        "command_dispatcher: switch-case 分发，已还原 1 条命令"
    ]


_NINE_CHAPTER_REPLY = (
    "# 恶意样本综合参考手册：report_proj\n\n"
    "## 1. 样本概览\n\n- 无数据（缺 phase0_summary）\n\n本章置信度：low\n\n"
    "## 2. 完整执行流程图\n\n无数据（缺 behavior_profile.execution_chain_skeleton）\n\n"
    "## 3. 操作能力矩阵（驻留 / 持久化 / 注入 / 窃取 / C2）\n\n无数据（缺 topic_summaries）\n\n"
    "## 4. 关键函数速查表\n\n无数据\n\n"
    "## 5. 动态分析断点指南\n\n无数据（缺 behavior_profile.breakpoint_matrix）\n\n"
    "## 6. 内存中的关键全局变量\n\n未发现（global_var_candidates 为空）\n\n"
    "## 7. C2 与配置提取方法\n\n无数据\n\n"
    "## 8. IoC 指标汇总\n\n无数据\n\n"
    "## 9. 调试注意事项（反调试对抗 / 特殊结构 / 日志清理）\n\n无数据\n"
)


def test_report_generator_node_consumes_topics_and_breakpoint_matrix(tmp_path, monkeypatch):
    """report_generator 上下文含主题摘要、state 原文的 breakpoint_matrix 与 orchestrator_report。"""
    monkeypatch.chdir(tmp_path)
    project = "report_proj"
    _write_board_summary(project, "topics/stealer", {
        "worker": "topic_analyzer", "topic": "stealer",
        "summary": "窃取浏览器保存的密码", "key_findings": ["读取 Login Data"],
        "confidence": "medium", "unresolved_count": 0,
    })

    model = _RecordingChatModel(reply=_NINE_CHAPTER_REPLY)
    node = make_report_generator_node(llm=model)
    asyncio.run(node({
        "sample_project_name": project,
        "behavior_profile": {
            "breakpoint_matrix": {
                "p0": [{"location": "sub_401000 入口", "purpose": "观察解密密钥",
                        "address_hint": "0x401000"}],
                "p1": [], "p2": [],
            },
        },
        "orchestrator_report": {"status": "success", "counts": {"gaps": 0}},
        "shard_reports": [],
    }))

    user_msg = model.recorded[0]
    # 章 3 数据源：主题摘要
    assert '"topic_summaries"' in user_msg
    assert "窃取浏览器保存的密码" in user_msg
    # 章 5 数据源：behavior_profile 的 breakpoint_matrix 直接消费（state 原文优先）
    assert '"breakpoint_matrix"' in user_msg
    assert "观察解密密钥" in user_msg
    # 章 4 数据源：orchestrator 质量编排报告
    assert '"orchestrator_report"' in user_msg


def test_report_generator_node_injects_user_md_special_requirements(tmp_path, monkeypatch):
    """USER.md 的 focus/已回答问题拼接进报告 prompt（影响章节详略）。"""
    monkeypatch.chdir(tmp_path)
    project = "report_proj"
    docs = os.path.join(board_base_dir(), "docs", project)
    os.makedirs(docs, exist_ok=True)
    with open(os.path.join(docs, "USER.md"), "w", encoding="utf-8") as f:
        f.write(
            "# 用户沟通记录：report_proj\n\n"
            "## Agent 的疑惑与待确认问题\n\n（暂无）\n\n"
            "## 用户着重关心的内容\n\n重点关注 C2 配置提取；驻留分析不需要展开\n"
        )

    model = _RecordingChatModel(reply=_NINE_CHAPTER_REPLY)
    node = make_report_generator_node(llm=model)
    asyncio.run(node({"sample_project_name": project, "shard_reports": []}))

    assert "【用户特殊要求" in model.recorded[0]
    assert "重点关注 C2 配置提取" in model.recorded[0]


def test_report_generator_node_includes_preclassified_iocs_and_fallback_funcs(
    tmp_path, monkeypatch
):
    """章 7/8 数据源：预提取分类产物（截断明细）与反编译失败函数列表进入上下文。"""
    monkeypatch.chdir(tmp_path)
    project = "report_proj"
    board = os.path.join(board_base_dir(), project)
    os.makedirs(os.path.join(board, "extracts"), exist_ok=True)
    with open(os.path.join(board, "extracts", "strings_categorized.json"), "w",
              encoding="utf-8") as f:
        json.dump({
            "total_count": 3,
            "category_counts": {"urls": 1},
            "categories": {
                "urls": {"count": 1, "items": [{"text": "http://evil.example/c2",
                                                "address": "00402000"}]},
            },
        }, f, ensure_ascii=False)
    with open(os.path.join(board, "extracts", "functions_extract.json"), "w",
              encoding="utf-8") as f:
        json.dump({
            "total_count": 2, "chunk_size": 100, "chunks": 1,
            "functions": [
                {"name": "sub_401000", "address": "0x401000", "type": "decompile"},
                {"name": "sub_402000", "address": "0x402000",
                 "type": "disassembly-fallback"},
            ],
        }, f, ensure_ascii=False)

    model = _RecordingChatModel(reply=_NINE_CHAPTER_REPLY)
    node = make_report_generator_node(llm=model)
    asyncio.run(node({"sample_project_name": project, "shard_reports": []}))

    user_msg = model.recorded[0]
    # 章 8 数据源：Phase -1 确定性分类产物（零 token，每类截断）
    assert '"preclassified_iocs"' in user_msg
    assert "http://evil.example/c2" in user_msg
    # 章 7 数据源：反编译失败函数（全量扫描 functions_extract，不受 100 条分片限制）
    assert '"decompile_failed_functions"' in user_msg
    assert "0x402000" in user_msg
    assert "0x401000" not in user_msg.split('"decompile_failed_functions"')[1]


def test_collect_global_var_candidates(tmp_path, monkeypatch):
    """章 6 数据源：从主题 artifact 与函数摘要中机器预扫描 g_ 变量（按名去重、含来源）。"""
    monkeypatch.chdir(tmp_path)
    project = "gvar_proj"
    bb_write_artifact("topic_stealer", {
        "status": "success", "topic": "stealer",
        "evidence": [{"address": "0x401000", "snippet": "g_config_key = buf;",
                      "source": "decompile"}],
    }, project)
    _write_board_summary(project, "phase3_funcs/func_0x402000", {
        "func_addr": "0x402000", "analysis_notes": "写入 g_config_key 与 g_session_flag",
    })

    candidates = _collect_global_var_candidates(project)
    by_name = {c["name"]: c["source"] for c in candidates}
    assert by_name["g_config_key"] == "topic_stealer"  # 首个来源保留
    assert by_name["g_session_flag"] == "phase3_funcs"

    # 无产物时返回空列表（报告据此标"未发现"而非编造）
    assert _collect_global_var_candidates("empty_proj") == []


def test_report_generator_node_nine_chapters_match_benchmark(tmp_path, monkeypatch):
    """空数据兜底：无主题/无摘要时仍生成 9 章齐全的最小手册（各章标注缺口），
    且 benchmark compare 的章节结构维度满分。"""
    result = _run_report_node(tmp_path, monkeypatch, _NINE_CHAPTER_REPLY)
    with open(result["report_md_path"], encoding="utf-8") as f:
        report_text = f.read()

    for chapter in [
        "## 1. 样本概览", "## 2. 完整执行流程图", "## 3. 操作能力矩阵",
        "## 4. 关键函数速查表", "## 5. 动态分析断点指南", "## 6. 内存中的关键全局变量",
        "## 7. C2 与配置提取方法", "## 8. IoC 指标汇总", "## 9. 调试注意事项",
    ]:
        assert chapter in report_text, chapter
    # 缺口标注而非删章
    assert "未发现" in report_text

    benchmark_result = compare("", report_text)
    assert benchmark_result["chapters"]["recall"] == 1.0
    assert benchmark_result["chapters"]["missing"] == []
