"""orchestrator_node（Phase 3 后置质量编排，纯代码不调 LLM）+ USER.md prompt 注入测试。

覆盖：AGENT_XX 归档与序号分配、五要素质量检查（quality_failed 标记）、
缺口识别（meta/gap_report.json）、矛盾发现启发式（→ USER.md 待确认问题）、
节点幂等、空 manifest 直通、主题节点 prompt 注入 USER.md 已回答问题。
全部在 tmp_path 下进行（fixture 已 chdir），不消耗真实 API token。
"""
import asyncio
import json
import os

import pytest
from langchain_core.messages import AIMessage

from graph_nodes import (
    _load_user_special_requirements,
    make_topic_node,
    orchestrator_node,
)
from tools.blackboard_tools import bb_write_artifact, board_path
from tools.docs_tools import docs_dir, user_md_append_answer, user_md_append_question, user_md_read

PROJECT = "orch_case"

TOPIC_PAYLOAD = {
    "status": "success",
    "topic": "stealer",
    "summary": "窃取浏览器凭据",
    "findings": [{"subject": "浏览器密码", "conclusion": "读取 Login Data", "confidence": "high"}],
    "evidence": [{"address": "0x401000", "snippet": "Login Data", "source": "strings"}],
    "confidence": "high",
    "unresolved": ["打包格式未知"],
}

FUNC_PAYLOAD = {
    "func_addr": "0x404000", "func_name": "sub_404000", "status": "success",
    "functionality": "network_init", "key_apis": ["WSAStartup"],
    "suspicious_behaviors": ["C2 connect"], "related_functions": [],
    "confidence": "medium", "analysis_notes": "test",
}


@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _topic_task(topic: str, addrs=None, depends_on=None) -> dict:
    return {
        "task_id": f"topic_{topic}", "kind": "topic", "topic": topic,
        "function_addrs": addrs or [], "depends_on": depends_on or [],
        "output_doc": "", "status": "pending",
    }


def _func_task(addr: str) -> dict:
    return {
        "task_id": f"func_{addr}", "kind": "function", "topic": None,
        "function_addrs": [addr], "depends_on": [], "output_doc": "", "status": "pending",
    }


def _state(tasks) -> dict:
    return {
        "sample_project_name": PROJECT,
        "sample_export_dir": "x",
        "task_manifest": {"tasks": tasks},
    }


# === 归档与计数 ===============================================================

def test_orchestrator_archives_reports_and_counts(board):
    """主题 + 函数产物按 manifest 顺序归档为 AGENT_XX，计数写入 orchestrator_report。"""
    bb_write_artifact("topic_stealer", TOPIC_PAYLOAD, PROJECT)
    bb_write_artifact("phase3_func_0x404000", FUNC_PAYLOAD, PROJECT)

    result = orchestrator_node(_state([_topic_task("stealer", ["0x401000"]), _func_task("0x404000")]))
    report = result["orchestrator_report"]

    assert report["status"] == "success"
    assert report["counts"] == {
        "docs_written": 2, "quality_failed": 0, "gaps": 0, "contradictions": 0,
    }
    assert os.path.exists(os.path.join(docs_dir(PROJECT), "AGENT_01_stealer.md"))
    assert os.path.exists(os.path.join(docs_dir(PROJECT), "AGENT_02_func_0x404000.md"))
    # 缺口报告始终落盘（无缺口时 gaps 为空）
    with open(board_path(PROJECT, "meta", "gap_report.json"), encoding="utf-8") as f:
        gap = json.load(f)
    assert gap["gaps"] == [] and gap["total_tasks"] == 2


def test_orchestrator_manifest_fallback_from_disk(board):
    """state 无 task_manifest 时回退读 meta/task_manifest.json（dispatch 已落盘）。"""
    bb_write_artifact("topic_stealer", TOPIC_PAYLOAD, PROJECT)
    meta_dir = board_path(PROJECT, "meta")
    os.makedirs(meta_dir, exist_ok=True)
    with open(os.path.join(meta_dir, "task_manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"tasks": [_topic_task("stealer")]}, f, ensure_ascii=False)

    result = orchestrator_node({"sample_project_name": PROJECT, "sample_export_dir": "x"})
    assert result["orchestrator_report"]["counts"]["docs_written"] == 1


def test_orchestrator_empty_manifest(board):
    """空任务清单（dispatch 直通场景）：节点正常执行，全部计数为 0。"""
    result = orchestrator_node(_state([]))
    report = result["orchestrator_report"]
    assert report["status"] == "success"
    assert report["counts"] == {
        "docs_written": 0, "quality_failed": 0, "gaps": 0, "contradictions": 0,
    }
    # 空清单也落 gap_report.json（记录本次检查发生）
    assert os.path.exists(board_path(PROJECT, "meta", "gap_report.json"))


# === 五要素质量检查 ============================================================

def test_orchestrator_quality_check_flags_missing_fields(board):
    """主题产物缺 findings/evidence → quality_failed 标记（不阻断归档，不重试）。"""
    bad = {"status": "success", "topic": "stealer", "summary": "有结论但无条目"}
    bb_write_artifact("topic_stealer", bad, PROJECT)

    report = orchestrator_node(_state([_topic_task("stealer")]))["orchestrator_report"]
    assert report["counts"]["quality_failed"] == 1
    assert report["quality_failed"][0]["task_id"] == "topic_stealer"
    assert set(report["quality_failed"][0]["missing"]) == {"findings", "evidence"}
    # 质量失败只标记：产物仍归档（docs 完整），重试留给后续批次
    assert report["counts"]["docs_written"] == 1


def test_orchestrator_quality_exempts_insufficient_data(board):
    """status=insufficient_data 是合法结论（数据不足），豁免质量检查。"""
    bb_write_artifact("topic_stealer", {"status": "insufficient_data", "topic": "stealer"}, PROJECT)
    report = orchestrator_node(_state([_topic_task("stealer")]))["orchestrator_report"]
    assert report["counts"]["quality_failed"] == 0
    assert report["counts"]["docs_written"] == 1


def test_orchestrator_quality_check_function_payload(board):
    """函数产物的"关键引用"对应 suspicious_behaviors/key_apis，全空算缺 evidence。"""
    bad = {"status": "success", "func_addr": "0x404000"}  # 无 functionality/行为/API
    bb_write_artifact("phase3_func_0x404000", bad, PROJECT)
    report = orchestrator_node(_state([_func_task("0x404000")]))["orchestrator_report"]
    assert report["counts"]["quality_failed"] == 1
    assert set(report["quality_failed"][0]["missing"]) == {"conclusion", "evidence"}


# === 缺口识别 ==================================================================

def test_orchestrator_gap_report(board):
    """manifest 有任务但 artifact 缺失 → 记入 meta/gap_report.json 与报告计数。"""
    bb_write_artifact("topic_stealer", TOPIC_PAYLOAD, PROJECT)
    state = _state([_topic_task("stealer", ["0x401000"]), _func_task("0x404000")])

    report = orchestrator_node(state)["orchestrator_report"]
    assert report["counts"]["gaps"] == 1
    assert report["gaps"][0] == {
        "task_id": "func_0x404000", "kind": "function",
        "artifact": "phase3_func_0x404000", "reason": "artifact_missing",
    }
    with open(board_path(PROJECT, "meta", "gap_report.json"), encoding="utf-8") as f:
        on_disk = json.load(f)
    assert on_disk["gaps"] == report["gaps"]


# === 矛盾发现（启发式） ==========================================================

def _topic_payload(topic: str, conclusion: str, summary: str, addr: str = "0x401000") -> dict:
    return {
        "status": "success", "topic": topic, "summary": summary,
        "findings": [{"subject": f"sub ({addr})", "conclusion": conclusion, "confidence": "medium"}],
        "evidence": [{"address": addr, "snippet": "xor eax", "source": "decompile"}],
        "confidence": "medium", "unresolved": [],
    }


def test_orchestrator_contradiction_goes_to_user_md(board):
    """两主题对同一函数地址的判定类别不相交（解密 vs 网络）→ USER.md 待确认问题。"""
    bb_write_artifact("topic_init_config_decrypt", _topic_payload(
        "init_config_decrypt", "完成配置解密（XOR 密钥）", "初始化与配置解密"), PROJECT)
    bb_write_artifact("topic_network_stack", _topic_payload(
        "network_stack", "负责网络回连 HTTP 请求", "网络通信栈"), PROJECT)
    state = _state([_topic_task("init_config_decrypt"), _topic_task("network_stack")])

    report = orchestrator_node(state)["orchestrator_report"]
    assert report["counts"]["contradictions"] == 1
    c = report["contradictions"][0]
    assert c["address"] == "0x401000"
    assert {c["topic_a"], c["topic_b"]} == {"init_config_decrypt", "network_stack"}
    assert c["categories_a"] == ["解密"] and c["categories_b"] == ["网络"]

    # 矛盾已写入 USER.md 编号问题（异步提请用户确认）
    read = user_md_read(PROJECT)
    assert len(read["questions"]) == 1
    assert "矛盾确认" in read["questions"][0]["title"]
    assert "0x401000" in read["questions"][0]["title"]
    assert read["questions"][0]["answered"] is False


def test_orchestrator_contradiction_not_reported_when_categories_overlap(board):
    """类别集相交（都提到"网络"）或一侧无类别时不报矛盾（保守规则）。"""
    bb_write_artifact("topic_network_stack", _topic_payload(
        "network_stack", "网络回连", "网络通信栈"), PROJECT)
    bb_write_artifact("topic_stealer", _topic_payload(
        "stealer", "窃取后经网络回传", "信息窃取与网络外传"), PROJECT)
    state = _state([_topic_task("network_stack"), _topic_task("stealer")])
    report = orchestrator_node(state)["orchestrator_report"]
    assert report["counts"]["contradictions"] == 0


def test_orchestrator_idempotent(board):
    """重跑幂等：同对象不重复归档（seq 不翻倍），USER.md 同标题问题不重复。"""
    bb_write_artifact("topic_init_config_decrypt", _topic_payload(
        "init_config_decrypt", "完成配置解密（XOR）", "初始化与配置解密"), PROJECT)
    bb_write_artifact("topic_network_stack", _topic_payload(
        "network_stack", "负责网络回连 HTTP", "网络通信栈"), PROJECT)
    state = _state([_topic_task("init_config_decrypt"), _topic_task("network_stack")])

    orchestrator_node(state)
    report2 = orchestrator_node(state)["orchestrator_report"]
    assert report2["counts"]["docs_written"] == 0  # 已归档对象跳过
    assert len(user_md_read(PROJECT)["questions"]) == 1  # 同标题去重


# === USER.md 回答注入主题 prompt ===============================================

def test_load_user_special_requirements(board):
    """_load_user_special_requirements：只拼接已回答问题与重点关注段。"""
    assert _load_user_special_requirements(PROJECT) == ""  # 无 USER.md → 空

    user_md_append_question(PROJECT, "未答问题", "还没回答")
    assert _load_user_special_requirements(PROJECT) == ""  # 未回答不注入

    user_md_append_answer(PROJECT, 1, "这是用户的回答")
    text = _load_user_special_requirements(PROJECT)
    assert "这是用户的回答" in text
    assert "未答问题" in text  # 标题随回答一起注入，供模型理解上下文


class _PromptRecorder:
    """记录 prompt 原文的假模型：主题调用返回固定 TopicAnalysis，其余当 extractor。"""

    def __init__(self):
        self.prompts: list[str] = []

    async def ainvoke(self, messages, config=None):
        text = "\n".join(getattr(m, "content", "") or "" for m in messages)
        self.prompts.append(text)
        if "主题分析专家" in text:
            return AIMessage(content=json.dumps({
                "status": "success", "topic": "stealer", "summary": "结论",
                "findings": [{"subject": "x", "conclusion": "y", "confidence": "low"}],
                "evidence": [{"address": "0x401000", "snippet": "s", "source": "decompile"}],
                "confidence": "low", "unresolved": [],
            }, ensure_ascii=False))
        return AIMessage(content=json.dumps({
            "worker": "extractor_topic", "key_findings": [], "confidence": "low",
        }, ensure_ascii=False))


def test_topic_node_injects_user_md_answers(board):
    """主题节点构建 prompt 前读 USER.md：已回答内容进入"特殊要求"段。"""
    user_md_append_question(PROJECT, "加壳确认", "样本是否已脱壳？")
    user_md_append_answer(PROJECT, 1, "已脱壳，直接分析。")

    fake = _PromptRecorder()
    node = make_topic_node(fake)
    result = asyncio.run(node({
        "sample_project_name": PROJECT,
        "sample_export_dir": "x",  # 无反编译文件也能走流程（snippet 为 None）
        "analysis_task": {
            "task_id": "topic_stealer", "kind": "topic", "topic": "stealer",
            "function_addrs": ["0x401000"], "depends_on": [],
        },
    }))

    topic_prompt = fake.prompts[0]
    assert "特殊要求" in topic_prompt
    assert "已脱壳，直接分析。" in topic_prompt
    assert "加壳确认" in topic_prompt
    assert result["topic_analysis_refs"][0]["topic"] == "stealer"


def test_topic_node_without_user_md_has_no_special_section(board):
    """无 USER.md 内容时 prompt 不含"特殊要求"段（保持原样）。"""
    fake = _PromptRecorder()
    node = make_topic_node(fake)
    asyncio.run(node({
        "sample_project_name": PROJECT,
        "sample_export_dir": "x",
        "analysis_task": {
            "task_id": "topic_stealer", "kind": "topic", "topic": "stealer",
            "function_addrs": ["0x401000"], "depends_on": [],
        },
    }))
    assert "特殊要求" not in fake.prompts[0]
