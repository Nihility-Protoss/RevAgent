"""docs 归档层 + USER.md 异步沟通通道（tools/docs_tools.py）测试。

覆盖：AGENT_XX 五要素渲染与落盘、docs_read_agent_reports 冷启动恢复、
USER.md 骨架自动创建、编号问题追加、"用户回答："代码块读写（追加语义）。
全部在 tmp_path 下进行（fixture 已 chdir），不污染仓库。
"""
import os
import re

import pytest

from tools.blackboard_tools import board_base_dir
from tools.docs_tools import (
    docs_dir,
    docs_read_agent_reports,
    docs_write_agent_report,
    user_md_append_answer,
    user_md_append_question,
    user_md_read,
)

PROJECT = "docs_case"

TOPIC_PAYLOAD = {
    "status": "success",
    "topic": "command_dispatcher",
    "summary": "命令分发器：switch-case 逐条分发，已还原 1 条命令语义",
    "findings": [
        {"subject": "cmd 0x06", "conclusion": "截屏回传", "confidence": "medium"},
    ],
    "evidence": [
        {"address": "0x401000", "snippet": "switch (cmd_id)", "source": "decompile"},
    ],
    "confidence": "medium",
    "unresolved": ["cmd 0x09 语义需动态验证"],
}

FUNC_PAYLOAD = {
    "func_addr": "0x404000",
    "func_name": "sub_404000",
    "status": "success",
    "functionality": "network_init",
    "key_apis": ["WSAStartup"],
    "suspicious_behaviors": ["C2 connect"],
    "related_functions": [],
    "confidence": "medium",
    "analysis_notes": "测试备注",
}


@pytest.fixture
def board(tmp_path, monkeypatch):
    """隔离黑板：chdir 到临时目录，docs 落在 {tmp}/data/output/docs/ 下。"""
    monkeypatch.chdir(tmp_path)
    return tmp_path


# === AGENT_XX 五要素归档 =====================================================

def test_write_agent_report_topic_payload_five_elements(board):
    """主题产物渲染为五要素 Markdown：分析对象/执行时间/分析结论/关键引用/未解之谜。"""
    result = docs_write_agent_report(PROJECT, 1, "command_dispatcher", TOPIC_PAYLOAD)
    assert result["status"] == "success"
    assert result["filename"] == "AGENT_01_command_dispatcher.md"
    assert os.path.exists(result["path"])
    # docs 目录跟随黑板 output_root（不另起配置）
    assert docs_dir(PROJECT) == os.path.join(board_base_dir(), "docs", PROJECT)

    with open(result["path"], encoding="utf-8") as f:
        content = f.read()
    for section in ["## 分析对象", "## 执行时间", "## 分析结论", "## 关键引用", "## 未解之谜"]:
        assert section in content, section
    # 五要素内容搬运自产物原文
    assert "命令分发器：switch-case 逐条分发" in content
    assert "cmd 0x06" in content and "截屏回传" in content
    assert "0x401000" in content and "switch (cmd_id)" in content
    assert "cmd 0x09 语义需动态验证" in content


def test_write_agent_report_function_payload(board):
    """函数产物（functionality/key_apis/suspicious_behaviors）也能渲染归档。"""
    result = docs_write_agent_report(PROJECT, 7, "func_0x404000", FUNC_PAYLOAD)
    assert result["status"] == "success"
    assert result["filename"] == "AGENT_07_func_0x404000.md"
    with open(result["path"], encoding="utf-8") as f:
        content = f.read()
    assert "network_init" in content
    assert "WSAStartup" in content and "C2 connect" in content
    assert "0x404000" in content  # 分析对象段归集函数地址


def test_write_agent_report_rejects_non_dict(board):
    """非 dict 产物返回 error，不抛异常。"""
    result = docs_write_agent_report(PROJECT, 1, "x", "not a dict")
    assert result["status"] == "error"


def test_read_agent_reports_roundtrip(board):
    """docs_read_agent_reports 按序号列出并读取已有报告（冷启动恢复）。"""
    # 目录不存在时返回空列表而不是报错
    empty = docs_read_agent_reports(PROJECT)
    assert empty["status"] == "success" and empty["reports"] == []

    docs_write_agent_report(PROJECT, 1, "stealer", TOPIC_PAYLOAD)
    docs_write_agent_report(PROJECT, 2, "func_0x401000", FUNC_PAYLOAD)
    result = docs_read_agent_reports(PROJECT)
    assert result["status"] == "success"
    assert result["count"] == 2
    assert [r["seq"] for r in result["reports"]] == [1, 2]
    assert [r["topic"] for r in result["reports"]] == ["stealer", "func_0x401000"]
    assert "## 分析结论" in result["reports"][0]["content"]


def test_agent_report_filename_sanitized(board):
    """主题名含 Windows 文件名禁用字符/空白时净化为安全文件名。"""
    result = docs_write_agent_report(PROJECT, 3, 'a/b:c d', TOPIC_PAYLOAD)
    assert result["status"] == "success"
    assert result["filename"] == "AGENT_03_a_b_c_d.md"


# === USER.md 异步沟通文档 =====================================================

def test_user_md_skeleton_created_on_first_append(board):
    """首次追加问题时自动建骨架：两段式（编号问题 + "用户着重关心的内容"空段）。"""
    result = user_md_append_question(PROJECT, "加壳方式待确认", "样本疑似 UPX 加壳，请确认是否先脱壳。")
    assert result["status"] == "success"
    assert result["question_no"] == 1

    read = user_md_read(PROJECT)
    assert read["status"] == "success"
    content = read["content"]
    assert "## Agent 的疑惑与待确认问题" in content
    assert "## 用户着重关心的内容" in content
    # 金标准格式：编号问题 + 正文 + "用户回答："代码块
    assert "1. 加壳方式待确认" in content
    assert "样本疑似 UPX 加壳" in content
    assert re.search(r"```\n用户回答：\n```", content)


def test_user_md_question_numbering_increments(board):
    """问题编号按已有最大值 +1 递增。"""
    user_md_append_question(PROJECT, "问题一", "正文一")
    r2 = user_md_append_question(PROJECT, "问题二", "正文二")
    assert r2["question_no"] == 2
    read = user_md_read(PROJECT)
    assert [q["no"] for q in read["questions"]] == [1, 2]
    assert read["questions"][0]["answered"] is False


def test_user_md_append_answer_and_read_back(board):
    """用户回答写入"用户回答："代码块；user_md_read 解析出 answered 状态。"""
    user_md_append_question(PROJECT, "C2 协议确认", "上线包疑似 HTTP，请确认。")
    result = user_md_append_answer(PROJECT, 1, "确认是 HTTP，端口 8443。")
    assert result["status"] == "success"

    read = user_md_read(PROJECT)
    q = read["questions"][0]
    assert q["answered"] is True
    assert q["answer"] == "确认是 HTTP，端口 8443。"
    # 回答确实落在"用户回答："代码块内
    assert re.search(r"```\n用户回答：\n确认是 HTTP，端口 8443。\n```", read["content"])


def test_user_md_append_answer_appends_history(board):
    """同一问题重复回答：保留历史，以分隔线追加（追加语义）。"""
    user_md_append_question(PROJECT, "标题", "正文")
    user_md_append_answer(PROJECT, 1, "第一次回答")
    user_md_append_answer(PROJECT, 1, "第二次补充")
    read = user_md_read(PROJECT)
    answer = read["questions"][0]["answer"]
    assert "第一次回答" in answer and "第二次补充" in answer
    assert "---" in answer


def test_user_md_append_answer_unknown_question(board):
    """编号不存在时返回 error（question_not_found），不改文件。"""
    user_md_append_question(PROJECT, "标题", "正文")
    result = user_md_append_answer(PROJECT, 99, "回答")
    assert result["status"] == "error"
    assert result["reason"] == "question_not_found"


def test_user_md_append_answer_rejects_empty(board):
    """空回答直接拒绝。"""
    user_md_append_question(PROJECT, "标题", "正文")
    assert user_md_append_answer(PROJECT, 1, "   ")["reason"] == "empty_answer"


def test_user_md_read_auto_creates_skeleton(board):
    """读取不存在的 USER.md 时自动建骨架，问题列表为空。"""
    read = user_md_read(PROJECT)
    assert read["status"] == "success"
    assert read["questions"] == []
    assert read["focus"] == ""
    assert os.path.exists(read["path"])


def test_user_md_focus_section_parsed(board, tmp_path):
    """"用户着重关心的内容"段的文本可被解析出来（供 prompt 注入）。"""
    read0 = user_md_read(PROJECT)  # 触发骨架
    with open(read0["path"], encoding="utf-8") as f:
        content = f.read()
    with open(read0["path"], "w", encoding="utf-8") as f:
        f.write(content.replace(
            "## 用户着重关心的内容\n\n（暂无）",
            "## 用户着重关心的内容\n\n只关心动调断点位置",
        ))
    read = user_md_read(PROJECT)
    assert read["focus"] == "只关心动调断点位置"
