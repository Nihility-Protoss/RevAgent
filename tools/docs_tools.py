"""docs 归档层 + USER.md 异步沟通通道（对齐金标准人工协作 Skill）。

金标准的核心机制是"一切交流落盘归档"：

- ``docs/{project}/AGENT_XX_{主题}.md``：五要素结论归档
  （分析对象 / 执行时间 / 分析结论 / 关键引用 / 未解之谜）；
- ``docs/{project}/USER.md``：异步人机沟通文档——Agent 运行中把疑惑/矛盾/
  深度边界问题写入编号列表（**不阻塞执行流**），用户随时在对应问题的
  "用户回答："代码块中填入回答，Agent 下次读取时获取。

docs 根目录跟随黑板 output_root（``{output_root}/docs/{project}/``，黑板根的
平级子目录），不另起配置。所有函数统一返回 ``{"status": "success"|"error", ...}``，
不向调用方抛异常。
"""
import os
import re
from typing import Optional

from tools.blackboard_tools import _now_iso, board_base_dir


def docs_dir(project_name: str) -> str:
    """docs 归档目录：{output_root}/docs/{project}/。"""
    return os.path.join(board_base_dir(), "docs", project_name)


# === AGENT_XX 五要素结论归档 ===============================================

# Windows 文件名禁用字符 + 空白（主题词含中文没问题，只需剔除路径保留字）
_FILENAME_BAD_CHARS = re.compile(r'[\\/:*?"<>|\s]+')

# 产物文本中的函数地址（0x 开头十六进制），用于"分析对象"段的地址归集
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")

_AGENT_FILE_RE = re.compile(r"^AGENT_(\d+)_(.+)\.md$")


def _safe_filename(text: str) -> str:
    """主题/对象名转文件名片段：剔除 Windows 禁用字符，空白折叠为下划线。"""
    return _FILENAME_BAD_CHARS.sub("_", str(text)).strip("_") or "untitled"


def _render_agent_report(seq: int, topic_or_subject: str, payload: dict) -> str:
    """把主题/函数分析产物渲染为五要素 Markdown。

    产物结构因轨而异（主题产物 TopicAnalysis：summary/findings/evidence/unresolved；
    函数产物：functionality/key_apis/suspicious_behaviors/analysis_notes），渲染按
    字段优先级逐个提取，缺席要素以"（无）"占位——只搬运产物内容，不编造。
    """
    status = payload.get("status", "success")
    conclusion = (
        payload.get("summary")
        or payload.get("functionality")
        or payload.get("overall_assessment")
        or ""
    )
    confidence = payload.get("confidence") or ""

    # 分析对象：主题/对象名 + 产物中可识别的函数地址（evidence.address / func_addr）
    addrs = set(_ADDR_RE.findall(str(payload.get("func_addr") or "")))
    for ev in payload.get("evidence") or []:
        if isinstance(ev, dict):
            addrs.update(_ADDR_RE.findall(str(ev.get("address") or "")))
    for f in payload.get("findings") or []:
        if isinstance(f, dict):
            addrs.update(_ADDR_RE.findall(str(f.get("subject") or "")))

    lines = [
        f"# AGENT_{seq:02d} {topic_or_subject}",
        "",
        "> 本文件由 orchestrator 节点自动归档（对齐金标准五要素格式；"
        "结构化原文见黑板 artifacts/）。",
        "",
        "## 分析对象",
        "",
        f"- 主题/对象：{topic_or_subject}",
    ]
    if addrs:
        lines.append(f"- 涉及函数：{', '.join(sorted(addrs))}")
    lines += [
        "",
        "## 执行时间",
        "",
        _now_iso(),
        "",
        "## 分析结论",
        "",
    ]
    if status == "insufficient_data":
        lines.append(
            "**数据不足（insufficient_data）**："
            + (payload.get("reason") or conclusion or "（无结论）")
        )
    else:
        head = conclusion or "（无结论）"
        if confidence:
            head = f"{head}（置信度：{confidence}）"
        lines.append(head)
    notes = payload.get("analysis_notes")
    if notes:
        lines += ["", f"补充说明：{notes}"]

    findings = [f for f in (payload.get("findings") or []) if isinstance(f, dict)]
    if findings:
        lines += ["", "### 逐条目发现", ""]
        for i, f in enumerate(findings, 1):
            conf = f.get("confidence")
            conf_text = f"（置信度：{conf}）" if conf else ""
            lines.append(
                f"{i}. **{f.get('subject') or '（未命名对象）'}**{conf_text}："
                f"{f.get('conclusion') or ''}"
            )

    # 函数轨产物没有 findings/evidence 列表，其行为/API 清单单列一段
    suspicious = payload.get("suspicious_behaviors") or []
    key_apis = payload.get("key_apis") or []
    if suspicious or key_apis:
        lines += ["", "### 可疑行为与关键 API", ""]
        for b in suspicious:
            lines.append(f"- 可疑行为：{b}")
        for a in key_apis:
            lines.append(f"- 关键 API：{a}")

    lines += ["", "## 关键引用", ""]
    evidence = [e for e in (payload.get("evidence") or []) if isinstance(e, dict)]
    if evidence:
        for e in evidence:
            lines.append(
                f"- `{e.get('address') or '?'}`（{e.get('source') or '未知来源'}）："
            )
            lines += ["", "  ```"]
            lines += ["  " + l for l in str(e.get("snippet") or "").splitlines()]
            lines += ["  ```", ""]
    else:
        lines.append("（无）")

    lines += ["", "## 未解之谜", ""]
    unresolved = payload.get("unresolved") or []
    if unresolved:
        for u in unresolved:
            lines.append(f"- {u}")
    else:
        lines.append("（无）")
    return "\n".join(lines) + "\n"


def docs_write_agent_report(
    project_name: str, seq: int, topic_or_subject: str, payload: dict
) -> dict:
    """把一份主题/函数分析产物渲染为五要素 Markdown，落盘
    ``docs/{project}/AGENT_{seq:02d}_{主题}.md``。

    Args:
        project_name: 黑板项目名。
        seq: 归档序号（文件名中的 XX，调用方负责递增分配）。
        topic_or_subject: 主题词或对象名（函数轨约定为 ``func_{addr}``）。
        payload: 分析产物 dict（主题 TopicAnalysis dump 或函数分析输出）。
    """
    if not isinstance(payload, dict):
        return {"status": "error", "reason": "payload_not_dict"}
    fname = f"AGENT_{seq:02d}_{_safe_filename(topic_or_subject)}.md"
    os.makedirs(docs_dir(project_name), exist_ok=True)
    path = os.path.join(docs_dir(project_name), fname)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(_render_agent_report(seq, topic_or_subject, payload))
        return {"status": "success", "path": path, "filename": fname, "seq": seq}
    except Exception as e:
        return {"status": "error", "reason": "write_error", "error": str(e)}


def docs_read_agent_reports(project_name: str) -> dict:
    """列出并读取 docs/{project}/ 下已有的 AGENT_XX 报告（冷启动恢复用）。

    目录不存在时返回空列表（status=success，不视为错误）。
    """
    d = docs_dir(project_name)
    if not os.path.isdir(d):
        return {"status": "success", "reports": [], "count": 0}
    reports = []
    for fname in sorted(os.listdir(d)):
        m = _AGENT_FILE_RE.match(fname)
        if not m:
            continue
        path = os.path.join(d, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            continue  # 单个文件读取失败不阻断整体恢复
        reports.append({
            "seq": int(m.group(1)),
            "topic": m.group(2),
            "filename": fname,
            "path": path,
            "content": content,
        })
    return {"status": "success", "reports": reports, "count": len(reports)}


# === USER.md 异步人机沟通文档 ==============================================

USER_MD_FILENAME = "USER.md"

_QUESTIONS_HEADER = "## Agent 的疑惑与待确认问题"
_FOCUS_HEADER = "## 用户着重关心的内容"
_EMPTY_PLACEHOLDER = "（暂无）"

# 骨架：两段式（编号问题列表 + 用户重点关注空段），对齐金标准格式规范
_USER_MD_SKELETON = """# 用户沟通记录：{project}

> 本文件是 Agent 与用户共同维护的异步沟通文档（对齐金标准 USER.md 机制）：
> Agent 运行中把疑惑、矛盾、深度边界问题写入下方编号列表，**不阻塞执行流**；
> 用户随时在对应问题的"用户回答："代码块中填入回答，Agent 下次读取时获取。

## Agent 的疑惑与待确认问题

（暂无）

## 用户着重关心的内容

（暂无）
"""

_QUESTION_RE = re.compile(r"^(\d+)\.\s+(.*)$")


def _user_md_path(project_name: str) -> str:
    return os.path.join(docs_dir(project_name), USER_MD_FILENAME)


def _ensure_user_md(project_name: str) -> str:
    """USER.md 不存在时建骨架（含"用户着重关心的内容"空段），返回路径。"""
    path = _user_md_path(project_name)
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(_USER_MD_SKELETON.format(project=project_name))
    return path


def _locate_sections(lines: list) -> tuple:
    """定位两个段落的起始行号：(questions_header_idx, focus_header_idx)，缺失为 None。"""
    q_start = f_start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(_QUESTIONS_HEADER):
            q_start = i
        elif stripped.startswith(_FOCUS_HEADER):
            f_start = i
    return q_start, f_start


def _question_block_ranges(lines: list, q_start: int, q_end: int) -> list:
    """在问题段行范围内找编号问题块，返回 [(start_idx, end_idx, no, title), ...]。"""
    starts = []
    for i in range(q_start + 1, q_end):
        m = _QUESTION_RE.match(lines[i].strip())
        if m:
            starts.append((i, int(m.group(1)), m.group(2).strip()))
    ranges = []
    for idx, (start, no, title) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else q_end
        ranges.append((start, end, no, title))
    return ranges


def _find_answer_fence(block: list) -> tuple:
    """在问题块内找"用户回答："代码块的围栏位置，返回 (open_idx, close_idx)。

    格式约定（金标准）：开围栏行的下一行以"用户回答："开头，其余行为回答内容。
    找不到返回 (None, None)。
    """
    j = 0
    while j < len(block):
        if block[j].strip().startswith("```"):
            k = j + 1
            while k < len(block) and not block[k].strip().startswith("```"):
                k += 1
            inner = block[j + 1:k]
            if inner and inner[0].strip().startswith("用户回答"):
                return j, k
            j = k + 1 if k < len(block) else len(block)
        else:
            j += 1
    return None, None


def _parse_user_md(content: str) -> dict:
    """解析 USER.md：编号问题列表（含"用户回答："代码块）+ 重点关注段文本。"""
    lines = content.splitlines()
    q_start, f_start = _locate_sections(lines)
    q_end = f_start if f_start is not None else len(lines)

    questions = []
    if q_start is not None:
        for start, end, no, title in _question_block_ranges(lines, q_start, q_end):
            block = lines[start + 1:end]
            fence_open, fence_close = _find_answer_fence(block)
            answer = None
            body_lines = block
            if fence_open is not None:
                inner = block[fence_open + 1:fence_close]
                ans = "\n".join(inner[1:]).strip()  # inner[0] 是"用户回答："标记行
                answer = ans or None
                # 正文剔除回答代码块，只留问题描述
                body_lines = block[:fence_open] + block[fence_close + 1:]
            questions.append({
                "no": no,
                "title": title,
                "body": "\n".join(body_lines).strip(),
                "answer": answer,
                "answered": answer is not None,
            })

    focus = ""
    if f_start is not None:
        focus = "\n".join(lines[f_start + 1:]).strip()
        if focus == _EMPTY_PLACEHOLDER:
            focus = ""
    return {"questions": questions, "focus": focus}


def user_md_append_question(project_name: str, title: str, body: str) -> dict:
    """向 USER.md 的"疑惑与待确认问题"段追加一个编号问题（自动建骨架）。

    问题格式（对齐金标准）：``N. 标题`` + 正文 + 空的"用户回答："代码块。
    编号为已有最大编号 + 1；本函数不做同标题去重（策略由调用方负责）。
    """
    path = _ensure_user_md(project_name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        parsed = _parse_user_md(content)
        no = max((q["no"] for q in parsed["questions"]), default=0) + 1

        lines = content.splitlines()
        q_start, f_start = _locate_sections(lines)
        if q_start is None:
            # 段缺失（用户手改文件）：文末补回问题段，再在其内插入
            lines += ["", _QUESTIONS_HEADER, "", _EMPTY_PLACEHOLDER]
            q_start = len(lines) - 3
            f_start = None
        insert_at = f_start if f_start is not None else len(lines)

        # 段内只有"（暂无）"占位行时先清掉
        seg_nonempty = [l.strip() for l in lines[q_start + 1:insert_at] if l.strip()]
        if seg_nonempty == [_EMPTY_PLACEHOLDER]:
            del lines[q_start + 1:insert_at]
            insert_at = q_start + 1

        block_lines = [f"{no}. {title}", "", body.strip(), "", "```", "用户回答：", "```"]
        new_lines = lines[:insert_at]
        if new_lines and new_lines[-1].strip():
            new_lines.append("")
        new_lines += block_lines + ["", ""] + lines[insert_at:]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines).rstrip("\n") + "\n")
        return {"status": "success", "question_no": no, "path": path}
    except Exception as e:
        return {"status": "error", "reason": "write_error", "error": str(e)}


def user_md_read(project_name: str) -> dict:
    """读取 USER.md（不存在时自动建骨架），返回原文 + 解析后的问题列表与重点关注段。"""
    path = _ensure_user_md(project_name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        return {"status": "error", "reason": "read_error", "error": str(e)}
    parsed = _parse_user_md(content)
    return {
        "status": "success",
        "path": path,
        "content": content,
        "questions": parsed["questions"],
        "focus": parsed["focus"],
    }


def user_md_set_focus(project_name: str, text: str) -> dict:
    """把文本写入 USER.md 的"用户着重关心的内容"段（幂等追加语义）。

    段内容为空或仅有占位符"（暂无）"时直接替换；已有内容且未包含本次文本时
    追加在其后（保留用户手写内容）；已包含（子串匹配）时不做任何修改。
    供 C2 启动参数（--focus/--exclude）落盘使用：重复执行/断点重跑不会产生重复行。
    """
    text = (text or "").strip()
    if not text:
        return {"status": "error", "reason": "empty_text"}
    path = _ensure_user_md(project_name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        lines = content.splitlines()
        _q_start, f_start = _locate_sections(lines)
        if f_start is None:
            # 段缺失（用户手改文件）：文末补回 focus 段
            lines += ["", _FOCUS_HEADER]
            f_start = len(lines) - 1
        # focus 段是文末段：范围 = f_start+1 到文件尾
        seg = "\n".join(lines[f_start + 1:]).strip()
        if text in seg:
            return {"status": "success", "path": path, "changed": False}  # 幂等命中
        if not seg or seg == _EMPTY_PLACEHOLDER:
            new_lines = lines[: f_start + 1] + ["", text, ""]
        else:
            new_lines = lines[: f_start + 1] + ["", seg, "", text, ""]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines).rstrip("\n") + "\n")
        return {"status": "success", "path": path, "changed": True}
    except Exception as e:
        return {"status": "error", "reason": "write_error", "error": str(e)}


def user_md_append_answer(project_name: str, question_no: int, answer: str) -> dict:
    """把用户回答写入指定编号问题的"用户回答："代码块（不存在时自动建骨架）。

    追加语义：该问题已有回答时保留原文，以 ``---`` 分隔后追加新回答；
    问题块缺失回答代码块（用户手删）时在块尾补建。编号不存在返回 error。
    """
    answer_text = (answer or "").strip()
    if not answer_text:
        return {"status": "error", "reason": "empty_answer", "question_no": question_no}
    path = _ensure_user_md(project_name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        lines = content.splitlines()
        q_start, f_start = _locate_sections(lines)
        if q_start is None:
            return {"status": "error", "reason": "question_not_found",
                    "question_no": question_no}
        q_end = f_start if f_start is not None else len(lines)
        target = None
        for start, end, no, _title in _question_block_ranges(lines, q_start, q_end):
            if no == question_no:
                target = (start, end)
                break
        if target is None:
            return {"status": "error", "reason": "question_not_found",
                    "question_no": question_no}

        start, end = target
        block = lines[start + 1:end]
        fence_open, fence_close = _find_answer_fence(block)
        if fence_open is not None:
            inner = block[fence_open + 1:fence_close]
            existing = inner[1:]  # inner[0] 是"用户回答："标记行
            new_inner = ["用户回答："]
            if "\n".join(existing).strip():
                new_inner += existing + ["", "---", ""]  # 追加语义：保留历史回答
            new_inner += answer_text.splitlines()
            block = block[:fence_open + 1] + new_inner + block[fence_close:]
        else:
            block += ["", "```", "用户回答："] + answer_text.splitlines() + ["```"]

        lines = lines[:start + 1] + block + lines[end:]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines).rstrip("\n") + "\n")
        return {"status": "success", "question_no": question_no, "path": path}
    except Exception as e:
        return {"status": "error", "reason": "write_error", "error": str(e)}
