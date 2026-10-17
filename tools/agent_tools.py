# -*- coding: utf-8 -*-
"""Minimal/Full 双模式 Agent 工具适配层。

- :func:`parse_command`：固定文法命令解析（``shlex``），只接受 ``next`` 与 ``key=value``，
  支持去除成对 Markdown 围栏；解析失败抛 ``ValueError``。
- :func:`make_minimal_tools`：按 :data:`MINIMAL_ROLE_TOOLS` 映射生成最小读取工具集，
  闭包预绑定 ``project_name / run_id / export_dir``，工具签名只保留 ``command: str``。
  所有执行错误统一返回 ``{"status": "error", "reason": ..., "expected_examples": [...]}``，
  绝不向模型暴露堆栈。
- :func:`make_full_tools`：通用分析工具（读取/历史/查询/上下文/创建/追加/验证），
  不返回 ``bb_review_entries / bb_flush_store / bb_set_runtime / bb_checkpoint``；
  写入包装器预绑定项目并校验 ``producer.run_id`` 与当前运行一致。
"""
import os
import shlex
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool

from config import cfg
from tools.blackboard_tools import bb_read_extract
from tools.entry_tools import (
    bb_append_version,
    bb_build_context,
    bb_create_entry,
    bb_find_operation,
    bb_get_entry,
    bb_get_entry_history,
    bb_query_entries,
    bb_validate_entry,
)
from tools.file_loaders import (
    load_exports,
    load_function_index,
    load_imports,
    load_strings,
)
from workers.knowledge import load_knowledge

# Minimal 模式：角色 → 最小读取工具名列表（映射固定，勿随意扩展）
MINIMAL_ROLE_TOOLS = {
    "string_artifact_analyst": ("read_strings_data",),
    "api_behavior_profiler": ("read_api_data", "read_strings_data"),
    "export_interface_analyzer": ("read_export_data", "read_function_index_data"),
    "behavior_profile_synthesizer": ("read_behavior_context",),
    "function_boundary_detector": (
        "read_function_index_data", "read_export_data", "read_arch_guide",
    ),
    "scheduler": ("read_scheduler_context",),
}

# extract 名 → 原始导出文件名（预提取 JSON 缺失时的兜底读取）
_EXTRACT_RAW_FALLBACK = {
    "read_strings_data": ("strings_extract", "strings.txt", load_strings),
    "read_api_data": ("imports_extract", "imports.txt", load_imports),
    "read_export_data": ("exports_extract", "exports.txt", load_exports),
    "read_function_index_data": ("functions_extract", "function_index.txt", load_function_index),
}


def parse_command(command: str, allowed_keys=frozenset()) -> Dict[str, Any]:
    """解析固定文法命令：只接受 ``next`` 与 ``key=value``。

    - 自动去除成对的 Markdown 围栏（```lang ... ```）。
    - 位置参数不允许与 ``key=value`` 混用；除 ``next`` 外的位置参数直接报错。
    - 重复 key 报错；``allowed_keys`` 非空时 key 必须在其中。
    """
    if not isinstance(command, str):
        raise ValueError("command 必须是字符串")

    text = command.strip()
    # 去除成对 Markdown 围栏
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline != -1 and text.rstrip().endswith("```"):
            text = text[first_newline + 1:].rstrip()[:-3].strip()

    tokens = shlex.split(text, posix=True)
    if not tokens:
        raise ValueError("空命令")

    result: Dict[str, Any] = {}
    has_kv = any("=" in token for token in tokens)
    for token in tokens:
        if token == "next":
            if has_kv:
                raise ValueError("next 不允许与 key=value 混用")
            if "next" in result:
                raise ValueError("next 重复")
            result["next"] = True
            continue
        if "=" not in token:
            raise ValueError(f"位置参数不允许: {token!r}")
        key, _, value = token.partition("=")
        key = key.strip()
        if not key:
            raise ValueError(f"非法 key=value: {token!r}")
        if allowed_keys and key not in allowed_keys:
            raise ValueError(f"未知参数 key: {key!r}")
        if key in result:
            raise ValueError(f"重复参数 key: {key!r}")
        result[key] = value
    return result


def _error(reason: str, examples: List[str], message: Optional[str] = None) -> dict:
    """统一的 minimal 工具错误返回：携带该工具的 expected_examples，绝不返回堆栈。"""
    data = {"status": "error", "reason": reason, "expected_examples": list(examples)}
    if message:
        data["error"] = message
    return data


def _make_extract_reader(tool_name: str, project_name: str, export_dir: str) -> StructuredTool:
    """生成一个 extract 读取工具：优先读预提取分片，缺失时回退到 export_dir 原始文件。"""
    extract_name, raw_filename, raw_loader = _EXTRACT_RAW_FALLBACK[tool_name]
    is_strings = tool_name == "read_strings_data"
    allowed = {"chunk", "keyword"} if is_strings else {"chunk"}
    examples = ["next", "chunk=0", "keyword=<文本>"] if is_strings else ["next", "chunk=0"]
    state = {"chunk": 0}

    def _read(command: str) -> dict:
        try:
            parsed = parse_command(command, allowed_keys=allowed)
        except ValueError as exc:
            return _error("invalid_command", examples, str(exc))
        try:
            if "keyword" in parsed:
                if not is_strings:
                    return _error("invalid_command", examples, "该工具不支持 keyword")
                return _read_strings_keyword(project_name, export_dir, raw_filename, parsed["keyword"])
            if "next" in parsed:
                chunk_index = state["chunk"]
            else:
                chunk_index = int(parsed.get("chunk", 0))
            result = bb_read_extract(extract_name, project_name, chunk_index=chunk_index)
            if result.get("status") == "error" and result.get("reason") == "extract_not_found":
                # 预提取缺失：回退到 export_dir 下的原始导出文件
                raw = raw_loader(os.path.join(export_dir, raw_filename))
                if raw.get("status") == "error":
                    return _error("extract_not_found", examples, raw.get("error"))
                return {"status": "success", "data": raw, "source": "raw"}
            state["chunk"] = chunk_index + 1 if result.get("status") == "success" else chunk_index
            return result
        except Exception as exc:  # 防御性：tool 不允许向模型抛异常
            return _error("read_error", examples, str(exc))

    descriptions = {
        "read_strings_data": "读取 strings 预提取数据。命令: next | chunk=N | keyword=<文本>",
        "read_api_data": "读取 imports/API 预提取数据。命令: next | chunk=N",
        "read_export_data": "读取 exports 预提取数据。命令: next | chunk=N",
        "read_function_index_data": "读取函数索引预提取数据。命令: next | chunk=N",
    }
    return StructuredTool.from_function(
        _read, name=tool_name, description=descriptions[tool_name]
    )


def _read_strings_keyword(project_name: str, export_dir: str, raw_filename: str, keyword: str) -> dict:
    """按关键字过滤字符串：直接读预提取全量 JSON（避免分片截断漏匹配），缺失时回退原始 strings.txt。"""
    import json

    from tools.blackboard_tools import board_path

    path = board_path(project_name, "extracts", "strings_extract.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            return _error("read_error", ["next", "chunk=0", "keyword=<文本>"], str(exc))
        texts = []
        for items in (data.get("by_category") or {}).values():
            for item in items:
                if isinstance(item, dict):
                    texts.append(item.get("text") or item.get("raw") or str(item))
                else:
                    texts.append(str(item))
        matched = [t for t in texts if keyword.lower() in t.lower()]
        return {"status": "success", "data": {"keyword": keyword, "matched": matched, "count": len(matched)}}

    raw_path = os.path.join(export_dir, raw_filename)
    raw = load_strings(raw_path)
    if raw.get("status") == "error":
        return _error("extract_not_found", ["next", "chunk=0", "keyword=<文本>"], raw.get("error"))
    matched = [s for s in raw.get("all_strings", []) if keyword.lower() in s.lower()]
    return {"status": "success", "data": {"keyword": keyword, "matched": matched, "count": len(matched)}}


def _make_context_reader(tool_name: str, consumer: str, project_name: str) -> StructuredTool:
    """生成消费者上下文读取工具：cursor 通过 next 或 cursor=<值> 传递。"""
    examples = ["next", "cursor=<值>"]
    state: Dict[str, Any] = {"cursor": None}

    def _read(command: str) -> dict:
        try:
            parsed = parse_command(command, allowed_keys={"cursor"})
        except ValueError as exc:
            return _error("invalid_command", examples, str(exc))
        try:
            if "next" in parsed:
                cursor = state["cursor"]
            else:
                cursor = parsed.get("cursor") or None
            result = bb_build_context(consumer, project_name, cursor=cursor)
            if result.get("status") == "success":
                state["cursor"] = result.get("next_cursor")
            return result
        except Exception as exc:
            return _error("read_error", examples, str(exc))

    description = {
        "read_behavior_context": "构建 phase1_behavior 消费者条目上下文。命令: next | cursor=<值>",
        "read_scheduler_context": "构建 scheduler 消费者条目上下文。命令: next | cursor=<值>",
    }[tool_name]
    return StructuredTool.from_function(_read, name=tool_name, description=description)


def _make_arch_guide_reader(tool_name: str, project_name: str, export_dir: str) -> StructuredTool:
    """生成知识 guide 读取工具：只接受空串、active 或注册表名称。"""
    examples = ["", "active", "<guide_name>"]

    def _read(command: str) -> dict:
        try:
            name = (command or "").strip()
        except Exception as exc:
            return _error("invalid_command", examples, str(exc))
        if name in ("", "active"):
            name = "__active__"
        try:
            return load_knowledge(name, project_name)
        except Exception as exc:
            return _error("read_error", examples, str(exc))

    return StructuredTool.from_function(
        _read,
        name="read_arch_guide",
        description="读取架构专项分析 guide。命令: 空串 | active | <guide_name>",
    )


_MINIMAL_TOOL_BUILDERS = {
    "read_strings_data": _make_extract_reader,
    "read_api_data": _make_extract_reader,
    "read_export_data": _make_extract_reader,
    "read_function_index_data": _make_extract_reader,
    "read_arch_guide": _make_arch_guide_reader,
}


def make_minimal_tools(role: str, project_name: str, run_id: str, export_dir: str) -> List[StructuredTool]:
    """按固定映射生成角色的最小读取工具集；未知角色抛 ValueError。"""
    tool_names = MINIMAL_ROLE_TOOLS.get(role)
    if tool_names is None:
        raise ValueError(f"未知角色: {role}")
    tools: List[StructuredTool] = []
    for name in tool_names:
        if name == "read_behavior_context":
            tools.append(_make_context_reader(name, "phase1_behavior", project_name))
        elif name == "read_scheduler_context":
            tools.append(_make_context_reader(name, "scheduler", project_name))
        else:
            tools.append(_MINIMAL_TOOL_BUILDERS[name](name, project_name, export_dir))
    return tools


def _wrap_full_tool(func, name: str, description: str, project_name: str,
                    run_id: Optional[str] = None) -> StructuredTool:
    """把 entry_tools 公开函数包装为预绑定项目的 StructuredTool。

    ``run_id`` 非空时视为写入工具：校验 ``producer.run_id`` 与当前运行一致。
    """
    def _tool(**kwargs) -> dict:
        kwargs = dict(kwargs)
        kwargs["project_name"] = project_name
        if run_id is not None:
            producer = kwargs.get("producer") or {}
            if producer.get("run_id") != run_id:
                return {"status": "error", "reason": "run_id_mismatch",
                        "expected": run_id, "actual": producer.get("run_id")}
        try:
            return func(**kwargs)
        except Exception as exc:  # 防御性：tool 不允许向模型抛异常
            return {"status": "error", "reason": "internal_error", "error": str(exc)}

    return StructuredTool.from_function(_tool, name=name, description=description)


def make_full_tools(project_name: str, run_id: str, export_dir: str) -> List[StructuredTool]:
    """通用分析工具集：读取/历史/查询/上下文/创建/追加/验证，排除特权维护工具。"""
    readers = [
        (bb_get_entry, "bb_get_entry", "读取单个条目（可指定历史版本）。"),
        (bb_get_entry_history, "bb_get_entry_history", "读取条目全部历史版本。"),
        (bb_query_entries, "bb_query_entries", "按过滤条件查询条目 head 版本。"),
        (bb_build_context, "bb_build_context", "为固定消费者构建有界条目上下文。"),
        (bb_find_operation, "bb_find_operation", "按幂等键查找已执行操作。"),
    ]
    writers = [
        (bb_create_entry, "bb_create_entry", "创建 v1 条目（幂等）。"),
        (bb_append_version, "bb_append_version", "在 head 版本基础上追加完整版本。"),
        (bb_validate_entry, "bb_validate_entry", "对指定版本写入校验结论。"),
    ]
    tools = [_wrap_full_tool(f, n, d, project_name) for f, n, d in readers]
    tools += [_wrap_full_tool(f, n, d, project_name, run_id=run_id) for f, n, d in writers]
    return tools


def get_agent_tools(role: str, project_name: str, run_id: str, export_dir: str,
                    mode: Optional[str] = None) -> List[StructuredTool]:
    """按模式返回 Agent 工具集；mode 缺省取 config.yaml 的 ``agents.tool_mode``。"""
    if mode is None:
        mode = cfg("agents.tool_mode", default="minimal")
    if mode == "minimal":
        return make_minimal_tools(role, project_name, run_id, export_dir)
    if mode == "full":
        return make_full_tools(project_name, run_id, export_dir)
    raise ValueError(f"未知工具模式: {mode!r}")
