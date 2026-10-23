import os
import json
from typing import Dict, Any, Optional

from config import cfg


def board_base_dir() -> str:
    """黑板（blackboard）根目录：config.yaml 的 paths.output_root（默认 data/output）。"""
    return cfg("paths.output_root", default=os.path.join("data", "output"))


def board_path(project_name: str, *subpaths: str) -> str:
    """在 {board_base}/{project_name}/ 下拼出完整路径。"""
    return os.path.join(board_base_dir(), project_name, *subpaths)


# 兼容旧引用（测试与历史代码）
_board_path = board_path


def _ensure_dirs(project_name: str) -> None:
    """确保黑板基础子目录存在（条目库与预提取分片）。"""
    for sub in ["extracts", "entries"]:
        os.makedirs(board_path(project_name, sub), exist_ok=True)


def _estimate_tokens(data: dict) -> int:
    """粗略估算 token 数：JSON 字符串长度 / 4。"""
    return len(json.dumps(data, ensure_ascii=False)) // 4


# --- Extracts（预提取分片）---

def bb_read_extract(extract_name: str, project_name: str, chunk_index: int = 0) -> dict:
    """从 extracts/{extract_name}.json 读取一个分片。"""
    path = board_path(project_name, "extracts", f"{extract_name}.json")
    if not os.path.exists(path):
        return {"status": "error", "reason": "extract_not_found", "path": path}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return {"status": "error", "reason": "parse_error", "error": str(e)}

    # 处理列表类数据的分片读取
    if "chunk_size" in data and "functions" in data:
        chunk_size = data.get("chunk_size", 100)
        all_items = data["functions"]
        start = chunk_index * chunk_size
        end = start + chunk_size
        data["functions"] = all_items[start:end]
        data["chunk_index"] = chunk_index
        data["has_more"] = end < len(all_items)
    elif "chunk_size" in data and "by_category" in data:
        chunk_size = data.get("chunk_size", 100)
        # by_type 是全量未分片副本（与 by_category 内容重复），每次调用都返回
        # 会把整张字符串表塞进 ReAct 上下文导致 token 爆炸，这里直接剔除。
        data.pop("by_type", None)
        all_cats = data.get("by_category", {})
        start = chunk_index * chunk_size
        end = start + chunk_size
        data["has_more"] = any(len(items) > end for items in all_cats.values())
        for cat, items in all_cats.items():
            data["by_category"][cat] = items[start:end]
        data["chunk_index"] = chunk_index

    return {"status": "success", "data": data}


def load_function_data(func_addr: str, export_dir: str, max_lines: int = 200) -> dict:
    """为单个函数加载反编译/反汇编片段。

    参数：
        func_addr: 函数地址（例如 '0x180001000'）。
        export_dir: IDA 导出目录路径（含 decompile/ 与 disassembly/）。
        max_lines: 每个文件最多读取的行数。

    返回：
        包含 status、addr、name、decompile_snippet、disassembly_snippet、xrefs 的字典。
    """
    result = {
        "status": "success",
        "error": None,
        "addr": func_addr,
        "name": None,
        "decompile_snippet": None,
        "disassembly_snippet": None,
        "xrefs_in": [],
        "xrefs_out": [],
        "size": 0,
    }

    addr_clean = func_addr.replace("0x", "").replace("0X", "")

    # 读取反编译产物
    decompile_path = os.path.join(export_dir, "decompile", f"{addr_clean}.c")
    if os.path.exists(decompile_path):
        try:
            with open(decompile_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:max_lines]
            result["decompile_snippet"] = "".join(lines)
        except Exception as e:
            result["error"] = f"decompile_read_error: {e}"

    # 读取反汇编产物
    disasm_path = os.path.join(export_dir, "disassembly", f"{addr_clean}.asm")
    if os.path.exists(disasm_path):
        try:
            with open(disasm_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:max_lines]
            result["disassembly_snippet"] = "".join(lines)
        except Exception as e:
            if result["error"]:
                result["error"] += f"; disassembly_read_error: {e}"
            else:
                result["error"] = f"disassembly_read_error: {e}"

    return result


# --- Utility（工具函数）---

def _now_iso() -> str:
    """ISO 格式的当前时间戳。"""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
