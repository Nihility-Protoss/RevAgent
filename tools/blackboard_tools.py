import os
import json
from typing import Dict, Any, Optional

from config import cfg


def board_base_dir() -> str:
    """黑板（blackboard）根目录：config.yaml 的 paths.output_root（默认 data/output）。"""
    return cfg("paths.output_root", env="BOARD_BASE_DIR", default=os.path.join("data", "output"))


def board_path(project_name: str, *subpaths: str) -> str:
    """在 {board_base}/{project_name}/ 下拼出完整路径。"""
    return os.path.join(board_base_dir(), project_name, *subpaths)


# 兼容旧引用（测试与历史代码）
_board_path = board_path


def _ensure_dirs(project_name: str) -> None:
    """确保黑板所有子目录都存在。"""
    for sub in ["extracts", "artifacts", "summary", "meta", "artifacts/latest"]:
        os.makedirs(board_path(project_name, *sub.split("/")), exist_ok=True)


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


# --- Summaries（摘要）---

def bb_read_summary(summary_name: str, project_name: str) -> dict:
    """从 summary/ 读取一份 summary JSON。"""
    path = board_path(project_name, "summary", f"{summary_name}.json")
    if not os.path.exists(path):
        return {"status": "error", "reason": "summary_not_found", "path": path}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return {"status": "success", "data": json.load(f)}
    except Exception as e:
        return {"status": "error", "reason": "parse_error", "error": str(e)}


def bb_list_summaries(prefix: str, project_name: str) -> list[dict]:
    """列出所有前缀匹配的 summary，并返回其完整内容。"""
    summary_dir = board_path(project_name, "summary")
    if not os.path.exists(summary_dir):
        return []

    results = []
    for root, _, files in os.walk(summary_dir):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            rel = os.path.relpath(os.path.join(root, fname), summary_dir).replace("\\", "/")
            name = rel.replace(".json", "")
            if name.startswith(prefix):
                try:
                    with open(os.path.join(root, fname), "r", encoding="utf-8") as f:
                        results.append(json.load(f))
                except Exception:
                    pass
    return results


def bb_write_summary(summary_name: str, content: dict, project_name: str) -> dict:
    """写入一份 summary JSON，硬性限制 ≤1500 token。"""
    _ensure_dirs(project_name)

    tokens = _estimate_tokens(content)
    if tokens > 1500:
        return {
            "status": "error",
            "reason": "summary_too_large",
            "estimated_tokens": tokens,
            "limit": 1500,
        }

    path = board_path(project_name, "summary", f"{summary_name}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(content, f, ensure_ascii=False, indent=2)
        return {"status": "success", "path": path, "estimated_tokens": tokens}
    except Exception as e:
        return {"status": "error", "reason": "write_error", "error": str(e)}


# --- Artifacts（完整产物）---

def bb_read_artifact(artifact_name: str, project_name: str) -> dict:
    """从 artifacts/ 读取完整 artifact。"""
    path = board_path(project_name, "artifacts", f"{artifact_name}.json")
    if not os.path.exists(path):
        return {"status": "error", "reason": "artifact_not_found", "path": path}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return {"status": "success", "data": json.load(f)}
    except Exception as e:
        return {"status": "error", "reason": "parse_error", "error": str(e)}


def bb_write_artifact(artifact_name: str, content: dict, project_name: str) -> dict:
    """写入完整 artifact，并更新 latest/ 索引。"""
    _ensure_dirs(project_name)

    path = board_path(project_name, "artifacts", f"{artifact_name}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(content, f, ensure_ascii=False, indent=2)

        latest_dir = board_path(project_name, "artifacts", "latest")
        os.makedirs(latest_dir, exist_ok=True)
        base_name = artifact_name
        for suffix in ["_timestamp", "_2026"]:
            if suffix in base_name:
                base_name = base_name.rsplit("_", 1)[0]
        latest_path = os.path.join(latest_dir, f"{base_name}.json")
        rel_ref = os.path.relpath(path, latest_dir).replace("\\", "/")
        with open(latest_path, "w", encoding="utf-8") as f:
            json.dump({"ref": rel_ref, "timestamp": _now_iso()}, f)

        return {"status": "success", "path": path}
    except Exception as e:
        return {"status": "error", "reason": "write_error", "error": str(e)}


def bb_has_artifact(artifact_name: str, project_name: str) -> bool:
    """判断某个 artifact 是否存在。"""
    path = board_path(project_name, "artifacts", f"{artifact_name}.json")
    return os.path.exists(path)


# --- Checkpoint / Resume（检查点与断点续跑）---

def bb_checkpoint(phase: str, project_name: str) -> dict:
    """保存 checkpoint：更新 state.json 并追加到 checkpoints.json。"""
    _ensure_dirs(project_name)

    meta_dir = board_path(project_name, "meta")
    state_path = os.path.join(meta_dir, "state.json")
    cp_path = os.path.join(meta_dir, "checkpoints.json")

    state = {}
    if os.path.exists(state_path):
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)

    state.update({
        "current_phase": phase,
        "last_updated": _now_iso(),
    })

    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    checkpoints = []
    if os.path.exists(cp_path):
        with open(cp_path, "r", encoding="utf-8") as f:
            checkpoints = json.load(f)

    checkpoints.append({"phase": phase, "timestamp": _now_iso()})

    with open(cp_path, "w", encoding="utf-8") as f:
        json.dump(checkpoints, f, ensure_ascii=False, indent=2)

    return {"status": "success", "phase": phase}


def bb_load_checkpoint(project_name: str) -> Optional[dict]:
    """加载最新的 checkpoint 状态；若无 checkpoint 则返回 None。"""
    state_path = board_path(project_name, "meta", "state.json")
    if not os.path.exists(state_path):
        return None

    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# --- Logging（日志）---

def bb_log_event(event_type: str, details: dict, project_name: str) -> dict:
    """追加一条日志事件到 execution_log.jsonl。"""
    _ensure_dirs(project_name)

    log_path = board_path(project_name, "meta", "execution_log.jsonl")
    entry = {
        "timestamp": _now_iso(),
        "event_type": event_type,
        "details": details,
    }

    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "reason": "write_error", "error": str(e)}


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
