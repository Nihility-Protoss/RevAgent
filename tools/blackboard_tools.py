import os
import json
from typing import Dict, Any, Optional


def _board_path(project_name: str, *subpaths: str) -> str:
    """Build path under .blackboard/{project_name}/."""
    return os.path.join(".blackboard", project_name, *subpaths)


def _ensure_dirs(project_name: str) -> None:
    """Ensure all blackboard subdirectories exist."""
    for sub in ["extracts", "artifacts", "summary", "meta", "artifacts/latest"]:
        os.makedirs(_board_path(project_name, *sub.split("/")), exist_ok=True)


def _estimate_tokens(data: dict) -> int:
    """Rough token estimate: JSON string length / 4."""
    return len(json.dumps(data, ensure_ascii=False)) // 4


# --- Extracts ---

def bb_read_extract(extract_name: str, project_name: str, chunk_index: int = 0) -> dict:
    """Read a chunk from extracts/{extract_name}.json."""
    path = _board_path(project_name, "extracts", f"{extract_name}.json")
    if not os.path.exists(path):
        return {"status": "error", "reason": "extract_not_found", "path": path}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return {"status": "error", "reason": "parse_error", "error": str(e)}

    # Handle chunked reads for lists
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


# --- Summaries ---

def bb_read_summary(summary_name: str, project_name: str) -> dict:
    """Read a summary JSON from summary/."""
    path = _board_path(project_name, "summary", f"{summary_name}.json")
    if not os.path.exists(path):
        return {"status": "error", "reason": "summary_not_found", "path": path}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return {"status": "success", "data": json.load(f)}
    except Exception as e:
        return {"status": "error", "reason": "parse_error", "error": str(e)}


def bb_list_summaries(prefix: str, project_name: str) -> list[dict]:
    """List all summaries matching prefix, returning their full contents."""
    summary_dir = _board_path(project_name, "summary")
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
    """Write a summary JSON. Enforces ≤1500 token hard limit."""
    _ensure_dirs(project_name)

    tokens = _estimate_tokens(content)
    if tokens > 1500:
        return {
            "status": "error",
            "reason": "summary_too_large",
            "estimated_tokens": tokens,
            "limit": 1500,
        }

    path = _board_path(project_name, "summary", f"{summary_name}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(content, f, ensure_ascii=False, indent=2)
        return {"status": "success", "path": path, "estimated_tokens": tokens}
    except Exception as e:
        return {"status": "error", "reason": "write_error", "error": str(e)}


# --- Artifacts ---

def bb_read_artifact(artifact_name: str, project_name: str) -> dict:
    """Read a full artifact from artifacts/."""
    path = _board_path(project_name, "artifacts", f"{artifact_name}.json")
    if not os.path.exists(path):
        return {"status": "error", "reason": "artifact_not_found", "path": path}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return {"status": "success", "data": json.load(f)}
    except Exception as e:
        return {"status": "error", "reason": "parse_error", "error": str(e)}


def bb_write_artifact(artifact_name: str, content: dict, project_name: str) -> dict:
    """Write a full artifact and update latest/ index."""
    _ensure_dirs(project_name)

    path = _board_path(project_name, "artifacts", f"{artifact_name}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(content, f, ensure_ascii=False, indent=2)

        latest_dir = _board_path(project_name, "artifacts", "latest")
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
    """Check if an artifact exists."""
    path = _board_path(project_name, "artifacts", f"{artifact_name}.json")
    return os.path.exists(path)


# --- Checkpoint / Resume ---

def bb_checkpoint(phase: str, project_name: str) -> dict:
    """Save a checkpoint: update state.json and append to checkpoints.json."""
    _ensure_dirs(project_name)

    meta_dir = _board_path(project_name, "meta")
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
    """Load the latest checkpoint state. Returns None if no checkpoint exists."""
    state_path = _board_path(project_name, "meta", "state.json")
    if not os.path.exists(state_path):
        return None

    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# --- Logging ---

def bb_log_event(event_type: str, details: dict, project_name: str) -> dict:
    """Append a log event to execution_log.jsonl."""
    _ensure_dirs(project_name)

    log_path = _board_path(project_name, "meta", "execution_log.jsonl")
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
    """Load decompile/disassembly snippets for a single function.

    Args:
        func_addr: Function address (e.g., '0x180001000').
        export_dir: Path to the IDA export directory (contains decompile/ and disassembly/).
        max_lines: Maximum lines to read from each file.

    Returns:
        Dict with status, addr, name, decompile_snippet, disassembly_snippet, xrefs.
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

    # Read decompile
    decompile_path = os.path.join(export_dir, "decompile", f"{addr_clean}.c")
    if os.path.exists(decompile_path):
        try:
            with open(decompile_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:max_lines]
            result["decompile_snippet"] = "".join(lines)
        except Exception as e:
            result["error"] = f"decompile_read_error: {e}"

    # Read disassembly
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


# --- Utility ---

def _now_iso() -> str:
    """Current timestamp in ISO format."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
