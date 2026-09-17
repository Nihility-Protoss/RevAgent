"""Knowledge base package: arch-specific analysis methodology files.

Knowledge files are Markdown documents with a small YAML-like frontmatter
header (parsed by a hand-rolled parser — pyyaml is intentionally not a
dependency). The registry is built once at import time.
"""
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.blackboard_tools import _board_path, _estimate_tokens

KNOWLEDGE_DIR = Path(__file__).parent

_ACTIVE_SENTINEL = "__active__"
_DEFAULT_GUIDE = "windows_pe"


@dataclass(frozen=True)
class KnowledgeMeta:
    """Frontmatter metadata of one knowledge file."""

    name: str
    title: str
    source: str
    applies_to: list
    priority: int
    max_tokens: int
    path: Path


def _parse_frontmatter(text: str) -> dict:
    """Parse the small frontmatter subset used by knowledge files.

    Supported keys: name, title, source (str); applies_to (inline list);
    priority, max_tokens (int). Unknown keys are ignored.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    meta: dict[str, Any] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key == "applies_to":
            inner = value.strip().lstrip("[").rstrip("]")
            meta[key] = [item.strip() for item in inner.split(",") if item.strip()]
        elif key in ("priority", "max_tokens"):
            meta[key] = int(value)
        else:
            meta[key] = value
    return meta


def _build_registry() -> dict:
    registry: dict[str, KnowledgeMeta] = {}
    for md_path in sorted(KNOWLEDGE_DIR.glob("*.md")):
        meta = _parse_frontmatter(md_path.read_text(encoding="utf-8"))
        if not meta.get("name"):
            continue  # not a knowledge file (missing/invalid frontmatter)
        registry[meta["name"]] = KnowledgeMeta(
            name=meta["name"],
            title=meta.get("title", meta["name"]),
            source=meta.get("source", ""),
            applies_to=meta.get("applies_to", []),
            priority=meta.get("priority", 50),
            max_tokens=meta.get("max_tokens", 1200),
            path=md_path,
        )
    return registry


KNOWLEDGE_REGISTRY: dict[str, KnowledgeMeta] = _build_registry()


def _read_guide(meta: KnowledgeMeta) -> dict:
    """Read one guide file, truncating to its token budget if oversized."""
    content = meta.path.read_text(encoding="utf-8")
    tokens = _estimate_tokens(content)
    truncated = False
    if tokens > meta.max_tokens:
        content = content[: meta.max_tokens * 4]
        tokens = _estimate_tokens(content)
        truncated = True
    return {
        "status": "success",
        "error": None,
        "name": meta.name,
        "title": meta.title,
        "content": content,
        "token_estimate": tokens,
        "truncated": truncated,
    }


def _load_active(project_name: str) -> dict:
    """Resolve the __active__ sentinel against meta/active_guides.json."""
    meta_path = _board_path(project_name, "meta", "active_guides.json")
    names = [_DEFAULT_GUIDE]
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            if doc.get("guides"):
                names = [g["name"] for g in doc["guides"] if g.get("name") in KNOWLEDGE_REGISTRY]
        except Exception:
            names = [_DEFAULT_GUIDE]
    if not names:
        names = [_DEFAULT_GUIDE]
    parts = []
    for name in names:
        result = _read_guide(KNOWLEDGE_REGISTRY[name])
        parts.append(f"=== {result['title']} ===\n{result['content']}")
    return {
        "status": "success",
        "error": None,
        "name": _ACTIVE_SENTINEL,
        "guides": names,
        "content": "\n\n".join(parts),
        "token_estimate": sum(_estimate_tokens(p) for p in parts),
        "truncated": False,
    }


def match_guides(arch_detection: dict) -> list:
    """Map an arch_detection dict to active guide names.

    windows_pe is always included as the baseline. Language/form-specific
    guides are only activated when confidence is not low.
    """
    arch = arch_detection or {}
    language = str(arch.get("language") or "unknown").lower()
    sample_form = str(arch.get("sample_form") or "").lower()
    confidence = str(arch.get("confidence") or "low").lower()

    names = [_DEFAULT_GUIDE]
    if confidence != "low":
        if language == "c_cpp":
            names.append("cpp")
        elif language == "rust":
            names.append("rust")
        elif language == "golang":
            names.append("golang")
        if sample_form == "exe_file_loader":
            names.append("file_loader_triage")

    ordered = sorted(
        (KNOWLEDGE_REGISTRY[n] for n in names if n in KNOWLEDGE_REGISTRY),
        key=lambda m: m.priority,
    )
    return [m.name for m in ordered]


def load_knowledge(name: str, project_name: str) -> dict:
    """Load one knowledge guide by name (or __active__ for sample-resolved set).

    Returns the standard tool result dict; never raises.
    """
    try:
        if name == _ACTIVE_SENTINEL:
            return _load_active(project_name)
        meta = KNOWLEDGE_REGISTRY.get(name)
        if meta is None:
            return {
                "status": "error",
                "error": f"unknown knowledge guide: {name}",
                "available": sorted(KNOWLEDGE_REGISTRY),
            }
        return _read_guide(meta)
    except Exception as exc:  # defensive: tools must not raise
        return {"status": "error", "error": f"load_error: {exc}"}
