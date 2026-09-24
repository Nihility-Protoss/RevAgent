"""知识库包：架构专项分析方法论文件。

知识文件是 Markdown 文档，带有一小段类 YAML 的 frontmatter 头部（由手写解析器解析——有意不依赖 pyyaml）。
注册表在 import 时构建一次。
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
    """单个知识文件的 frontmatter 元数据。"""

    name: str
    title: str
    source: str
    applies_to: list
    priority: int
    max_tokens: int
    path: Path


def _parse_frontmatter(text: str) -> dict:
    """解析知识文件使用的那一小部分 frontmatter。

    支持的键：name、title、source（str）；applies_to（内联列表）；priority、max_tokens（int）。未知键会被忽略。
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
            continue  # 不是知识文件（frontmatter 缺失或无效）
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
    """读取单个 guide 文件，若超出其 token 预算则截断。"""
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
    """解析 __active__ 哨兵值，对照 meta/active_guides.json 确定生效的 guide 集合。"""
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


def match_guides(arch_detection: dict) -> list[str]:
    """依据 applies_to 标签，把 arch_detection dict 映射为生效的 guide 名称列表。

    基线 guide（applies_to 含 "baseline"，例如 windows_pe）始终包含。其他 guide 声明 "key:value" 形式的标签，其中 key 是 arch_detection 的字段（例如 language、sample_form）；当该字段与 value 匹配（不区分大小写）时该 guide 被包含。当 confidence 为 low（或未设置）时，只有基线 guide 生效。
    """
    arch = arch_detection or {}
    confidence = str(arch.get("confidence") or "low").lower()

    names = []
    for name, meta in KNOWLEDGE_REGISTRY.items():
        tags = meta.applies_to or []
        if "baseline" in tags:
            names.append(name)
            continue
        if confidence == "low":
            continue
        for tag in tags:
            key, sep, value = tag.partition(":")
            if not sep:
                continue
            arch_value = str(arch.get(key) or "").lower()
            if arch_value and arch_value == value.strip().lower():
                names.append(name)
                break

    if not names:
        names = [_DEFAULT_GUIDE]

    ordered = sorted(
        (KNOWLEDGE_REGISTRY[n] for n in names if n in KNOWLEDGE_REGISTRY),
        key=lambda m: m.priority,
    )
    return [m.name for m in ordered]


def load_knowledge(name: str, project_name: str) -> dict:
    """按名称加载单个知识 guide（或用 __active__ 表示按样本解析出的集合）。

    返回标准的 tool 结果 dict；从不抛异常。
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
    except Exception as exc:  # 防御性：tool 不允许抛异常
        return {"status": "error", "error": f"load_error: {exc}"}
