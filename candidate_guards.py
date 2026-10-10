"""Phase 3 候选函数的代码级护栏（A0 主修复，确定性后置修正）。

真实运行暴露的问题：LLM 按 xrefs 排序选出的 Top 20 全是样本高地址尾部的
运行时库函数（CRT），导出函数与真正的核心逻辑函数（命令分发器、反调试线程等）
一个都没选上。本模块在 graph_nodes._select_phase3_candidates 中对 LLM 输出做
确定性的后置修正，与提示词修正（辅）双管齐下：

1. 导出函数无条件强制置顶（不在 LLM 候选里的导出地址合成条目补入）；
2. 疑似库函数降权排除：xrefs 超过阈值 + 无名 sub_ + 地址位于样本高地址尾部
   区间（size 未知即 0 时不阻断）的候选判为 CRT/库函数，导出函数永远豁免；
3. 其余 LLM 候选按 analysis_priority 降序补足 Top N（保持原有 >=7 过滤语义）。

MODIFY 人工指定路径不经过本护栏（见 _select_phase3_candidates）。
阈值均可经 config.yaml 的 analysis.* 配置（环境变量兜底）：
  analysis.phase3_top_n        候选数量上限，默认 20
  analysis.lib_xref_threshold  库函数判定的 xrefs 阈值，默认 50
  analysis.lib_tail_ratio      尾部区间起点比例（相对样本函数地址范围），默认 0.45
  analysis.lib_size_max        库函数判定的 size 上限（0=不启用 size 条件），默认 512
"""
import json
import os
from typing import Optional

from tools.blackboard_tools import bb_read_extract, board_path

# 默认阈值（被 config.yaml 的 analysis.* 覆盖；此处为最终兜底）
DEFAULT_TOP_N = 20
DEFAULT_LIB_XREF_THRESHOLD = 50
# 按真实样本校准：库函数聚簇从地址范围约 45% 处开始（0x1800Bxxxx 起），
# 而导出/核心函数均位于 25% 之前，0.45 可把两者稳定分开
DEFAULT_LIB_TAIL_RATIO = 0.45
DEFAULT_LIB_SIZE_MAX = 512
# 沿用旧 _select_phase3_candidates 的优先级过滤语义
MIN_ANALYSIS_PRIORITY = 7


def normalize_addr(addr) -> str:
    """规范化地址为小写 0x 前缀形式；无法解析时返回空串。"""
    if not isinstance(addr, str):
        return ""
    s = addr.strip().lower()
    if not s:
        return ""
    if not s.startswith("0x"):
        s = "0x" + s
    try:
        int(s, 16)
    except ValueError:
        return ""
    return s


def parse_addr(addr) -> Optional[int]:
    """把地址字符串解析为 int；失败返回 None。"""
    normalized = normalize_addr(addr)
    return int(normalized, 16) if normalized else None


def is_unnamed_func(name) -> bool:
    """无名函数判定：名称为空或 sub_ 前缀（大小写不敏感）。"""
    if not isinstance(name, str) or not name.strip():
        return True
    return name.strip().lower().startswith("sub_")


def collect_export_addrs(state: dict, project_name: str) -> dict:
    """收集导出函数地址 → 导出名 的有序映射（键为规范化小写地址）。

    来源优先级：state 的 export_interface_analysis（ordinal_mapping +
    suspicious_exports）> 黑板 extracts/exports_extract.json 兜底。
    任何来源缺失/失败都静默降级为空映射，绝不中断流水线。
    """
    exports: dict = {}

    analysis = state.get("export_interface_analysis") or {}
    if isinstance(analysis, dict):
        for entry in analysis.get("ordinal_mapping") or []:
            if isinstance(entry, dict):
                addr = normalize_addr(entry.get("address"))
                if addr:
                    exports.setdefault(addr, entry.get("name") or "")
        for entry in analysis.get("suspicious_exports") or []:
            if isinstance(entry, dict):
                addr = normalize_addr(entry.get("address"))
                if addr:
                    exports.setdefault(addr, entry.get("name") or "")

    if not exports and project_name:
        # 兜底：预提取分片（exports_extract.json 的 exports[].address/name）
        result = bb_read_extract("exports_extract", project_name)
        if result.get("status") == "success":
            data = result.get("data") or {}
            for entry in data.get("exports") or []:
                if isinstance(entry, dict):
                    addr = normalize_addr(entry.get("address"))
                    if addr:
                        exports.setdefault(addr, entry.get("name") or "")
    return exports


def function_addr_range(project_name: str, fallback_addrs) -> Optional[tuple]:
    """样本函数地址范围 (min, max)。

    优先取黑板 functions_extract.json 的全量函数地址（真正的"样本尾部区间"语义）。
    注意必须直读文件：bb_read_extract 对 functions 类数据会按 chunk 分片，
    默认只返回前 100 个函数，无法得到全量地址范围。
    读取失败时回退到 fallback_addrs（候选 + 导出地址集合）的 min/max；
    全都不可用时返回 None（尾部条件退化为不启用，不误伤候选）。
    """
    addrs: list[int] = []
    if project_name:
        path = board_path(project_name, "extracts", "functions_extract.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict):
            for entry in data.get("functions") or []:
                if isinstance(entry, dict):
                    parsed = parse_addr(entry.get("address"))
                    if parsed is not None:
                        addrs.append(parsed)
    if not addrs:
        for item in fallback_addrs or []:
            parsed = parse_addr(item)
            if parsed is not None:
                addrs.append(parsed)
    if not addrs:
        return None
    return (min(addrs), max(addrs))


def tail_start_addr(addr_range: tuple, tail_ratio: float) -> int:
    """尾部区间起点：min + (max - min) * tail_ratio。"""
    lo, hi = addr_range
    return lo + int((hi - lo) * tail_ratio)


def is_likely_library_function(
    candidate: dict,
    *,
    export_addrs: dict,
    xref_threshold: int,
    tail_start: Optional[int],
    size_max: int,
) -> bool:
    """库函数（CRT/运行时）启发判定，以下条件需同时满足：

    - xrefs 超过阈值（真实样本中运行时库函数调用面极宽）；
    - 无名函数（空名或 sub_ 前缀）；
    - 地址位于样本高地址尾部区间（tail_start 为 None 时该条件不满足，不误伤）；
    - size 未知（0）或不超过 size_max（size_max<=0 表示不启用 size 条件）。

    导出函数永远豁免（导出地址集合内的候选直接判非库函数）。
    """
    addr_n = normalize_addr(candidate.get("func_addr"))
    if addr_n and addr_n in export_addrs:
        return False
    try:
        xrefs = int(candidate.get("xrefs") or 0)
    except (TypeError, ValueError):
        xrefs = 0
    if xrefs <= xref_threshold:
        return False
    if not is_unnamed_func(candidate.get("func_name")):
        return False
    if tail_start is None:
        return False
    parsed = parse_addr(candidate.get("func_addr"))
    if parsed is None or parsed < tail_start:
        return False
    if size_max > 0:
        try:
            size = int(candidate.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        # 函数索引普遍提取不到 size（恒 0），未知不阻断排除
        if size > size_max:
            return False
    return True


def _synthesized_export_candidate(addr: str, name: str) -> dict:
    """为 LLM 候选中缺失的导出函数合成最小条目（字段与 FuncCandidate 对齐）。"""
    return {
        "func_addr": addr,
        "func_name": name or f"sub_{addr[2:]}",
        "size": 0,
        "xrefs": 0,
        "is_thunk": False,
        "is_export": True,
        "analysis_priority": 10,
        "priority_reason": "导出函数（代码护栏强制置顶）",
    }


def synthesized_human_candidate(addr: str) -> dict:
    """为 MODIFY 人工指定的、不在 LLM 候选中的地址合成最小条目（字段与 FuncCandidate 对齐）。

    A1 缺陷修复：原实现把不在 LLM candidates 里的 MODIFY 地址过滤丢弃，
    人工指定语义被静默破坏；现改为无条件采纳（合成条目补入）。
    """
    return {
        "func_addr": addr,
        "func_name": f"sub_{addr[2:]}" if addr.startswith("0x") else f"sub_{addr}",
        "size": 0,
        "xrefs": 0,
        "is_thunk": False,
        "is_export": False,
        "analysis_priority": 10,
        "priority_reason": "人工 MODIFY 指定（不在 LLM 候选中，无条件采纳）",
    }


def apply_candidate_guards(
    candidates: list,
    export_addrs: dict,
    *,
    top_n: int = DEFAULT_TOP_N,
    xref_threshold: int = DEFAULT_LIB_XREF_THRESHOLD,
    tail_ratio: float = DEFAULT_LIB_TAIL_RATIO,
    size_max: int = DEFAULT_LIB_SIZE_MAX,
    addr_range: Optional[tuple] = None,
    min_priority: int = MIN_ANALYSIS_PRIORITY,
) -> list:
    """护栏主入口：导出置顶 + 库函数排除 + 按 analysis_priority 补足 Top N。

    Args:
        candidates: LLM（function_boundary_detector）输出的候选 dict 列表。
        export_addrs: collect_export_addrs 的导出地址 → 名映射（规范化地址为键）。
        top_n: 候选数量上限。
        xref_threshold / tail_ratio / size_max: 库函数判定阈值（见模块 docstring）。
        addr_range: 样本函数地址范围 (min, max)；None 时用候选+导出地址估算。
        min_priority: LLM 候选补足的最低优先级（沿用旧的 >=7 语义）。

    Returns:
        新的候选 dict 列表（不修改入参），导出条目在前，整体截断到 top_n。
    """
    # 拷贝条目，避免护栏写标记（is_export）时污染图状态里的原始 LLM 输出
    cands = [dict(c) for c in candidates if isinstance(c, dict)]

    if addr_range is None:
        addr_range = function_addr_range(
            "", [c.get("func_addr") for c in cands] + list(export_addrs)
        )
    tail_start = tail_start_addr(addr_range, tail_ratio) if addr_range else None

    # 1. 库函数排除（导出豁免在判定函数内）；保留原顺序
    kept = [
        c for c in cands
        if not is_likely_library_function(
            c,
            export_addrs=export_addrs,
            xref_threshold=xref_threshold,
            tail_start=tail_start,
            size_max=size_max,
        )
    ]
    kept_by_addr = {}
    for c in kept:
        addr_n = normalize_addr(c.get("func_addr"))
        if addr_n and addr_n not in kept_by_addr:
            kept_by_addr[addr_n] = c

    # 2. 导出函数强制置顶：已在候选里的复用条目（补 is_export 标记），
    #    缺失的合成最小条目补入
    export_entries = []
    for addr, name in export_addrs.items():
        existing = kept_by_addr.get(addr)
        if existing is not None:
            existing["is_export"] = True
            export_entries.append(existing)
        else:
            export_entries.append(_synthesized_export_candidate(addr, name))

    # 3. 其余 LLM 候选按 analysis_priority 降序（稳定排序，同级保持 LLM 原顺序），
    #    过滤 min_priority 后补足剩余位置
    rest = [
        c for c in kept
        if normalize_addr(c.get("func_addr")) not in export_addrs
        and (c.get("analysis_priority") or 0) >= min_priority
    ]
    rest.sort(key=lambda c: c.get("analysis_priority") or 0, reverse=True)

    return (export_entries + rest)[:top_n]
