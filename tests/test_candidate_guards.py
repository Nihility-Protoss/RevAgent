"""A0 候选函数护栏测试（candidate_guards + _select_phase3_candidates 接线）。

覆盖：导出函数强制置顶、库函数排除（xrefs 阈值 + 无名 sub_ + 高地址尾部）、
Top N 截断、MODIFY 人工列表不受护栏影响、配置项生效、黑板兜底数据源。
全部为纯 Python 确定性逻辑，不发起 LLM 调用。
"""
import json
import os

import pytest

from candidate_guards import (
    apply_candidate_guards,
    collect_export_addrs,
    function_addr_range,
    is_likely_library_function,
    is_unnamed_func,
    normalize_addr,
    tail_start_addr,
)
from graph_nodes import _select_phase3_candidates
from tools.blackboard_tools import board_path


def _candidate(addr, name=None, xrefs=10, size=128, priority=9, is_export=False):
    return {
        "func_addr": addr,
        "func_name": name if name is not None else f"sub_{addr[2:]}",
        "size": size,
        "xrefs": xrefs,
        "is_thunk": False,
        "is_export": is_export,
        "analysis_priority": priority,
        "priority_reason": "测试",
    }


def _boundary(*cands):
    return {"status": "success", "total_functions": len(cands), "candidates": list(cands)}


# === 地址与命名工具函数 ===================================================================

def test_normalize_addr():
    assert normalize_addr("0x180013D80") == "0x180013d80"
    assert normalize_addr("180013d80") == "0x180013d80"
    assert normalize_addr(" 0X401000 ") == "0x401000"
    assert normalize_addr("不是地址") == ""
    assert normalize_addr(None) == ""
    assert normalize_addr(123) == ""


def test_is_unnamed_func():
    assert is_unnamed_func("sub_1800B0160")
    assert is_unnamed_func("SUB_401000")  # 大小写不敏感
    assert is_unnamed_func("")
    assert is_unnamed_func(None)
    assert not is_unnamed_func("module_windows_2")
    assert not is_unnamed_func("DllEntryPoint")


def test_tail_start_addr():
    assert tail_start_addr((0x1000, 0x11000), 0.5) == 0x9000


# === 库函数判定（is_likely_library_function） ==============================================

def test_library_function_judgement():
    export_addrs = {"0xa200": "ordinal_1"}
    # 同时满足：xrefs 高 + 无名 + 尾部 + size 小 → 库函数
    assert is_likely_library_function(
        _candidate("0xa000", xrefs=100, size=64),
        export_addrs=export_addrs, xref_threshold=50, tail_start=0x9000, size_max=512,
    )
    # xrefs 不超过阈值 → 不排除
    assert not is_likely_library_function(
        _candidate("0xa000", xrefs=50),
        export_addrs=export_addrs, xref_threshold=50, tail_start=0x9000, size_max=512,
    )
    # 命名函数（如 module_windows_2）→ 不排除
    assert not is_likely_library_function(
        _candidate("0xa000", name="module_windows_2", xrefs=100),
        export_addrs=export_addrs, xref_threshold=50, tail_start=0x9000, size_max=512,
    )
    # 不在尾部区间 → 不排除
    assert not is_likely_library_function(
        _candidate("0x2000", xrefs=100),
        export_addrs=export_addrs, xref_threshold=50, tail_start=0x9000, size_max=512,
    )
    # 导出函数永远豁免（即使其余特征全部命中）
    assert not is_likely_library_function(
        _candidate("0xA200", xrefs=200),
        export_addrs=export_addrs, xref_threshold=50, tail_start=0x9000, size_max=512,
    )
    # size 未知（0）不阻断；size 明确超过 size_max 则不排除
    assert is_likely_library_function(
        _candidate("0xa000", xrefs=100, size=0),
        export_addrs=export_addrs, xref_threshold=50, tail_start=0x9000, size_max=512,
    )
    assert not is_likely_library_function(
        _candidate("0xa000", xrefs=100, size=2000),
        export_addrs=export_addrs, xref_threshold=50, tail_start=0x9000, size_max=512,
    )
    # 地址范围未知（tail_start=None）时尾部条件不启用，不误伤
    assert not is_likely_library_function(
        _candidate("0xa000", xrefs=100),
        export_addrs=export_addrs, xref_threshold=50, tail_start=None, size_max=512,
    )


# === 导出地址收集（collect_export_addrs） ====================================================

def test_collect_export_addrs_from_state():
    state = {
        "export_interface_analysis": {
            "ordinal_mapping": [
                {"ordinal": 1, "name": "ordinal_1", "address": "0x180013D80"},
                {"ordinal": 2, "name": "ordinal_2", "address": "0x180056920"},
            ],
            "suspicious_exports": [{"name": "DllEntryPoint", "address": "0x180146C9C"}],
        },
    }
    addrs = collect_export_addrs(state, "nonexistent_project")
    assert list(addrs) == ["0x180013d80", "0x180056920", "0x180146c9c"]
    assert addrs["0x180013d80"] == "ordinal_1"


def test_collect_export_addrs_falls_back_to_blackboard(tmp_path, monkeypatch):
    """state 无 export_interface_analysis 时，从黑板 exports_extract.json 兜底。"""
    monkeypatch.chdir(tmp_path)
    os.makedirs(board_path("proj", "extracts"))
    with open(board_path("proj", "extracts", "exports_extract.json"), "w", encoding="utf-8") as f:
        json.dump({"total_count": 2, "exports": [
            {"address": "0x180013d80", "name": "ordinal_1"},
            {"address": None, "name": "无地址条目跳过"},
        ]}, f, ensure_ascii=False)
    addrs = collect_export_addrs({}, "proj")
    assert addrs == {"0x180013d80": "ordinal_1"}


def test_collect_export_addrs_all_sources_missing(tmp_path, monkeypatch):
    """所有来源缺失时静默降级为空映射。"""
    monkeypatch.chdir(tmp_path)
    assert collect_export_addrs({}, "ghost") == {}


# === 地址范围（function_addr_range） =========================================================

def test_function_addr_range_reads_full_extract_not_chunked(tmp_path, monkeypatch):
    """必须直读 functions_extract.json 全量（bb_read_extract 分片只返回前 100 条）。"""
    monkeypatch.chdir(tmp_path)
    os.makedirs(board_path("proj", "extracts"))
    funcs = [{"address": f"0x{0x180001000 + i * 0x100:x}", "name": f"f{i}",
              "size": 0, "xrefs_count": 0} for i in range(300)]
    with open(board_path("proj", "extracts", "functions_extract.json"), "w", encoding="utf-8") as f:
        json.dump({"total_count": 300, "functions": funcs, "chunk_size": 100, "chunks": 3}, f)
    lo, hi = function_addr_range("proj", [])
    assert lo == 0x180001000
    assert hi == 0x180001000 + 299 * 0x100  # 第 300 个函数，证明未被分片截断


def test_function_addr_range_fallback_to_given_addrs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # 无黑板
    assert function_addr_range("ghost", ["0x401000", "0x409000"]) == (0x401000, 0x409000)
    assert function_addr_range("ghost", []) is None


# === 护栏主入口（apply_candidate_guards） =====================================================

def test_guards_force_exports_to_top_even_when_absent_from_candidates():
    """导出函数不在 LLM 候选里时合成条目置顶，在候选里时复用并提前。"""
    cands = [_candidate("0x401000", xrefs=9), _candidate("0x402000", xrefs=8)]
    export_addrs = {"0x180013d80": "ordinal_1", "0x402000": "ordinal_2"}
    result = apply_candidate_guards(
        cands, export_addrs, addr_range=(0x401000, 0x500000),
    )
    addrs = [c["func_addr"] for c in result]
    assert addrs[:2] == ["0x180013d80", "0x402000"]  # 导出按 export_addrs 顺序置顶
    synthesized = result[0]
    assert synthesized["is_export"] is True
    assert synthesized["analysis_priority"] == 10
    assert synthesized["func_name"] == "ordinal_1"
    # 已在候选中的导出复用原条目（保留 LLM 填的元数据），仅补 is_export 标记
    reused = result[1]
    assert reused["xrefs"] == 8 and reused["is_export"] is True
    # 其余候选按 priority 补足
    assert addrs[2] == "0x401000"


def test_guards_exclude_library_functions():
    """高 xref + 无名 + 尾部的候选被排除；导出与低地址函数保留。"""
    cands = [
        _candidate("0x1800b0160", xrefs=173),   # 尾部库函数 → 排除
        _candidate("0x18012ff60", xrefs=98),    # 尾部库函数 → 排除
        _candidate("0x180056920", name="module_windows_2", xrefs=44),  # 命名 → 保留
        _candidate("0x180003bf0", xrefs=5),     # 低地址核心函数 → 保留
    ]
    export_addrs = {"0x180013d80": "ordinal_1"}
    result = apply_candidate_guards(
        cands, export_addrs,
        xref_threshold=50, tail_ratio=0.45,
        addr_range=(0x180001000, 0x1801702BC),
    )
    addrs = [c["func_addr"] for c in result]
    assert addrs[0] == "0x180013d80"  # 导出置顶
    assert "0x1800b0160" not in addrs and "0x18012ff60" not in addrs
    assert "0x180056920" in addrs and "0x180003bf0" in addrs


def test_guards_cap_top_n_and_keep_min_priority_filter():
    """整体截断到 top_n；沿用旧的 analysis_priority>=7 过滤语义。"""
    cands = [_candidate(f"0x{0x401000 + i * 0x100:x}", priority=9) for i in range(25)]
    cands.append(_candidate("0x500000", priority=6))  # 低优先级被过滤
    result = apply_candidate_guards(cands, {}, addr_range=(0x401000, 0x500000))
    assert len(result) == 20
    assert "0x500000" not in [c["func_addr"] for c in result]

    # top_n 含导出条目：2 个导出 + 补足 LLM 候选 = top_n
    result = apply_candidate_guards(
        cands[:10], {"0x100000": "e1", "0x100100": "e2"},
        top_n=5, addr_range=(0x100000, 0x500000),
    )
    assert len(result) == 5
    assert [c["func_addr"] for c in result[:2]] == ["0x100000", "0x100100"]


def test_guards_sort_rest_by_priority_descending_stable():
    cands = [
        _candidate("0x401000", priority=8),
        _candidate("0x402000", priority=9),
        _candidate("0x403000", priority=9),  # 与上一条同级，保持原相对顺序
    ]
    result = apply_candidate_guards(cands, {}, addr_range=(0x401000, 0x403000))
    assert [c["func_addr"] for c in result] == ["0x402000", "0x403000", "0x401000"]


def test_guards_do_not_mutate_input():
    cands = [_candidate("0x401000")]
    original = json.loads(json.dumps(cands))
    apply_candidate_guards(cands, {"0x401000": "DllMain"}, addr_range=(0x401000, 0x401000))
    assert cands == original  # is_export 标记不得污染入参


# === _select_phase3_candidates 接线 ==========================================================

def test_select_candidates_modify_bypasses_guards(tmp_path, monkeypatch):
    """MODIFY 人工列表优先：即使指定的是会被护栏排除的库函数，也原样保留。"""
    monkeypatch.chdir(tmp_path)
    lib = _candidate("0x1800b0160", xrefs=300, size=32)
    state = {
        "sample_project_name": "ghost",
        "function_boundary_analysis": _boundary(lib, _candidate("0x401000")),
        "human_approved_functions": ["0x1800b0160"],
    }
    result = _select_phase3_candidates(state)
    assert [c["func_addr"] for c in result] == ["0x1800b0160"]


def test_select_candidates_applies_guards_with_state_exports(tmp_path, monkeypatch):
    """CONFIRM 路径：导出函数从 state 的 export_interface_analysis 取出并置顶。"""
    monkeypatch.chdir(tmp_path)
    state = {
        "sample_project_name": "ghost",
        "function_boundary_analysis": _boundary(_candidate("0x401000", xrefs=9)),
        "export_interface_analysis": {
            "ordinal_mapping": [{"ordinal": 1, "name": "ordinal_1", "address": "0x180013d80"}],
        },
    }
    result = _select_phase3_candidates(state)
    assert result[0]["func_addr"] == "0x180013d80"
    assert result[0]["is_export"] is True
    assert result[1]["func_addr"] == "0x401000"


def test_select_candidates_env_overrides_top_n(tmp_path, monkeypatch):
    """PHASE3_TOP_N 环境变量控制候选上限。"""
    monkeypatch.chdir(tmp_path)  # 避开仓库 config.yaml
    monkeypatch.setenv("PHASE3_TOP_N", "3")
    state = {
        "sample_project_name": "ghost",
        "function_boundary_analysis": _boundary(
            *[_candidate(f"0x{0x401000 + i * 0x100:x}") for i in range(10)]
        ),
    }
    assert len(_select_phase3_candidates(state)) == 3


def test_select_candidates_env_overrides_lib_threshold(tmp_path, monkeypatch):
    """LIB_XREF_THRESHOLD 控制库函数排除阈值。"""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LIB_XREF_THRESHOLD", "200")
    lib = _candidate("0x1800b0160", xrefs=100)  # 100 <= 200，阈值调高后不再排除
    state = {
        "sample_project_name": "ghost",
        "function_boundary_analysis": _boundary(lib),
    }
    result = _select_phase3_candidates(state)
    assert [c["func_addr"] for c in result] == ["0x1800b0160"]
