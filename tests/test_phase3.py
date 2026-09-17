import os
import tempfile
import pytest

from tools.blackboard_tools import load_function_data
from workers.phase3.function_deep_analyzer import build_func_analysis_prompt, function_deep_analyzer


def test_load_function_data_reads_decompile():
    fixture_dir = os.path.join(os.path.dirname(__file__), "..", "data", "module.upx_export_for_ai")
    if not os.path.exists(fixture_dir):
        pytest.skip("Fixture data not found")

    result = load_function_data("0x180001000", fixture_dir)
    assert result["status"] == "success"
    assert result["addr"] == "0x180001000"
    assert "decompile_snippet" in result or "disassembly_snippet" in result


def test_func_analyzer_prompt_includes_constraints():
    prompt = build_func_analysis_prompt(
        func_addr="0x180001000",
        func_name="sub_180001000",
        func_data={"size": 128, "decompile_snippet": "void fn() {}"}
    )
    assert "0x180001000" in prompt
    assert "1000 tokens" in prompt
    assert "functionality" in prompt


def test_function_deep_analyzer_exists():
    assert function_deep_analyzer.name == "function_deep_analyzer"


def test_build_func_analysis_prompt_truncation():
    """Prompt should truncate decompile/disassembly to 2500 chars and 120 lines."""
    from workers.phase3.function_deep_analyzer import build_func_analysis_prompt
    long_decompile = "A" * 5000
    long_disasm = "B" * 5000
    func_data = {
        "decompile_snippet": long_decompile,
        "disassembly_snippet": long_disasm,
        "size": 256,
        "xrefs_in": ["0x401000"],
        "xrefs_out": ["0x402000"],
    }
    prompt = build_func_analysis_prompt("0x403000", "sub_403000", func_data)
    assert prompt.count("A") <= 2503  # 2500 from snippet + 3 from "API" in template
    assert prompt.count("B") <= 2500
    assert "120" in prompt


def test_func_analysis_prompt_includes_guides_and_project():
    from workers.phase3.function_deep_analyzer import build_func_analysis_prompt
    func_data = {
        "status": "success",
        "decompile_snippet": "int __fastcall sub_401000(int a1) { return a1 + 1; }",
        "disassembly_snippet": "",
    }
    prompt = build_func_analysis_prompt(
        "0x401000", "sub_401000", func_data,
        guides="=== Rust 样本静态分析方法论 ===\n禁止遍历全部函数",
        project_name="demo_proj",
    )
    assert "Rust 样本静态分析方法论" in prompt
    assert "demo_proj" in prompt
    assert "load_arch_guide" in prompt

    # 默认参数向后兼容
    prompt_default = build_func_analysis_prompt("0x401000", "sub_401000", func_data)
    assert "专项分析方法论" not in prompt_default
