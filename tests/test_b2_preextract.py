"""B2 批次测试：Phase -1 预提取加码（字符串分类增强 / API 功能分类 / 函数四桶分桶）
+ 反编译失败 fallback 路由（decompile_failed 标注与 prompt 反汇编专项段切换）。

- 分类提取用合成数据验证规则正确性；
- 四桶分桶额外用真实 fixture（data/input/module.upx_export_for_ai）验证一次：
  exports 桶应含 ordinal_1（0x180013d80）/ ordinal_2（0x180056920），
  library_suspect 桶应含 0x1800b0160 等高 xref 尾部函数；
- fallback 用合成目录 + 真实 fixture 双验证（0x180013d80 反编译失败只有反汇编）。
"""
import json
import os

import pytest

from tools.blackboard_tools import board_base_dir, load_function_data
from tools.file_loaders import (
    load_function_index,
    load_imports,
    load_strings,
    pre_extract_sample,
)
from workers.phase3.function_deep_analyzer import build_func_analysis_prompt
from workers.topics.topic_prompts import build_topic_prompt

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "data", "input", "module.upx_export_for_ai"
)


# === 合成数据构造 ==============================================================

def _write_strings_txt(path):
    """合成 strings.txt：标准 `addr | len | type | text` 行 + 一行纯文本兼容。"""
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n\n")
        f.write("0x180171968 | 28 | ASCII | http://evil.example.com/beacon\n")
        f.write("0x180171970 | 15 | ASCII | 45.77.123.10:8080\n")
        f.write("0x180171980 | 45 | ASCII | HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n")
        f.write("0x180171990 | 24 | ASCII | C:\\Windows\\Temp\\stage.dat\n")
        f.write("0x1801719a0 | 26 | ASCII | %APPDATA%\\Microsoft\\cache\n")
        f.write("0x1801719b0 | 18 | ASCII | Global\\MyMutex_123\n")
        f.write("0x1801719c0 | 30 | ASCII | cmd /c powershell -enc SQBFAFgA\n")
        f.write("0x1801719d0 | 38 | ASCII | D:\\work\\rat\\server\\Release\\server.pdb\n")
        f.write("0x1801719e0 | 18 | ASCII | c2.evil-domain.xyz\n")
        f.write("0x1801719f0 | 12 | ASCII | kernel32.dll\n")  # 不应误判为域名
        f.write("0x180171a00 |  5 | ASCII | hello\n")
        f.write("plain text line without header\n")  # 非标准行兼容


def _write_imports_addr_style(path):
    """合成 imports.txt（真实 fixture 同款 addr:name 格式）。"""
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Imports\n# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        f.write("0x1801710f0:VirtualAllocEx\n")
        f.write("0x1801710f8:CreateRemoteThread\n")
        f.write("0x180171100:IsDebuggerPresent\n")
        f.write("0x180171108:CryptEncrypt\n")
        f.write("0x180171110:InternetOpenA\n")
        f.write("0x180171118:RegSetValueExA\n")
        f.write("0x180171120:CreateFileA\n")
        f.write("0x180171128:CreateProcessW\n")
        f.write("0x180171130:GetLocalTime\n")


def _func_block(name, address, calls, ftype="decompile"):
    """构造一个 function_index.txt 函数块（80 列 '=' 分隔，真实格式）。"""
    callee_lines = "\n".join(
        f"  - 0x10002000 (sub_10002000) -> decompile/10002000.c" for _ in range(calls)
    )
    calls_section = f"Calls ({calls}):\n{callee_lines}" if calls else "Calls: none"
    return (
        "=" * 80 + "\n"
        f"Function: {name}\n"
        f"Address: {address}\n"
        f"File: decompile/{address[2:]}.c\n"
        f"Type: {ftype}\n\n"
        "Called by: none\n\n"
        f"{calls_section}\n\n"
    )


def _write_function_index_txt(path):
    """合成 function_index.txt：4 函数覆盖四桶。

    地址范围 0x10001000..0x10010000 → tail_start = 0x10001000 + int(0xF000*0.45)
    = 0x10007C00；0x10009000 位于尾部区间且 Calls(60) > 阈值 50。
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Function Index\n# Total exported: 4\n")
        f.write("#" + "=" * 79 + "\n\n")
        f.write(_func_block("DllMain", "0x10001000", 3))            # exports 桶
        f.write(_func_block("my_function", "0x10002000", 5))        # named 桶
        f.write(_func_block("sub_10009000", "0x10009000", 60))      # library_suspect 桶
        f.write(_func_block("sub_10010000", "0x10010000", 2))       # other 桶


def _write_exports_txt(path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Exports\n# Format: func-addr:func-name\n\n")
        f.write("0x10001000:DllMain\n")


def _make_synthetic_export_dir(tmp_path):
    """建最小合成导出目录（strings/imports/exports/function_index + 反汇编目录）。"""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    _write_strings_txt(str(export_dir / "strings.txt"))
    _write_imports_addr_style(str(export_dir / "imports.txt"))
    _write_exports_txt(str(export_dir / "exports.txt"))
    _write_function_index_txt(str(export_dir / "function_index.txt"))
    (export_dir / "decompile").mkdir()
    (export_dir / "disassembly").mkdir()
    return str(export_dir)


def _read_extract(tmp_path, project, name):
    path = os.path.join(
        str(tmp_path), board_base_dir(), project, "extracts", name
    )
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# === 字符串分类增强 ============================================================

def test_strings_categorized_synthetic(tmp_path):
    """8 类字符串确定性归类：各类计数精确，kernel32.dll 不误判为域名。"""
    export_dir = _make_synthetic_export_dir(tmp_path)
    result = pre_extract_sample(export_dir, "b2cat", output_base=str(tmp_path))
    assert result["status"] == "success"

    data = _read_extract(tmp_path, "b2cat", "strings_categorized.json")
    counts = data["category_counts"]
    assert data["total_count"] == 12
    assert counts["urls"] == 1
    assert counts["ips"] == 1
    assert counts["registry_paths"] == 1
    assert counts["file_paths"] == 2          # 盘符 + %ENV% 各一
    assert counts["mutex_candidates"] == 1
    assert counts["command_lines"] == 1
    assert counts["pdb_paths"] == 1
    assert counts["domains"] == 1             # c2.evil-domain.xyz
    # 明细带原文与地址
    url_items = data["categories"]["urls"]["items"]
    assert url_items[0]["text"] == "http://evil.example.com/beacon"
    assert url_items[0]["address"] == "0x180171968"
    # kernel32.dll / hello / 纯文本行不进任何类别
    assert sum(counts.values()) == 9


# === API 功能分类 ==============================================================

def test_imports_categorized_addr_name_format(tmp_path):
    """addr:name 格式（真实 fixture 同款）：七类单归属计数精确。"""
    export_dir = _make_synthetic_export_dir(tmp_path)
    pre_extract_sample(export_dir, "b2imp", output_base=str(tmp_path))

    data = _read_extract(tmp_path, "b2imp", "imports_categorized.json")
    counts = data["category_counts"]
    assert data["total_count"] == 9
    assert counts["injection"] == 2     # VirtualAllocEx + CreateRemoteThread
    assert counts["anti_debug"] == 1    # IsDebuggerPresent
    assert counts["crypto"] == 1        # CryptEncrypt
    assert counts["network"] == 1       # InternetOpenA
    assert counts["registry"] == 1      # RegSetValueExA
    assert counts["file"] == 1          # CreateFileA
    assert counts["process"] == 1       # CreateProcessW
    assert counts["other"] == 1         # GetLocalTime
    # 明细保留 api 名与原始行
    inj_items = data["categories"]["injection"]["items"]
    assert {i["api"] for i in inj_items} == {"VirtualAllocEx", "CreateRemoteThread"}
    assert inj_items[0]["raw"].startswith("0x1801710f0:")


def test_imports_categorized_dll_section_format(tmp_path):
    """DLL 分节格式兼容：DLL 行不计入 API，dll 字段正确归属。"""
    export_dir = tmp_path / "export_dll"
    export_dir.mkdir()
    with open(str(export_dir / "imports.txt"), "w", encoding="utf-8") as f:
        f.write("kernel32.dll\nVirtualAllocEx\nCreateFileA\n")
        f.write("advapi32.dll\nRegOpenKeyExA\n")
    result = pre_extract_sample(str(export_dir), "b2impdll", output_base=str(tmp_path))
    assert result["status"] == "success"

    data = _read_extract(tmp_path, "b2impdll", "imports_categorized.json")
    assert data["total_count"] == 3
    assert data["dll_names"] == ["kernel32.dll", "advapi32.dll"]
    counts = data["category_counts"]
    assert counts["injection"] == 1
    assert counts["file"] == 1
    assert counts["registry"] == 1
    reg_item = data["categories"]["registry"]["items"][0]
    assert reg_item["dll"] == "advapi32.dll"


# === 函数索引四桶分桶 ============================================================

def test_functions_buckets_synthetic(tmp_path):
    """四桶分桶：exports / named / library_suspect / other 归属精确（护栏同款规则）。"""
    export_dir = _make_synthetic_export_dir(tmp_path)
    pre_extract_sample(export_dir, "b2bucket", output_base=str(tmp_path))

    data = _read_extract(tmp_path, "b2bucket", "functions_buckets.json")
    assert data["total_count"] == 4
    counts = data["bucket_counts"]
    assert counts["exports"] == 1
    assert counts["named"] == 1
    assert counts["library_suspect"] == 1
    assert counts["other"] == 1
    assert sum(counts.values()) == 4

    buckets = data["buckets"]
    assert buckets["exports"]["functions"][0]["address"] == "0x10001000"
    assert buckets["exports"]["functions"][0]["export_name"] == "DllMain"
    assert buckets["named"]["functions"][0]["name"] == "my_function"
    lib = buckets["library_suspect"]["functions"][0]
    assert lib["address"] == "0x10009000"      # 高 xref(60) + 无名 + 尾部区间
    assert buckets["other"]["functions"][0]["address"] == "0x10010000"
    # 分桶规则随产物落盘（可审计）
    assert data["rules"]["xref_threshold"] == 50
    assert data["rules"]["tail_start_addr"] == "0x10007c00"


def test_functions_buckets_real_fixture(tmp_path):
    """真实 fixture 验证：exports 桶含 ordinal_1/2 地址，library_suspect 含 0x1800B0160。"""
    if not os.path.exists(FIXTURE_DIR):
        pytest.skip("Fixture data not found")

    result = pre_extract_sample(FIXTURE_DIR, "b2real", output_base=str(tmp_path))
    assert result["status"] == "success"

    data = _read_extract(tmp_path, "b2real", "functions_buckets.json")
    assert data["total_count"] == 2694
    counts = data["bucket_counts"]
    assert sum(counts.values()) == 2694

    buckets = data["buckets"]
    export_addrs = {f["address"].lower() for f in buckets["exports"]["functions"]}
    assert "0x180013d80" in export_addrs      # ordinal_1
    assert "0x180056920" in export_addrs      # ordinal_2
    assert "0x180146c9c" in export_addrs      # DllEntryPoint
    assert counts["exports"] == 3

    lib_addrs = {f["address"].lower() for f in buckets["library_suspect"]["functions"]}
    assert "0x1800b0160" in lib_addrs          # 高 xref(173) 尾部无名函数

    # 反编译失败标记：ordinal_1 是 disassembly-fallback 函数
    ordinal1 = next(
        f for f in buckets["exports"]["functions"] if f["address"].lower() == "0x180013d80"
    )
    assert ordinal1["decompile_failed"] is True
    assert ordinal1["type"] == "disassembly-fallback"


def test_categorized_extracts_real_fixture_counts(tmp_path):
    """真实 fixture 的字符串/API 分类产物存在且计数闭环合理。"""
    if not os.path.exists(FIXTURE_DIR):
        pytest.skip("Fixture data not found")

    pre_extract_sample(FIXTURE_DIR, "b2real2", output_base=str(tmp_path))

    strings_data = _read_extract(tmp_path, "b2real2", "strings_categorized.json")
    assert strings_data["total_count"] == 1962
    s_counts = strings_data["category_counts"]
    assert set(s_counts) == {
        "pdb_paths", "urls", "ips", "registry_paths", "command_lines",
        "mutex_candidates", "file_paths", "domains",
    }
    assert sum(s_counts.values()) <= 1962
    # 真实样本（UPX 加壳）实测：registry_paths=2、file_paths=8，无 PDB/URL 明文
    assert s_counts["registry_paths"] >= 1
    assert s_counts["file_paths"] >= 1

    imports_data = _read_extract(tmp_path, "b2real2", "imports_categorized.json")
    assert imports_data["total_count"] == 243
    i_counts = imports_data["category_counts"]
    assert sum(i_counts.values()) == 243
    # 真实样本含注入三件套相关导入
    inj_apis = {i["api"] for i in imports_data["categories"]["injection"]["items"]}
    assert "VirtualAllocEx" in inj_apis
    assert "CreateRemoteThread" in inj_apis


# === Worker 工具侧：产物优先 + 回退兼容 ==========================================

def test_load_strings_prefers_categorized_extract(tmp_path, monkeypatch):
    """load_strings 传 project_name 且产物存在时走分类产物，all_strings 置空。"""
    export_dir = _make_synthetic_export_dir(tmp_path)
    pre_extract_sample(export_dir, "b2tool", output_base=str(tmp_path))
    monkeypatch.chdir(tmp_path)

    result = load_strings(os.path.join(export_dir, "strings.txt"), project_name="b2tool")
    assert result["status"] == "success"
    assert result["source"] == "extracts/strings_categorized.json"
    assert result["all_strings"] == []  # 分类产物不含全量原文
    assert result["urls"] == ["http://evil.example.com/beacon"]
    assert result["mutex_names"] == ["Global\\MyMutex_123"]
    assert result["powershell_params"] == ["cmd /c powershell -enc SQBFAFgA"]
    assert result["categorized"]["category_counts"]["domains"] == 1


def test_load_strings_falls_back_without_extract(tmp_path):
    """产物不存在（不传 project_name / 黑板无产物）时回退原始解析，行为不变。"""
    export_dir = _make_synthetic_export_dir(tmp_path)
    strings_path = os.path.join(export_dir, "strings.txt")

    plain = load_strings(strings_path)
    assert plain["source"] == "raw_file"
    # 现有原始解析不过滤 # 注释行、不拆分 `addr | len | type | text` 前缀
    # （历史行为，不在本批次改动范围；URL 等分类能力由分类产物路径提供）
    assert len(plain["all_strings"]) == 14
    assert "0x180171968 | 28 | ASCII | http://evil.example.com/beacon" in plain["all_strings"]

    ghost = load_strings(strings_path, project_name="ghost_proj")
    assert ghost["source"] == "raw_file"
    assert len(ghost["all_strings"]) == 14


def test_load_imports_prefers_categorized_extract(tmp_path, monkeypatch):
    """load_imports 走分类产物时 api_categories 映射正确且保留七类原文。"""
    export_dir = _make_synthetic_export_dir(tmp_path)
    pre_extract_sample(export_dir, "b2tooli", output_base=str(tmp_path))
    monkeypatch.chdir(tmp_path)

    result = load_imports(os.path.join(export_dir, "imports.txt"), project_name="b2tooli")
    assert result["source"] == "extracts/imports_categorized.json"
    assert len(result["imports"]) == 9
    inj = result["api_categories"]["process_injection"]
    assert any("VirtualAllocEx" in s for s in inj)
    assert any("CreateRemoteThread" in s for s in inj)
    assert result["categorized"]["category_counts"]["crypto"] == 1

    # 回退路径不受影响
    plain = load_imports(os.path.join(export_dir, "imports.txt"))
    assert plain["source"] == "raw_file"


def test_load_function_index_prefers_buckets(tmp_path, monkeypatch):
    """load_function_index 走分桶产物：四桶结构 + 合并列表带 bucket 标记。"""
    export_dir = _make_synthetic_export_dir(tmp_path)
    pre_extract_sample(export_dir, "b2toolf", output_base=str(tmp_path))
    monkeypatch.chdir(tmp_path)

    result = load_function_index(
        os.path.join(export_dir, "function_index.txt"), project_name="b2toolf"
    )
    assert result["source"] == "extracts/functions_buckets.json"
    assert result["total_functions"] == 4
    assert result["bucket_counts"] == {
        "exports": 1, "named": 1, "library_suspect": 1, "other": 1,
    }
    by_addr = {f["address"]: f for f in result["functions"]}
    assert by_addr["0x10001000"]["bucket"] == "exports"
    assert by_addr["0x10009000"]["bucket"] == "library_suspect"
    assert by_addr["0x10009000"]["xrefs"] == 60

    # 回退路径：无产物时走原始解析
    plain = load_function_index(os.path.join(export_dir, "function_index.txt"))
    assert plain["source"] == "raw_file"


# === 反编译失败 fallback 路由 =====================================================

def test_load_function_data_marks_decompile_failed(tmp_path):
    """反编译缺失时 decompile_failed=True（数据行为不变，仅显式标注）。"""
    export_dir = tmp_path / "export"
    (export_dir / "decompile").mkdir(parents=True)
    (export_dir / "disassembly").mkdir(parents=True)
    # 只有反汇编的函数（fallback）
    with open(str(export_dir / "disassembly" / "1000A000.asm"), "w", encoding="utf-8") as f:
        f.write("mov eax, 0x5A\nxor ebx, ebx\ncall dword ptr [0x1801710f0]\n")
    # 有反编译的正常函数
    with open(str(export_dir / "decompile" / "10001000.c"), "w", encoding="utf-8") as f:
        f.write("int __fastcall sub_10001000() { return 0; }\n")

    fallback = load_function_data("0x1000a000", str(export_dir))  # 地址小写、文件名大写
    assert fallback["status"] == "success"
    assert fallback["decompile_failed"] is True
    assert fallback["decompile_snippet"] is None
    assert "mov eax" in fallback["disassembly_snippet"]

    normal = load_function_data("0x10001000", str(export_dir))
    assert normal["decompile_failed"] is False
    assert "sub_10001000" in normal["decompile_snippet"]


def test_load_function_data_real_fallback_addr():
    """真实 fixture：核心函数 ordinal_1（0x180013d80）反编译失败只有反汇编。"""
    if not os.path.exists(FIXTURE_DIR):
        pytest.skip("Fixture data not found")

    result = load_function_data("0x180013d80", FIXTURE_DIR)
    assert result["status"] == "success"
    assert result["decompile_failed"] is True
    assert result["decompile_snippet"] is None
    assert result["disassembly_snippet"]  # 反汇编 fallback 可用

    normal = load_function_data("0x180001000", FIXTURE_DIR)
    assert normal["decompile_failed"] is False
    assert normal["decompile_snippet"]


def test_func_prompt_switches_to_disasm_section():
    """decompile_failed=True 时函数 prompt 出现反汇编专项段；正常函数不出现。"""
    fallback_data = {
        "size": 31510,
        "decompile_failed": True,
        "decompile_snippet": None,
        "disassembly_snippet": "push rbp\nmov rbp, rsp\ncall qword ptr [rip+0x1234]",
    }
    prompt = build_func_analysis_prompt("0x180003E80", "sub_180003E80", fallback_data)
    assert "反编译失败函数专项分析要求" in prompt
    assert "API 调用序列" in prompt
    assert "断点" in prompt
    assert "常量与魔数" in prompt

    normal = build_func_analysis_prompt(
        "0x180001000", "sub_180001000",
        {"size": 128, "decompile_snippet": "void fn() {}", "decompile_failed": False},
    )
    assert "反编译失败函数专项分析要求" not in normal


def test_topic_prompt_marks_fallback_functions():
    """主题 prompt：fallback 函数标题行标记 + 专项要求段只注入一次。"""
    contexts = [
        {"addr": "0x180013d80", "name": "module_windows_1", "decompile_failed": True,
         "decompile_snippet": None, "disassembly_snippet": "mov eax, 1\ncall rbx"},
        {"addr": "0x180056920", "name": "sub_180056920",
         "decompile_snippet": "int fn() { return 1; }", "disassembly_snippet": ""},
    ]
    prompt = build_topic_prompt("export_interface", ["0x180013d80", "0x180056920"], contexts)
    assert "反编译失败函数专项要求" in prompt
    assert prompt.count("反编译失败函数专项要求") == 1  # 多 fallback 也只注入一次
    assert "===== 函数 module_windows_1 (0x180013d80)（反编译失败，只有反汇编） =====" in prompt
    assert "===== 函数 sub_180056920 (0x180056920) =====" in prompt  # 正常函数不标记

    normal = build_topic_prompt("stealer", ["0x180056920"], contexts[1:])
    assert "反编译失败函数专项要求" not in normal
