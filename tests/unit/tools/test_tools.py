import tempfile
import os
import math

from tools.file_loaders import load_strings, load_exports, load_imports, load_function_index, load_pe_info, detect_sample_type
from tools.pe_utils import calculate_entropy


# === load_strings 测试 ===

def test_load_strings_basic():
    with tempfile.TemporaryDirectory() as tmpdir:
        strings_path = os.path.join(tmpdir, "strings.txt")
        with open(strings_path, "w", encoding="utf-8") as f:
            f.write("kernel32.dll\n")
            f.write("C:\\Windows\\System32\\config.ini\n")
            f.write("http://evil.com/c2\n")
            f.write("Mozilla/5.0\n")
            f.write("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n")
            f.write("\\x00\\x01\\x02\\x03\n")

        result = load_strings(strings_path)
        assert result["status"] == "success"
        assert "all_strings" in result
        assert len(result["all_strings"]) == 6
        assert result["file_path"] == strings_path
        assert len(result["urls"]) == 1
        assert len(result["registry_paths"]) == 1
        assert len(result["data_filenames"]) == 1


def test_load_strings_not_found():
    result = load_strings("/nonexistent/strings.txt")
    assert result["status"] == "error"
    assert "not found" in result["error"].lower()


# === load_exports 测试 ===

def test_load_exports_basic():
    with tempfile.TemporaryDirectory() as tmpdir:
        exports_path = os.path.join(tmpdir, "exports.txt")
        with open(exports_path, "w", encoding="utf-8") as f:
            f.write("1 DllMain 0x401000\n")
            f.write("2 Ordinal_2 0x401200\n")
            f.write("3 InstallService 0x401400\n")
            f.write("TlsCallback_0 0x401800\n")

        result = load_exports(exports_path)
        assert result["status"] == "success"
        assert len(result["exports"]) == 4
        assert result["has_tls_callback"] is True
        assert len(result["suspicious_export_names"]) == 1
        assert result["suspicious_export_names"][0] == "3 InstallService 0x401400"
        assert len(result["ordinal_mapping"]) == 3


# === load_imports 测试 ===

def test_load_imports_basic():
    with tempfile.TemporaryDirectory() as tmpdir:
        imports_path = os.path.join(tmpdir, "imports.txt")
        with open(imports_path, "w", encoding="utf-8") as f:
            f.write("kernel32.dll\n")
            f.write("VirtualAlloc\n")
            f.write("CreateThread\n")
            f.write("advapi32.dll\n")
            f.write("RegOpenKeyExA\n")

        result = load_imports(imports_path)
        assert result["status"] == "success"
        assert "kernel32.dll" in result["dll_to_apis"]
        assert "VirtualAlloc" in result["dll_to_apis"]["kernel32.dll"]
        assert len(result["api_categories"]["process_injection"]) == 2
        assert len(result["api_categories"]["registry"]) == 1


# === load_function_index 测试 ===

def test_load_function_index_basic():
    with tempfile.TemporaryDirectory() as tmpdir:
        idx_path = os.path.join(tmpdir, "function_index.txt")
        with open(idx_path, "w", encoding="utf-8") as f:
            f.write("0x401000 DllMain 256 5\n")
            f.write("0x401200 sub_401200 128 2\n")
            f.write("0x401300 thunk_VirtualAlloc 8 0\n")

        result = load_function_index(idx_path)
        assert result["status"] == "success"
        assert result["total_functions"] == 3
        assert result["functions"][0]["name"] == "DllMain"
        assert result["functions"][0]["size"] == 256
        assert result["functions"][0]["xrefs"] == 5


# === load_pe_info 测试 ===

def test_load_pe_info_basic():
    with tempfile.TemporaryDirectory() as tmpdir:
        pe_path = os.path.join(tmpdir, "pe_info.json")
        with open(pe_path, "w", encoding="utf-8") as f:
            f.write('{"machine": "x64", "subsystem": "WINDOWS_GUI"}')

        result = load_pe_info(pe_path)
        assert result["status"] == "success"
        assert result["pe_info"]["machine"] == "x64"


# === detect_sample_type 测试 ===

def test_detect_sample_type_pe():
    with tempfile.TemporaryDirectory() as tmpdir:
        # 创建 PE 标志文件
        open(os.path.join(tmpdir, "exports.txt"), "w").close()
        open(os.path.join(tmpdir, "imports.txt"), "w").close()

        result = detect_sample_type(tmpdir)
        assert result["status"] == "success"
        assert result["sample_type"] == "pe"
        assert result["confidence"] == "high"


# === calculate_entropy 测试 ===

def test_calculate_entropy_uniform():
    """均匀分布的字节值应具有最大熵 ~8.0。
    """
    data = bytes(range(256))
    result = calculate_entropy(data)
    assert result["status"] == "success"
    assert abs(result["entropy"] - 8.0) < 0.1


def test_calculate_entropy_constant():
    """常量数据的熵应为 0。
    """
    data = b"\x00" * 256
    result = calculate_entropy(data)
    assert result["status"] == "success"
    assert result["entropy"] == 0.0


def test_calculate_entropy_high():
    """加密/压缩数据应具有高熵 > 7.0。
    """
    import random
    random.seed(42)
    data = bytes([random.randint(0, 255) for _ in range(1024)])
    result = calculate_entropy(data)
    assert result["status"] == "success"
    assert result["entropy"] > 7.0


# === data/input 自动发现测试 ===

def _make_input_root(tmpdir, names):
    input_root = os.path.join(tmpdir, "data", "input")
    for name in names:
        os.makedirs(os.path.join(input_root, name), exist_ok=True)
    return input_root


def test_find_export_dirs_filters_suffix():
    from tools.file_loaders import find_export_dirs
    with tempfile.TemporaryDirectory() as tmpdir:
        input_root = _make_input_root(tmpdir, [
            "b_export_for_ai", "a_export_for_ai", "not_an_export",
        ])
        # 文件（非目录）不应被列出
        with open(os.path.join(input_root, "file_export_for_ai"), "w") as f:
            f.write("x")
        assert find_export_dirs(input_root) == ["a_export_for_ai", "b_export_for_ai"]
        assert find_export_dirs(os.path.join(tmpdir, "missing")) == []


def test_resolve_export_dir_unique_candidate():
    from tools.file_loaders import resolve_export_dir
    with tempfile.TemporaryDirectory() as tmpdir:
        input_root = _make_input_root(tmpdir, ["sample_export_for_ai"])
        result = resolve_export_dir(project_name="anything", input_root=input_root)
        assert result["status"] == "success"
        assert result["export_dir"].endswith("sample_export_for_ai")


def test_resolve_export_dir_project_prefix_match():
    from tools.file_loaders import resolve_export_dir
    with tempfile.TemporaryDirectory() as tmpdir:
        input_root = _make_input_root(tmpdir, [
            "module.upx_export_for_ai", "other_export_for_ai",
        ])
        result = resolve_export_dir(project_name="module", input_root=input_root)
        assert result["status"] == "success"
        assert result["export_dir"].endswith("module.upx_export_for_ai")


def test_resolve_export_dir_explicit_input_name():
    from tools.file_loaders import resolve_export_dir
    with tempfile.TemporaryDirectory() as tmpdir:
        input_root = _make_input_root(tmpdir, [
            "module.upx_export_for_ai", "other_export_for_ai",
        ])
        # 省略后缀也能匹配
        result = resolve_export_dir(input_name="other", input_root=input_root)
        assert result["status"] == "success"
        assert result["export_dir"].endswith("other_export_for_ai")
        # 未知名称报错并列出候选
        bad = resolve_export_dir(input_name="nope", input_root=input_root)
        assert bad["status"] == "error"
        assert len(bad["candidates"]) == 2


def test_resolve_export_dir_ambiguous_and_empty():
    from tools.file_loaders import resolve_export_dir
    with tempfile.TemporaryDirectory() as tmpdir:
        input_root = _make_input_root(tmpdir, [
            "a_export_for_ai", "b_export_for_ai",
        ])
        result = resolve_export_dir(project_name="zzz", input_root=input_root)
        assert result["status"] == "error"
        assert "input-name" in result["error"]

        empty_root = os.path.join(tmpdir, "empty")
        os.makedirs(empty_root)
        none = resolve_export_dir(input_root=empty_root)
        assert none["status"] == "error"
        assert none["candidates"] == []
