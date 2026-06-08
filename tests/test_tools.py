import tempfile
import os
import math

from tools.file_loaders import load_strings, load_exports, load_imports, load_function_index, load_pe_info, detect_sample_type
from tools.pe_utils import calculate_entropy


# === Tests for load_strings ===

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


# === Tests for load_exports ===

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


# === Tests for load_imports ===

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


# === Tests for load_function_index ===

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


# === Tests for load_pe_info ===

def test_load_pe_info_basic():
    with tempfile.TemporaryDirectory() as tmpdir:
        pe_path = os.path.join(tmpdir, "pe_info.json")
        with open(pe_path, "w", encoding="utf-8") as f:
            f.write('{"machine": "x64", "subsystem": "WINDOWS_GUI"}')

        result = load_pe_info(pe_path)
        assert result["status"] == "success"
        assert result["pe_info"]["machine"] == "x64"


# === Tests for detect_sample_type ===

def test_detect_sample_type_pe():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create PE indicator files
        open(os.path.join(tmpdir, "exports.txt"), "w").close()
        open(os.path.join(tmpdir, "imports.txt"), "w").close()

        result = detect_sample_type(tmpdir)
        assert result["status"] == "success"
        assert result["sample_type"] == "pe"
        assert result["confidence"] == "high"


# === Tests for calculate_entropy ===

def test_calculate_entropy_uniform():
    """Uniform distribution should have max entropy ~8.0 for byte values."""
    data = bytes(range(256))
    result = calculate_entropy(data)
    assert result["status"] == "success"
    assert abs(result["entropy"] - 8.0) < 0.1


def test_calculate_entropy_constant():
    """Constant data should have entropy 0."""
    data = b"\x00" * 256
    result = calculate_entropy(data)
    assert result["status"] == "success"
    assert result["entropy"] == 0.0


def test_calculate_entropy_high():
    """Encrypted/compressed data should have high entropy > 7.0."""
    import random
    random.seed(42)
    data = bytes([random.randint(0, 255) for _ in range(1024)])
    result = calculate_entropy(data)
    assert result["status"] == "success"
    assert result["entropy"] > 7.0
