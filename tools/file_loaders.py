import os
import json
from typing import Dict, Any, Optional

from config import cfg
from tools.blackboard_tools import board_base_dir

# 输入根目录默认值：data/input 下按 *_export_for_ai 命名存放 IDA 导出产物
DEFAULT_INPUT_ROOT = os.path.join("data", "input")
EXPORT_DIR_SUFFIX = "_export_for_ai"


def default_input_root() -> str:
    """输入根目录：config.yaml paths.input_root（默认 data/input）。"""
    return cfg("paths.input_root", env="INPUT_ROOT", default=DEFAULT_INPUT_ROOT)


def find_export_dirs(input_root: Optional[str] = None) -> list:
    """列出 input_root 下所有 *_export_for_ai 目录名（排序后）。"""
    input_root = input_root or default_input_root()
    if not os.path.isdir(input_root):
        return []
    return sorted(
        name
        for name in os.listdir(input_root)
        if name.endswith(EXPORT_DIR_SUFFIX)
        and os.path.isdir(os.path.join(input_root, name))
    )


def resolve_export_dir(
    project_name: Optional[str] = None,
    input_name: Optional[str] = None,
    input_root: Optional[str] = None,
) -> dict:
    """按规则自动定位 data/input 下的 *_export_for_ai 导出目录。

    优先级：显式 input_name（可省略 _export_for_ai 后缀）
           > project_name 前缀匹配 > 唯一候选自动选用。

    Returns:
        包含 status、export_dir、candidates 的字典。
    """
    input_root = input_root or default_input_root()
    candidates = find_export_dirs(input_root)
    if not candidates:
        return {
            "status": "error",
            "error": f"未在 {input_root} 下找到任何 *{EXPORT_DIR_SUFFIX} 目录",
            "export_dir": None,
            "candidates": [],
        }

    if input_name:
        name = input_name
        if not name.endswith(EXPORT_DIR_SUFFIX):
            name = name + EXPORT_DIR_SUFFIX
        matches = [c for c in candidates if c == name or c == input_name]
        if matches:
            return {
                "status": "success",
                "error": None,
                "export_dir": os.path.join(input_root, matches[0]),
                "candidates": candidates,
            }
        return {
            "status": "error",
            "error": f"input_name={input_name!r} 未匹配任何导出目录",
            "export_dir": None,
            "candidates": candidates,
        }

    if project_name:
        prefixed = [c for c in candidates if c.startswith(project_name)]
        if len(prefixed) == 1:
            return {
                "status": "success",
                "error": None,
                "export_dir": os.path.join(input_root, prefixed[0]),
                "candidates": candidates,
            }

    if len(candidates) == 1:
        return {
            "status": "success",
            "error": None,
            "export_dir": os.path.join(input_root, candidates[0]),
            "candidates": candidates,
        }

    return {
        "status": "error",
        "error": "存在多个导出目录，无法自动选择，请用 -i/--input-name 指定",
        "export_dir": None,
        "candidates": candidates,
    }


def pre_extract_sample(export_dir: str, project_name: str, output_base: str = ".") -> dict:
    """Phase -1：把所有原始 IDA 导出文件预提取为结构化 JSON。

    不做内容过滤，只做最小化清理（去空行、修编码）。
    输出目录为 {output_base}/{board_base}/{project_name}/extracts/。
    """
    result = {"status": "success", "error": None, "extracts_dir": None}

    try:
        board_dir = os.path.join(output_base, board_base_dir(), project_name)
        extracts_dir = os.path.join(board_dir, "extracts")
        os.makedirs(extracts_dir, exist_ok=True)
        result["extracts_dir"] = extracts_dir

        # 处理 strings.txt
        strings_path = os.path.join(export_dir, "strings.txt")
        if os.path.exists(strings_path):
            _extract_strings(strings_path, extracts_dir)

        # 处理 imports.txt
        imports_path = os.path.join(export_dir, "imports.txt")
        if os.path.exists(imports_path):
            _extract_imports(imports_path, extracts_dir)

        # 处理 exports.txt
        exports_path = os.path.join(export_dir, "exports.txt")
        if os.path.exists(exports_path):
            _extract_exports(exports_path, extracts_dir)

        # 处理 function_index.txt
        func_idx_path = os.path.join(export_dir, "function_index.txt")
        if os.path.exists(func_idx_path):
            _extract_functions(func_idx_path, export_dir, extracts_dir)

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def _extract_strings(strings_path: str, extracts_dir: str) -> None:
    """解析 IDA 的 strings.txt 为结构化 JSON。"""
    with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    by_type = {"ASCII": [], "UNICODE": [], "UTF8": [], "OTHER": []}
    by_category = {
        "urls": [], "registry_keys": [], "file_paths": [],
        "mutexes": [], "pdb_paths": [], "error_messages": [], "other": []
    }

    for raw in lines:
        parts = raw.split(" | ")
        if len(parts) >= 4:
            addr, length, stype, text = parts[0], parts[1], parts[2], " | ".join(parts[3:])
        else:
            stype, text = "OTHER", raw

        entry = {"text": text, "raw": raw}
        type_key = stype if stype in by_type else "OTHER"
        by_type[type_key].append(entry)

        text_lower = text.lower()
        if text.startswith("http://") or text.startswith("https://"):
            by_category["urls"].append(entry)
        elif "HKCU" in text or "HKLM" in text or "registry" in text_lower:
            by_category["registry_keys"].append(entry)
        elif ".pdb" in text_lower:
            by_category["pdb_paths"].append(entry)
        elif "Global\\" in text or "Local\\" in text:
            by_category["mutexes"].append(entry)
        elif any(e in text_lower for e in [".dat", ".bin", ".config", ".ini", ".dll", ".exe"]):
            by_category["file_paths"].append(entry)
        elif any(e in text_lower for e in ["error", "fail", "invalid", "not found", "exception"]):
            by_category["error_messages"].append(entry)
        else:
            by_category["other"].append(entry)

    chunk_size = 100
    output = {
        "total_count": len(lines),
        "by_type": by_type,
        "by_category": by_category,
        "chunk_size": chunk_size,
        "chunks": (len(lines) + chunk_size - 1) // chunk_size,
    }

    with open(os.path.join(extracts_dir, "strings_extract.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)


def _extract_imports(imports_path: str, extracts_dir: str) -> None:
    """解析 IDA 的 imports.txt 为结构化 JSON。"""
    with open(imports_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    dll_to_apis = {}
    current_dll = "unknown"
    imports_flat = []

    for line in lines:
        if line.lower().endswith(".dll"):
            current_dll = line
            dll_to_apis[current_dll] = []
            continue
        dll_to_apis.setdefault(current_dll, []).append(line)
        imports_flat.append(f"{current_dll}!{line}")

    output = {
        "total_count": len(imports_flat),
        "dll_to_apis": dll_to_apis,
        "imports_flat": imports_flat,
    }

    with open(os.path.join(extracts_dir, "imports_extract.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)


def _extract_exports(exports_path: str, extracts_dir: str) -> None:
    """解析 IDA 的 exports.txt 为结构化 JSON。"""
    with open(exports_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    exports = []
    for line in lines:
        if ":" in line:
            addr, name = line.split(":", 1)
            exports.append({"address": addr.strip(), "name": name.strip()})
        else:
            exports.append({"address": None, "name": line})

    output = {
        "total_count": len(exports),
        "exports": exports,
    }

    with open(os.path.join(extracts_dir, "exports_extract.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)


def _extract_functions(func_idx_path: str, export_dir: str, extracts_dir: str) -> None:
    """解析 IDA 的 function_index.txt 为结构化 JSON + manifest。"""
    with open(func_idx_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    functions = []
    manifest = {}
    blocks = content.split("=" * 80)

    for block in blocks:
        lines = [l.strip() for l in block.splitlines() if l.strip()]
        if not lines:
            continue

        func_entry = {"name": None, "address": None, "size": 0, "xrefs_count": 0}

        for line in lines:
            if line.startswith("Function:"):
                func_entry["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("Address:"):
                func_entry["address"] = line.split(":", 1)[1].strip()
            elif line.startswith("File:"):
                func_entry["file"] = line.split(":", 1)[1].strip()
            elif line.startswith("Calls ("):
                num = line.split("(")[1].split(")")[0]
                try:
                    func_entry["xrefs_count"] = int(num)
                except ValueError:
                    pass

        if func_entry["address"]:
            functions.append(func_entry)
            addr_clean = func_entry["address"].replace("0x", "")
            manifest[func_entry["address"]] = {
                "decompile": f"decompile/{addr_clean}.c" if os.path.exists(
                    os.path.join(export_dir, "decompile", f"{addr_clean}.c")
                ) else None,
                "disassembly": f"disassembly/{addr_clean}.asm" if os.path.exists(
                    os.path.join(export_dir, "disassembly", f"{addr_clean}.asm")
                ) else None,
            }

    chunk_size = 100
    output = {
        "total_count": len(functions),
        "functions": functions,
        "chunk_size": chunk_size,
        "chunks": (len(functions) + chunk_size - 1) // chunk_size,
    }

    with open(os.path.join(extracts_dir, "functions_extract.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    with open(os.path.join(extracts_dir, "functions_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)


def load_strings(file_path: str) -> Dict[str, Any]:
    """从 IDA 导出的 strings.txt 中加载并分类字符串。

    Args:
        file_path: strings.txt 文件路径。

    Returns:
        包含 status、all_strings 及各类别字符串的字典。
    """
    result = {
        "status": "success",
        "error": None,
        "file_path": file_path,
        "all_strings": [],
        "data_filenames": [],
        "pdb_paths": [],
        "urls": [],
        "registry_paths": [],
        "mutex_names": [],
        "suspicious_keywords": [],
        "powershell_params": [],
    }

    try:
        if not os.path.exists(file_path):
            result["status"] = "error"
            result["error"] = f"File not found: {file_path}"
            return result

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]

        result["all_strings"] = lines

        for s in lines:
            s_lower = s.lower()
            # 数据文件名
            if any(ext in s_lower for ext in [".dat", ".pptx", ".ini", ".config", ".bin"]):
                result["data_filenames"].append(s)
            # PDB 路径
            if ".pdb" in s_lower:
                result["pdb_paths"].append(s)
            # URL
            if s.startswith("http://") or s.startswith("https://"):
                result["urls"].append(s)
            # 注册表路径
            if "HKCU" in s or "HKLM" in s or "registry" in s_lower:
                result["registry_paths"].append(s)
            # 互斥体名
            if "Global\\" in s or "Local\\" in s:
                result["mutex_names"].append(s)
            # PowerShell 参数
            if any(p in s_lower for p in ["-enc", "-encodedcommand", "-windowstyle hidden", "-noprofile"]):
                result["powershell_params"].append(s)
            # 可疑关键字（cmd、powershell 等）
            if any(k in s_lower for k in ["cmd /c", "cmd /k", "powershell", "wscript", "cscript"]):
                result["suspicious_keywords"].append(s)

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def load_exports(file_path: str) -> Dict[str, Any]:
    """从 IDA 导出的 exports.txt 中加载导出表。

    Args:
        file_path: exports.txt 文件路径。

    Returns:
        包含 status、exports 列表、序号映射和加载模式指标的字典。
    """
    result = {
        "status": "success",
        "error": None,
        "file_path": file_path,
        "exports": [],
        "ordinal_mapping": [],
        "has_tls_callback": False,
        "suspicious_export_names": [],
    }

    try:
        if not os.path.exists(file_path):
            result["status"] = "error"
            result["error"] = f"File not found: {file_path}"
            return result

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]

        result["exports"] = lines

        suspicious_names = {"install", "servicemain", "dllinjection", "inject",
                           "payload", "shell", "rat", "stealer", "loader"}

        for line in lines:
            name_lower = line.lower()
            # 检查 TLS 回调
            if "tlscallback" in name_lower:
                result["has_tls_callback"] = True
            # 检查可疑名称
            if any(sus in name_lower for sus in suspicious_names):
                result["suspicious_export_names"].append(line)
            # 构建序号映射（格式：ordinal name address）
            parts = line.split()
            if len(parts) >= 3:
                try:
                    ordinal = int(parts[0])
                    addr = parts[-1]
                    name = " ".join(parts[1:-1])
                    result["ordinal_mapping"].append({
                        "ordinal": ordinal,
                        "name": name,
                        "address": addr,
                    })
                except ValueError:
                    pass

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def load_imports(file_path: str) -> Dict[str, Any]:
    """从 IDA 导出的 imports.txt 中加载导入表。

    Args:
        file_path: imports.txt 文件路径。

    Returns:
        包含 status、imports 列表、DLL 映射和 API 分类的字典。
    """
    result = {
        "status": "success",
        "error": None,
        "file_path": file_path,
        "imports": [],
        "dll_to_apis": {},
        "api_categories": {
            "process_injection": [],
            "file_operations": [],
            "network": [],
            "registry": [],
            "crypto": [],
            "anti_analysis": [],
            "persistence": [],
            "info_stealing": [],
            "uac_bypass": [],
        },
        "ordinal_imports": [],
    }

    api_signatures = {
        "process_injection": ["openprocess", "virtualalloc", "virtualallocex", "writeprocessmemory",
                              "createremotethread", "virtualprotectex", "ntunmapviewofsection", "createthread"],
        "file_operations": ["createfile", "readfile", "writefile", "fopen", "fread",
                           "movefileex", "deletefile"],
        "network": ["internetopen", "httpopenrequest", "internetconnect", "socket",
                   "connect", "send", "recv", "wsastartup", "wininet", "winhttp"],
        "registry": ["regopenkeyex", "regsetvalueex", "regqueryvalueex", "regcreatekeyex"],
        "crypto": ["crypt", "bcrypt", "ncrypt", "advapi32"],
        "anti_analysis": ["isdebuggerpresent", "checkremotedebuggerpresent", "gettickcount",
                         "enumwindows", "outputdebugstring"],
        "persistence": ["openscmanager", "createservice", "regsetvalueex", "movefileex"],
        "info_stealing": ["sqlite3_open", "openclipboard", "getclipboarddata",
                         "getforegroundwindow", "getwindowtext", "findfirstfile"],
        "uac_bypass": ["shellexecuteex", "runas", "com", "cmstplua"],
    }

    try:
        if not os.path.exists(file_path):
            result["status"] = "error"
            result["error"] = f"File not found: {file_path}"
            return result

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]

        result["imports"] = lines
        current_dll = "unknown"

        for line in lines:
            # DLL 名称行（通常整行就是 DLL 名）
            if line.lower().endswith(".dll"):
                current_dll = line
                result["dll_to_apis"][current_dll] = []
                continue

            if current_dll not in result["dll_to_apis"]:
                result["dll_to_apis"][current_dll] = []

            result["dll_to_apis"][current_dll].append(line)

            line_lower = line.lower()
            # API 归类
            for category, signatures in api_signatures.items():
                if any(sig in line_lower for sig in signatures):
                    result["api_categories"][category].append(f"{current_dll}!{line}")

            # 检查序号导入
            if line.startswith("Ordinal_") or line.startswith("ordinal"):
                result["ordinal_imports"].append(f"{current_dll}!{line}")

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def load_function_index(file_path: str) -> Dict[str, Any]:
    """从 IDA 导出的 function_index.txt 中加载函数索引。

    Args:
        file_path: function_index.txt 文件路径。

    Returns:
        包含 status 和函数列表（address、name、size、xrefs）的字典。
    """
    result = {
        "status": "success",
        "error": None,
        "file_path": file_path,
        "functions": [],
        "total_functions": 0,
    }

    try:
        if not os.path.exists(file_path):
            result["status"] = "error"
            result["error"] = f"File not found: {file_path}"
            return result

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]

        for line in lines:
            # 预期格式：address name size xrefs
            # 例如："0x401000 sub_401000 256 12"
            parts = line.split()
            if len(parts) >= 2:
                func_entry = {
                    "address": parts[0],
                    "name": parts[1] if len(parts) > 1 else "unknown",
                    "size": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                    "xrefs": int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0,
                }
                result["functions"].append(func_entry)

        result["total_functions"] = len(result["functions"])

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def load_pe_info(file_path: str) -> Dict[str, Any]:
    """从 pe_info.json 中加载预生成的 PE 信息。

    Args:
        file_path: pe_info.json 文件路径。

    Returns:
        包含 PE 头和节区信息的字典。
    """
    result = {
        "status": "success",
        "error": None,
        "file_path": file_path,
        "pe_info": {},
    }

    try:
        if not os.path.exists(file_path):
            result["status"] = "error"
            result["error"] = f"File not found: {file_path}"
            return result

        with open(file_path, "r", encoding="utf-8") as f:
            result["pe_info"] = json.load(f)

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def detect_sample_type(export_dir: str) -> Dict[str, Any]:
    """根据导出文件判定样本类型。

    Args:
        export_dir: IDA 导出目录路径。

    Returns:
        包含判定类型和置信度的字典。
    """
    result = {
        "status": "success",
        "error": None,
        "sample_type": "unknown",
        "confidence": "low",
        "indicators": [],
    }

    try:
        if not os.path.isdir(export_dir):
            result["status"] = "error"
            result["error"] = f"Directory not found: {export_dir}"
            return result

        has_pe = os.path.exists(os.path.join(export_dir, "pe_info.json"))
        has_strings = os.path.exists(os.path.join(export_dir, "strings.txt"))
        has_exports = os.path.exists(os.path.join(export_dir, "exports.txt"))
        has_imports = os.path.exists(os.path.join(export_dir, "imports.txt"))

        if has_pe or (has_exports and has_imports):
            result["sample_type"] = "pe"
            result["confidence"] = "high"
            result["indicators"].append("PE export files present")
        elif has_strings:
            # 尝试从字符串推断
            strings_result = load_strings(os.path.join(export_dir, "strings.txt"))
            if strings_result["status"] == "success":
                all_str = " ".join(strings_result["all_strings"]).lower()
                if "mz" in all_str or "pe" in all_str:
                    result["sample_type"] = "pe"
                    result["confidence"] = "medium"
                    result["indicators"].append("PE indicators in strings")

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result
