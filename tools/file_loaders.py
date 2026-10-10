import os
import json
import re
from typing import Dict, Any, List, Optional

from candidate_guards import (
    DEFAULT_LIB_SIZE_MAX,
    DEFAULT_LIB_TAIL_RATIO,
    DEFAULT_LIB_XREF_THRESHOLD,
    is_likely_library_function,
    is_unnamed_func,
    normalize_addr,
    parse_addr,
    tail_start_addr,
)
from config import cfg, cfg_int
from tools.blackboard_tools import board_base_dir, board_path

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
            # B2：护栏同款规则四桶分桶（exports/named/library_suspect/other）
            _bucket_functions(func_idx_path, export_dir, extracts_dir)

        # B2：字符串分类增强（URL/IP/域名/注册表/文件路径/互斥体/命令行/PDB）
        if os.path.exists(strings_path):
            _categorize_strings(strings_path, extracts_dir)

        # B2：API 按功能类归类计数（网络/文件/注册表/进程/注入/加密/反调试）
        if os.path.exists(imports_path):
            _categorize_imports(imports_path, extracts_dir)

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


def _parse_function_index(func_idx_path: str) -> List[dict]:
    """解析 IDA 的 function_index.txt 分块格式为函数条目列表。

    每个块形如：
        Function: sub_180001000
        Address: 0x180001000
        File: decompile/180001000.c
        Type: decompile | disassembly-fallback
        Calls (N): ...

    返回条目字段：name / address / size（索引普遍缺失，恒 0）/ xrefs_count（出向 Calls 数）/
    type（decompile 或 disassembly-fallback，后者即反编译失败函数）。
    """
    with open(func_idx_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    functions = []
    blocks = content.split("=" * 80)

    for block in blocks:
        lines = [l.strip() for l in block.splitlines() if l.strip()]
        if not lines:
            continue

        func_entry = {
            "name": None, "address": None, "size": 0, "xrefs_count": 0,
            "type": "decompile",
        }

        for line in lines:
            if line.startswith("Function:"):
                func_entry["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("Address:"):
                func_entry["address"] = line.split(":", 1)[1].strip()
            elif line.startswith("File:"):
                func_entry["file"] = line.split(":", 1)[1].strip()
            elif line.startswith("Type:"):
                func_entry["type"] = line.split(":", 1)[1].strip() or "decompile"
            elif line.startswith("Calls ("):
                num = line.split("(")[1].split(")")[0]
                try:
                    func_entry["xrefs_count"] = int(num)
                except ValueError:
                    pass

        if func_entry["address"]:
            functions.append(func_entry)

    return functions


def _list_filenames_lower(dir_path: str) -> set:
    """目录下全部文件名的 lower 集合（目录不存在时为空集），供大小写兼容查找。"""
    if not os.path.isdir(dir_path):
        return set()
    try:
        return {name.lower() for name in os.listdir(dir_path)}
    except OSError:
        return set()


def _extract_functions(func_idx_path: str, export_dir: str, extracts_dir: str) -> None:
    """解析 IDA 的 function_index.txt 为结构化 JSON + manifest。"""
    functions = _parse_function_index(func_idx_path)

    # 反编译/反汇编文件名大小写兼容：function_index 里地址为小写，
    # 真实导出文件名常为大写 hex（如 180013D80.asm），Windows 不敏感但 Linux 敏感。
    decompile_files = _list_filenames_lower(os.path.join(export_dir, "decompile"))
    disasm_files = _list_filenames_lower(os.path.join(export_dir, "disassembly"))

    manifest = {}
    for func_entry in functions:
        addr_clean = func_entry["address"].replace("0x", "").replace("0X", "")
        manifest[func_entry["address"]] = {
            "decompile": (
                f"decompile/{addr_clean}.c"
                if f"{addr_clean}.c".lower() in decompile_files else None
            ),
            "disassembly": (
                f"disassembly/{addr_clean}.asm"
                if f"{addr_clean}.asm".lower() in disasm_files else None
            ),
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


# === B2：规则化预提取加码（零 token 确定性提取） ===

# 字符串分类的正则/关键词规则（全部纯 Python，确定性）。
# 分类为单归属：按 _STRING_CATEGORY_ORDER 顺序判定，命中即止。
_RE_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$")
# 域名：多段小写字母数字+连字符，尾段必须是常见 TLD（白名单制，
# 避免把 "kernel32.dll" 这类文件名误判为域名）
_RE_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,24})$")
_DOMAIN_TLDS = {
    "com", "net", "org", "io", "cn", "ru", "info", "biz", "top", "xyz",
    "cc", "me", "tv", "co", "su", "ws", "online", "site", "club", "live",
    "pro", "us", "uk", "de", "jp", "kr", "in", "br", "au", "fr",
}
_RE_DRIVE_PATH = re.compile(r"^[a-zA-Z]:[\\/]")
# %ENV%\ 开头的路径（要求变量名后跟路径分隔符，避免把 printf 格式串 %s%c%s 误判）
_RE_ENV_PATH = re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%[\\/]")
# 相对/子路径形态：分隔符后出现 文件名.扩展名（避免 CRT 字符表这类含 \ 与 . 的乱串误判）
_RE_REL_PATH = re.compile(r"[\\/][^\\/]{0,64}\.[A-Za-z0-9]{1,5}(?:\b|$)")

_REGISTRY_PREFIXES = (
    "hkcu\\", "hklm\\", "hku\\", "hkcr\\", "hkcc\\", "hkey_",
)
# 命令行片段特征（小写子串匹配）
_COMMAND_LINE_HINTS = (
    "cmd /c", "cmd /k", "powershell", "wscript", "cscript", "rundll32",
    "regsvr32", "schtasks", "mshta", "bitsadmin", "certutil",
    "-enc", "-windowstyle hidden", "-noprofile",
)

STRING_CATEGORIES = (
    "pdb_paths", "urls", "ips", "registry_paths", "command_lines",
    "mutex_candidates", "file_paths", "domains",
)


def _split_string_line(raw: str) -> tuple:
    """拆分 strings.txt 行（address | length | type | text）。

    返回 (address, text)；非标准行（纯文本）返回 (None, 整行)。
    """
    parts = raw.split(" | ")
    if len(parts) >= 4:
        return parts[0].strip(), " | ".join(parts[3:]).strip()
    return None, raw.strip()


def _classify_string_text(text: str) -> Optional[str]:
    """对单条字符串文本判定类别（STRING_CATEGORIES 之一），不匹配返回 None。"""
    if not text:
        return None
    text_lower = text.lower()

    if text_lower.endswith(".pdb") or ".pdb" in text_lower:
        return "pdb_paths"
    if text_lower.startswith(("http://", "https://", "ftp://")):
        return "urls"
    if _RE_IPV4.match(text):
        return "ips"
    if text_lower.startswith(_REGISTRY_PREFIXES) or "software\\microsoft\\windows" in text_lower:
        return "registry_paths"
    if any(hint in text_lower for hint in _COMMAND_LINE_HINTS):
        return "command_lines"
    if text.startswith(("Global\\", "Local\\")):
        return "mutex_candidates"
    if (
        _RE_DRIVE_PATH.match(text)
        or _RE_ENV_PATH.match(text)
        or text.startswith(("\\\\", ".\\", "..\\", "./"))
        or _RE_REL_PATH.search(text)
    ):
        return "file_paths"
    domain_match = _RE_DOMAIN.match(text_lower)
    if domain_match and domain_match.group(1) in _DOMAIN_TLDS:
        return "domains"
    return None


def _categorize_strings(strings_path: str, extracts_dir: str) -> None:
    """字符串分类增强：8 类确定性归类，统计与明细落盘 strings_categorized.json。

    类别（单归属，按优先级）：pdb_paths / urls / ips / registry_paths /
    command_lines / mutex_candidates / file_paths / domains。
    明细条目：{"text", "address"}（address 可能为 None）。
    """
    with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    categories = {cat: {"count": 0, "items": []} for cat in STRING_CATEGORIES}
    for raw in lines:
        address, text = _split_string_line(raw)
        cat = _classify_string_text(text)
        if cat is None:
            continue
        categories[cat]["count"] += 1
        categories[cat]["items"].append({"text": text, "address": address})

    output = {
        "total_count": len(lines),
        "category_counts": {cat: categories[cat]["count"] for cat in STRING_CATEGORIES},
        "categories": categories,
    }
    with open(os.path.join(extracts_dir, "strings_categorized.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)


# API 功能类签名（小写子串匹配；按优先级单归属，命中即止）。
# 顺序即优先级：注入 > 反调试 > 加密 > 网络 > 注册表 > 文件 > 进程 > other。
# 参考 windows_pe.md 的导入定型顺序与 load_imports 的既有签名表。
_IMPORT_CATEGORY_SIGNATURES = (
    ("injection", (
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "virtualprotectex", "queueuserapc", "ntunmapviewofsection",
        "setthreadcontext", "getthreadcontext", "rtlcreateuserthread",
        "ntcreatethreadex", "openprocess", "loadlibrary", "getprocaddress",
        "virtualprotect",
    )),
    ("anti_debug", (
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "outputdebugstring", "gettickcount",
        "queryperformancecounter", "ntsetinformationthread",
    )),
    ("crypto", (
        "crypt", "bcrypt", "ncrypt",
    )),
    ("network", (
        "internetopen", "internetconnect", "httpopenrequest", "httpsendrequest",
        "internetreadfile", "internetwritefile", "socket", "connect", "recv",
        "wsastartup", "getaddrinfo", "gethostbyname", "inet_addr", "winhttp",
        "urldownloadtofile", "closesocket", "send",
    )),
    ("registry", (
        "regopenkey", "regsetvalue", "regqueryvalue", "regcreatekey",
        "regdeletekey", "regenumkey", "regenumvalue", "regclosekey",
    )),
    ("file", (
        "createfile", "readfile", "writefile", "copyfile", "deletefile",
        "movefile", "getfilesize", "findfirstfile", "findnextfile",
        "gettemppath", "getlogicaldrive", "setfilepointer", "createdirectory",
        "getmodulefilename", "getfileattributes", "createfilemapping",
        "mapviewoffile", "fopen", "fread", "fwrite",
    )),
    ("process", (
        "createprocess", "terminateprocess", "process32", "toolhelp32",
        "shellexecute", "winexec", "exitprocess", "getcurrentprocess",
        "openprocesstoken", "createprocessasuser", "waitforsingleobject",
    )),
)

IMPORT_CATEGORIES = tuple(name for name, _ in _IMPORT_CATEGORY_SIGNATURES) + ("other",)


def _classify_import_api(api_name: str) -> str:
    """按功能类判定单个 API 名（IMPORT_CATEGORIES 之一，未命中为 other）。"""
    api_lower = api_name.lower()
    for category, signatures in _IMPORT_CATEGORY_SIGNATURES:
        if any(sig in api_lower for sig in signatures):
            return category
    return "other"


def _split_import_line(line: str) -> tuple:
    """拆分 imports.txt 行，兼容两种真实格式：

    - ``addr:APIName``（如 ``0x1801710f0:MultiByteToWideChar``）→ (api 名, 原行)
    - DLL 分节格式（DLL 名独占一行，其后每行一个 API 名）→ (原行, 原行)

    返回 (api_name, raw)；DLL 分节行由调用方先行识别，不会走到这里。
    """
    if line.lower().startswith("0x") and ":" in line:
        return line.split(":", 1)[1].strip(), line
    return line.strip(), line


def _categorize_imports(imports_path: str, extracts_dir: str) -> None:
    """API 分类统计：按功能类归类计数，落盘 imports_categorized.json。

    类别（单归属按优先级）：injection / anti_debug / crypto / network /
    registry / file / process / other。明细条目 {"api", "raw", "dll"}。
    兼容 DLL 分节与 addr:name 两种 imports.txt 格式。
    """
    with open(imports_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    categories = {cat: {"count": 0, "items": []} for cat in IMPORT_CATEGORIES}
    current_dll = None
    dll_names = []
    total_apis = 0

    for line in lines:
        # DLL 分节行（整行即 DLL 名）；addr:name 格式不含 .dll 行
        if line.lower().endswith(".dll") and ":" not in line:
            current_dll = line
            dll_names.append(line)
            continue
        api_name, raw = _split_import_line(line)
        if not api_name:
            continue
        total_apis += 1
        cat = _classify_import_api(api_name)
        categories[cat]["count"] += 1
        categories[cat]["items"].append({"api": api_name, "raw": raw, "dll": current_dll})

    output = {
        "total_count": total_apis,
        "dll_names": dll_names,
        "category_counts": {cat: categories[cat]["count"] for cat in IMPORT_CATEGORIES},
        "categories": categories,
    }
    with open(os.path.join(extracts_dir, "imports_categorized.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)


def _parse_export_addrs(exports_path: str) -> dict:
    """解析 exports.txt 为 {规范化地址: 导出名} 映射。

    兼容两种真实格式：``addr:name``（如 ``0x180013d80:ordinal_1``）与
    ``ordinal name addr``（如 ``1 DllMain 0x401000``）。
    """
    exports = {}
    if not os.path.exists(exports_path):
        return exports
    with open(exports_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    for line in lines:
        addr, name = None, None
        if ":" in line:
            head, tail = line.split(":", 1)
            if parse_addr(head.strip()) is not None:
                addr, name = head.strip(), tail.strip()
        if addr is None:
            parts = line.split()
            if len(parts) >= 2 and parse_addr(parts[-1]) is not None:
                addr, name = parts[-1], " ".join(parts[1:-1]) or parts[0]
        normalized = normalize_addr(addr)
        if normalized:
            exports.setdefault(normalized, name or "")
    return exports


def _bucket_functions(func_idx_path: str, export_dir: str, extracts_dir: str) -> None:
    """函数索引四桶分桶（与 candidate_guards 护栏同款规则），落盘 functions_buckets.json。

    分桶优先级（单归属）：
      1. exports          地址命中导出表（exports.txt）；
      2. named            有名函数（名称非空且非 sub_ 前缀）；
      3. library_suspect  无名 sub_ + xrefs 超阈值 + 地址位于样本高地址尾部区间
                          （复用 candidate_guards.is_likely_library_function，阈值同
                          analysis.lib_xref_threshold / lib_tail_ratio / lib_size_max）；
      4. other            其余函数。

    Worker 后续可按需只读自己关心的桶，不必翻全量索引。
    """
    functions = _parse_function_index(func_idx_path)
    export_addrs = _parse_export_addrs(os.path.join(export_dir, "exports.txt"))

    xref_threshold = cfg_int(
        "analysis.lib_xref_threshold", env="LIB_XREF_THRESHOLD", default=DEFAULT_LIB_XREF_THRESHOLD
    )
    tail_ratio = float(
        cfg("analysis.lib_tail_ratio", env="LIB_TAIL_RATIO", default=DEFAULT_LIB_TAIL_RATIO)
    )
    size_max = cfg_int("analysis.lib_size_max", env="LIB_SIZE_MAX", default=DEFAULT_LIB_SIZE_MAX)

    parsed_addrs = [
        parse_addr(f["address"]) for f in functions if parse_addr(f["address"]) is not None
    ]
    addr_range = (min(parsed_addrs), max(parsed_addrs)) if parsed_addrs else None
    tail_start = tail_start_addr(addr_range, tail_ratio) if addr_range else None

    buckets = {name: {"count": 0, "functions": []}
               for name in ("exports", "named", "library_suspect", "other")}

    for func in functions:
        addr_n = normalize_addr(func.get("address"))
        entry = {
            "address": func.get("address"),
            "name": func.get("name"),
            "xrefs_count": func.get("xrefs_count", 0),
            "type": func.get("type", "decompile"),
            "decompile_failed": func.get("type") == "disassembly-fallback",
        }
        if addr_n and addr_n in export_addrs:
            entry["export_name"] = export_addrs[addr_n]
            bucket = "exports"
        elif not is_unnamed_func(func.get("name")):
            bucket = "named"
        elif is_likely_library_function(
            {
                "func_addr": func.get("address"),
                "func_name": func.get("name"),
                "xrefs": func.get("xrefs_count", 0),
                "size": func.get("size", 0),
            },
            export_addrs=export_addrs,
            xref_threshold=xref_threshold,
            tail_start=tail_start,
            size_max=size_max,
        ):
            bucket = "library_suspect"
        else:
            bucket = "other"
        buckets[bucket]["count"] += 1
        buckets[bucket]["functions"].append(entry)

    output = {
        "total_count": len(functions),
        "rules": {
            "xref_threshold": xref_threshold,
            "tail_ratio": tail_ratio,
            "tail_start_addr": hex(tail_start) if tail_start is not None else None,
            "size_max": size_max,
            "addr_range": [hex(addr_range[0]), hex(addr_range[1])] if addr_range else None,
        },
        "bucket_counts": {name: buckets[name]["count"] for name in buckets},
        "buckets": buckets,
    }
    with open(os.path.join(extracts_dir, "functions_buckets.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)


def _load_categorized_extract(project_name: Optional[str], extract_name: str) -> Optional[dict]:
    """读取黑板 extracts/ 下的 B2 分类产物；project_name 为空或产物不存在返回 None。"""
    if not project_name:
        return None
    path = board_path(project_name, "extracts", extract_name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_strings(file_path: str, project_name: Optional[str] = None) -> Dict[str, Any]:
    """从 IDA 导出的 strings.txt 中加载并分类字符串。

    Args:
        file_path: strings.txt 文件路径。
        project_name: 可选，黑板项目名。提供且 Phase -1 已产出
            extracts/strings_categorized.json 时优先返回规则化分类产物
            （URL/IP/域名/注册表/文件路径/互斥体/命令行/PDB 八类），
            此时不重复扫描全量原文（all_strings 置空）；产物不存在时回退原始解析。

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

    # B2：优先读预提取分类产物（兼容旧数据：产物缺失时回退现有原始解析逻辑）
    categorized = _load_categorized_extract(project_name, "strings_categorized.json")
    if categorized is not None:
        cats = categorized.get("categories", {})

        def _texts(cat):
            return [item.get("text", "") for item in cats.get(cat, {}).get("items", [])]

        command_lines = _texts("command_lines")
        result.update({
            "source": "extracts/strings_categorized.json",
            "note": "已返回 Phase -1 规则化分类产物（8 类明细见 categorized 字段）；"
                    "all_strings 置空，全量原文请读 strings.txt 或 strings_extract 分片",
            "urls": _texts("urls"),
            "registry_paths": _texts("registry_paths"),
            "mutex_names": _texts("mutex_candidates"),
            "pdb_paths": _texts("pdb_paths"),
            "data_filenames": _texts("file_paths"),
            "suspicious_keywords": command_lines,
            "powershell_params": [s for s in command_lines if "powershell" in s.lower()],
            "categorized": categorized,
        })
        return result

    result["source"] = "raw_file"

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


def load_imports(file_path: str, project_name: Optional[str] = None) -> Dict[str, Any]:
    """从 IDA 导出的 imports.txt 中加载导入表。

    Args:
        file_path: imports.txt 文件路径。
        project_name: 可选，黑板项目名。提供且 Phase -1 已产出
            extracts/imports_categorized.json 时优先返回规则化 API 分类产物
            （injection/anti_debug/crypto/network/registry/file/process/other），
            产物不存在时回退原始解析。

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

    # B2：优先读预提取分类产物（兼容旧数据：产物缺失时回退现有原始解析逻辑）
    categorized = _load_categorized_extract(project_name, "imports_categorized.json")
    if categorized is not None:
        cats = categorized.get("categories", {})
        # 七类功能分类 → 既有 api_categories 键的映射（其余键无对应，留空）
        key_map = {
            "injection": "process_injection",
            "file": "file_operations",
            "network": "network",
            "registry": "registry",
            "crypto": "crypto",
            "anti_debug": "anti_analysis",
        }
        all_imports = []
        dll_to_apis: Dict[str, list] = {}
        for cat in IMPORT_CATEGORIES:
            for item in cats.get(cat, {}).get("items", []):
                api_name = item.get("api", "")
                raw = item.get("raw", api_name)
                dll = item.get("dll")
                all_imports.append(raw)
                label = f"{dll}!{api_name}" if dll else raw
                if cat in key_map:
                    result["api_categories"][key_map[cat]].append(label)
                if dll:
                    dll_to_apis.setdefault(dll, []).append(api_name)
                if api_name.lower().startswith("ordinal"):
                    result["ordinal_imports"].append(label)
        result.update({
            "source": "extracts/imports_categorized.json",
            "imports": all_imports,
            "dll_to_apis": dll_to_apis,
            "categorized": categorized,
        })
        return result

    result["source"] = "raw_file"

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


def load_function_index(file_path: str, project_name: Optional[str] = None) -> Dict[str, Any]:
    """从 IDA 导出的 function_index.txt 中加载函数索引。

    Args:
        file_path: function_index.txt 文件路径。
        project_name: 可选，黑板项目名。提供且 Phase -1 已产出
            extracts/functions_buckets.json 时优先返回四桶分桶产物
            （exports / named / library_suspect / other，护栏同款规则），
            Worker 可按需只读对应桶而非翻全量索引；产物不存在时回退原始解析。

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

    # B2：优先读预提取分桶产物（兼容旧数据：产物缺失时回退现有原始解析逻辑）
    bucketed = _load_categorized_extract(project_name, "functions_buckets.json")
    if bucketed is not None:
        buckets = bucketed.get("buckets", {})
        merged = []
        for bucket_name in ("exports", "named", "library_suspect", "other"):
            for entry in buckets.get(bucket_name, {}).get("functions", []):
                merged.append({
                    "address": entry.get("address"),
                    "name": entry.get("name") or "unknown",
                    "size": 0,  # function_index 普遍缺失 size，保持与原结构一致
                    "xrefs": entry.get("xrefs_count", 0),
                    "bucket": bucket_name,
                    "type": entry.get("type", "decompile"),
                    "decompile_failed": entry.get("decompile_failed", False),
                })
        result.update({
            "source": "extracts/functions_buckets.json",
            "functions": merged,
            "total_functions": bucketed.get("total_count", len(merged)),
            "buckets": buckets,
            "bucket_counts": bucketed.get("bucket_counts", {}),
            "bucket_rules": bucketed.get("rules", {}),
        })
        return result

    result["source"] = "raw_file"

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
