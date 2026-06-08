import os
import json
from typing import Dict, Any


def load_strings(file_path: str) -> Dict[str, Any]:
    """Load and categorize strings from IDA-exported strings.txt.

    Args:
        file_path: Path to strings.txt file.

    Returns:
        Dict with status, all_strings, and categorized strings.
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
            # Data filenames
            if any(ext in s_lower for ext in [".dat", ".pptx", ".ini", ".config", ".bin"]):
                result["data_filenames"].append(s)
            # PDB paths
            if ".pdb" in s_lower:
                result["pdb_paths"].append(s)
            # URLs
            if s.startswith("http://") or s.startswith("https://"):
                result["urls"].append(s)
            # Registry paths
            if "HKCU" in s or "HKLM" in s or "registry" in s_lower:
                result["registry_paths"].append(s)
            # Mutex names
            if "Global\\" in s or "Local\\" in s:
                result["mutex_names"].append(s)
            # PowerShell params
            if any(p in s_lower for p in ["-enc", "-encodedcommand", "-windowstyle hidden", "-noprofile"]):
                result["powershell_params"].append(s)
            # Suspicious keywords (cmd, powershell, etc.)
            if any(k in s_lower for k in ["cmd /c", "cmd /k", "powershell", "wscript", "cscript"]):
                result["suspicious_keywords"].append(s)

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def load_exports(file_path: str) -> Dict[str, Any]:
    """Load export table from IDA-exported exports.txt.

    Args:
        file_path: Path to exports.txt file.

    Returns:
        Dict with status, exports list, ordinal mapping, and loading pattern indicators.
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
            # Check for TLS callback
            if "tlscallback" in name_lower:
                result["has_tls_callback"] = True
            # Check for suspicious names
            if any(sus in name_lower for sus in suspicious_names):
                result["suspicious_export_names"].append(line)
            # Build ordinal mapping (format: ordinal name address)
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
    """Load import table from IDA-exported imports.txt.

    Args:
        file_path: Path to imports.txt file.

    Returns:
        Dict with status, imports list, dll mapping, and API categories.
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
            # DLL name line (often just the DLL name)
            if line.lower().endswith(".dll"):
                current_dll = line
                result["dll_to_apis"][current_dll] = []
                continue

            if current_dll not in result["dll_to_apis"]:
                result["dll_to_apis"][current_dll] = []

            result["dll_to_apis"][current_dll].append(line)

            line_lower = line.lower()
            # Categorize API
            for category, signatures in api_signatures.items():
                if any(sig in line_lower for sig in signatures):
                    result["api_categories"][category].append(f"{current_dll}!{line}")

            # Check for ordinal imports
            if line.startswith("Ordinal_") or line.startswith("ordinal"):
                result["ordinal_imports"].append(f"{current_dll}!{line}")

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def load_function_index(file_path: str) -> Dict[str, Any]:
    """Load function index from IDA-exported function_index.txt.

    Args:
        file_path: Path to function_index.txt file.

    Returns:
        Dict with status and function list (address, name, size, xrefs).
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
            # Expected format: address name size xrefs
            # e.g.: "0x401000 sub_401000 256 12"
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
    """Load pre-generated PE info from pe_info.json.

    Args:
        file_path: Path to pe_info.json file.

    Returns:
        Dict with PE header and section information.
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
    """Detect sample type based on exported files.

    Args:
        export_dir: Path to the IDA export directory.

    Returns:
        Dict with detected type and confidence.
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
            # Try to infer from strings
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
