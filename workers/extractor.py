import json


EXTRACTION_PROMPT_TEMPLATE = """你是一个结构化摘要提取器。你的任务是从一份完整的分析结果中提取关键发现，生成供后续 Worker 读取的轻量摘要。

输入 Artifact 类型: {artifact_type}

约束（硬约束，必须遵守）：
1. 摘要必须 ≤ 1500 tokens（当前估算: 每4个字符约1个token）
2. 只保留 high/medium 置信度的发现，low 置信度丢弃
3. 列表类保留前 N 个: IoC/URL/注册表保留最多10个，函数保留最多5个
4. 不要解释性文字，纯结构化数据
5. 必须包含 "confidence" 和 "key_findings" 字段
6. 如果输入中没有值得提取的发现，输出空 key_findings 并标注 confidence=low

输出格式（严格 JSON）：
{output_schema}

规则:
- 不添加输入中不存在的字段
- 数值和字符串直接搬运，不做推断
- 如果某字段在输入中不存在，设为 null 或空列表

以下是完整的 Artifact 内容，请提取摘要:

{artifact_json}
"""

SUMMARY_SCHEMAS = {
    "strings": """{
  "worker": "string_artifact_analyst",
  "key_findings": {
    "suspicious_urls": [{"url": "...", "confidence": "high"}],
    "registry_keys": [{"key": "...", "purpose": "persistence", "confidence": "medium"}],
    "mutexes": [{"name": "...", "confidence": "high"}],
    "pdb_paths": [{"path": "...", "confidence": "medium"}],
    "data_files": [{"name": "...", "confidence": "medium"}]
  },
  "behavior_indicators": ["疑似网络通信", "疑似持久化"],
  "confidence": "medium",
  "token_estimate": 1200,
  "arch_detection": {
    "language": "...",
    "compiler_hints": ["..."],
    "packer_protector": ["..."],
    "sample_form": "...",
    "confidence": "high|medium|low",
    "evidence": ["..."]
  }
}""",
    "api": """{
  "worker": "api_behavior_profiler",
  "mitre_techniques": [{"id": "T1055", "name": "Process Injection", "confidence": "high"}],
  "api_combinations": [{"pattern": "OpenProcess+VirtualAllocEx", "purpose": "injection"}],
  "dll_dependencies": ["kernel32", "ws2_32"],
  "suspicious_apis": [{"api": "CreateRemoteThread", "dll": "kernel32", "confidence": "high"}],
  "confidence": "high"
}""",
    "exports": """{
  "worker": "export_interface_analyzer",
  "loading_pattern": {"pattern_type": "标准插件型", "confidence": "high"},
  "ordinal_mapping": [{"ordinal": 1, "name": "DllEntryPoint", "likely_role": "初始化"}],
  "tls_callback": {"has_tls_callback": false, "suspicious": false},
  "packer_indicators": [],
  "confidence": "medium"
}""",
    "behavior": """{
  "worker": "behavior_profile_synthesizer",
  "behavior_profile": {"primary_type": "Stealer", "confidence": "medium"},
  "command_and_residence": {"has_command_dispatcher": true, "residence_type": "常驻"},
  "info_stealing_capabilities": [{"target": "Chromium密码", "confidence": "high"}],
  "persistence_mechanisms": [{"mechanism": "注册表Run键", "confidence": "medium"}],
  "anti_debugging": [],
  "breakpoint_matrix": {"p0": [], "p1": [], "p2": []},
  "confidence": "medium"
}""",
    "functions": """{
  "worker": "function_boundary_detector",
  "top_candidates": [{"func_addr": "0x401000", "func_name": "sub_401000", "priority": 9, "reason": "高xrefs"}],
  "excluded_thunks": 15,
  "total_functions": 2694,
  "confidence": "high"
}""",
    "function_deep": """{
  "func_addr": "0x180001000",
  "func_name": "sub_180001000",
  "functionality": "network_initialization",
  "suspicious": false,
  "key_apis": ["WSAStartup", "socket"],
  "confidence": "high",
  "related_to": ["0x180002500"]
}""",
}


def build_extraction_prompt(artifact: dict, artifact_type: str) -> str:
    """为指定 artifact 类型构建摘要提取 prompt。"""
    schema = SUMMARY_SCHEMAS.get(artifact_type, SUMMARY_SCHEMAS["strings"])
    return EXTRACTION_PROMPT_TEMPLATE.format(
        artifact_type=artifact_type,
        output_schema=schema,
        artifact_json=json.dumps(artifact, ensure_ascii=False, indent=2),
    )
