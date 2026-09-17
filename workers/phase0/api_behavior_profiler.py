from google.adk.agents import LlmAgent
from workers.shared_prompts import FIVE_SECTION_TEMPLATE, JSON_OUTPUT_RULE, CONFIDENCE_RULES, DATA_SUFFICIENCY_RULE
from tools.file_loaders import load_imports, load_strings

API_BEHAVIOR_PROFILER_INSTRUCTION = FIVE_SECTION_TEMPLATE.format(
    role_definition=DATA_SUFFICIENCY_RULE + "\n\n" + """你是一名恶意代码行为分析专家，专注于通过 PE 文件的导入表（Import Directory Table）和导入地址表（IAT）推断样本的潜在恶意行为模式。
你的核心任务是从 imports.txt 中识别 API 组合、行为画像，并与 MITRE ATT&CK 技术进行映射。""",

    input_data_description="""你将通过工具 bb_read_extract 读取预提取的结构化导入数据（imports_extract.json）。
数据已按 DLL 分组：
- dll_to_apis: {DLL名: [API列表]}
- imports_flat: 所有导入的扁平列表

辅助信息（如有）：
- strings_extract.json 中的可疑字符串（用于交叉验证 API 哈希动态解析）""",

    analysis_dimensions="""请从以下维度进行分析：
1. API 组合分析：识别同时出现的 API 组合，这些组合强烈暗示特定恶意行为：
   - 进程注入: OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
   - 文件加载型: CreateFileW/ReadFile + VirtualAlloc + CreateThread
   - 持久化: RegOpenKeyEx + RegSetValueEx（Run键）或 OpenSCManager + CreateService
   - 网络通信: InternetOpen + InternetConnect + HttpSendRequest 或 socket + connect + send
   - 信息窃取: sqlite3_open、OpenClipboard + GetClipboardData、GetForegroundWindow
   - 反分析: IsDebuggerPresent + CheckRemoteDebuggerPresent + GetTickCount + EnumWindows
   - UAC绕过: ShellExecuteEx（runas）
   - 凭据窃取: LsaOpenPolicy、SamConnect、CredEnumerate

2. DLL 依赖分析：关注非标准 DLL 的导入。系统 DLL（kernel32, ntdll, user32）是正常的，但以下 DLL 需要关注：
   - ws2_32.dll / wininet.dll（网络功能）
   - crypt32.dll / advapi32.dll（加密/权限操作）
   - urlmon.dll / winhttp.dll（HTTP下载）

3. API 哈希动态解析迹象：当 IAT "看起来正常"（只有 CRT/STL API）但 strings 中有可疑内容时，标记为高度可疑的 API 哈希动态解析

4. 序数导入：通过序号而非名称导入的函数（尤其是 ntdll 中的函数）可能是试图隐藏 API 调用的迹象

5. 导入表整体健康度：评估 IAT 是否过于"干净"（可能是 API 哈希动态解析的反向指标）

若分析过程中发现与编译语言、加壳/保护方式或样本形态（EXE 文件加载型 / DLL 插件型）相关的证据（如异常稀疏的导入表、Install/ServiceMain 类导出、保护壳特征 API），请在结论的相应字段或 notes 中注明并附证据；无需输出独立结构。""",

    output_format=JSON_OUTPUT_RULE.format(json_schema="""{
  "total_imported_dlls": 数量,
  "total_imported_functions": 数量,
  "suspicious_apis": [
    {
      "api": "函数名",
      "dll": "所属DLL",
      "threat_category": "进程注入|持久化|信息窃取|网络通信|反分析|UAC绕过|凭据窃取|文件操作|其他",
      "risk_description": "该API在恶意语境中的典型用途"
    }
  ],
  "behavior_profiles": [
    {
      "profile_name": "行为画像名称（如'进程注入型'）",
      "matched_apis": ["构成该画像的API列表"],
      "confidence": "high|medium|low",
      "confidence_reason": "置信度理由"
    }
  ],
  "mitre_techniques": [
    {
      "technique_id": "TXXXX.XXX",
      "technique_name": "MITRE ATT&CK技术名称",
      "matched_apis": ["支持该技术判断的API"]
    }
  ],
  "api_combination_risks": [
    {
      "apis": ["API1", "API2", "API3"],
      "risk_description": "该组合暗示的具体攻击行为",
      "severity": "high|medium|low"
    }
  ],
  "api_hash_resolution_indicators": {
    "suspicious": true/false,
    "evidence": "支持判断的证据",
    "confidence": "high|medium|low"
  },
  "ordinal_imports_analysis": {
    "count": 数量,
    "suspicious": true/false,
    "notes": "分析备注"
  },
  "overall_assessment": "导入表整体评估结论"
}""") + CONFIDENCE_RULES,

    error_control="""- 仅基于实际输入的 API 列表进行判断，不要假设存在未列出的 API
- behavior_profiles 的 confidence 为 high 的强制要求：
  1. matched_apis 列表中的每个 API 必须全部存在于输入数据的 imports_flat 列表中
  2. matched_apis 数量 ≥ 3（单一 API 不得构成 high confidence 画像）
  3. 必须同时存在至少 2 个不同 DLL 的 API
- MITRE 技术映射需有 ≥2 个 API 支持，单一 API 不得映射到 MITRE 技术
- api_hash_resolution_indicators.suspicious=true 且 confidence=high → 必须在 strings_extract 中列出具体的 hash 解析相关字符串作为证据
- 序数导入的函数如果无法解析名称，标注为 ordinal_import_unresolved
""",
)

api_behavior_profiler = LlmAgent(
    name="api_behavior_profiler",
    description="Profiles API behavior from imports.txt to identify malware patterns and MITRE mappings.",
    instruction=API_BEHAVIOR_PROFILER_INSTRUCTION,
    tools=[load_imports, load_strings],
    output_key="api_behavior_analysis",
)
