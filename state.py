"""LangGraph 状态定义：结构化的 worker 输出 + AnalysisState TypedDict。"""
from operator import add
from typing import Annotated, Literal, Optional, TypedDict

from pydantic import BaseModel, Field, field_validator, model_validator

# ---- 枚举类型（与 worker 提示词中的取值约束一致）----
ConfidenceLevel = Literal["high", "medium", "low"]
AnalysisStatus = Literal["success", "insufficient_data"]
SampleForm = Literal["exe_file_loader", "dll_plugin", "plain_exe", "unknown"]
SampleLanguage = Literal["c_cpp", "rust", "golang", "unknown"]
BehaviorPrimaryType = Literal["RAT", "Stealer", "Loader", "Backdoor", "Unknown"]
ChecklistStatus = Literal["covered", "partial", "not_covered"]

# arch_detection.code_frameworks 的建议取值词表（C1：框架/引擎级证据，多选、可空）。
# 与 workers/knowledge/ 中各框架指南的 applies_to 标签（code_frameworks:<值>）一一对应；
# 词表外取值不报错（list[str] 宽松兜底），但不会匹配到任何指南。
ARCH_CODE_FRAMEWORK_VOCABULARY = (
    "vm_protected",      # VM 保护 / OLLVM 控制流平坦化等重度混淆
    "lua_scripted",      # Lua 5.1 / LuaJIT 脚本引擎驱动
    "encrypted_sqlite",  # 嵌入式加密 SQLite 数据库（脚本/规则/配置载体）
    "yara_embedded",     # 内嵌 libyara 引擎
)


# ---- 各 worker 输出定义为 Pydantic 模型（根治 JSON 字符串状态）----
class ArchDetection(BaseModel):
    """arch_detection 子结构：样本编译语言/编译器/加壳方式/形态/框架引擎判定。"""

    language: SampleLanguage = "unknown"
    compiler_hints: list[str] = Field(default_factory=list)
    packer_protector: list[str] = Field(default_factory=list)
    sample_form: SampleForm = "unknown"
    # C1 扩容新增（可选，向后兼容）：框架/引擎级证据，取值见 ARCH_CODE_FRAMEWORK_VOCABULARY
    code_frameworks: list[str] = Field(default_factory=list)
    confidence: ConfidenceLevel = "low"
    evidence: list[str] = Field(default_factory=list)


class StringAnalysis(BaseModel):
    """Phase 0 string_artifact_analyst 的结构化输出。"""

    status: AnalysisStatus = "success"
    sample_family_hints: list[str] = Field(default_factory=list)
    file_loader_indicators: dict = Field(default_factory=dict)
    pdb_analysis: dict = Field(default_factory=dict)
    key_strings: list[dict] = Field(default_factory=list)
    network_indicators: dict = Field(default_factory=dict)
    persistence_indicators: dict = Field(default_factory=dict)
    suspicious_patterns: list[dict] = Field(default_factory=list)
    overall_assessment: str = ""
    arch_detection: ArchDetection = Field(default_factory=ArchDetection)
    recommended_next_steps: list[str] = Field(default_factory=list)


class FuncCandidate(BaseModel):
    """function_boundary_detector 推荐的单个候选函数。"""

    func_addr: str = ""
    func_name: str = ""
    size: int = 0
    xrefs: int = 0
    is_thunk: bool = False
    is_export: bool = False
    analysis_priority: int = 0
    priority_reason: str = ""


class FunctionBoundaryAnalysis(BaseModel):
    """Phase 1 function_boundary_detector 的结构化输出。"""

    status: AnalysisStatus = "success"
    total_functions: int = 0
    filtered_functions: int = 0
    candidates: list[FuncCandidate] = Field(default_factory=list)
    recommended_top_n: int = 20
    exclusion_notes: list[dict] = Field(default_factory=list)
    export_functions_highlight: list[dict] = Field(default_factory=list)


# ---- Phase 0 api_behavior_profiler ----
class SuspiciousApi(BaseModel):
    """单个可疑 API 条目。"""

    api: str = ""
    dll: str = ""
    # 取值：进程注入|持久化|信息窃取|网络通信|反分析|UAC绕过|凭据窃取|文件操作|其他
    threat_category: str = "其他"
    risk_description: str = ""


class ApiProfile(BaseModel):
    """API 组合行为画像（behavior_profiles 列表项）。"""

    profile_name: str = ""
    matched_apis: list[str] = Field(default_factory=list)
    confidence: ConfidenceLevel = "low"
    confidence_reason: str = ""


class MitreTechnique(BaseModel):
    """MITRE ATT&CK 技术映射条目。"""

    technique_id: str = ""
    technique_name: str = ""
    matched_apis: list[str] = Field(default_factory=list)


class ApiCombinationRisk(BaseModel):
    """API 组合风险条目（severity 取值与置信度词表一致）。"""

    apis: list[str] = Field(default_factory=list)
    risk_description: str = ""
    severity: ConfidenceLevel = "low"


class ApiHashResolutionIndicators(BaseModel):
    """API 哈希动态解析迹象。"""

    suspicious: bool = False
    evidence: str = ""
    confidence: ConfidenceLevel = "low"


class OrdinalImportsAnalysis(BaseModel):
    """序数导入分析。"""

    count: int = 0
    suspicious: bool = False
    notes: str = ""


class ApiBehaviorAnalysis(BaseModel):
    """Phase 0 api_behavior_profiler 的结构化输出。"""

    status: AnalysisStatus = "success"
    total_imported_dlls: int = 0
    total_imported_functions: int = 0
    suspicious_apis: list[SuspiciousApi] = Field(default_factory=list)
    behavior_profiles: list[ApiProfile] = Field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    api_combination_risks: list[ApiCombinationRisk] = Field(default_factory=list)
    api_hash_resolution_indicators: ApiHashResolutionIndicators = Field(
        default_factory=ApiHashResolutionIndicators
    )
    ordinal_imports_analysis: OrdinalImportsAnalysis = Field(
        default_factory=OrdinalImportsAnalysis
    )
    overall_assessment: str = ""


# ---- Phase 0 export_interface_analyzer ----
class LoadingPattern(BaseModel):
    """加载方式判定（五选一）。"""

    # 提示词取值：标准插件型|反射加载|侧加载|宿主Patch|未知；
    # 分析维度段另允许"混合型|无法确定"，两处表述不完全一致，故保持 str 宽松兜底
    pattern_type: str = "未知"
    confidence: ConfidenceLevel = "low"
    evidence: list[str] = Field(default_factory=list)


class OrdinalMappingEntry(BaseModel):
    """导出 ordinal 映射条目。"""

    ordinal: int = 0
    name: str = ""
    address: str = ""
    likely_role: str = "其他"  # 初始化|命令分发|回调注册|其他


class TlsCallbackAnalysis(BaseModel):
    """TLS 回调检查结论。"""

    has_tls_callback: bool = False
    suspicious: bool = False
    assessment: str = ""


class PackerIndicator(BaseModel):
    """加壳迹象条目。"""

    indicator: str = ""
    confidence: ConfidenceLevel = "low"
    evidence: str = ""


class SuspiciousExport(BaseModel):
    """可疑导出函数条目。"""

    name: str = ""
    address: str = ""
    assessment: str = ""


class CommandDispatcherInference(BaseModel):
    """命令分发器接口推断（DLL 插件型）。"""

    has_command_dispatcher: bool = False
    dispatcher_ordinal: Optional[int | str] = None  # ordinal 号或 null
    cmd_offset_semantics: str = ""
    confidence: ConfidenceLevel = "low"


class CallbackArchitecture(BaseModel):
    """回调架构推断（地址无法推断时为 null）。"""

    main_callback_addr: Optional[str] = None
    string_callback_addr: Optional[str] = None
    file_callback_addr: Optional[str] = None
    notes: str = ""


class ExportInterfaceAnalysis(BaseModel):
    """Phase 0 export_interface_analyzer 的结构化输出。"""

    status: AnalysisStatus = "success"
    loading_pattern: LoadingPattern = Field(default_factory=LoadingPattern)
    ordinal_mapping: list[OrdinalMappingEntry] = Field(default_factory=list)
    tls_callback_analysis: TlsCallbackAnalysis = Field(default_factory=TlsCallbackAnalysis)
    packer_indicators: list[PackerIndicator] = Field(default_factory=list)
    suspicious_exports: list[SuspiciousExport] = Field(default_factory=list)
    command_dispatcher_inference: CommandDispatcherInference = Field(
        default_factory=CommandDispatcherInference
    )
    callback_architecture: CallbackArchitecture = Field(default_factory=CallbackArchitecture)
    overall_assessment: str = ""


# ---- Phase 1 behavior_profile_synthesizer ----
class BehaviorTyping(BaseModel):
    """behavior_profile 子结构：行为定型结论（RAT/Stealer/Loader/Backdoor）。"""

    primary_type: BehaviorPrimaryType = "Unknown"
    secondary_types: list[str] = Field(default_factory=list)
    confidence: ConfidenceLevel = "low"
    evidence: list[str] = Field(default_factory=list)


class CommandAndResidence(BaseModel):
    """命令分发与驻留模式。"""

    has_command_dispatcher: bool = False
    dispatcher_type: str = "unknown"  # switch-case|callback-driven|other|unknown
    residence_type: str = "未知"  # 常驻|一次性|混合|未知
    notes: str = ""


class InfoStealingCapability(BaseModel):
    """信息窃取能力条目。"""

    target: str = ""
    apis: list[str] = Field(default_factory=list)
    confidence: ConfidenceLevel = "low"


class PersistenceMechanism(BaseModel):
    """持久化机制条目。"""

    mechanism: str = ""
    evidence: str = ""
    confidence: ConfidenceLevel = "low"


class AntiDebuggingTechnique(BaseModel):
    """反调试对抗条目。"""

    technique: str = ""
    evidence: str = ""
    confidence: ConfidenceLevel = "low"


class BreakpointSuggestion(BaseModel):
    """单个断点建议（address_hint 无法从输入推断时为 null）。"""

    location: str = ""
    purpose: str = ""
    address_hint: Optional[str] = None


class BreakpointMatrix(BaseModel):
    """P0/P1/P2 断点矩阵。"""

    p0: list[BreakpointSuggestion] = Field(default_factory=list)
    p1: list[BreakpointSuggestion] = Field(default_factory=list)
    p2: list[BreakpointSuggestion] = Field(default_factory=list)


class AnalysisChecklist(BaseModel):
    """8 步分析 checklist 完成状态。"""

    export_table_strings: ChecklistStatus = "not_covered"
    execution_chain: ChecklistStatus = "not_covered"
    callback_decrypt: ChecklistStatus = "not_covered"
    command_semantics: ChecklistStatus = "not_covered"
    memory_execution: ChecklistStatus = "not_covered"
    info_stealing: ChecklistStatus = "not_covered"
    persistence: ChecklistStatus = "not_covered"
    anti_debug: ChecklistStatus = "not_covered"


class BehaviorProfile(BaseModel):
    """Phase 1 behavior_profile_synthesizer 的结构化输出。"""

    status: AnalysisStatus = "success"
    behavior_profile: BehaviorTyping = Field(default_factory=BehaviorTyping)
    command_and_residence: CommandAndResidence = Field(default_factory=CommandAndResidence)
    info_stealing_capabilities: list[InfoStealingCapability] = Field(default_factory=list)
    persistence_mechanisms: list[PersistenceMechanism] = Field(default_factory=list)
    anti_debugging: list[AntiDebuggingTechnique] = Field(default_factory=list)
    execution_chain_skeleton: str = ""
    breakpoint_matrix: BreakpointMatrix = Field(default_factory=BreakpointMatrix)
    analysis_checklist: AnalysisChecklist = Field(default_factory=AnalysisChecklist)
    overall_assessment: str = ""
    recommended_next_steps: list[str] = Field(default_factory=list)


# ---- Phase 2 scheduler ----

# 分析主题词表：scheduler 的 proposed_topics 与 AnalysisTask.topic 的建议取值
# （批次 A1 仅落地数据模型；主题制编排接线在批次 A2）
ANALYSIS_TOPIC_VOCABULARY = (
    "init_config_decrypt",
    "command_dispatcher",
    "persistence",
    "injection_loader",
    "stealer",
    "network_stack",
    "anti_analysis",
    "export_interface",
)


class SchedulerSummary(BaseModel):
    """scheduler_decision 的 summary 子结构：定型结论与关键计数。"""

    behavior_type: str = "Unknown"
    confidence: ConfidenceLevel = "low"
    high_risk_count: int = 0
    candidate_functions: int = 0


class SchedulerDetails(BaseModel):
    """scheduler_decision 的 details 子结构：分来源关键发现。"""

    string_key_findings: list[str] = Field(default_factory=list)
    api_key_findings: list[str] = Field(default_factory=list)
    export_key_findings: list[str] = Field(default_factory=list)
    top_candidates: list[str] = Field(default_factory=list)


class SchedulerDecision(BaseModel):
    """Phase 2 scheduler 的结构化输出。"""

    status: AnalysisStatus = "success"
    phase: str = "initial_complete"
    action: str = "AWAITING_HUMAN_REVIEW"
    summary: SchedulerSummary = Field(default_factory=SchedulerSummary)
    details: SchedulerDetails = Field(default_factory=SchedulerDetails)
    # 根据行为定型建议的后续深度分析主题（取值见 ANALYSIS_TOPIC_VOCABULARY；
    # 仅供批次 A2 的主题制编排消费，本批次不影响图拓扑）
    proposed_topics: list[str] = Field(default_factory=list)


# ---- Phase 2 任务清单（task manifest，批次 A1：仅数据模型，编排接线在 A2）----
TaskKind = Literal["topic", "function"]
TaskStatus = Literal["pending", "in_progress", "done", "failed", "skipped"]


class AnalysisTask(BaseModel):
    """任务清单中的单个分析任务：主题制（topic）或函数制（function）。"""

    task_id: str = ""
    kind: TaskKind = "function"
    topic: Optional[str] = None  # kind=topic 时的主题词（建议取 ANALYSIS_TOPIC_VOCABULARY）
    function_addrs: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)  # 依赖的前置 task_id
    output_doc: str = ""  # 产出文档落盘路径（批次 A2 归档输出约定）
    status: TaskStatus = "pending"


class TaskManifest(BaseModel):
    """分析任务清单：批次 A2 主题制批次分析的执行队列。"""

    tasks: list[AnalysisTask] = Field(default_factory=list)


# ---- Phase 3 双轨制：主题 Worker 输出（批次 A2）----
class TopicFinding(BaseModel):
    """主题分析的单条发现：逐命令/逐机制条目（五要素之分析对象 + 结论）。"""

    subject: str = ""  # 分析对象：命令编号 / 机制名 / 函数地址等
    conclusion: str = ""  # 对该对象的结论
    confidence: ConfidenceLevel = "low"


class TopicEvidence(BaseModel):
    """主题分析的关键引用：地址 + 代码片段/字符串 + 来源。"""

    address: str = ""
    snippet: str = ""  # 逐字引用的代码片段或字符串原文
    source: str = ""  # 来源类型：decompile|disassembly|strings|imports 等


class TopicAnalysis(BaseModel):
    """主题 Worker 的结构化输出：围绕一个分析主题（ANALYSIS_TOPIC_VOCABULARY）的
    成体系结论，对齐金标准五要素（分析对象/结论/关键引用/置信度/未解之谜）。"""

    status: AnalysisStatus = "success"
    topic: str = ""
    summary: str = ""  # 主题总体结论（一段话）
    findings: list[TopicFinding] = Field(default_factory=list)  # 逐命令/逐机制条目
    evidence: list[TopicEvidence] = Field(default_factory=list)  # 关键引用
    confidence: ConfidenceLevel = "low"
    unresolved: list[str] = Field(default_factory=list)  # 未解之谜


# ---- Phase 3 后置 verification_agent ----
VerificationVerdict = Literal["verified", "disputed", "unverifiable"]
_VERIFICATION_VERDICTS = ("verified", "disputed", "unverifiable")


class VerificationFinding(BaseModel):
    """单条 high 置信度发现的证据回查结论。"""

    finding: str = ""  # 被验证的发现原文（逐字引用，禁止改写）
    source: str = ""  # 发现来源（如 strings_summary / phase3_func_0x401000）
    verdict: VerificationVerdict = "unverifiable"
    reason: str = ""  # 分类理由（disputed 必须写明具体矛盾点）
    evidence_ref: str = ""  # 回查到的 artifact 名称或原文片段；unverifiable 时为空

    @field_validator("verdict", mode="before")
    @classmethod
    def _normalize_verdict(cls, v):
        """大小写/空白容错；词表外取值一律归入 unverifiable（宁缺毋滥）。"""
        s = str(v).strip().lower()
        return s if s in _VERIFICATION_VERDICTS else "unverifiable"


class VerificationReport(BaseModel):
    """验证 Worker 的结构化输出：high 置信度发现按证据回查结果分三类。"""

    status: AnalysisStatus = "success"
    verified: list[VerificationFinding] = Field(default_factory=list)
    disputed: list[VerificationFinding] = Field(default_factory=list)
    unverifiable: list[VerificationFinding] = Field(default_factory=list)
    overall_assessment: str = ""

    @model_validator(mode="before")
    @classmethod
    def _bucket_flat_findings(cls, data):
        """容错分类：模型若输出扁平 findings 列表，按 verdict 归入三个桶。

        与已有分桶并存时做合并；非 dict 条目直接丢弃。
        """
        if not isinstance(data, dict):
            return data
        data = dict(data)
        findings = data.pop("findings", None)
        if not isinstance(findings, list):
            return data
        buckets: dict[str, list] = {k: [] for k in _VERIFICATION_VERDICTS}
        for item in findings:
            if not isinstance(item, dict):
                continue
            verdict = str(item.get("verdict", "")).strip().lower()
            if verdict not in buckets:
                verdict = "unverifiable"
                item = {**item, "verdict": verdict}
            buckets[verdict].append(item)
        for key, items in buckets.items():
            existing = data.get(key)
            data[key] = (list(existing) if isinstance(existing, list) else []) + items
        return data


# ---- 图状态：只放小结构 + 黑板引用，不放 artifact 原文 ----
class AnalysisState(TypedDict, total=False):
    """LangGraph 图状态（替代 ADK session.state 的 JSON 字符串）。"""

    # 初始化参数
    sample_project_name: str
    sample_export_dir: str
    sample_type: str
    resume: bool  # True 时跳过 Phase -1 预提取（黑板已有 checkpoint）
    # C2 用户分析优先级（启动参数 --focus / --exclude 的逗号分隔原文）：
    # pre_extract 节点落盘 USER.md，各 prompt 注入点经 _load_user_special_requirements 合并读取
    user_focus: str
    user_exclude: str
    # Phase 0/1/2 结构化输出（同名直译 output_key）
    string_analysis: dict
    api_behavior_analysis: dict
    export_interface_analysis: dict
    behavior_profile: dict
    function_boundary_analysis: dict
    scheduler_decision: dict
    # HITL 人工审批节点写入的字段
    phase2_human_decision: str
    human_approved_functions: list[str]
    # Phase 3/4：扇出结果用 reducer 聚合
    func_analysis_refs: Annotated[list[dict], add]  # {"addr":..., "artifact":..., "summary_ref":...}
    # Phase 3 双轨制（批次 A2）：调度节点写任务清单，主题 Worker 结果经 reducer 聚合
    task_manifest: dict  # TaskManifest model_dump（meta/task_manifest.json 同步落盘）
    topic_analysis_refs: Annotated[list[dict], add]  # {"topic":..., "task_id":..., "summary":...}
    # Phase 3 后置验证 Worker 的结构化输出（VerificationReport model_dump）
    verification_report: dict
    # Phase 3 后置质量编排（orchestrator，纯代码节点）：docs 归档 +
    # 五要素质量检查 + 缺口识别（meta/gap_report.json）+ 矛盾发现（→ USER.md）的计数报告
    orchestrator_report: dict
    shard_reports: Annotated[list[dict], add]
    final_report_ref: str
    # 综合报告 Worker 落盘的 Markdown 手册路径（data/output/{project}/final_report.md）
    report_md_path: str
