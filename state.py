"""LangGraph state definition: structured worker outputs + AnalysisState TypedDict."""
from operator import add
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, Field

# ---- 枚举类型（与 worker 提示词中的取值约束一致）----
ConfidenceLevel = Literal["high", "medium", "low"]
AnalysisStatus = Literal["success", "insufficient_data"]
SampleForm = Literal["exe_file_loader", "dll_plugin", "plain_exe", "unknown"]
SampleLanguage = Literal["c_cpp", "rust", "golang", "unknown"]


# ---- 各 worker 输出定义为 Pydantic 模型（根治 JSON 字符串状态）----
class ArchDetection(BaseModel):
    """arch_detection 子结构：样本编译语言/编译器/加壳方式/形态判定。"""

    language: SampleLanguage = "unknown"
    compiler_hints: list[str] = Field(default_factory=list)
    packer_protector: list[str] = Field(default_factory=list)
    sample_form: SampleForm = "unknown"
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


# ---- 图状态：只放小结构 + 黑板引用，不放 artifact 原文 ----
class AnalysisState(TypedDict, total=False):
    """LangGraph 图状态（替代 ADK session.state 的 JSON 字符串）。"""

    # 初始化参数
    sample_project_name: str
    sample_export_dir: str
    sample_type: str
    resume: bool  # True 时跳过 Phase -1 预提取（黑板已有 checkpoint）
    # Phase 0/1/2 结构化输出（同名直译 output_key）
    string_analysis: dict
    api_behavior_analysis: dict
    export_interface_analysis: dict
    behavior_profile: dict
    function_boundary_analysis: dict
    scheduler_decision: dict
    # HITL
    phase2_human_decision: str
    human_approved_functions: list[str]
    # Phase 3/4：扇出结果用 reducer 聚合
    func_analysis_refs: Annotated[list[dict], add]  # {"addr":..., "artifact":..., "summary_ref":...}
    shard_reports: Annotated[list[dict], add]
    final_report_ref: str
