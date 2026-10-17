"""统一版本化条目黑板的存储模型与整数枚举映射。

所有枚举均为 IntEnum，且 StorageModel 开启 use_enum_values=True，
保证模型 dump 后只含普通整数，便于持久化与跨进程比较。
"""

from enum import IntEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EntryType(IntEnum):
    SAMPLE = 1
    FINDING = 2
    FUNCTION = 3
    DECISION = 4
    REPORT = 5


class SubjectKind(IntEnum):
    SAMPLE = 1
    ASM_ADDRESS = 2
    STRING = 3
    API = 4
    EXPORT = 5
    BEHAVIOR = 6
    IOC = 7
    DECISION = 8
    REPORT = 9


class DataValidationStatus(IntEnum):
    INVALID = 0
    VALID = 1


class SubjectValidationStatus(IntEnum):
    UNKNOWN = 0
    VALID = 1
    INVALID = 2
    INSUFFICIENT_DATA = 3


class ConclusionValidationStatus(IntEnum):
    UNVERIFIED = 0
    VALID = 1
    INVALID = 2
    DISPUTED = 3


class ReviewStatus(IntEnum):
    PENDING = 0
    CONFIRMED = 1
    REJECTED = 2


class ChangeReason(IntEnum):
    ANALYSIS = 1
    VALIDATION = 2
    REVIEW = 3
    ANNOTATION = 4


def enum_to_int(enum_cls, value) -> int:
    if isinstance(value, bool):
        raise ValueError("布尔值不是合法枚举")
    if isinstance(value, str):
        try:
            value = enum_cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"未知枚举名称: {value}") from exc
    try:
        return int(enum_cls(value))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"非法枚举值: {value}") from exc


def enum_to_name(enum_cls, value) -> str:
    return enum_cls(enum_to_int(enum_cls, value)).name.lower()


def normalize_asm_address(value: str) -> str:
    clean = value.strip().lower()
    if clean.startswith("sub_"):
        clean = clean[4:]
    if clean.startswith("0x"):
        clean = clean[2:]
    if not clean:
        raise ValueError("空函数地址")
    return f"0x{int(clean, 16):x}"


class StorageModel(BaseModel):
    model_config = ConfigDict(
        use_enum_values=True, validate_default=True, extra="forbid"
    )


class Subject(StorageModel):
    kind: SubjectKind
    key: str


class Producer(StorageModel):
    phase: str
    agent: str
    run_id: str


class EntryRef(StorageModel):
    entry_id: str
    version: int


class DataValidation(StorageModel):
    status: DataValidationStatus = DataValidationStatus.VALID
    errors: list[str] = Field(default_factory=list)


class SubjectValidation(StorageModel):
    status: SubjectValidationStatus = SubjectValidationStatus.UNKNOWN
    evidence_refs: list[str] = Field(default_factory=list)


class ConclusionValidation(StorageModel):
    status: ConclusionValidationStatus = ConclusionValidationStatus.UNVERIFIED
    evidence_refs: list[str] = Field(default_factory=list)


class Validation(StorageModel):
    data: DataValidation = Field(default_factory=DataValidation)
    subject: SubjectValidation = Field(default_factory=SubjectValidation)
    conclusion: ConclusionValidation = Field(default_factory=ConclusionValidation)


class Review(StorageModel):
    status: ReviewStatus = ReviewStatus.PENDING
    reviewer: str | None = None
    reviewed_at: str | None = None
    note: str | None = None


class EntryVersion(StorageModel):
    version: int
    producer: Producer
    idempotency_key: str
    conclusion: str = Field(max_length=500)
    payload: dict[str, Any]
    confidence: Literal["high", "medium", "low"]
    evidence_refs: list[str] = Field(default_factory=list)
    validation: Validation = Field(default_factory=Validation)
    review: Review = Field(default_factory=Review)
    annotations: dict[str, str] = Field(default_factory=dict)
    relation_refs: list[EntryRef] = Field(default_factory=list)
    change_reason: ChangeReason
    created_at: str


class Entry(StorageModel):
    entry_id: str
    entry_type: EntryType
    subject: Subject
    head_version: int
    versions: list[EntryVersion]
    created_at: str


class WorkerOutput(StorageModel):
    status: Literal["success", "insufficient_data", "parse_failed"]
    conclusion: str = Field(max_length=500)
    confidence: Literal["high", "medium", "low"] = "low"
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    annotations: dict[str, str] = Field(default_factory=dict)


class SamplePayload(StorageModel):
    overall_assessment: str = ""
    arch_detection: dict[str, Any] = Field(default_factory=dict)


class FindingPayload(StorageModel):
    category: str
    name: str
    details: dict[str, Any] = Field(default_factory=dict)


class FunctionCandidatePayload(StorageModel):
    priority: int = 0
    priority_reason: str = ""
    size: int = 0
    xrefs: int = 0
    is_thunk: bool = False
    is_export: bool = False


class FunctionAnalysisPayload(StorageModel):
    functionality: str = ""
    key_apis: list[str] = Field(default_factory=list)
    suspicious_behaviors: list[dict[str, Any]] = Field(default_factory=list)
    related_functions: list[str] = Field(default_factory=list)
    analysis_notes: str = ""


class FunctionPayload(StorageModel):
    func_name: str = ""
    candidate: FunctionCandidatePayload | None = None
    analysis: FunctionAnalysisPayload | None = None


class DecisionPayload(StorageModel):
    action: str
    selected_function_refs: list[EntryRef] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class ReportPayload(StorageModel):
    report_kind: Literal["shard", "final"]
    shard_id: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)


PAYLOAD_MODELS = {
    EntryType.SAMPLE: SamplePayload,
    EntryType.FINDING: FindingPayload,
    EntryType.FUNCTION: FunctionPayload,
    EntryType.DECISION: DecisionPayload,
    EntryType.REPORT: ReportPayload,
}


def validate_payload(entry_type, payload: dict) -> dict:
    kind = EntryType(enum_to_int(EntryType, entry_type))
    return PAYLOAD_MODELS[kind].model_validate(payload).model_dump()
