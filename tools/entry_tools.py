# -*- coding: utf-8 -*-
"""统一条目黑板的公开工具边界层。

所有公开函数仅接受关键词参数，返回纯 dict（``{"status": "success"|"error", ...}``）。
捕获 ``StoreError / ValueError / ValidationError / OSError`` 后统一封装为
``{"status": "error", "reason": <code>, "error": <可读描述>}``，绝不向 Agent 返回堆栈。
存储侧枚举一律为整数，公开视图通过 :func:`entry_public_dict` 逐字段映射为小写字符串。
"""

import copy
import functools
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import ValidationError

from tools.entry_models import (
    ChangeReason,
    ConclusionValidationStatus,
    DataValidationStatus,
    EntryType,
    ReviewStatus,
    SubjectKind,
    SubjectValidationStatus,
    enum_to_int,
    enum_to_name,
)
from tools.entry_store import StoreError, get_store, utc_now

# 点分路径 → 枚举类型：查询过滤时字符串值先按对应枚举转换为整数再比较
_ENUM_FILTER_FIELDS = {
    "entry_type": EntryType,
    "subject.kind": SubjectKind,
    "validation.data.status": DataValidationStatus,
    "validation.subject.status": SubjectValidationStatus,
    "validation.conclusion.status": ConclusionValidationStatus,
    "review.status": ReviewStatus,
}

_MISSING = object()


def _version_public(version):
    """把单个版本的存储整数枚举逐字段映射为小写字符串。"""
    data = version.model_dump()
    data["change_reason"] = enum_to_name(ChangeReason, data["change_reason"])
    data["validation"]["data"]["status"] = enum_to_name(
        DataValidationStatus, data["validation"]["data"]["status"]
    )
    data["validation"]["subject"]["status"] = enum_to_name(
        SubjectValidationStatus, data["validation"]["subject"]["status"]
    )
    data["validation"]["conclusion"]["status"] = enum_to_name(
        ConclusionValidationStatus, data["validation"]["conclusion"]["status"]
    )
    data["review"]["status"] = enum_to_name(ReviewStatus, data["review"]["status"])
    return data


def entry_public_dict(entry, include_history=False) -> dict:
    """条目存储模型 → 公开 dict；逐字段转换枚举，不做递归字符串替换。"""
    data = entry.model_dump()
    data["entry_type"] = enum_to_name(EntryType, data["entry_type"])
    data["subject"]["kind"] = enum_to_name(SubjectKind, data["subject"]["kind"])
    versions = entry.versions if include_history else [entry.versions[-1]]
    data["versions"] = [_version_public(version) for version in versions]
    return data


def _get_path(data: dict, path: str):
    """按点分路径取值；缺失时返回 _MISSING。"""
    current = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _set_path(target: dict, path: str, value) -> None:
    """按点分路径写入（必要时创建中间 dict）。"""
    parts = path.split(".")
    current = target
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def _error(exc: Exception, reason: Optional[str] = None) -> dict:
    """统一错误封装：reason 取 StoreError code 或按异常类别归类。"""
    if isinstance(exc, StoreError):
        code = exc.code
        detail = f"（{exc.details}）" if exc.details else ""
        message = f"存储层错误: {code}{detail}"
    elif isinstance(exc, ValidationError):
        code = "validation_error"
        message = f"数据校验失败: {exc.errors()[:3]}"
    elif isinstance(exc, ValueError):
        code = "invalid_argument"
        message = str(exc) or "非法参数"
    elif isinstance(exc, OSError):
        code = "io_error"
        message = f"IO 错误: {exc}"
    else:  # 兜底：任何未预期异常也不得返回堆栈
        code = reason or "internal_error"
        message = f"未预期错误: {type(exc).__name__}"
    return {"status": "error", "reason": code, "error": message}


def _wrap(func):
    """工具边界装饰器：统一捕获并封装异常。"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (StoreError, ValueError, ValidationError, OSError) as exc:
            return _error(exc)

    return wrapper


# ---------- 条目写入 ----------


@_wrap
def bb_create_entry(
    entry_type,
    subject_kind,
    subject_key,
    output,
    producer,
    project_name,
    idempotency_key,
) -> dict:
    """创建 v1 条目；同幂等键重放返回已有条目。"""
    store = get_store(project_name)
    entry = store.create_entry(
        entry_type, subject_kind, subject_key, output, producer, idempotency_key
    )
    return {"status": "success", "data": entry_public_dict(entry)}


@_wrap
def bb_append_version(
    entry_id,
    base_version,
    changes,
    producer,
    project_name,
    idempotency_key,
    change_reason,
) -> dict:
    """在 head 版本基础上追加完整版本；非 head 基准返回 version_conflict。"""
    store = get_store(project_name)
    entry = store.append_version(
        entry_id, base_version, changes, producer, idempotency_key, change_reason
    )
    return {"status": "success", "data": entry_public_dict(entry)}


# ---------- 条目读取 ----------


@_wrap
def bb_get_entry(entry_id, project_name, version=None, include_history=False) -> dict:
    """读取条目；可指定历史版本号，默认只返回 head 版本。"""
    store = get_store(project_name)
    if version is None:
        entry = store.get_entry(entry_id, include_history=include_history)
    else:
        full = store.get_entry(entry_id, include_history=True)
        target = store.get_version(entry_id, version)
        full.versions = [target]
        entry = full
    return {"status": "success", "data": entry_public_dict(entry, include_history)}


@_wrap
def bb_get_entry_history(entry_id, project_name) -> dict:
    """读取条目全部历史版本的公开视图。"""
    store = get_store(project_name)
    entry = store.get_entry(entry_id, include_history=True)
    return {"status": "success", "data": entry_public_dict(entry, include_history=True)}


@_wrap
def bb_query_entries(project_name, filters=None, fields=None, limit=50, cursor=None) -> dict:
    """按过滤条件查询全部条目的 head 版本。

    ``filters`` 的键为点分路径（如 ``producer.phase``、``validation.conclusion.status``），
    字符串枚举值先按 :data:`_ENUM_FILTER_FIELDS` 转换为整数再比较。
    ``fields`` 为点分路径白名单投影；缺省返回完整公开 head 视图。
    ``cursor`` 为字符串形式的偏移量，配合 ``limit`` 分页。
    """
    store = get_store(project_name)
    filters = dict(filters or {})

    # 预解析枚举过滤值：字符串 → 整数；非法名称直接报错
    parsed_filters: List[tuple] = []
    for path, value in filters.items():
        enum_cls = _ENUM_FILTER_FIELDS.get(path)
        if enum_cls is not None and isinstance(value, str):
            value = enum_to_int(enum_cls, value)
        parsed_filters.append((path, value))

    offset = 0
    if cursor is not None:
        offset = int(cursor)
    limit = max(1, int(limit))

    matches = []
    for entry in store.list_entries():
        # 查询视图：head 版本的存储整数视图，保证枚举比较基于整数
        head_view = entry.versions[-1].model_dump()
        head_view["entry_type"] = entry.entry_type
        head_view["subject"] = entry.subject.model_dump()
        ok = True
        for path, value in parsed_filters:
            actual = _get_path(head_view, path)
            if actual is _MISSING or actual != value:
                ok = False
                break
        if not ok:
            continue
        public = entry_public_dict(entry)
        if fields:
            projected: Dict[str, Any] = {}
            for path in fields:
                value = _get_path(public, path)
                if value is not _MISSING:
                    _set_path(projected, path, copy.deepcopy(value))
            # 投影时保留条目定位信息
            projected.setdefault("entry_id", public["entry_id"])
            projected.setdefault("head_version", public["head_version"])
            public = projected
        matches.append(public)

    page = matches[offset:offset + limit]
    next_cursor = None
    if offset + limit < len(matches):
        next_cursor = str(offset + limit)
    return {
        "status": "success",
        "data": page,
        "total": len(matches),
        "next_cursor": next_cursor,
    }


# ---------- 校验与人工审查 ----------


@_wrap
def bb_validate_entry(
    entry_id,
    version,
    project_name,
    producer,
    data_status=None,
    subject_status=None,
    conclusion_status=None,
    evidence_refs=None,
) -> dict:
    """对指定版本写入校验结论，追加 change_reason=validation 的完整版本。"""
    store = get_store(project_name)
    head = store.get_entry(entry_id, include_history=True)
    if version != head.head_version:
        raise StoreError(
            "version_conflict", {"head": head.head_version, "requested": version}
        )
    validation = head.versions[-1].validation.model_dump()
    if data_status is not None:
        validation["data"]["status"] = enum_to_int(DataValidationStatus, data_status)
    if subject_status is not None:
        validation["subject"]["status"] = enum_to_int(
            SubjectValidationStatus, subject_status
        )
    if conclusion_status is not None:
        validation["conclusion"]["status"] = enum_to_int(
            ConclusionValidationStatus, conclusion_status
        )
    if evidence_refs is not None:
        validation["conclusion"]["evidence_refs"] = list(evidence_refs)
    changes = {"validation": validation}
    entry = store.append_version(
        entry_id,
        version,
        changes,
        producer,
        f"validate:{entry_id}:{version}:{uuid4().hex}",
        ChangeReason.VALIDATION,
    )
    return {"status": "success", "data": entry_public_dict(entry)}


@_wrap
def bb_review_entries(refs, decision, project_name, reviewer="human", note="") -> dict:
    """批量人工审查：先校验全部 ref 均为当前 head，再逐项追加审查版本。

    任何一个 ref 版本过期都返回 ``version_conflict`` 且不写入任何内容；
    同一 ``entry_id`` 的重复 ref 返回 ``invalid_request`` 且不写入任何内容；
    全部成功后强制 ``flush()`` 落盘。返回 ``reviewed_refs`` 含更新后的版本号。
    """
    store = get_store(project_name)
    status_int = enum_to_int(ReviewStatus, decision)

    # 第一遍：校验全部 ref 都是当前 head，避免部分成功后才冲突；
    # 同一 entry_id 出现重复 ref 会破坏 all-or-nothing，直接拒绝
    heads: Dict[str, int] = {}
    producers: Dict[str, dict] = {}
    for ref in refs:
        entry_id = ref["entry_id"]
        if entry_id in heads:
            raise StoreError(
                "invalid_request", {"entry_id": entry_id, "issue": "duplicate_ref"}
            )
        entry = store.get_entry(entry_id, include_history=True)
        if ref["version"] != entry.head_version:
            raise StoreError(
                "version_conflict",
                {"entry_id": entry_id, "head": entry.head_version},
            )
        heads[entry_id] = entry.head_version
        # 审查 producer 复用被审版本的 producer，保证审计可追溯
        producers[entry_id] = entry.versions[-1].producer.model_dump()

    # 第二遍：逐项追加 change_reason=review 的完整版本（保留分析内容）
    reviewed_refs = []
    for ref in refs:
        entry_id = ref["entry_id"]
        review = {
            "status": status_int,
            "reviewer": reviewer,
            "reviewed_at": utc_now(),
            "note": note,
        }
        entry = store.append_version(
            entry_id,
            heads[entry_id],
            {"review": review},
            producers[entry_id],
            f"review:{entry_id}:{uuid4().hex}",
            ChangeReason.REVIEW,
        )
        reviewed_refs.append({"entry_id": entry_id, "version": entry.head_version})

    store.flush()
    return {"status": "success", "reviewed_refs": reviewed_refs}


# ---------- 幂等与维护 ----------


@_wrap
def bb_find_operation(idempotency_key, project_name) -> dict:
    """按幂等键查找已执行的操作，返回 ``{"entry_id", "version"}`` 或 None。"""
    store = get_store(project_name)
    result = store.find_operation(idempotency_key)
    data = {"entry_id": result[0], "version": result[1]} if result else None
    return {"status": "success", "data": data}


@_wrap
def bb_flush_store(project_name) -> dict:
    """强制把项目条目库落盘。"""
    store = get_store(project_name)
    store.flush()
    return {"status": "success"}


# ---------- runtime 键值区 ----------


@_wrap
def bb_set_runtime(key, value, project_name) -> dict:
    """写入 runtime 键值；默认不强制落盘，由 dirty 策略处理。"""
    store = get_store(project_name)
    store.set_runtime(key, value)
    return {"status": "success"}


@_wrap
def bb_get_runtime(key, project_name, default=None):
    """读取 runtime 键值；不存在时返回 default。"""
    store = get_store(project_name)
    return store.get_runtime(key, default)


@_wrap
def bb_checkpoint(phase, project_name) -> dict:
    """记录阶段 checkpoint：更新 current_phase / last_updated / run_id 并强制落盘。"""
    store = get_store(project_name)
    now = utc_now()
    run_id = store.get_runtime("run_id")
    if not run_id:
        run_id = f"run-{uuid4().hex[:8]}"
        store.set_runtime("run_id", run_id)
    store.set_runtime("current_phase", phase)
    store.set_runtime("last_updated", now)
    record = {"current_phase": phase, "run_id": run_id, "at": now}
    history = store.get_runtime("checkpoints", []) or []
    history.append(record)
    store.set_runtime("checkpoints", history)
    store.flush()
    return {"status": "success", "data": record}


@_wrap
def bb_load_checkpoint(project_name):
    """返回最近一次 checkpoint 记录；从未记录时返回 None。"""
    store = get_store(project_name)
    history = store.get_runtime("checkpoints", []) or []
    return history[-1] if history else None


@_wrap
def bb_log_event(event_type, details, project_name) -> dict:
    """向 runtime.execution_log 追加一条带 UTC 时间戳的事件。"""
    store = get_store(project_name)
    log = store.get_runtime("execution_log", []) or []
    log.append({"event_type": event_type, "details": details, "at": utc_now()})
    store.set_runtime("execution_log", log)
    return {"status": "success"}
