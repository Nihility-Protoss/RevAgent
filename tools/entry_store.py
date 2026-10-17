"""进程内版本化条目库。

本任务只维护内存状态与完整版本规则；落盘、定时刷新与备份由后续任务补齐。
所有公开读取接口都返回深拷贝，避免调用方绕过版本规则修改库内数据。
"""

import copy
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from tools.entry_models import (
    ChangeReason,
    Entry,
    EntryType,
    EntryVersion,
    SubjectKind,
    enum_to_int,
    normalize_asm_address,
    validate_payload,
)


class StoreError(Exception):
    """带错误码的存储层异常，便于上层按 code 分支处理。"""

    def __init__(self, code: str, details: dict | None = None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProjectStore:
    """单个项目的条目库，保存条目的全部历史版本。"""

    ENTRY_PREFIXES = {
        1: "sm", 2: "fd", 3: "fn", 4: "dc", 5: "rp",
    }

    def __init__(
        self,
        project_name: str,
        directory: str | Path,
        flush_every_writes: int = 20,
        flush_interval_seconds: float = 5,
        backup_limit: int = 10,
    ):
        self.project_name = project_name
        self.directory = Path(directory)
        self.flush_every_writes = flush_every_writes
        self.flush_interval_seconds = flush_interval_seconds
        self.backup_limit = backup_limit

        self.entries: dict[str, Entry] = {}
        self.subject_index: dict[tuple[int, str], str] = {}
        self.idempotency_index: dict[str, tuple[str, int]] = {}
        self.runtime: dict[str, object] = {}
        self.revision = 0
        self.dirty = 0

        self._lock = threading.RLock()
        self._flush_lock = threading.Lock()

    # ---------- 写入 ----------

    def create_entry(
        self,
        entry_type,
        subject_kind,
        subject_key,
        output: dict,
        producer: dict,
        idempotency_key: str,
    ) -> Entry:
        """创建 v1 条目；同幂等键重放返回已有条目，同主题不同操作则冲突。"""
        with self._lock:
            existing = self.idempotency_index.get(idempotency_key)
            if existing:
                return copy.deepcopy(self.entries[existing[0]])

            type_int = enum_to_int(EntryType, entry_type)
            kind_int = enum_to_int(SubjectKind, subject_kind)
            key = self._normalize_subject_key(kind_int, subject_key)
            subject = (kind_int, key)
            if subject in self.subject_index:
                raise StoreError(
                    "subject_conflict",
                    {"entry_id": self.subject_index[subject]},
                )

            entry_id = self._new_entry_id(type_int)
            now = utc_now()
            version = EntryVersion(
                version=1,
                producer=producer,
                idempotency_key=idempotency_key,
                conclusion=output.get("conclusion", ""),
                payload=validate_payload(
                    type_int, copy.deepcopy(output.get("payload", {}))
                ),
                confidence=output.get("confidence", "low"),
                evidence_refs=copy.deepcopy(output.get("evidence_refs", [])),
                annotations=copy.deepcopy(output.get("annotations", {})),
                relation_refs=copy.deepcopy(output.get("relation_refs", [])),
                change_reason=ChangeReason.ANALYSIS,
                created_at=now,
            )
            entry = Entry(
                entry_id=entry_id,
                entry_type=type_int,
                subject={"kind": kind_int, "key": key},
                head_version=1,
                versions=[version],
                created_at=now,
            )

            self.entries[entry_id] = entry
            self.subject_index[subject] = entry_id
            self.idempotency_index[idempotency_key] = (entry_id, 1)
            self._mark_dirty()
            return copy.deepcopy(entry)

    def append_version(
        self,
        entry_id: str,
        base_version: int,
        changes: dict,
        producer: dict,
        idempotency_key: str,
        change_reason,
    ) -> Entry:
        """在 head 版本基础上追加完整版本；非 head 基准直接冲突。"""
        with self._lock:
            existing = self.idempotency_index.get(idempotency_key)
            if existing:
                return copy.deepcopy(self.entries[existing[0]])

            entry = self.entries.get(entry_id)
            if entry is None:
                raise StoreError("entry_not_found", {"entry_id": entry_id})
            if base_version != entry.head_version:
                raise StoreError("version_conflict", {"head": entry.head_version})

            reason = enum_to_int(ChangeReason, change_reason)
            data = entry.versions[-1].model_dump()
            data.update(copy.deepcopy(changes))
            data["version"] = entry.head_version + 1
            data["producer"] = producer
            data["idempotency_key"] = idempotency_key
            data["change_reason"] = reason
            data["created_at"] = utc_now()
            data["payload"] = validate_payload(entry.entry_type, data["payload"])
            if reason == int(ChangeReason.ANALYSIS):
                data["validation"]["conclusion"]["status"] = 0
                data["review"] = {
                    "status": 0, "reviewer": None,
                    "reviewed_at": None, "note": None,
                }
            new_version = type(entry.versions[-1]).model_validate(data)

            entry.versions.append(new_version)
            entry.head_version = new_version.version
            self.idempotency_index[idempotency_key] = (entry_id, new_version.version)
            self._mark_dirty()
            return copy.deepcopy(entry)

    def _mark_dirty(self) -> None:
        """本任务仅递增计数器；落盘触发在后续任务接入。"""
        with self._lock:
            self.revision += 1
            self.dirty += 1

    # ---------- 读取 ----------

    def get_entry(self, entry_id: str, include_history: bool = False) -> Entry:
        with self._lock:
            entry = self.entries.get(entry_id)
            if entry is None:
                raise StoreError("entry_not_found", {"entry_id": entry_id})
            view = copy.deepcopy(entry)
            if not include_history:
                view.versions = [view.versions[-1]]
            return view

    def get_version(self, entry_id: str, version: int) -> EntryVersion:
        with self._lock:
            entry = self.entries.get(entry_id)
            if entry is None:
                raise StoreError("entry_not_found", {"entry_id": entry_id})
            for item in entry.versions:
                if item.version == version:
                    return copy.deepcopy(item)
            raise StoreError(
                "version_not_found", {"entry_id": entry_id, "version": version}
            )

    def list_entries(self) -> list[Entry]:
        with self._lock:
            views = []
            for entry in self.entries.values():
                view = copy.deepcopy(entry)
                view.versions = [view.versions[-1]]
                views.append(view)
            return views

    def find_operation(self, idempotency_key: str) -> tuple[str, int] | None:
        with self._lock:
            return self.idempotency_index.get(idempotency_key)

    # ---------- 运行时键值区 ----------

    def set_runtime(self, key: str, value) -> None:
        with self._lock:
            self.runtime[key] = copy.deepcopy(value)
            self._mark_dirty()

    def get_runtime(self, key: str, default=None):
        with self._lock:
            if key not in self.runtime:
                return copy.deepcopy(default)
            return copy.deepcopy(self.runtime[key])

    # ---------- 内部工具 ----------

    @staticmethod
    def _normalize_subject_key(kind_int: int, subject_key: str) -> str:
        if kind_int == int(SubjectKind.ASM_ADDRESS):
            return normalize_asm_address(subject_key)
        return str(subject_key).strip()

    def _new_entry_id(self, type_int: int) -> str:
        prefix = self.ENTRY_PREFIXES[type_int]
        return f"{prefix}_{uuid4().hex[:12]}"
