"""进程内版本化条目库。

维护内存状态与完整版本规则，并支持原子 pickle 快照落盘、定时刷新与备份恢复。
所有公开读取接口都返回深拷贝，避免调用方绕过版本规则修改库内数据。
"""

import atexit
import copy
import hashlib
import os
import pickle
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from config import cfg_int
from tools.blackboard_tools import board_path

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
        self.dirty = False
        # 未落盘写计数与已落盘版本号，用于写次数触发与 dirty 判定
        self._unflushed = 0
        self.persisted_revision = 0
        # 最近一次成功加载的快照来源路径；新建库时为 None
        self.recovered_from: str | None = None
        self._closed = False
        self._timer: threading.Timer | None = None

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
        """递增 revision 与未落盘计数，并按需触发写次数/定时刷新。"""
        with self._lock:
            self.revision += 1
            self.dirty = True
            self._unflushed += 1
            if self._unflushed >= self.flush_every_writes:
                self.flush()
            elif (
                not self._closed
                and self.flush_interval_seconds > 0
                and self._timer is None
            ):
                self._timer = threading.Timer(
                    self.flush_interval_seconds, self._on_flush_timer
                )
                self._timer.daemon = True
                self._timer.start()

    def _on_flush_timer(self) -> None:
        """定时器回调：到期后清理引用并落盘（守护线程，不阻塞 pytest 退出）。"""
        with self._lock:
            self._timer = None
            if self._closed:
                return
        self.flush()

    # ---------- 落盘与恢复 ----------

    def _encode_snapshot(self, revision: int) -> bytes:
        """把当前条目与运行时区编码为带 sha256 校验的信封字节串（仅普通 dict/int）。"""
        payload = {
            "entries": [entry.model_dump() for entry in self.entries.values()],
            "runtime": copy.deepcopy(self.runtime),
        }
        payload_bytes = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
        envelope = {
            "format_version": 1,
            "project_name": self.project_name,
            "revision": revision,
            "payload": payload_bytes,
            "sha256": hashlib.sha256(payload_bytes).hexdigest(),
        }
        return pickle.dumps(envelope, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def _decode_snapshot(cls, data: bytes, project_name: str):
        """校验并还原快照字节串；与启动加载使用同一套校验规则。

        返回 (revision, entries, runtime)；任何一步失败抛 ValueError。
        """
        envelope = pickle.loads(data)
        if not isinstance(envelope, dict):
            raise ValueError("快照信封不是 dict")
        if envelope.get("format_version") != 1:
            raise ValueError("不支持的快照格式版本")
        if envelope.get("project_name") != project_name:
            raise ValueError("快照项目名不匹配")
        payload_bytes = envelope.get("payload")
        sha256 = envelope.get("sha256")
        if not isinstance(payload_bytes, (bytes, bytearray)):
            raise ValueError("快照 payload 缺失")
        if hashlib.sha256(payload_bytes).hexdigest() != sha256:
            raise ValueError("快照 sha256 校验失败")
        payload = pickle.loads(payload_bytes)
        if not isinstance(payload, dict) or "entries" not in payload or "runtime" not in payload:
            raise ValueError("快照 payload 结构非法")
        entries = {}
        for raw in payload["entries"]:
            entry = Entry.model_validate(raw)
            entries[entry.entry_id] = entry
        return envelope["revision"], entries, copy.deepcopy(payload["runtime"])

    def _backup_path(self, index: int):
        return self.directory / f"store.bak.{index:03d}.pickle"

    def _rotate_and_replace(self, temp_path):
        oldest = self._backup_path(self.backup_limit)
        if oldest.exists():
            oldest.unlink()
        for index in range(self.backup_limit - 1, 0, -1):
            source = self._backup_path(index)
            if source.exists():
                os.replace(source, self._backup_path(index + 1))
        main_path = self.directory / "store.pickle"
        if main_path.exists():
            shutil.copy2(main_path, self._backup_path(1))
        os.replace(temp_path, main_path)

    def flush(self) -> None:
        """原子落盘：抓版本快照 → 写临时文件并回读校验 → 轮换替换 → 推进 persisted_revision。"""
        with self._lock:
            revision = self.revision
            data = self._encode_snapshot(revision)
        with self._flush_lock:
            self.directory.mkdir(parents=True, exist_ok=True)
            temp_path = self.directory / "store.pickle.tmp"
            with open(temp_path, "wb") as f:
                f.write(data)
            # 与启动加载使用相同的校验函数，写后回读验证再轮换
            self._decode_snapshot(data, self.project_name)
            self._rotate_and_replace(temp_path)
        with self._lock:
            self.persisted_revision = revision
            self.dirty = self.revision > self.persisted_revision
            self._unflushed = 0

    @classmethod
    def load_or_create(
        cls,
        project_name: str,
        directory,
        flush_every_writes: int = 20,
        flush_interval_seconds: float = 5,
        backup_limit: int = 10,
    ) -> "ProjectStore":
        """加载既有快照；主文件损坏时依次尝试备份；全部无效时 fail-closed。

        目录可能尚不存在（新建项目），此时返回全新空库，首次 flush 时再建目录。
        """
        directory = Path(directory)
        candidates = [directory / "store.pickle"]
        candidates += [
            directory / f"store.bak.{index:03d}.pickle" for index in range(1, backup_limit + 1)
        ]
        for candidate in candidates:
            if not candidate.exists():
                continue
            try:
                revision, entries, runtime = cls._decode_snapshot(
                    candidate.read_bytes(), project_name
                )
            except Exception:
                continue
            store = cls(
                project_name,
                directory=directory,
                flush_every_writes=flush_every_writes,
                flush_interval_seconds=flush_interval_seconds,
                backup_limit=backup_limit,
            )
            store.entries = entries
            store.runtime = runtime
            store.revision = revision
            store.persisted_revision = revision
            store.dirty = False
            store.recovered_from = str(candidate)
            # 快照不冗余保存索引：加载后扫描全部条目与版本重建
            for entry in entries.values():
                store.subject_index[(int(entry.subject.kind), entry.subject.key)] = entry.entry_id
                for version in entry.versions:
                    store.idempotency_index[version.idempotency_key] = (
                        entry.entry_id, version.version,
                    )
            return store
        if any(candidate.exists() for candidate in candidates):
            raise StoreError("snapshot_invalid", {"project_name": project_name})
        return cls(
            project_name,
            directory=directory,
            flush_every_writes=flush_every_writes,
            flush_interval_seconds=flush_interval_seconds,
            backup_limit=backup_limit,
        )

    def close(self) -> None:
        """取消定时刷新；仍有未落盘数据时强制 flush。可重复调用。"""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        if self.dirty:
            self.flush()

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


# ---------- 项目级 Store 注册表 ----------

_store_registry: dict[str, ProjectStore] = {}
_registry_lock = threading.Lock()


def get_store(project_name: str) -> ProjectStore:
    """按项目名获取（或创建）共享 Store；缓存键为 entries 目录的绝对路径。"""
    directory = os.path.abspath(board_path(project_name, "entries"))
    with _registry_lock:
        store = _store_registry.get(directory)
        if store is None:
            store = ProjectStore.load_or_create(
                project_name,
                directory=directory,
                flush_every_writes=cfg_int(
                    "blackboard.flush_every_writes", env="BB_FLUSH_EVERY_WRITES", default=20
                ),
                flush_interval_seconds=cfg_int(
                    "blackboard.flush_interval_seconds",
                    env="BB_FLUSH_INTERVAL_SECONDS", default=5,
                ),
                backup_limit=cfg_int(
                    "blackboard.backup_limit", env="BB_BACKUP_LIMIT", default=10
                ),
            )
            _store_registry[directory] = store
        return store


def shutdown_stores() -> None:
    """关闭全部缓存 Store（dirty 时强制落盘）并清空注册表。"""
    global _store_registry
    with _registry_lock:
        stores = list(_store_registry.values())
        _store_registry = {}
    for store in stores:
        store.close()


atexit.register(shutdown_stores)
