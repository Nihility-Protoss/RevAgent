import os
import time
from tools.entry_store import ProjectStore


def test_flush_rotation_and_recovery(tmp_path):
    directory = tmp_path / "entries"
    store = ProjectStore("p", directory=directory, backup_limit=10)
    for index in range(12):
        store.set_runtime("counter", index)
        store.flush()
    assert (directory / "store.pickle").exists()
    backups = sorted(directory.glob("store.bak.*.pickle"))
    assert len(backups) == 10
    store.close()

    (directory / "store.pickle").write_bytes(b"broken")
    recovered = ProjectStore.load_or_create("p", directory=directory, backup_limit=10)
    assert recovered.get_runtime("counter") == 10
    assert recovered.recovered_from.endswith("store.bak.001.pickle")
    recovered.close()


def test_interval_flush_uses_background_timer(tmp_path):
    store = ProjectStore("p", directory=tmp_path / "entries", flush_interval_seconds=0.02)
    store.set_runtime("ready", True)
    deadline = time.time() + 2
    while not (tmp_path / "entries" / "store.pickle").exists() and time.time() < deadline:
        time.sleep(0.01)
    assert (tmp_path / "entries" / "store.pickle").exists()
    store.close()


import pickle
import pytest
from tools.entry_store import StoreError


def test_write_count_dirty_tracking_and_plain_int_pickle(tmp_path, monkeypatch):
    store = ProjectStore(
        "p", directory=tmp_path / "entries",
        flush_every_writes=2, flush_interval_seconds=999,
    )
    store.set_runtime("first", 1)
    assert not (tmp_path / "entries" / "store.pickle").exists()
    store.set_runtime("second", 2)
    assert (tmp_path / "entries" / "store.pickle").exists()

    store.create_entry(
        "function", "asm_address", "0x401000",
        {"conclusion": "候选", "confidence": "low",
         "payload": {"func_name": "sub_401000"},
         "evidence_refs": [], "annotations": {}, "relation_refs": []},
        {"phase": "phase1", "agent": "boundary", "run_id": "run-1"}, "op-1",
    )
    store.flush_every_writes = 100
    original_encode = store._encode_snapshot

    def encode_and_modify(revision):
        encoded = original_encode(revision)
        store.set_runtime("written_during_flush", True)
        return encoded

    monkeypatch.setattr(store, "_encode_snapshot", encode_and_modify)
    store.flush()
    assert store.dirty is True

    envelope = pickle.loads((tmp_path / "entries" / "store.pickle").read_bytes())
    payload = pickle.loads(envelope["payload"])
    raw = payload["entries"][0]
    assert type(raw["entry_type"]) is int
    assert type(raw["subject"]["kind"]) is int
    assert type(raw["versions"][0]["change_reason"]) is int
    monkeypatch.setattr(store, "_encode_snapshot", original_encode)
    store.close()


def test_all_invalid_snapshots_fail_closed(tmp_path):
    directory = tmp_path / "entries"
    store = ProjectStore("p", directory=directory)
    store.set_runtime("value", 1)
    store.flush()
    store.close()
    for path in directory.glob("store*.pickle"):
        path.write_bytes(b"broken")
    with pytest.raises(StoreError) as exc:
        ProjectStore.load_or_create("p", directory=directory)
    assert exc.value.code == "snapshot_invalid"
