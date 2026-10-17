from concurrent.futures import ThreadPoolExecutor

import pytest
from tools.entry_models import ChangeReason
from tools.entry_store import ProjectStore, StoreError


def producer():
    return {"phase": "phase1", "agent": "boundary", "run_id": "run-1"}


def function_output():
    return {
        "conclusion": "候选函数",
        "confidence": "medium",
        "payload": {"func_name": "sub_401000", "candidate": {"priority": 9}},
        "evidence_refs": ["functions_extract:0x401000"],
        "annotations": {},
        "relation_refs": [],
    }


def test_create_append_full_version_and_idempotency(tmp_path):
    store = ProjectStore("p", directory=tmp_path / "entries")
    entry = store.create_entry(
        "function", "asm_address", "401000", function_output(),
        producer(), "run-1:phase1:0x401000",
    )
    assert entry.subject.key == "0x401000"
    assert entry.head_version == 1
    assert store.create_entry(
        "function", "asm_address", "0x401000", function_output(),
        producer(), "run-1:phase1:0x401000",
    ).head_version == 1

    head_payload = entry.versions[0].payload
    head_payload["analysis"] = {"functionality": "network_init"}
    updated = store.append_version(
        entry.entry_id, 1,
        {"conclusion": "网络初始化", "payload": head_payload,
         "annotations": {"recommended_name": "init_network"}},
        {"phase": "phase3", "agent": "deep", "run_id": "run-1"},
        "run-1:phase3:0x401000", ChangeReason.ANALYSIS,
    )
    assert updated.head_version == 2
    assert updated.versions[0].conclusion == "候选函数"
    assert updated.versions[1].review.status == 0
    assert updated.versions[1].validation.conclusion.status == 0
    assert store.find_operation("run-1:phase3:0x401000") == (entry.entry_id, 2)


def test_non_head_append_and_copy_mutation_are_rejected(tmp_path):
    store = ProjectStore("p", directory=tmp_path / "entries")
    entry = store.create_entry(
        "function", "asm_address", "0x401000", function_output(), producer(), "op-1"
    )
    with pytest.raises(StoreError) as exc:
        store.append_version(entry.entry_id, 0, {}, producer(), "op-2", "analysis")
    assert exc.value.code == "version_conflict"
    copied = store.get_entry(entry.entry_id)
    copied.versions[0].conclusion = "绕过工具修改"
    assert store.get_entry(entry.entry_id).versions[0].conclusion == "候选函数"


def test_concurrent_create_and_runtime_copy(tmp_path):
    store = ProjectStore("p", directory=tmp_path / "entries")

    def create(index):
        output = function_output()
        output["payload"] = {
            "func_name": f"sub_{index:x}", "candidate": {"priority": index},
        }
        return store.create_entry(
            "function", "asm_address", f"0x{0x500000 + index:x}", output,
            producer(), f"create-{index}",
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        created = list(pool.map(create, range(20)))
    assert len(store.list_entries()) == 20
    assert len({entry.entry_id for entry in created}) == 20

    with pytest.raises(StoreError) as exc:
        store.create_entry(
            "function", "asm_address", "0x500000", function_output(),
            producer(), "different-operation",
        )
    assert exc.value.code == "subject_conflict"

    store.set_runtime("nested", {"items": [1]})
    copied = store.get_runtime("nested")
    copied["items"].append(2)
    assert store.get_runtime("nested") == {"items": [1]}


def test_sequential_annotation_versions(tmp_path):
    store = ProjectStore("p", directory=tmp_path / "entries")
    entry = store.create_entry(
        "function", "asm_address", "0x401000", function_output(), producer(), "op-1"
    )
    for index in range(10):
        head = store.get_entry(entry.entry_id).head_version
        store.append_version(
            entry.entry_id, head,
            {"annotations": {"recommended_name": f"analyze_{index}"}},
            producer(), f"annotation-{index}", "annotation",
        )
    assert store.get_entry(entry.entry_id, include_history=True).head_version == 11
