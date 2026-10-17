import pytest
from pydantic import ValidationError

from tools.entry_models import (
    EntryType, SubjectKind, ReviewStatus, ChangeReason,
    Subject, Review, enum_to_int, enum_to_name, normalize_asm_address,
)


def test_enum_boundaries_and_plain_int_storage():
    subject = Subject(kind=SubjectKind.ASM_ADDRESS, key="0x401000")
    review = Review(status=ReviewStatus.PENDING)
    assert subject.model_dump()["kind"] == 2
    assert type(subject.model_dump()["kind"]) is int
    assert review.model_dump()["status"] == 0
    assert enum_to_int(EntryType, "function") == 3
    assert enum_to_int(ChangeReason, 1) == 1
    assert enum_to_name(EntryType, 3) == "function"


def test_unknown_enum_and_bool_are_rejected():
    with pytest.raises(ValueError):
        enum_to_int(EntryType, 99)
    with pytest.raises(ValueError):
        enum_to_int(ReviewStatus, True)
    with pytest.raises(ValidationError):
        Review(status=99)


def test_asm_address_normalization():
    assert normalize_asm_address("0X00401000") == "0x401000"
    assert normalize_asm_address("sub_401000") == "0x401000"
    with pytest.raises(ValueError):
        normalize_asm_address("not-an-address")

from tools.entry_models import Entry, EntryVersion, validate_payload


def test_entry_roundtrip_preserves_plain_integer_enums():
    entry = Entry(
        entry_id="fn_1", entry_type=EntryType.FUNCTION,
        subject=Subject(kind=SubjectKind.ASM_ADDRESS, key="0x401000"),
        head_version=1,
        versions=[EntryVersion(
            version=1,
            producer={"phase": "phase3", "agent": "deep", "run_id": "run-1"},
            idempotency_key="run-1:phase3:fn_1",
            conclusion="网络初始化", payload={"func_name": "sub_401000"},
            confidence="medium", change_reason=ChangeReason.ANALYSIS,
            created_at="2026-10-16T00:00:00+00:00",
        )],
        created_at="2026-10-16T00:00:00+00:00",
    )
    dump = entry.model_dump()
    values = [
        dump["entry_type"], dump["subject"]["kind"],
        dump["versions"][0]["validation"]["data"]["status"],
        dump["versions"][0]["validation"]["subject"]["status"],
        dump["versions"][0]["validation"]["conclusion"]["status"],
        dump["versions"][0]["review"]["status"],
        dump["versions"][0]["change_reason"],
    ]
    assert all(type(value) is int for value in values)
    assert Entry.model_validate(dump).model_dump() == dump


@pytest.mark.parametrize("kind,payload", [
    ("sample", {}),
    ("finding", {"category": "api", "name": "socket"}),
    ("function", {}),
    ("decision", {"action": "AWAITING_HUMAN_REVIEW"}),
    ("report", {"report_kind": "shard", "shard_id": 1}),
])
def test_all_payload_models_have_minimal_valid_input(kind, payload):
    assert isinstance(validate_payload(kind, payload), dict)


def test_report_payload_rejects_unknown_kind():
    with pytest.raises(ValidationError):
        validate_payload("report", {"report_kind": "unknown"})
