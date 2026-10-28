
import json
from pathlib import Path

import pytest

from backend.audit_logger import (
    AuditLogger,
    canonical_serialize,
    compute_record_hash,
    verify_audit_log,
)


def test_canonical_serialization_is_deterministic():
    first = canonical_serialize({"b": 2, "a": 1})
    second = canonical_serialize({"a": 1, "b": 2})
    assert first == second


def test_record_hash_is_deterministic():
    record = {
        "sequence": 1,
        "event_type": "scan",
        "event_data": {"finding_count": 2},
        "previous_hash": "0" * 64,
    }
    assert compute_record_hash(record) == compute_record_hash(record)


def test_append_and_verify_single_event(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path)
    logger.append_event("scan", {"finding_count": 2})

    result = verify_audit_log(log_path)
    assert result.valid is True
    assert result.records_checked == 1


def test_modified_record_is_detected(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path)
    logger.append_event("scan", {"finding_count": 2})
    logger.append_event("patch", {"rule": "PY002"})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["event_data"]["finding_count"] = 999
    lines[0] = json.dumps(record)

    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(log_path)
    assert result.valid is False


def test_deleted_record_is_detected(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path)
    logger.append_event("scan", {"id": 1})
    logger.append_event("patch", {"id": 2})
    logger.append_event("verify", {"id": 3})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    log_path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")

    result = verify_audit_log(log_path)
    assert result.valid is False


def test_invalid_event_type_is_rejected(tmp_path: Path):
    logger = AuditLogger(tmp_path / "audit.jsonl")

    with pytest.raises((TypeError, ValueError)):
        logger.append_event("", {"test": True})
