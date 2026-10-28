
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


# ---------------------------------------------------------------------------
# New integrity-verification tests
# ---------------------------------------------------------------------------

# 1. Reordering detection
# ---------------------------------------------------------------------------

def test_reordered_records_are_detected(tmp_path: Path):
    """Swapping two valid records must invalidate the chain.

    The first record in the reordered log has sequence=2, which does not match
    the expected starting sequence of 1, so verify_audit_log returns valid=False
    immediately at the first line (failing_index=0, records_checked=0).
    """
    log_path = tmp_path / "reorder.jsonl"
    logger = AuditLogger(log_path)
    logger.append_event("scan", {"id": 1})
    logger.append_event("patch", {"id": 2})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    # Swap the two lines — now the higher-sequence record appears first.
    lines[0], lines[1] = lines[1], lines[0]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(log_path)

    assert result.valid is False
    # The failure must be reported at the first (0-based) record position.
    assert result.failing_index == 0
    assert result.records_checked == 0
    assert "sequence" in (result.error_message or "").lower()


# 2. Malformed JSON detection
# ---------------------------------------------------------------------------

def test_malformed_json_line_is_detected(tmp_path: Path):
    """A line that cannot be parsed as JSON must produce valid=False.

    Implementation behaviour (verified against source):
    - records_checked equals the 0-based *line index* (``idx``) of the bad line
      (i.e. the count of successfully processed records before the failure).
    - failing_index equals the same ``idx`` value.
    """
    log_path = tmp_path / "malformed.jsonl"
    logger = AuditLogger(log_path)
    logger.append_event("scan", {"id": 1})   # line 0 — good
    logger.append_event("patch", {"id": 2})  # line 1 — will be corrupted

    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[1] = "{this is not valid json"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(log_path)

    assert result.valid is False
    # One clean record (line 0) was processed before the bad line (line 1).
    assert result.records_checked == 1
    assert result.failing_index == 1
    assert result.error_message is not None
    assert "malformed" in result.error_message.lower() or "json" in result.error_message.lower()


def test_malformed_json_does_not_raise(tmp_path: Path):
    """verify_audit_log must return a VerificationResult, never raise, on bad JSON."""
    log_path = tmp_path / "nocrash.jsonl"
    log_path.write_text("{completely broken\n", encoding="utf-8")

    # Must not raise any exception.
    result = verify_audit_log(log_path)
    assert result.valid is False


# 3. Field-level tampering detection
# ---------------------------------------------------------------------------

def test_tampered_sequence_number_is_detected(tmp_path: Path):
    """Overwriting a record's sequence field must break chain verification.

    The sequence value is part of the hashed body; changing it means the
    recomputed hash no longer matches the stored current_hash.  The verifier
    catches this as a hash mismatch (or, if the written sequence is out of
    order, as a sequence mismatch) — either way valid=False.
    """
    log_path = tmp_path / "seq_tamper.jsonl"
    logger = AuditLogger(log_path)
    logger.append_event("scan", {"id": 1})
    logger.append_event("patch", {"id": 2})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["sequence"] = 99           # tamper with stored sequence
    lines[0] = json.dumps(record)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(log_path)
    assert result.valid is False


def test_tampered_previous_hash_is_detected(tmp_path: Path):
    """Overwriting a record's previous_hash field must invalidate the chain.

    previous_hash is checked directly against the prior record's current_hash
    *before* the hash is recomputed, so any change to it is detected
    immediately at that record's position.
    """
    log_path = tmp_path / "prevhash_tamper.jsonl"
    logger = AuditLogger(log_path)
    logger.append_event("scan", {"id": 1})
    logger.append_event("patch", {"id": 2})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    # Replace the legitimate previous_hash with an all-zeros value.
    record["previous_hash"] = "a" * 64
    lines[1] = json.dumps(record)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(log_path)

    assert result.valid is False
    # The failure must be on the second record (0-based index 1).
    assert result.failing_index == 1
    assert "previous hash" in (result.error_message or "").lower()


def test_tampered_current_hash_is_detected(tmp_path: Path):
    """Overwriting a record's stored current_hash must be detected on verification.

    current_hash is not part of the hash input; the verifier recomputes it from
    the body fields and compares.  A forged current_hash that does not match
    the recomputed value triggers a 'Hash mismatch' failure.
    """
    log_path = tmp_path / "curhash_tamper.jsonl"
    logger = AuditLogger(log_path)
    logger.append_event("scan", {"id": 1})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["current_hash"] = "f" * 64   # forged hash
    lines[0] = json.dumps(record)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(log_path)

    assert result.valid is False
    assert result.failing_index == 0
    assert "hash" in (result.error_message or "").lower()


# 4. Empty log contracts
# ---------------------------------------------------------------------------

def test_nonexistent_log_file_is_invalid(tmp_path: Path):
    """A path that does not exist must return valid=False, records_checked=0."""
    result = verify_audit_log(tmp_path / "does_not_exist.jsonl")

    assert result.valid is False
    assert result.records_checked == 0
    assert result.error_message is not None


def test_empty_log_file_is_valid_with_zero_records(tmp_path: Path):
    """An existing but empty log file represents a valid, empty chain.

    The implementation's loop never executes, so expected_sequence stays at 1
    and records_checked = expected_sequence - 1 = 0.
    """
    log_path = tmp_path / "empty.jsonl"
    log_path.write_text("", encoding="utf-8")    # file exists, zero bytes

    result = verify_audit_log(log_path)

    assert result.valid is True
    assert result.records_checked == 0
    assert result.error_message is None
    assert result.failing_index is None


def test_blank_lines_only_log_is_valid_with_zero_records(tmp_path: Path):
    """A log containing only blank lines must behave the same as an empty file.

    Blank lines are skipped by the verifier (``if not line: continue``), so
    the outcome is identical to the empty-file case.
    """
    log_path = tmp_path / "blank.jsonl"
    log_path.write_text("\n\n\n", encoding="utf-8")

    result = verify_audit_log(log_path)

    assert result.valid is True
    assert result.records_checked == 0


# 5. Multi-record untampered log
# ---------------------------------------------------------------------------

def test_multi_record_untampered_log_verifies_successfully(tmp_path: Path):
    """A cleanly written N-record log must verify as valid with records_checked == N."""
    log_path = tmp_path / "multi.jsonl"
    logger = AuditLogger(log_path)

    n = 5
    for i in range(n):
        logger.append_event("scan", {"step": i})

    result = verify_audit_log(log_path)

    assert result.valid is True
    assert result.records_checked == n
    assert result.error_message is None
    assert result.failing_index is None


def test_multi_record_records_checked_equals_record_count(tmp_path: Path):
    """records_checked must equal the exact number of records appended."""
    log_path = tmp_path / "count.jsonl"
    logger = AuditLogger(log_path)

    for event_type in ("scan", "patch", "verify", "scan"):
        logger.append_event(event_type, {"ok": True})

    result = verify_audit_log(log_path)

    assert result.valid is True
    assert result.records_checked == 4
