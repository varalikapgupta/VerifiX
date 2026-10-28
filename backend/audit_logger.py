"""
backend/audit_logger.py
=======================
Cryptographic SHA-256 hash-chain audit logging system for VerifiX.

Security & Architectural Properties:
1. APPEND-ONLY HASH CHAIN: Every audit event record is cryptographically linked
   to its predecessor via its SHA-256 hash.
2. DETERMINISTIC CANONICAL SERIALIZATION: Records are serialized into canonical
   JSON with sorted keys and compact delimiters (`sort_keys=True, separators=(',', ':')`)
   prior to hashing.
3. FIXED GENESIS HASH: The initial event (sequence 1) strictly references
   a documented, invariant genesis hash (64 hex zeros).
4. TAMPER DETECTION: Verification detects:
   - Modified / edited record contents (hash mismatch).
   - Deleted records (sequence gap & broken previous_hash chain).
   - Reordered or inserted records (sequence collision & hash linkage failure).
   - Truncated or corrupted log lines.
5. INPUT & DATA SANITIZATION:
   - Event types must be non-empty strings matching clean identifier syntax.
   - Event data must be a valid mapping serializable to deterministic JSON.
   - Never evaluates, executes, or runs arbitrary code from event data.
6. THREAD-SAFE CONCURRENCY: In-process appends to the same log path are protected
   with threading locks.
7. PURE STANDARD LIBRARY: Uses only built-in Python modules (`hashlib`, `json`,
   `datetime`, `pathlib`, `threading`, `dataclasses`).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import threading
from typing import Any, Mapping


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Invariant Genesis Hash (64 hex zeros) for sequence 1
GENESIS_HASH: str = "0" * 64

# Strict pattern for valid event type identifiers (e.g. SCAN_COMPLETED, PROBE_EXECUTED)
_EVENT_TYPE_REGEX = re.compile(r"^[A-Z0-9_]{2,64}$")

# Predefined standard VerifiX event types
STANDARD_EVENT_TYPES: frozenset[str] = frozenset({
    "SCAN_INITIATED",
    "SCAN_COMPLETED",
    "FINDING_DETECTED",
    "HYPOTHESIS_FORMULATED",
    "PROBE_DISPATCHED",
    "PROBE_RESULT_RECORDED",
    "PATCH_ATTEMPTED",
    "PATCH_APPLIED",
    "PATCH_FAILED",
    "REGRESSION_TEST_STARTED",
    "REGRESSION_TEST_COMPLETED",
    "VERIFICATION_SUCCESSFUL",
    "VERIFICATION_FAILED",
    "SYSTEM_ALERT",
    "AUDIT_CHAIN_INITIALIZED",
})


# ---------------------------------------------------------------------------
# In-process Concurrency Locks
# ---------------------------------------------------------------------------

_GLOBAL_LOCK = threading.Lock()
_PATH_LOCKS: dict[Path, threading.Lock] = {}


def _get_path_lock(log_path: Path) -> threading.Lock:
    """Retrieve or create an in-process threading lock for *log_path*."""
    resolved = log_path.resolve()
    with _GLOBAL_LOCK:
        if resolved not in _PATH_LOCKS:
            _PATH_LOCKS[resolved] = threading.Lock()
        return _PATH_LOCKS[resolved]


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditRecord:
    """An individual immutable audit event record in the hash chain."""

    sequence: int
    timestamp: str
    event_type: str
    event_data: dict[str, Any]
    previous_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        """Convert record to a serializable dictionary."""
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "event_data": self.event_data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)


@dataclass(frozen=True)
class VerificationResult:
    """Structured result of an audit chain verification."""

    is_valid: bool
    record_count: int
    error_message: str | None = None
    failed_index: int | None = None
    failed_sequence: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to a serializable dictionary."""
        return {
            "is_valid": self.is_valid,
            "record_count": self.record_count,
            "error_message": self.error_message,
            "failed_index": self.failed_index,
            "failed_sequence": self.failed_sequence,
        }

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)


# ---------------------------------------------------------------------------
# Serialization & Hashing Utilities
# ---------------------------------------------------------------------------

def canonical_serialize(data: Any) -> bytes:
    """Serialize *data* into deterministic, canonical UTF-8 JSON bytes.

    Guarantees:
    - Sorted keys (sort_keys=True).
    - Compact delimiters (separators=(',', ':')).
    - Disallows non-standard floats (allow_nan=False).
    - Rejects cyclic or non-JSON serializable objects with TypeError.
    """
    try:
        serialized = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Data cannot be deterministically serialized to JSON: {exc}") from exc

    return serialized.encode("utf-8")


def compute_record_payload(
    sequence: int,
    timestamp: str,
    event_type: str,
    event_data: Mapping[str, Any],
    previous_hash: str,
) -> dict[str, Any]:
    """Construct the canonical dictionary of record fields prior to hashing."""
    return {
        "event_data": dict(event_data),
        "event_type": event_type,
        "previous_hash": previous_hash,
        "sequence": sequence,
        "timestamp": timestamp,
    }


def compute_record_hash(
    sequence: int,
    timestamp: str,
    event_type: str,
    event_data: Mapping[str, Any],
    previous_hash: str,
) -> str:
    """Compute the SHA-256 hex digest of an audit record's canonical payload."""
    payload = compute_record_payload(
        sequence=sequence,
        timestamp=timestamp,
        event_type=event_type,
        event_data=event_data,
        previous_hash=previous_hash,
    )
    return hashlib.sha256(canonical_serialize(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------------------------

def is_valid_event_type(event_type: Any) -> bool:
    """Validate that *event_type* conforms to a safe alphanumeric identifier."""
    if not isinstance(event_type, str):
        return False
    cleaned = event_type.strip()
    if cleaned != event_type:
        return False
    return bool(_EVENT_TYPE_REGEX.match(cleaned))


def validate_event_input(event_type: Any, event_data: Any) -> tuple[str, dict[str, Any]]:
    """Validate event type and payload data before appending to the audit log.

    Raises:
        ValueError: If event_type is malformed or event_data is not serializable.
        TypeError: If event_data is not a mapping.
    """
    if not is_valid_event_type(event_type):
        raise ValueError(
            f"Invalid event_type: {event_type!r}. Must be an uppercase alphanumeric "
            "string matching pattern ^[A-Z0-9_]{2,64}$."
        )

    if not isinstance(event_data, Mapping):
        raise TypeError(
            f"event_data must be a mapping (dict), got {type(event_data).__name__}"
        )

    # Test deterministic serializability
    try:
        canonical_serialize(event_data)
    except ValueError as exc:
        raise ValueError(f"event_data contains non-serializable content: {exc}") from exc

    return str(event_type), dict(event_data)


# ---------------------------------------------------------------------------
# Core Reading & Verification Functions
# ---------------------------------------------------------------------------

def read_audit_log(log_path: str | Path) -> list[AuditRecord]:
    """Read and parse all audit records from a JSON Lines (.jsonl) file.

    Parameters:
        log_path: Path to the .jsonl audit file.

    Returns:
        List of parsed AuditRecord objects. If the file does not exist, returns [].

    Raises:
        ValueError: If any line contains malformed JSON or lacks required fields.
        IOError: If an unexpected I/O error occurs during reading.
    """
    path = Path(log_path)
    if not path.exists():
        return []

    records: list[AuditRecord] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Corrupted log line {line_no} in {path}: Invalid JSON ({exc})"
                ) from exc

            if not isinstance(raw, dict):
                raise ValueError(
                    f"Malformed record at line {line_no} in {path}: Expected JSON object"
                )

            required_keys = {"sequence", "timestamp", "event_type", "event_data", "previous_hash", "hash"}
            missing = required_keys - raw.keys()
            if missing:
                raise ValueError(
                    f"Incomplete record at line {line_no} in {path}: Missing keys {missing}"
                )

            records.append(
                AuditRecord(
                    sequence=int(raw["sequence"]),
                    timestamp=str(raw["timestamp"]),
                    event_type=str(raw["event_type"]),
                    event_data=dict(raw["event_data"]),
                    previous_hash=str(raw["previous_hash"]),
                    hash=str(raw["hash"]),
                )
            )

    return records


def verify_chain(records_or_path: list[AuditRecord] | str | Path) -> VerificationResult:
    """Verify the integrity of an audit hash chain.

    Checks:
    1. Empty log is valid with 0 records.
    2. Strict consecutive sequence starting at 1 (1, 2, 3...).
    3. Genesis hash linkage: record[0].previous_hash == GENESIS_HASH.
    4. Previous hash linkage: record[i].previous_hash == record[i-1].hash.
    5. Content integrity: recomputed SHA-256 matches recorded hash.
    6. Timestamp ISO-8601 validity.

    Returns:
        VerificationResult with is_valid=True or is_valid=False and error details.
    """
    if isinstance(records_or_path, (str, Path)):
        try:
            records = read_audit_log(records_or_path)
        except ValueError as exc:
            return VerificationResult(
                is_valid=False,
                record_count=0,
                error_message=f"Log file parsing failure: {exc}",
                failed_index=None,
                failed_sequence=None,
            )
        except Exception as exc:
            return VerificationResult(
                is_valid=False,
                record_count=0,
                error_message=f"I/O error reading log file: {exc}",
                failed_index=None,
                failed_sequence=None,
            )
    elif isinstance(records_or_path, list):
        records = records_or_path
    else:
        return VerificationResult(
            is_valid=False,
            record_count=0,
            error_message=f"Invalid argument type: {type(records_or_path).__name__}",
        )

    count = len(records)
    if count == 0:
        return VerificationResult(is_valid=True, record_count=0)

    for i, record in enumerate(records):
        expected_seq = i + 1

        # 1. Sequence order check
        if record.sequence != expected_seq:
            return VerificationResult(
                is_valid=False,
                record_count=count,
                error_message=(
                    f"Sequence discontinuity at index {i}: expected sequence "
                    f"{expected_seq}, found {record.sequence} (possible deletion or insertion)"
                ),
                failed_index=i,
                failed_sequence=record.sequence,
            )

        # 2. Previous hash link check
        if i == 0:
            if record.previous_hash != GENESIS_HASH:
                return VerificationResult(
                    is_valid=False,
                    record_count=count,
                    error_message=(
                        f"Genesis linkage broken at index 0: expected {GENESIS_HASH}, "
                        f"found {record.previous_hash}"
                    ),
                    failed_index=0,
                    failed_sequence=record.sequence,
                )
        else:
            prev_record = records[i - 1]
            if record.previous_hash != prev_record.hash:
                return VerificationResult(
                    is_valid=False,
                    record_count=count,
                    error_message=(
                        f"Hash chain broken at index {i} (seq {record.sequence}): "
                        f"previous_hash '{record.previous_hash}' does not match prior record hash '{prev_record.hash}'"
                    ),
                    failed_index=i,
                    failed_sequence=record.sequence,
                )

        # 3. Content integrity & recomputed hash check
        recomputed_hash = compute_record_hash(
            sequence=record.sequence,
            timestamp=record.timestamp,
            event_type=record.event_type,
            event_data=record.event_data,
            previous_hash=record.previous_hash,
        )

        if recomputed_hash != record.hash:
            return VerificationResult(
                is_valid=False,
                record_count=count,
                error_message=(
                    f"Tamper detected at record index {i} (seq {record.sequence}): "
                    f"recomputed hash '{recomputed_hash}' does not match recorded hash '{record.hash}'"
                ),
                failed_index=i,
                failed_sequence=record.sequence,
            )

        # 4. Timestamp format validation
        try:
            datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
        except (ValueError, TypeError) as exc:
            return VerificationResult(
                is_valid=False,
                record_count=count,
                error_message=f"Malformed timestamp at index {i} (seq {record.sequence}): {record.timestamp}",
                failed_index=i,
                failed_sequence=record.sequence,
            )

    return VerificationResult(is_valid=True, record_count=count)


# ---------------------------------------------------------------------------
# Append Engine & AuditLogger Class
# ---------------------------------------------------------------------------

class AuditLogger:
    """Thread-safe append-only audit logger writing to a JSON Lines file.

    Note on Concurrency:
    Thread-safety is enforced within a single process via threading locks.
    For multi-process coordination across distinct OS processes, an external
    coordinator or OS-level file lock is required.
    """

    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path).resolve()
        self._lock = _get_path_lock(self.log_path)

    def append(
        self,
        event_type: str,
        event_data: Mapping[str, Any],
        timestamp: str | None = None,
    ) -> AuditRecord:
        """Append an audit event to the hash chain.

        Parameters:
            event_type: Standard or custom uppercase event type identifier.
            event_data: Mapping of serializable payload parameters.
            timestamp: Optional UTC ISO-8601 string; defaults to current UTC time.

        Returns:
            The constructed and committed AuditRecord.

        Raises:
            ValueError: If input validation fails or the existing log is corrupted.
            IOError: If writing to the file fails.
        """
        valid_type, valid_data = validate_event_input(event_type, event_data)

        if timestamp is None:
            ts = datetime.now(timezone.utc).isoformat()
        else:
            ts = str(timestamp)

        with self._lock:
            # Ensure parent directory exists
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

            # Determine previous record sequence and hash
            existing_records = read_audit_log(self.log_path)

            if existing_records:
                # Verify existing chain integrity before appending
                verification = verify_chain(existing_records)
                if not verification.is_valid:
                    raise ValueError(
                        f"Cannot append to corrupted audit log: {verification.error_message}"
                    )
                last_record = existing_records[-1]
                new_sequence = last_record.sequence + 1
                previous_hash = last_record.hash
            else:
                new_sequence = 1
                previous_hash = GENESIS_HASH

            # Compute new hash
            current_hash = compute_record_hash(
                sequence=new_sequence,
                timestamp=ts,
                event_type=valid_type,
                event_data=valid_data,
                previous_hash=previous_hash,
            )

            record = AuditRecord(
                sequence=new_sequence,
                timestamp=ts,
                event_type=valid_type,
                event_data=valid_data,
                previous_hash=previous_hash,
                hash=current_hash,
            )

            # Atomic write line
            line_data = json.dumps(
                record.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ) + "\n"

            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line_data)
                f.flush()

            return record

    def verify(self) -> VerificationResult:
        """Verify the integrity of the audit chain file."""
        with self._lock:
            return verify_chain(self.log_path)


# ---------------------------------------------------------------------------
# Module-level Convenience Functions
# ---------------------------------------------------------------------------

def append_event(
    log_path: str | Path,
    event_type: str,
    event_data: Mapping[str, Any],
    timestamp: str | None = None,
) -> AuditRecord:
    """Convenience helper to append an event to the specified log path."""
    logger = AuditLogger(log_path)
    return logger.append(event_type, event_data, timestamp=timestamp)


def verify_audit_log(log_path: str | Path) -> VerificationResult:
    """Convenience helper to verify the integrity of the specified audit log."""
    logger = AuditLogger(log_path)
    return logger.verify()
