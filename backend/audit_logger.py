import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Fixed genesis hash for the first record in the chain
GENESIS_HASH = "0" * 64


def canonical_serialize(obj: Any) -> str:
    """Return a deterministic JSON string for *obj*.

    The function uses ``json.dumps`` with ``sort_keys=True`` and a compact
    separator configuration so that the same logical object always yields the
    same byte representation regardless of insertion order or whitespace.
    ``allow_nan`` is disabled to avoid non‑standard values.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def compute_record_hash(record: Dict[str, Any]) -> str:
    """Compute the SHA‑256 hash for an audit *record*.

    The *record* dictionary must contain the fields that participate in the
    chain: ``sequence``, ``timestamp``, ``event_type``, ``event_data`` and
    ``previous_hash``. The hash is calculated over the deterministic JSON
    representation produced by :func:`canonical_serialize`.
    """
    import hashlib

    serialized = canonical_serialize(record).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    """Immutable representation of a single audit log entry.

    ``current_hash`` is **not** part of the hash computation – it is the hash
    derived from the other fields.
    """

    sequence: int
    timestamp: str
    event_type: str
    event_data: Any
    previous_hash: str
    current_hash: str

    @staticmethod
    def from_dict(raw: Dict[str, Any]) -> "AuditRecord":
        """Create an :class:`AuditRecord` from a plain ``dict``.

        Validates required keys and types; raises ``ValueError`` on malformed
        data.
        """
        try:
            return AuditRecord(
                sequence=int(raw["sequence"]),
                timestamp=str(raw["timestamp"]),
                event_type=str(raw["event_type"]),
                event_data=raw["event_data"],
                previous_hash=str(raw["previous_hash"]),
                current_hash=str(raw["current_hash"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid audit record structure: {exc}") from exc

    def to_dict(self) -> Dict[str, Any]:
        """Return a ``dict`` suitable for JSON serialisation."""
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "event_data": self.event_data,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
        }


@dataclass(frozen=True)
class VerificationResult:
    """Result of a chain verification operation.

    Attributes
    ----------
    valid: bool
        ``True`` when the entire log is consistent; ``False`` otherwise.
    records_checked: int
        Number of records examined.
    error_message: Optional[str]
        Human‑readable description of the first failure, if any.
    failing_index: Optional[int]
        Zero‑based index of the record that caused the failure.
    """

    valid: bool
    records_checked: int
    error_message: Optional[str] = None
    failing_index: Optional[int] = None


# Global lock registry – one ``threading.Lock`` per log file path.
_LOCK_REGISTRY: Dict[Path, threading.Lock] = {}
_LOCK_REGISTRY_LOCK = threading.Lock()


def _get_path_lock(path: Path) -> threading.Lock:
    """Return a lock object that serialises *path*‑specific operations.

    The registry itself is protected by a global lock to avoid race conditions
    when the first request for a particular path arrives.
    """
    with _LOCK_REGISTRY_LOCK:
        if path not in _LOCK_REGISTRY:
            _LOCK_REGISTRY[path] = threading.Lock()
        return _LOCK_REGISTRY[path]


class AuditLogger:
    """Append‑only, hash‑chained audit logger.

    Parameters
    ----------
    log_path: Path | str
        Destination file in JSON‑Lines format. Parent directories are created
        automatically if they do not exist.
    """

    def __init__(self, log_path: Path | str) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = _get_path_lock(self.log_path)

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------
    def _load_last_record(self) -> Optional[AuditRecord]:
        """Return the most recent record from the log, or ``None`` if empty.
        """
        if not self.log_path.is_file():
            return None
        try:
            with self.log_path.open("r", encoding="utf-8") as fh:
                lines = fh.readlines()
                if not lines:
                    return None
                last_line = lines[-1].strip()
                if not last_line:
                    return None
                raw = json.loads(last_line)
                return AuditRecord.from_dict(raw)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(f"Failed to read audit log: {exc}") from exc

    @staticmethod
    def _validate_event(event_type: str, event_data: Any) -> None:
        """Validate *event_type* and *event_data*.

        * ``event_type`` must be a non‑empty ``str``.
        * ``event_data`` must be JSON‑serialisable via ``canonical_serialize``.
        """
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("event_type must be a non‑empty string")
        try:
            canonical_serialize(event_data)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"event_data is not JSON‑serialisable: {exc}") from exc

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------
    def append_event(self, event_type: str, event_data: Any) -> AuditRecord:
        """Append a new audit *event* to the log.

        Thread‑safe within the same process. Returns the written
        :class:`AuditRecord`.
        """
        self._validate_event(event_type, event_data)
        with self._lock:
            prev = self._load_last_record()
            sequence = 1 if prev is None else prev.sequence + 1
            timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            previous_hash = GENESIS_HASH if prev is None else prev.current_hash

            # Record body without ``current_hash`` for hashing.
            record_body: Dict[str, Any] = {
                "sequence": sequence,
                "timestamp": timestamp,
                "event_type": event_type,
                "event_data": event_data,
                "previous_hash": previous_hash,
            }
            current_hash = compute_record_hash(record_body)
            record_body["current_hash"] = current_hash

            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record_body, ensure_ascii=False) + "\n")

            return AuditRecord(**record_body)  # type: ignore[arg-type]


def verify_audit_log(log_path: Path | str) -> VerificationResult:
    """Verify the integrity of an audit log.

    Walks the file line‑by‑line, recomputes each record's hash and checks
    sequence continuity, previous‑hash linkage and hash correctness.
    Returns a :class:`VerificationResult` describing the outcome.
    """
    path = Path(log_path)
    if not path.is_file():
        return VerificationResult(valid=False, records_checked=0, error_message="Log file does not exist")

    try:
        with path.open("r", encoding="utf-8") as fh:
            previous_hash = GENESIS_HASH
            expected_sequence = 1
            for idx, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    return VerificationResult(
                        valid=False,
                        records_checked=idx,
                        error_message=f"Malformed JSON at line {idx + 1}: {exc}",
                        failing_index=idx,
                    )
                required = {"sequence", "timestamp", "event_type", "event_data", "previous_hash", "current_hash"}
                if not required.issubset(raw):
                    return VerificationResult(
                        valid=False,
                        records_checked=idx,
                        error_message=f"Missing required fields at line {idx + 1}",
                        failing_index=idx,
                    )
                if int(raw["sequence"]) != expected_sequence:
                    return VerificationResult(
                        valid=False,
                        records_checked=idx,
                        error_message=f"Unexpected sequence number at line {idx + 1}: expected {expected_sequence}, got {raw['sequence']}",
                        failing_index=idx,
                    )
                if str(raw["previous_hash"]) != previous_hash:
                    return VerificationResult(
                        valid=False,
                        records_checked=idx,
                        error_message=f"Previous hash mismatch at line {idx + 1}",
                        failing_index=idx,
                    )
                # Re‑compute hash from record body (excluding stored current_hash)
                body = {
                    "sequence": raw["sequence"],
                    "timestamp": raw["timestamp"],
                    "event_type": raw["event_type"],
                    "event_data": raw["event_data"],
                    "previous_hash": raw["previous_hash"],
                }
                expected_hash = compute_record_hash(body)
                if str(raw["current_hash"]) != expected_hash:
                    return VerificationResult(
                        valid=False,
                        records_checked=idx,
                        error_message=f"Hash mismatch at line {idx + 1}",
                        failing_index=idx,
                    )
                previous_hash = raw["current_hash"]
                expected_sequence += 1
    except OSError as exc:
        return VerificationResult(valid=False, records_checked=0, error_message=str(exc))

    return VerificationResult(valid=True, records_checked=expected_sequence - 1)