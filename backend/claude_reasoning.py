"""
backend/claude_reasoning.py
===========================
Deterministic, offline vulnerability reasoning engine for VerifiX.

Responsibilities:
1. Reason about static AST scanner findings offline without external API keys
   or network connectivity.
2. Formulate structured vulnerability hypotheses from static scanner findings.
3. Enforce a strict allow-list of registered runtime probe IDs.
4. Prevent arbitrary command execution, arbitrary URLs, or untrusted probe injection.
5. Provide safe default fallbacks for unknown or unsupported finding rules.

This module is strictly passive: it selects and validates probe IDs only.
It NEVER executes probes, accesses network sockets, or modifies filesystem state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping


# ---------------------------------------------------------------------------
# Strict Probe Allow-List
# ---------------------------------------------------------------------------
# Only these exact probe IDs are permitted. Any other probe ID, arbitrary URL,
# or user-supplied command MUST be rejected by the validation guardrail.

REGISTERED_PROBE_IDS: frozenset[str] = frozenset({
    "PROBE-PT-001",   # Path traversal: ../ escape demonstration
    "PROBE-PT-002",   # Path traversal: in-bounds safe read baseline
    "PROBE-SQL-001",  # SQL injection: safe single-user lookup baseline
    "PROBE-SQL-002",  # SQL injection: injection tautology demonstration
    "PROBE-BOLA-001", # Broken Object Level Authorization (BOLA) demonstration
})


# ---------------------------------------------------------------------------
# Static Rule -> Probe Allow-List Mapping
# ---------------------------------------------------------------------------
# Maps static AST scanner rules to predefined validation probe IDs.

RULE_PROBE_MAPPING: dict[str, list[str]] = {
    "AUTH001": ["PROBE-BOLA-001"],
    "PY002": ["PROBE-PT-001", "PROBE-PT-002"],
    "PY003": ["PROBE-SQL-001", "PROBE-SQL-002"],
}


# ---------------------------------------------------------------------------
# Pre-computed Hypotheses Knowledge Base (Offline Reasoning)
# ---------------------------------------------------------------------------

_RULE_METADATA: dict[str, dict[str, str]] = {
    "AUTH001": {
        "hypothesis": (
            "Missing authorization or ownership check allows Broken Object Level "
            "Authorization (BOLA), allowing users to access unauthorized records."
        ),
        "confidence": "high",
        "reasoning": (
            "Static analysis detected resource access based on user-supplied identifiers "
            "without validating document ownership against authenticated identity. "
            "PROBE-BOLA-001 confirms cross-user access under controlled test conditions."
        ),
    },
    "PY002": {
        "hypothesis": (
            "Unsafe dynamic path concatenation in os.path.join permits directory "
            "traversal sequences ('../') to access files outside the intended base directory."
        ),
        "confidence": "high",
        "reasoning": (
            "Static analysis identified dynamic path components supplied to os.path.join() "
            "without path canonicalization or boundary checks. PROBE-PT-001 tests escape "
            "from the public directory, while PROBE-PT-002 validates the in-bounds baseline."
        ),
    },
    "PY003": {
        "hypothesis": (
            "Dynamic SQL query construction via string formatting or f-strings creates an "
            "unparameterized SQL injection vulnerability."
        ),
        "confidence": "high",
        "reasoning": (
            "Static analysis detected unparameterized string formatting passed to database "
            "execution calls. PROBE-SQL-001 confirms normal lookup behavior, and PROBE-SQL-002 "
            "validates query manipulation via boolean tautology injection."
        ),
    },
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VulnerabilityHypothesis:
    """Structured hypothesis for a potential vulnerability finding."""

    finding_rule: str
    hypothesis: str
    selected_probe_ids: list[str]
    confidence: str
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        """Convert hypothesis to a plain serializable dictionary."""
        return {
            "finding_rule": self.finding_rule,
            "hypothesis": self.hypothesis,
            "selected_probe_ids": list(self.selected_probe_ids),
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }

    def __getitem__(self, item: str) -> Any:
        """Allow subscript access for compatibility with dictionary consumers."""
        return getattr(self, item)


# ---------------------------------------------------------------------------
# Validation & Guardrail Functions
# ---------------------------------------------------------------------------

def is_valid_probe_id(probe_id: Any) -> bool:
    """Check if *probe_id* is a valid, registered probe identifier.

    Guards against:
    - Non-string inputs
    - Arbitrary URLs (http://, https://)
    - Shell commands or execution syntax
    - Unregistered probe IDs
    - Malformed formats
    """
    if not isinstance(probe_id, str):
        return False

    candidate = probe_id.strip()
    if candidate != probe_id:
        return False

    if not candidate.startswith("PROBE-"):
        return False

    return candidate in REGISTERED_PROBE_IDS


def validate_probe_ids(probe_ids: Iterable[Any]) -> list[str]:
    """Validate an iterable of candidate probe IDs against the strict allow-list.

    Parameters:
        probe_ids: Iterable of candidate probe ID strings.

    Returns:
        List of validated probe ID strings.

    Raises:
        TypeError: If probe_ids is not an iterable.
        ValueError: If any probe ID is not a registered, valid probe ID or is malformed.
    """
    if not isinstance(probe_ids, (list, tuple, set, frozenset)):
        raise TypeError(f"Expected iterable of probe IDs, got {type(probe_ids).__name__}")

    validated: list[str] = []
    for pid in probe_ids:
        if not isinstance(pid, str):
            raise ValueError(f"Probe ID must be a string, got {type(pid).__name__}: {pid!r}")

        cleaned = pid.strip()
        if cleaned != pid:
            raise ValueError(f"Probe ID contains illegal whitespace: {pid!r}")

        if not is_valid_probe_id(cleaned):
            raise ValueError(
                f"Rejected probe ID: {cleaned!r}. Only predefined registered probe IDs "
                f"are permitted ({sorted(REGISTERED_PROBE_IDS)})."
            )
        validated.append(cleaned)

    return validated


# ---------------------------------------------------------------------------
# Core Reasoning Engine
# ---------------------------------------------------------------------------

def generate_hypothesis(finding_rule: Any) -> VulnerabilityHypothesis:
    """Generate a structured vulnerability hypothesis for a given static finding rule.

    Parameters:
        finding_rule: String rule ID (e.g. "AUTH001", "PY002", "PY003") or a
                      finding dictionary containing a "rule" key.

    Returns:
        A structured VulnerabilityHypothesis. If the finding rule is unknown,
        unsupported, or malformed, a safe result with no selected probes is returned.
    """
    # Normalize input: extract rule string if a dictionary/mapping was passed
    if isinstance(finding_rule, Mapping):
        rule_str = str(finding_rule.get("rule", "")).strip()
    elif isinstance(finding_rule, str):
        rule_str = finding_rule.strip()
    else:
        # Non-string, non-mapping input: safe default with no probes
        return VulnerabilityHypothesis(
            finding_rule=str(finding_rule) if finding_rule is not None else "",
            hypothesis="Malformed or unsupported finding rule input.",
            selected_probe_ids=[],
            confidence="low",
            reasoning="Input could not be parsed as a valid finding rule. No probes selected.",
        )

    # Unknown rule: return safe result with no selected probes
    if not rule_str or rule_str not in RULE_PROBE_MAPPING:
        return VulnerabilityHypothesis(
            finding_rule=rule_str,
            hypothesis="No automated runtime validation probe available for this finding rule.",
            selected_probe_ids=[],
            confidence="low",
            reasoning=(
                f"Rule '{rule_str}' is either unrecognized or does not have a predefined, "
                "safe runtime validation probe in the allow-list. No probes selected to ensure system safety."
            ),
        )

    candidate_probes = RULE_PROBE_MAPPING[rule_str]

    # Guardrail check: ensure every mapped probe satisfies the strict allow-list
    validated_probes = validate_probe_ids(candidate_probes)

    metadata = _RULE_METADATA.get(rule_str, {})
    hypothesis_text = metadata.get(
        "hypothesis",
        f"Potential vulnerability associated with static rule {rule_str}.",
    )
    confidence = metadata.get("confidence", "medium")
    reasoning = metadata.get(
        "reasoning",
        f"Rule {rule_str} triggered candidate runtime probes {validated_probes}.",
    )

    return VulnerabilityHypothesis(
        finding_rule=rule_str,
        hypothesis=hypothesis_text,
        selected_probe_ids=validated_probes,
        confidence=confidence,
        reasoning=reasoning,
    )


def generate_hypotheses_for_findings(findings: Iterable[Any]) -> list[VulnerabilityHypothesis]:
    """Generate structured hypotheses for a list of scanner findings.

    Parameters:
        findings: Iterable of finding dicts or rule ID strings.

    Returns:
        List of VulnerabilityHypothesis objects.
    """
    if not isinstance(findings, (list, tuple, set, frozenset)):
        return []

    return [generate_hypothesis(f) for f in findings]


def get_registered_probe_ids() -> list[str]:
    """Return a sorted list of all registered, allowed probe IDs."""
    return sorted(REGISTERED_PROBE_IDS)
