# src/analysis/outcomes.py

"""
Outcome classification and aggregation for Bluetooth security experiments.

This module converts observations from HCI/SMP traces into stable,
machine-readable outcome records.

It is intentionally observation-based. It does not claim that a pairing
exchange succeeded merely because some SMP key-distribution packets were
seen. For stronger conclusions, the caller should provide controller-level
evidence such as:

* encryption-change events;
* authenticated/encrypted link state;
* service-level verification;
* application-level challenge/response results.

Typical use:

    outcome = classify_observation(
        trial_id="trial-0001",
        smp_report=report,
        encryption_enabled=True,
        target_reached=True,
    )

    counter = OutcomeCounter()
    counter.add(outcome)

    print(counter.report().to_dict())
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any, Iterable, Mapping


class OutcomeClassification(str, Enum):
    """Stable top-level outcome labels."""

    SUCCESS = "success"
    PAIRING_FAILED = "pairing_failed"
    ENCRYPTION_NOT_ENABLED = "encryption_not_enabled"
    TARGET_NOT_REACHED = "target_not_reached"
    TIMEOUT = "timeout"
    MALFORMED_TRACE = "malformed_trace"
    NO_SMP_PACKETS = "no_smp_packets"
    SECURITY_REQUEST_ONLY = "security_request_only"
    PAIRING_IN_PROGRESS = "pairing_in_progress"
    UNKNOWN = "unknown"


class OutcomeError(ValueError):
    """Base exception for outcome-analysis errors."""


@dataclass(frozen=True, slots=True)
class OutcomeEvidence:
    """
    Evidence used to classify one experiment trial.

    All fields are optional because different experiments expose different
    levels of evidence. The classifier remains conservative when evidence is
    incomplete.
    """

    smp_packet_count: int = 0
    malformed_packet_count: int = 0
    non_smp_packet_count: int = 0

    pairing_failed: bool = False
    pairing_failure_reason: int | None = None
    pairing_failure_reason_name: str | None = None

    encryption_enabled: bool | None = None
    encryption_event_seen: bool = False

    target_reached: bool | None = None
    service_verified: bool | None = None
    timeout: bool = False

    trace_outcome: str | None = None
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        integer_fields = (
            "smp_packet_count",
            "malformed_packet_count",
            "non_smp_packet_count",
        )

        for field_name in integer_fields:
            value = getattr(self, field_name)

            if isinstance(value, bool) or not isinstance(
                value,
                int,
            ):
                raise TypeError(
                    f"{field_name} must be an integer"
                )

            if value < 0:
                raise ValueError(
                    f"{field_name} cannot be negative"
                )

        if self.pairing_failure_reason is not None:
            if isinstance(
                self.pairing_failure_reason,
                bool,
            ) or not isinstance(
                self.pairing_failure_reason,
                int,
            ):
                raise TypeError(
                    "pairing_failure_reason must be an integer"
                )

            if not 0 <= self.pairing_failure_reason <= 0xFF:
                raise ValueError(
                    "pairing_failure_reason must be between "
                    "0 and 255"
                )

        if not isinstance(self.notes, tuple):
            raise TypeError("notes must be a tuple")

    @property
    def has_trace(self) -> bool:
        """Return whether any SMP packet was observed."""

        return self.smp_packet_count > 0

    @property
    def trace_is_malformed(self) -> bool:
        """Return whether malformed packets were observed."""

        return self.malformed_packet_count > 0


@dataclass(frozen=True, slots=True)
class TrialOutcome:
    """Classification result for one experiment trial."""

    trial_id: str
    classification: OutcomeClassification
    evidence: OutcomeEvidence
    detail: str = ""
    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    @property
    def outcome(self) -> str:
        """Return the stable string representation."""

        return self.classification.value

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""

        return {
            "trial_id": self.trial_id,
            "outcome": self.outcome,
            "classification": self.classification.value,
            "detail": self.detail,
            "evidence": evidence_to_dict(
                self.evidence
            ),
            "metadata": dict(self.metadata),
        }

    def to_json(
        self,
        *,
        indent: int | None = None,
    ) -> str:
        """Serialize this result as JSON."""

        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
        )


@dataclass(frozen=True, slots=True)
class OutcomeReport:
    """Aggregate counts and trial-level results."""

    total_trials: int
    counts: dict[str, int]
    rates: dict[str, float]
    trials: tuple[TrialOutcome, ...]

    @property
    def successful_trials(self) -> int:
        """Return the number of successful trials."""

        return self.counts.get(
            OutcomeClassification.SUCCESS.value,
            0,
        )

    @property
    def failed_trials(self) -> int:
        """Return the number of explicitly failed trials."""

        return (
            self.counts.get(
                OutcomeClassification.PAIRING_FAILED.value,
                0,
            )
            + self.counts.get(
                OutcomeClassification.ENCRYPTION_NOT_ENABLED.value,
                0,
            )
            + self.counts.get(
                OutcomeClassification.TARGET_NOT_REACHED.value,
                0,
            )
            + self.counts.get(
                OutcomeClassification.TIMEOUT.value,
                0,
            )
        )

    def to_dict(
        self,
        *,
        include_trials: bool = True,
    ) -> dict[str, Any]:
        """Return a JSON-serialisable aggregate report."""

        result: dict[str, Any] = {
            "total_trials": self.total_trials,
            "counts": dict(self.counts),
            "rates": dict(self.rates),
            "successful_trials": (
                self.successful_trials
            ),
            "failed_trials": self.failed_trials,
        }

        if include_trials:
            result["trials"] = [
                trial.to_dict()
                for trial in self.trials
            ]

        return result

    def to_json(
        self,
        *,
        indent: int | None = 2,
        include_trials: bool = True,
    ) -> str:
        """Serialize the aggregate report as JSON."""

        return json.dumps(
            self.to_dict(
                include_trials=include_trials,
            ),
            indent=indent,
            sort_keys=True,
        )


class OutcomeCounter:
    """
    Incremental counter for trial outcomes.

    The counter preserves trial records in insertion order and rejects
    duplicate trial IDs by default.
    """

    def __init__(
        self,
        *,
        reject_duplicate_trial_ids: bool = True,
    ) -> None:
        self.reject_duplicate_trial_ids = (
            reject_duplicate_trial_ids
        )
        self._trials: list[TrialOutcome] = []
        self._trial_ids: set[str] = set()

    def add(
        self,
        outcome: TrialOutcome,
    ) -> None:
        """Add one classified trial."""

        if not isinstance(outcome, TrialOutcome):
            raise TypeError(
                "outcome must be a TrialOutcome"
            )

        if (
            self.reject_duplicate_trial_ids
            and outcome.trial_id in self._trial_ids
        ):
            raise OutcomeError(
                f"duplicate trial_id: {outcome.trial_id!r}"
            )

        self._trials.append(outcome)
        self._trial_ids.add(outcome.trial_id)

    def add_observation(
        self,
        *,
        trial_id: str,
        smp_report: Any | None = None,
        encryption_enabled: bool | None = None,
        encryption_event_seen: bool = False,
        target_reached: bool | None = None,
        service_verified: bool | None = None,
        timeout: bool = False,
        metadata: Mapping[str, Any] | None = None,
        notes: Iterable[str] = (),
    ) -> TrialOutcome:
        """
        Classify and add one observation.

        Returns the created ``TrialOutcome``.
        """

        outcome = classify_observation(
            trial_id=trial_id,
            smp_report=smp_report,
            encryption_enabled=encryption_enabled,
            encryption_event_seen=(
                encryption_event_seen
            ),
            target_reached=target_reached,
            service_verified=service_verified,
            timeout=timeout,
            metadata=metadata,
            notes=notes,
        )

        self.add(outcome)
        return outcome

    def extend(
        self,
        outcomes: Iterable[TrialOutcome],
    ) -> None:
        """Add multiple classified trial outcomes."""

        for outcome in outcomes:
            self.add(outcome)

    def clear(self) -> None:
        """Remove all accumulated outcomes."""

        self._trials.clear()
        self._trial_ids.clear()

    def trials(self) -> tuple[TrialOutcome, ...]:
        """Return trial outcomes in insertion order."""

        return tuple(self._trials)

    def counts(self) -> dict[str, int]:
        """Return raw outcome counts."""

        counter = Counter(
            outcome.outcome
            for outcome in self._trials
        )

        return dict(
            sorted(counter.items())
        )

    def report(self) -> OutcomeReport:
        """Build an aggregate report."""

        counts = self.counts()
        total = len(self._trials)

        if total == 0:
            rates: dict[str, float] = {}
        else:
            rates = {
                outcome: count / total
                for outcome, count in counts.items()
            }

        return OutcomeReport(
            total_trials=total,
            counts=counts,
            rates=rates,
            trials=self.trials(),
        )


def classify_observation(
    *,
    trial_id: str,
    smp_report: Any | None = None,
    encryption_enabled: bool | None = None,
    encryption_event_seen: bool = False,
    target_reached: bool | None = None,
    service_verified: bool | None = None,
    timeout: bool = False,
    metadata: Mapping[str, Any] | None = None,
    notes: Iterable[str] = (),
) -> TrialOutcome:
    """
    Classify one experiment observation.

    Classification precedence is deliberately conservative:

    1. timeout;
    2. target not reached;
    3. malformed trace without usable SMP evidence;
    4. explicit SMP pairing failure;
    5. no SMP packets;
    6. security-request-only or pairing-in-progress;
    7. encryption not enabled;
    8. service verification;
    9. encryption evidence;
    10. unknown.

    A trace containing key-distribution messages is not by itself classified
    as ``success``. Either ``service_verified=True`` or
    ``encryption_enabled=True`` is required.
    """

    normalized_trial_id = normalize_trial_id(
        trial_id
    )

    evidence = evidence_from_smp_report(
        smp_report,
        encryption_enabled=encryption_enabled,
        encryption_event_seen=(
            encryption_event_seen
        ),
        target_reached=target_reached,
        service_verified=service_verified,
        timeout=timeout,
        notes=notes,
    )

    classification, detail = _classify_evidence(
        evidence
    )

    return TrialOutcome(
        trial_id=normalized_trial_id,
        classification=classification,
        evidence=evidence,
        detail=detail,
        metadata=dict(metadata or {}),
    )


def evidence_from_smp_report(
    smp_report: Any | None,
    *,
    encryption_enabled: bool | None = None,
    encryption_event_seen: bool = False,
    target_reached: bool | None = None,
    service_verified: bool | None = None,
    timeout: bool = False,
    notes: Iterable[str] = (),
) -> OutcomeEvidence:
    """
    Convert an SMPTraceReport-like object into OutcomeEvidence.

    The function uses attributes rather than importing the analyzer module,
    which keeps this module usable with stored JSON-derived reports and
    lightweight test doubles.
    """

    if smp_report is None:
        return OutcomeEvidence(
            encryption_enabled=encryption_enabled,
            encryption_event_seen=(
                encryption_event_seen
            ),
            target_reached=target_reached,
            service_verified=service_verified,
            timeout=timeout,
            notes=tuple(notes),
        )

    packet_count = _read_int(
        smp_report,
        "smp_pdu_count",
        default=0,
    )

    malformed_count = _read_int(
        smp_report,
        "malformed_packet_count",
        default=0,
    )

    non_smp_count = _read_int(
        smp_report,
        "non_smp_packet_count",
        default=0,
    )

    trace_outcome = _read_optional_str(
        smp_report,
        "outcome",
    )

    failure_counts = _read_mapping(
        smp_report,
        "failure_counts",
    )

    pairing_failed = (
        trace_outcome == "pairing_failed"
        or sum(
            int(value)
            for value in failure_counts.values()
        )
        > 0
    )

    reason_name: str | None = None

    if len(failure_counts) == 1:
        reason_name = next(
            iter(failure_counts)
        )

    return OutcomeEvidence(
        smp_packet_count=packet_count,
        malformed_packet_count=malformed_count,
        non_smp_packet_count=non_smp_count,
        pairing_failed=pairing_failed,
        pairing_failure_reason_name=reason_name,
        encryption_enabled=encryption_enabled,
        encryption_event_seen=(
            encryption_event_seen
        ),
        target_reached=target_reached,
        service_verified=service_verified,
        timeout=timeout,
        trace_outcome=trace_outcome,
        notes=tuple(notes),
    )


def classify_from_dict(
    observation: Mapping[str, Any],
) -> TrialOutcome:
    """
    Classify an observation dictionary.

    Expected keys are the same as ``classify_observation``. This helper is
    useful when processing JSONL experiment records.
    """

    if "trial_id" not in observation:
        raise OutcomeError(
            "observation is missing required key 'trial_id'"
        )

    smp_report = observation.get(
        "smp_report"
    )

    return classify_observation(
        trial_id=str(
            observation["trial_id"]
        ),
        smp_report=smp_report,
        encryption_enabled=observation.get(
            "encryption_enabled"
        ),
        encryption_event_seen=bool(
            observation.get(
                "encryption_event_seen",
                False,
            )
        ),
        target_reached=observation.get(
            "target_reached"
        ),
        service_verified=observation.get(
            "service_verified"
        ),
        timeout=bool(
            observation.get(
                "timeout",
                False,
            )
        ),
        metadata=observation.get(
            "metadata"
        ),
        notes=observation.get(
            "notes",
            (),
        ),
    )


def raw_outcome_counts(
    outcomes: Iterable[TrialOutcome],
) -> dict[str, int]:
    """Return raw counts keyed by stable outcome name."""

    counter = Counter(
        outcome.outcome
        for outcome in outcomes
    )

    return dict(
        sorted(counter.items())
    )


def merge_outcome_reports(
    reports: Iterable[OutcomeReport],
    *,
    reject_duplicate_trial_ids: bool = True,
) -> OutcomeReport:
    """Merge multiple reports into one aggregate report."""

    counter = OutcomeCounter(
        reject_duplicate_trial_ids=(
            reject_duplicate_trial_ids
        )
    )

    for report in reports:
        counter.extend(report.trials)

    return counter.report()


def normalize_trial_id(trial_id: str) -> str:
    """Normalize and validate a trial identifier."""

    if not isinstance(trial_id, str):
        raise TypeError(
            "trial_id must be a string"
        )

    normalized = trial_id.strip()

    if not normalized:
        raise ValueError(
            "trial_id cannot be empty"
        )

    return normalized


def evidence_to_dict(
    evidence: OutcomeEvidence,
) -> dict[str, Any]:
    """Convert evidence to a JSON-serialisable dictionary."""

    return {
        "smp_packet_count": (
            evidence.smp_packet_count
        ),
        "malformed_packet_count": (
            evidence.malformed_packet_count
        ),
        "non_smp_packet_count": (
            evidence.non_smp_packet_count
        ),
        "pairing_failed": (
            evidence.pairing_failed
        ),
        "pairing_failure_reason": (
            evidence.pairing_failure_reason
        ),
        "pairing_failure_reason_name": (
            evidence.pairing_failure_reason_name
        ),
        "encryption_enabled": (
            evidence.encryption_enabled
        ),
        "encryption_event_seen": (
            evidence.encryption_event_seen
        ),
        "target_reached": (
            evidence.target_reached
        ),
        "service_verified": (
            evidence.service_verified
        ),
        "timeout": evidence.timeout,
        "trace_outcome": evidence.trace_outcome,
        "notes": list(evidence.notes),
    }


def _classify_evidence(
    evidence: OutcomeEvidence,
) -> tuple[OutcomeClassification, str]:
    if evidence.timeout:
        return (
            OutcomeClassification.TIMEOUT,
            "experiment timeout was recorded",
        )

    if evidence.target_reached is False:
        return (
            OutcomeClassification.TARGET_NOT_REACHED,
            "authorized target was not reached",
        )

    if (
        evidence.trace_is_malformed
        and not evidence.has_trace
    ):
        return (
            OutcomeClassification.MALFORMED_TRACE,
            "trace contained malformed packets but no "
            "usable SMP PDU",
        )

    if evidence.pairing_failed:
        detail = "SMP pairing failure was observed"

        if evidence.pairing_failure_reason_name:
            detail += (
                ": "
                f"{evidence.pairing_failure_reason_name}"
            )

        return (
            OutcomeClassification.PAIRING_FAILED,
            detail,
        )

    if not evidence.has_trace:
        if evidence.trace_is_malformed:
            return (
                OutcomeClassification.MALFORMED_TRACE,
                "no usable SMP packet was observed",
            )

        return (
            OutcomeClassification.NO_SMP_PACKETS,
            "no SMP packet was observed",
        )

    if evidence.trace_outcome == "security_request_only":
        return (
            OutcomeClassification.SECURITY_REQUEST_ONLY,
            "only an SMP Security Request was observed",
        )

    if evidence.trace_outcome == "pairing_in_progress":
        if (
            evidence.encryption_enabled is not True
            and evidence.service_verified is not True
        ):
            return (
                OutcomeClassification.PAIRING_IN_PROGRESS,
                "pairing messages were observed without "
                "completion evidence",
            )

    if evidence.encryption_enabled is False:
        return (
            OutcomeClassification.ENCRYPTION_NOT_ENABLED,
            "pairing-related traffic was observed but "
            "encryption was not enabled",
        )

    if evidence.service_verified is True:
        return (
            OutcomeClassification.SUCCESS,
            "application/service-level verification succeeded",
        )

    if evidence.encryption_enabled is True:
        return (
            OutcomeClassification.SUCCESS,
            "controller encryption evidence was observed",
        )

    if evidence.encryption_event_seen:
        return (
            OutcomeClassification.SUCCESS,
            "an encryption-change event was observed",
        )

    return (
        OutcomeClassification.UNKNOWN,
        "SMP traffic was observed without sufficient "
        "completion evidence",
    )


def _read_int(
    obj: Any,
    name: str,
    *,
    default: int,
) -> int:
    if isinstance(obj, Mapping):
        value = obj.get(name, default)
    else:
        value = getattr(
            obj,
            name,
            default,
        )

    if value is None:
        return default

    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise OutcomeError(
            f"{name} must be integer-like"
        ) from exc

    if result < 0:
        raise OutcomeError(
            f"{name} cannot be negative"
        )

    return result


def _read_optional_str(
    obj: Any,
    name: str,
) -> str | None:
    if isinstance(obj, Mapping):
        value = obj.get(name)
    else:
        value = getattr(
            obj,
            name,
            None,
        )

    if value is None:
        return None

    return str(value)


def _read_mapping(
    obj: Any,
    name: str,
) -> Mapping[str, Any]:
    if isinstance(obj, Mapping):
        value = obj.get(name, {})
    else:
        value = getattr(
            obj,
            name,
            {},
        )

    if value is None:
        return {}

    if not isinstance(value, Mapping):
        raise OutcomeError(
            f"{name} must be a mapping"
        )

    return value


__all__ = [
    "OutcomeClassification",
    "OutcomeCounter",
    "OutcomeError",
    "OutcomeEvidence",
    "OutcomeReport",
    "TrialOutcome",
    "classify_from_dict",
    "classify_observation",
    "evidence_from_smp_report",
    "evidence_to_dict",
    "merge_outcome_reports",
    "normalize_trial_id",
    "raw_outcome_counts",
]
