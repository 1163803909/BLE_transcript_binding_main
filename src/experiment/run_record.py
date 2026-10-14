from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Mapping, Optional


OUTCOME_VALUES = frozenset(
    {
        "paired",
        "explicit_pairing_failed",
        "hci_disconnect",
        "timeout",
        "local_transcript_mismatch",
        "local_crypto_rejection",
        "transport_error",
        "setup_error",
        "unknown",
    }
)


@dataclass(frozen=True)
class ArtifactPaths:
    """
    Paths of files generated or consumed by one experiment run.

    All paths are stored as strings so that the record can be serialized
    directly to JSON. They may be relative to the repository root or to an
    experiment output directory.
    """

    pcap: Optional[str] = None
    hci_log: Optional[str] = None
    injected_packet: Optional[str] = None
    wireshark_file: Optional[str] = None
    stdout_log: Optional[str] = None
    stderr_log: Optional[str] = None


@dataclass(frozen=True)
class PacketRecord:
    """
    Raw packet information associated with one experiment run.

    The values are lowercase hexadecimal strings without separators.
    The packet fields intentionally distinguish the SMP PDU from any
    surrounding L2CAP, HCI, or link-layer headers.
    """

    pairing_request: Optional[str] = None
    pairing_response: Optional[str] = None
    injected_pairing_request: Optional[str] = None
    injected_pairing_response: Optional[str] = None
    pairing_failed_pdu: Optional[str] = None


@dataclass(frozen=True)
class ExperimentRunRecord:
    """
    Machine-readable record for one execution of an experiment case.

    This structure is deliberately independent of a specific HCI backend.
    A future raw-HCI runner can populate the fields without changing the
    result format.
    """

    run_id: str
    case_name: str
    mode: str

    outcome: str

    started_at: str
    finished_at: Optional[str] = None

    packet_record: PacketRecord = field(
        default_factory=PacketRecord
    )

    transcript_hex: Optional[str] = None
    standard_f4_hex: Optional[str] = None
    context_f4_hex: Optional[str] = None

    initiator_address: Optional[str] = None
    responder_address: Optional[str] = None
    controller: Optional[str] = None

    disconnect_reason: Optional[str] = None
    smp_failure_reason: Optional[str] = None
    error_message: Optional[str] = None

    artifacts: ArtifactPaths = field(
        default_factory=ArtifactPaths
    )

    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not self.run_id:
            raise ValueError("run_id must not be empty")

        if not self.case_name:
            raise ValueError("case_name must not be empty")

        if not self.mode:
            raise ValueError("mode must not be empty")

        if self.outcome not in OUTCOME_VALUES:
            allowed = ", ".join(sorted(OUTCOME_VALUES))
            raise ValueError(
                f"unsupported outcome {self.outcome!r}; "
                f"expected one of: {allowed}"
            )

        if not self.started_at:
            raise ValueError("started_at must not be empty")

    @classmethod
    def new(
        cls,
        *,
        run_id: str,
        case_name: str,
        mode: str,
        outcome: str = "unknown",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "ExperimentRunRecord":
        """
        Create a new run record using the current UTC time.

        The default outcome is ``unknown`` because a run should only be
        classified after the execution has finished.
        """
        started_at = _utc_now()

        return cls(
            run_id=run_id,
            case_name=case_name,
            mode=mode,
            outcome=outcome,
            started_at=started_at,
            metadata=dict(metadata or {}),
        )

    def finished(
        self,
        *,
        outcome: str,
        finished_at: Optional[str] = None,
        packet_record: Optional[PacketRecord] = None,
        transcript_hex: Optional[str] = None,
        standard_f4_hex: Optional[str] = None,
        context_f4_hex: Optional[str] = None,
        initiator_address: Optional[str] = None,
        responder_address: Optional[str] = None,
        controller: Optional[str] = None,
        disconnect_reason: Optional[str] = None,
        smp_failure_reason: Optional[str] = None,
        error_message: Optional[str] = None,
        artifacts: Optional[ArtifactPaths] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "ExperimentRunRecord":
        """
        Return a new immutable record containing the final run result.

        Existing values are preserved when an argument is omitted.
        """
        merged_metadata = dict(self.metadata)

        if metadata is not None:
            merged_metadata.update(metadata)

        return ExperimentRunRecord(
            run_id=self.run_id,
            case_name=self.case_name,
            mode=self.mode,
            outcome=outcome,
            started_at=self.started_at,
            finished_at=finished_at or _utc_now(),
            packet_record=packet_record or self.packet_record,
            transcript_hex=(
                transcript_hex
                if transcript_hex is not None
                else self.transcript_hex
            ),
            standard_f4_hex=(
                standard_f4_hex
                if standard_f4_hex is not None
                else self.standard_f4_hex
            ),
            context_f4_hex=(
                context_f4_hex
                if context_f4_hex is not None
                else self.context_f4_hex
            ),
            initiator_address=(
                initiator_address
                if initiator_address is not None
                else self.initiator_address
            ),
            responder_address=(
                responder_address
                if responder_address is not None
                else self.responder_address
            ),
            controller=(
                controller
                if controller is not None
                else self.controller
            ),
            disconnect_reason=(
                disconnect_reason
                if disconnect_reason is not None
                else self.disconnect_reason
            ),
            smp_failure_reason=(
                smp_failure_reason
                if smp_failure_reason is not None
                else self.smp_failure_reason
            ),
            error_message=(
                error_message
                if error_message is not None
                else self.error_message
            ),
            artifacts=artifacts or self.artifacts,
            metadata=merged_metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the record into a JSON-compatible dictionary.
        """
        return asdict(self)

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        """
        Serialize this record as JSON.
        """
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
        )

    def to_json_line(self) -> str:
        """
        Serialize this record as one compact JSON Lines record.

        JSONL is suitable for appending one record per experiment run.
        """
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def _utc_now() -> str:
    """
    Return an ISO-8601 UTC timestamp with a trailing ``Z``.
    """
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
