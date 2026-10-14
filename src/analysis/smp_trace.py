# src/analysis/smp_trace.py

"""
Bluetooth LE SMP trace analysis.

This module consumes HCI ACL packets and extracts complete, unfragmented
SMP PDUs carried on L2CAP CID 0x0006.

It is intended for:

* raw HCI trace inspection;
* packet-count and outcome analysis;
* JSONL/JSON artifact generation;
* correlating controller handles with observed SMP messages.

This module does not:

* send packets;
* perform pairing;
* derive cryptographic keys;
* decrypt encrypted traffic;
* reassemble ACL fragments;
* infer packet direction from the HCI packet itself.

The caller must provide the direction, normally one of:

    "host_to_controller"
    "controller_to_host"
    "tx"
    "rx"
    "unknown"

Example:

    analyzer = SMPTraceAnalyzer()

    analyzer.add_hci_packet(
        raw_packet,
        direction="controller_to_host",
        timestamp_ns=123456789,
    )

    report = analyzer.report()
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Final, Iterable, Mapping

from src.hci.acl_l2cap import (
    FragmentedPacketError,
    HCIACLFormatError,
    HCIACLPacket,
    L2CAPFormatError,
    L2CAP_CID_SMP,
    extract_l2cap_frame,
    parse_hci_acl_packet,
)
from src.hci.connection import normalize_bd_addr


# SMP command opcodes from the Bluetooth Core Specification.
SMP_PAIRING_REQUEST: Final[int] = 0x01
SMP_PAIRING_RESPONSE: Final[int] = 0x02
SMP_PAIRING_CONFIRM: Final[int] = 0x03
SMP_PAIRING_RANDOM: Final[int] = 0x04
SMP_PAIRING_FAILED: Final[int] = 0x05
SMP_ENCRYPTION_INFORMATION: Final[int] = 0x06
SMP_MASTER_IDENTIFICATION: Final[int] = 0x07
SMP_IDENTITY_INFORMATION: Final[int] = 0x08
SMP_IDENTITY_ADDRESS_INFORMATION: Final[int] = 0x09
SMP_SIGNING_INFORMATION: Final[int] = 0x0A
SMP_SECURITY_REQUEST: Final[int] = 0x0B
SMP_PAIRING_PUBLIC_KEY: Final[int] = 0x0C
SMP_PAIRING_DHKEY_CHECK: Final[int] = 0x0D
SMP_KEYPRESS_NOTIFICATION: Final[int] = 0x0E
SMP_PAIRING_KEYPRESS_NOTIFICATION: Final[int] = 0x0E

# SMP Pairing Failed reason codes.
SMP_REASON_PASSKEY_ENTRY_FAILED: Final[int] = 0x01
SMP_REASON_OOB_NOT_AVAILABLE: Final[int] = 0x02
SMP_REASON_AUTHENTICATION_REQUIREMENTS: Final[int] = 0x03
SMP_REASON_CONFIRM_VALUE_FAILED: Final[int] = 0x04
SMP_REASON_PAIRING_NOT_SUPPORTED: Final[int] = 0x05
SMP_REASON_ENCRYPTION_KEY_SIZE: Final[int] = 0x06
SMP_REASON_COMMAND_NOT_SUPPORTED: Final[int] = 0x07
SMP_REASON_UNSPECIFIED_REASON: Final[int] = 0x08
SMP_REASON_REPEATED_ATTEMPTS: Final[int] = 0x09
SMP_REASON_INVALID_PARAMETERS: Final[int] = 0x0A
SMP_REASON_DHKEY_CHECK_FAILED: Final[int] = 0x0B
SMP_REASON_NUMERIC_COMPARISON_FAILED: Final[int] = 0x0C
SMP_REASON_BREDR_PAIRING_IN_PROGRESS: Final[int] = 0x0D
SMP_REASON_CROSS_TRANSPORT_KEY_DERIVATION: Final[int] = 0x0E
SMP_REASON_KEY_REJECTED: Final[int] = 0x0F


SMP_COMMAND_NAMES: Final[dict[int, str]] = {
    SMP_PAIRING_REQUEST: "pairing_request",
    SMP_PAIRING_RESPONSE: "pairing_response",
    SMP_PAIRING_CONFIRM: "pairing_confirm",
    SMP_PAIRING_RANDOM: "pairing_random",
    SMP_PAIRING_FAILED: "pairing_failed",
    SMP_ENCRYPTION_INFORMATION: "encryption_information",
    SMP_MASTER_IDENTIFICATION: "master_identification",
    SMP_IDENTITY_INFORMATION: "identity_information",
    SMP_IDENTITY_ADDRESS_INFORMATION: "identity_address_information",
    SMP_SIGNING_INFORMATION: "signing_information",
    SMP_SECURITY_REQUEST: "security_request",
    SMP_PAIRING_PUBLIC_KEY: "pairing_public_key",
    SMP_PAIRING_DHKEY_CHECK: "pairing_dhkey_check",
    SMP_KEYPRESS_NOTIFICATION: "keypress_notification",
}


SMP_FAILURE_REASON_NAMES: Final[dict[int, str]] = {
    SMP_REASON_PASSKEY_ENTRY_FAILED: "passkey_entry_failed",
    SMP_REASON_OOB_NOT_AVAILABLE: "oob_not_available",
    SMP_REASON_AUTHENTICATION_REQUIREMENTS: (
        "authentication_requirements"
    ),
    SMP_REASON_CONFIRM_VALUE_FAILED: "confirm_value_failed",
    SMP_REASON_PAIRING_NOT_SUPPORTED: "pairing_not_supported",
    SMP_REASON_ENCRYPTION_KEY_SIZE: "encryption_key_size",
    SMP_REASON_COMMAND_NOT_SUPPORTED: "command_not_supported",
    SMP_REASON_UNSPECIFIED_REASON: "unspecified_reason",
    SMP_REASON_REPEATED_ATTEMPTS: "repeated_attempts",
    SMP_REASON_INVALID_PARAMETERS: "invalid_parameters",
    SMP_REASON_DHKEY_CHECK_FAILED: "dhkey_check_failed",
    SMP_REASON_NUMERIC_COMPARISON_FAILED: (
        "numeric_comparison_failed"
    ),
    SMP_REASON_BREDR_PAIRING_IN_PROGRESS: (
        "bredr_pairing_in_progress"
    ),
    SMP_REASON_CROSS_TRANSPORT_KEY_DERIVATION: (
        "cross_transport_key_derivation"
    ),
    SMP_REASON_KEY_REJECTED: "key_rejected",
}


DIRECTION_HOST_TO_CONTROLLER: Final[str] = "host_to_controller"
DIRECTION_CONTROLLER_TO_HOST: Final[str] = "controller_to_host"
DIRECTION_TX: Final[str] = "tx"
DIRECTION_RX: Final[str] = "rx"
DIRECTION_UNKNOWN: Final[str] = "unknown"


class SMPTraceError(ValueError):
    """Base exception for SMP trace analysis errors."""


class UnsupportedDirectionError(SMPTraceError):
    """Raised when a direction value is not recognized."""


@dataclass(frozen=True, slots=True)
class SMPPDU:
    """A decoded SMP PDU."""

    command_code: int
    command_name: str
    payload: bytes
    raw: bytes
    fields: dict[str, object] = field(
        default_factory=dict
    )

    @property
    def payload_length(self) -> int:
        return len(self.payload)

    @property
    def pdu_length(self) -> int:
        return len(self.raw)

    @property
    def is_pairing_failure(self) -> bool:
        return self.command_code == SMP_PAIRING_FAILED

    @property
    def failure_reason(self) -> int | None:
        if not self.is_pairing_failure:
            return None

        if len(self.payload) != 1:
            return None

        return self.payload[0]


@dataclass(frozen=True, slots=True)
class SMPTraceRecord:
    """One observed SMP message together with its HCI metadata."""

    sequence: int
    timestamp_ns: int | None
    direction: str
    connection_handle: int
    pb_flag: int
    bc_flag: int
    pdu: SMPPDU
    raw_hci_hex: str
    l2cap_hex: str
    acl_payload_hex: str

    @property
    def command_code(self) -> int:
        return self.pdu.command_code

    @property
    def command_name(self) -> str:
        return self.pdu.command_name

    def to_dict(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "timestamp_ns": self.timestamp_ns,
            "direction": self.direction,
            "connection_handle": self.connection_handle,
            "connection_handle_hex": (
                f"0x{self.connection_handle:03x}"
            ),
            "pb_flag": self.pb_flag,
            "bc_flag": self.bc_flag,
            "command_code": self.pdu.command_code,
            "command_code_hex": (
                f"0x{self.pdu.command_code:02x}"
            ),
            "command_name": self.pdu.command_name,
            "pdu_length": self.pdu.pdu_length,
            "pdu_hex": self.pdu.raw.hex(),
            "pdu_fields": self.pdu.fields,
            "acl_payload_hex": self.acl_payload_hex,
            "l2cap_hex": self.l2cap_hex,
            "raw_hci_hex": self.raw_hci_hex,
        }


@dataclass(frozen=True, slots=True)
class SMPParseErrorRecord:
    """A malformed or non-decodable input packet."""

    sequence: int
    timestamp_ns: int | None
    direction: str
    error_type: str
    error: str
    raw_hci_hex: str

    def to_dict(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "timestamp_ns": self.timestamp_ns,
            "direction": self.direction,
            "error_type": self.error_type,
            "error": self.error,
            "raw_hci_hex": self.raw_hci_hex,
        }


@dataclass(frozen=True, slots=True)
class SMPTraceReport:
    """Immutable summary of an SMP trace."""

    packet_count: int
    smp_pdu_count: int
    malformed_packet_count: int
    non_smp_packet_count: int
    command_counts: dict[str, int]
    command_code_counts: dict[str, int]
    direction_counts: dict[str, int]
    failure_counts: dict[str, int]
    handle_counts: dict[str, int]
    outcome: str
    records: tuple[SMPTraceRecord, ...]
    errors: tuple[SMPParseErrorRecord, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "packet_count": self.packet_count,
            "smp_pdu_count": self.smp_pdu_count,
            "malformed_packet_count": (
                self.malformed_packet_count
            ),
            "non_smp_packet_count": (
                self.non_smp_packet_count
            ),
            "command_counts": dict(self.command_counts),
            "command_code_counts": dict(
                self.command_code_counts
            ),
            "direction_counts": dict(self.direction_counts),
            "failure_counts": dict(self.failure_counts),
            "handle_counts": dict(self.handle_counts),
            "outcome": self.outcome,
            "records": [
                record.to_dict()
                for record in self.records
            ],
            "errors": [
                error.to_dict()
                for error in self.errors
            ],
        }


class SMPTraceAnalyzer:
    """
    Incremental SMP trace analyzer.

    ``add_hci_packet`` accepts one complete HCI ACL packet. It does not
    reassemble ACL fragments. A continuation packet is recorded as an error
    unless ``ignore_fragment_errors=True`` is configured.
    """

    def __init__(
        self,
        *,
        has_h4: bool = True,
        strict: bool = True,
        ignore_non_smp: bool = True,
        ignore_fragment_errors: bool = False,
    ) -> None:
        self.has_h4 = has_h4
        self.strict = strict
        self.ignore_non_smp = ignore_non_smp
        self.ignore_fragment_errors = (
            ignore_fragment_errors
        )

        self._packet_count = 0
        self._sequence = 0
        self._records: list[SMPTraceRecord] = []
        self._errors: list[SMPParseErrorRecord] = []
        self._non_smp_packet_count = 0

    def add_hci_packet(
        self,
        raw: bytes | bytearray | memoryview,
        *,
        direction: str = DIRECTION_UNKNOWN,
        timestamp_ns: int | None = None,
    ) -> SMPTraceRecord | None:
        """
        Parse and add one HCI ACL packet.

        Returns:
            SMPTraceRecord for an SMP packet, otherwise ``None``.

        Non-SMP ACL packets are not errors. They increase
        ``non_smp_packet_count`` when ``ignore_non_smp`` is enabled.

        Malformed packets are retained in ``errors`` and do not raise,
        which makes the analyzer suitable for lossy HCI logs.
        """

        direction_value = normalize_direction(direction)
        raw_bytes = _as_bytes(raw)

        sequence = self._sequence
        self._sequence += 1
        self._packet_count += 1

        try:
            acl = parse_hci_acl_packet(
                raw_bytes,
                has_h4=self.has_h4,
                strict=self.strict,
            )

            if acl.is_continuation:
                raise FragmentedPacketError(
                    "ACL continuation fragment requires reassembly"
                )

            l2cap = extract_l2cap_frame(
                raw_bytes,
                has_h4=self.has_h4,
                strict=self.strict,
            )

            if l2cap.cid != L2CAP_CID_SMP:
                self._non_smp_packet_count += 1

                if self.ignore_non_smp:
                    return None

                return None

            if not l2cap.payload:
                raise SMPTraceError(
                    "SMP L2CAP frame contains an empty PDU"
                )

            pdu = parse_smp_pdu(l2cap.payload)

            record = SMPTraceRecord(
                sequence=sequence,
                timestamp_ns=timestamp_ns,
                direction=direction_value,
                connection_handle=acl.connection_handle,
                pb_flag=acl.pb_flag,
                bc_flag=acl.bc_flag,
                pdu=pdu,
                raw_hci_hex=acl.raw.hex(),
                l2cap_hex=l2cap.raw.hex(),
                acl_payload_hex=acl.payload.hex(),
            )

            self._records.append(record)
            return record

        except (
            HCIACLFormatError,
            L2CAPFormatError,
            FragmentedPacketError,
            SMPTraceError,
        ) as exc:
            error_record = SMPParseErrorRecord(
                sequence=sequence,
                timestamp_ns=timestamp_ns,
                direction=direction_value,
                error_type=type(exc).__name__,
                error=str(exc),
                raw_hci_hex=raw_bytes.hex(),
            )

            if (
                isinstance(exc, FragmentedPacketError)
                and self.ignore_fragment_errors
            ):
                return None

            self._errors.append(error_record)
            return None

    def add_many(
        self,
        packets: Iterable[
            bytes
            | bytearray
            | memoryview
        ],
        *,
        direction: str = DIRECTION_UNKNOWN,
        timestamp_ns: int | None = None,
    ) -> int:
        """
        Add multiple packets with one common direction.

        Returns the number of decoded SMP records.
        """

        added = 0

        for packet in packets:
            record = self.add_hci_packet(
                packet,
                direction=direction,
                timestamp_ns=timestamp_ns,
            )

            if record is not None:
                added += 1

        return added

    def records(self) -> tuple[SMPTraceRecord, ...]:
        """Return decoded records in input order."""

        return tuple(self._records)

    def errors(self) -> tuple[SMPParseErrorRecord, ...]:
        """Return malformed-packet records in input order."""

        return tuple(self._errors)

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def non_smp_packet_count(self) -> int:
        return self._non_smp_packet_count

    def report(self) -> SMPTraceReport:
        """Build an immutable aggregate report."""

        command_counts = Counter(
            record.command_name
            for record in self._records
        )

        command_code_counts = Counter(
            f"0x{record.command_code:02x}"
            for record in self._records
        )

        direction_counts = Counter(
            record.direction
            for record in self._records
        )

        failure_counts = Counter(
            record.pdu.fields.get(
                "reason_name",
                "unknown",
            )
            for record in self._records
            if record.pdu.is_pairing_failure
        )

        handle_counts = Counter(
            f"0x{record.connection_handle:03x}"
            for record in self._records
        )

        return SMPTraceReport(
            packet_count=self._packet_count,
            smp_pdu_count=len(self._records),
            malformed_packet_count=len(self._errors),
            non_smp_packet_count=(
                self._non_smp_packet_count
            ),
            command_counts=dict(command_counts),
            command_code_counts=dict(command_code_counts),
            direction_counts=dict(direction_counts),
            failure_counts=dict(failure_counts),
            handle_counts=dict(handle_counts),
            outcome=classify_outcome(
                self._records
            ),
            records=tuple(self._records),
            errors=tuple(self._errors),
        )

    def clear(self) -> None:
        """Clear all accumulated packets, records, and errors."""

        self._packet_count = 0
        self._sequence = 0
        self._records.clear()
        self._errors.clear()
        self._non_smp_packet_count = 0


def parse_smp_pdu(
    raw: bytes | bytearray | memoryview,
) -> SMPPDU:
    """
    Parse one SMP PDU.

    The first byte is the SMP command code. The remaining bytes are the
    command payload. Known fixed-format fields are decoded when possible;
    the raw payload is always retained.
    """

    data = _as_bytes(raw)

    if not data:
        raise SMPTraceError(
            "SMP PDU is empty"
        )

    command_code = data[0]
    payload = data[1:]
    command_name = SMP_COMMAND_NAMES.get(
        command_code,
        f"unknown_0x{command_code:02x}",
    )

    fields = decode_smp_fields(
        command_code,
        payload,
    )

    return SMPPDU(
        command_code=command_code,
        command_name=command_name,
        payload=payload,
        raw=data,
        fields=fields,
    )


def decode_smp_fields(
    command_code: int,
    payload: bytes | bytearray | memoryview,
) -> dict[str, object]:
    """
    Decode selected SMP command fields.

    Unknown or length-invalid fields are kept as ``payload_hex`` rather than
    causing the whole trace record to be discarded.
    """

    data = _as_bytes(payload)
    fields: dict[str, object] = {
        "payload_length": len(data),
        "payload_hex": data.hex(),
    }

    if command_code in {
        SMP_PAIRING_REQUEST,
        SMP_PAIRING_RESPONSE,
    }:
        if len(data) == 6:
            fields.update(
                {
                    "io_capability": data[0],
                    "oob_data_flag": data[1],
                    "auth_req": data[2],
                    "max_encryption_key_size": data[3],
                    "initiator_key_distribution": data[4],
                    "responder_key_distribution": data[5],
                }
            )
        else:
            fields["format_error"] = (
                "pairing command payload must be 6 bytes"
            )

    elif command_code in {
        SMP_PAIRING_CONFIRM,
        SMP_PAIRING_RANDOM,
    }:
        if len(data) == 16:
            fields["value_hex"] = data.hex()
        else:
            fields["format_error"] = (
                "confirm/random payload must be 16 bytes"
            )

    elif command_code == SMP_PAIRING_FAILED:
        if len(data) == 1:
            reason = data[0]
            fields.update(
                {
                    "reason": reason,
                    "reason_hex": f"0x{reason:02x}",
                    "reason_name": SMP_FAILURE_REASON_NAMES.get(
                        reason,
                        f"unknown_0x{reason:02x}",
                    ),
                }
            )
        else:
            fields["format_error"] = (
                "pairing failed payload must be 1 byte"
            )

    elif command_code == SMP_ENCRYPTION_INFORMATION:
        if len(data) == 16:
            fields["ltk_hex"] = data.hex()
        else:
            fields["format_error"] = (
                "encryption information payload must be 16 bytes"
            )

    elif command_code == SMP_MASTER_IDENTIFICATION:
        if len(data) == 10:
            fields.update(
                {
                    "ediv": int.from_bytes(
                        data[0:2],
                        byteorder="little",
                    ),
                    "rand_hex": data[2:10].hex(),
                }
            )
        else:
            fields["format_error"] = (
                "master identification payload must be 10 bytes"
            )

    elif command_code == SMP_IDENTITY_INFORMATION:
        if len(data) == 16:
            fields["irk_hex"] = data.hex()
        else:
            fields["format_error"] = (
                "identity information payload must be 16 bytes"
            )

    elif command_code == SMP_IDENTITY_ADDRESS_INFORMATION:
        if len(data) == 7:
            fields.update(
                {
                    "address_type": data[0],
                    "address": format_wire_bd_addr(
                        data[1:7]
                    ),
                }
            )
        else:
            fields["format_error"] = (
                "identity address payload must be 7 bytes"
            )

    elif command_code == SMP_SIGNING_INFORMATION:
        if len(data) == 16:
            fields["csrk_hex"] = data.hex()
        else:
            fields["format_error"] = (
                "signing information payload must be 16 bytes"
            )

    elif command_code == SMP_SECURITY_REQUEST:
        if len(data) == 1:
            fields["auth_req"] = data[0]
        else:
            fields["format_error"] = (
                "security request payload must be 1 byte"
            )

    elif command_code == SMP_PAIRING_PUBLIC_KEY:
        if len(data) == 64:
            fields["public_key_hex"] = data.hex()
        else:
            fields["format_error"] = (
                "pairing public key payload must be 64 bytes"
            )

    elif command_code == SMP_PAIRING_DHKEY_CHECK:
        if len(data) == 16:
            fields["dhkey_check_hex"] = data.hex()
        else:
            fields["format_error"] = (
                "DHKey check payload must be 16 bytes"
            )

    elif command_code == SMP_KEYPRESS_NOTIFICATION:
        if len(data) == 1:
            fields["notification_type"] = data[0]
        else:
            fields["format_error"] = (
                "keypress notification payload must be 1 byte"
            )

    return fields


def classify_outcome(
    records: Iterable[SMPTraceRecord],
) -> str:
    """
    Classify the observed trace outcome.

    Possible values:

    * ``no_smp_packets``
    * ``pairing_failed``
    * ``pairing_completed_or_keys_exchanged``
    * ``pairing_in_progress``
    * ``security_request_only``
    * ``unknown_smp_exchange``

    This is an observation-based label, not a cryptographic proof of
    successful pairing.
    """

    items = tuple(records)

    if not items:
        return "no_smp_packets"

    if any(
        record.command_code == SMP_PAIRING_FAILED
        for record in items
    ):
        return "pairing_failed"

    command_codes = {
        record.command_code
        for record in items
    }

    if (
        SMP_ENCRYPTION_INFORMATION in command_codes
        or SMP_MASTER_IDENTIFICATION in command_codes
        or SMP_IDENTITY_INFORMATION in command_codes
        or SMP_SIGNING_INFORMATION in command_codes
        or SMP_PAIRING_DHKEY_CHECK in command_codes
    ):
        return "pairing_completed_or_keys_exchanged"

    if command_codes == {SMP_SECURITY_REQUEST}:
        return "security_request_only"

    if (
        SMP_PAIRING_REQUEST in command_codes
        or SMP_PAIRING_RESPONSE in command_codes
        or SMP_PAIRING_CONFIRM in command_codes
        or SMP_PAIRING_RANDOM in command_codes
        or SMP_PAIRING_PUBLIC_KEY in command_codes
    ):
        return "pairing_in_progress"

    return "unknown_smp_exchange"


def normalize_direction(direction: str) -> str:
    """
    Normalize a packet direction.

    Accepted aliases:

    * ``tx`` / ``host_to_controller``
    * ``rx`` / ``controller_to_host``
    * ``unknown``
    """

    if not isinstance(direction, str):
        raise TypeError("direction must be a string")

    value = direction.strip().lower().replace("-", "_")

    aliases = {
        "tx": DIRECTION_TX,
        "out": DIRECTION_TX,
        "outgoing": DIRECTION_TX,
        "host_to_controller": DIRECTION_HOST_TO_CONTROLLER,
        "host": DIRECTION_HOST_TO_CONTROLLER,
        "rx": DIRECTION_RX,
        "in": DIRECTION_RX,
        "incoming": DIRECTION_RX,
        "controller_to_host": (
            DIRECTION_CONTROLLER_TO_HOST
        ),
        "controller": DIRECTION_CONTROLLER_TO_HOST,
        "unknown": DIRECTION_UNKNOWN,
        "": DIRECTION_UNKNOWN,
    }

    if value not in aliases:
        raise UnsupportedDirectionError(
            f"unsupported direction: {direction!r}"
        )

    return aliases[value]


def format_wire_bd_addr(
    address: bytes | bytearray | memoryview,
) -> str:
    """
    Format a Bluetooth address encoded in wire byte order.

    SMP identity address fields use the same little-endian octet order
    convention as HCI Bluetooth address fields.
    """

    raw = _as_bytes(address)

    if len(raw) != 6:
        raise SMPTraceError(
            "Bluetooth address must contain 6 bytes"
        )

    return normalize_bd_addr(
        ":".join(
            f"{octet:02X}"
            for octet in reversed(raw)
        )
    )


def report_from_packets(
    packets: Iterable[
        bytes
        | bytearray
        | memoryview
    ],
    *,
    direction: str = DIRECTION_UNKNOWN,
    has_h4: bool = True,
    strict: bool = True,
) -> SMPTraceReport:
    """Convenience function for analyzing a finite packet iterable."""

    analyzer = SMPTraceAnalyzer(
        has_h4=has_h4,
        strict=strict,
    )

    analyzer.add_many(
        packets,
        direction=direction,
    )

    return analyzer.report()


def _as_bytes(
    value: bytes | bytearray | memoryview,
) -> bytes:
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, memoryview):
        return value.tobytes()

    raise TypeError(
        "packet data must be bytes, bytearray, or memoryview"
    )


__all__ = [
    "DIRECTION_CONTROLLER_TO_HOST",
    "DIRECTION_HOST_TO_CONTROLLER",
    "DIRECTION_RX",
    "DIRECTION_TX",
    "DIRECTION_UNKNOWN",
    "SMPPDU",
    "SMPTraceAnalyzer",
    "SMPTraceError",
    "SMPTraceRecord",
    "SMPTraceReport",
    "SMPParseErrorRecord",
    "SMP_COMMAND_NAMES",
    "SMP_FAILURE_REASON_NAMES",
    "SMP_PAIRING_CONFIRM",
    "SMP_PAIRING_DHKEY_CHECK",
    "SMP_PAIRING_FAILED",
    "SMP_PAIRING_PUBLIC_KEY",
    "SMP_PAIRING_RANDOM",
    "SMP_PAIRING_REQUEST",
    "SMP_PAIRING_RESPONSE",
    "SMP_SECURITY_REQUEST",
    "classify_outcome",
    "decode_smp_fields",
    "format_wire_bd_addr",
    "normalize_direction",
    "parse_smp_pdu",
    "report_from_packets",
]
