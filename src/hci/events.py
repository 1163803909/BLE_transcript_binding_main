# src/hci/events.py

"""
Bluetooth HCI Event parsing helpers.

Supported event types:

* HCI Command Complete                 0x0E
* HCI Command Status                   0x0F
* HCI Disconnection Complete           0x05
* HCI LE Meta Event                    0x3E
* LE Connection Complete               0x01
* LE Enhanced Connection Complete      0x0A

Supported input formats:

1. H4 HCI Event packet:

       04 <event_code> <parameter_length> <parameters...>

2. HCI Event packet without H4 transport byte:

       <event_code> <parameter_length> <parameters...>

The parser does not maintain connection state. Use the parsed
LEConnectionComplete or LEEnhancedConnectionComplete object to update a
separate connection registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


# H4 packet type for HCI Event packets.
H4_EVENT_PACKET_TYPE: Final[int] = 0x04

# HCI event codes.
HCI_EVENT_DISCONNECTION_COMPLETE: Final[int] = 0x05
HCI_EVENT_COMMAND_COMPLETE: Final[int] = 0x0E
HCI_EVENT_COMMAND_STATUS: Final[int] = 0x0F
HCI_EVENT_LE_META: Final[int] = 0x3E

# LE Meta Event subevent codes.
LE_SUBEVENT_CONNECTION_COMPLETE: Final[int] = 0x01
LE_SUBEVENT_ENHANCED_CONNECTION_COMPLETE: Final[int] = 0x0A

# HCI event header lengths.
HCI_EVENT_HEADER_LENGTH: Final[int] = 2
H4_EVENT_HEADER_LENGTH: Final[int] = 3

# Bluetooth LE address length.
BD_ADDR_LENGTH: Final[int] = 6

# LE address types.
LE_ADDR_TYPE_PUBLIC: Final[int] = 0x00
LE_ADDR_TYPE_RANDOM: Final[int] = 0x01
LE_ADDR_TYPE_PUBLIC_IDENTITY: Final[int] = 0x02
LE_ADDR_TYPE_RANDOM_IDENTITY: Final[int] = 0x03
LE_ADDR_TYPE_ANONYMOUS: Final[int] = 0xFF

# LE connection roles.
LE_ROLE_CENTRAL: Final[int] = 0x00
LE_ROLE_PERIPHERAL: Final[int] = 0x01


class HCIEventFormatError(ValueError):
    """Raised when an HCI event is malformed."""


@dataclass(frozen=True, slots=True)
class HCIEvent:
    """Generic parsed HCI event."""

    event_code: int
    parameters: bytes
    declared_parameter_length: int
    raw: bytes
    has_h4: bool
    trailing_data: bytes = b""

    @property
    def parameter_length(self) -> int:
        """Return the actual parameter length."""

        return len(self.parameters)

    @property
    def is_le_meta(self) -> bool:
        """Return whether this is an LE Meta Event."""

        return self.event_code == HCI_EVENT_LE_META

    def to_bytes(self) -> bytes:
        """Return the event without ignored trailing bytes."""

        return self.raw

    def __bytes__(self) -> bytes:
        return self.to_bytes()


@dataclass(frozen=True, slots=True)
class LEMetaEvent:
    """Parsed LE Meta Event."""

    subevent_code: int
    data: bytes
    raw: bytes
    declared_data_length: int
    trailing_data: bytes = b""

    @property
    def data_length(self) -> int:
        """Return the actual subevent data length."""

        return len(self.data)

    def to_bytes(self) -> bytes:
        """Return subevent code plus subevent data."""

        return self.raw

    def __bytes__(self) -> bytes:
        return self.to_bytes()


@dataclass(frozen=True, slots=True)
class LEConnectionComplete:
    """
    LE Legacy Connection Complete event.

    Wire format after the LE subevent code:

        Status                  1 byte
        Connection_Handle       2 bytes
        Role                    1 byte
        Peer_Address_Type       1 byte
        Peer_Address            6 bytes
        Connection_Interval     2 bytes
        Peripheral_Latency      2 bytes
        Supervision_Timeout     2 bytes
        Central_Clock_Accuracy   1 byte
    """

    status: int
    connection_handle: int
    role: int
    peer_address_type: int
    peer_address: str
    connection_interval: int
    peripheral_latency: int
    supervision_timeout: int
    central_clock_accuracy: int
    raw: bytes

    @property
    def succeeded(self) -> bool:
        """Return whether the controller reported success."""

        return self.status == 0

    @property
    def role_name(self) -> str:
        """Return a human-readable LE role."""

        return role_name(self.role)

    @property
    def peer_address_type_name(self) -> str:
        """Return a human-readable LE address type."""

        return address_type_name(self.peer_address_type)

    @property
    def connection_handle_hex(self) -> str:
        """Return the handle in canonical hexadecimal form."""

        return f"0x{self.connection_handle:03x}"

    @property
    def connection_interval_ms(self) -> float:
        """
        Return the connection interval in milliseconds.

        LE connection interval units are 1.25 ms.
        """

        return self.connection_interval * 1.25

    @property
    def supervision_timeout_ms(self) -> float:
        """
        Return the supervision timeout in milliseconds.

        LE supervision timeout units are 10 ms.
        """

        return self.supervision_timeout * 10.0


@dataclass(frozen=True, slots=True)
class LEEnhancedConnectionComplete:
    """
    LE Enhanced Connection Complete event.

    Wire format after the LE subevent code:

        Status                         1 byte
        Connection_Handle              2 bytes
        Role                           1 byte
        Peer_Address_Type               1 byte
        Peer_Address                    6 bytes
        Local_Resolvable_Private_Address 6 bytes
        Peer_Resolvable_Private_Address  6 bytes
        Connection_Interval             2 bytes
        Peripheral_Latency              2 bytes
        Supervision_Timeout             2 bytes
        Central_Clock_Accuracy           1 byte
    """

    status: int
    connection_handle: int
    role: int
    peer_address_type: int
    peer_address: str
    local_resolvable_private_address: str
    peer_resolvable_private_address: str
    connection_interval: int
    peripheral_latency: int
    supervision_timeout: int
    central_clock_accuracy: int
    raw: bytes

    @property
    def succeeded(self) -> bool:
        """Return whether the controller reported success."""

        return self.status == 0

    @property
    def role_name(self) -> str:
        """Return a human-readable LE role."""

        return role_name(self.role)

    @property
    def peer_address_type_name(self) -> str:
        """Return a human-readable LE address type."""

        return address_type_name(self.peer_address_type)

    @property
    def connection_handle_hex(self) -> str:
        """Return the handle in canonical hexadecimal form."""

        return f"0x{self.connection_handle:03x}"

    @property
    def connection_interval_ms(self) -> float:
        """Return the connection interval in milliseconds."""

        return self.connection_interval * 1.25

    @property
    def supervision_timeout_ms(self) -> float:
        """Return the supervision timeout in milliseconds."""

        return self.supervision_timeout * 10.0


@dataclass(frozen=True, slots=True)
class DisconnectionComplete:
    """
    HCI Disconnection Complete event.

    Wire format:

        Status              1 byte
        Connection_Handle   2 bytes
        Reason              1 byte
    """

    status: int
    connection_handle: int
    reason: int
    raw: bytes

    @property
    def succeeded(self) -> bool:
        """Return whether the controller reported successful processing."""

        return self.status == 0

    @property
    def connection_handle_hex(self) -> str:
        """Return the handle in canonical hexadecimal form."""

        return f"0x{self.connection_handle:03x}"

    @property
    def reason_name(self) -> str:
        """Return a common HCI disconnection reason name."""

        return disconnection_reason_name(self.reason)


@dataclass(frozen=True, slots=True)
class CommandComplete:
    """HCI Command Complete event."""

    num_hci_command_packets: int
    opcode: int
    return_parameters: bytes
    raw: bytes


@dataclass(frozen=True, slots=True)
class CommandStatus:
    """HCI Command Status event."""

    status: int
    num_hci_command_packets: int
    opcode: int
    raw: bytes


def parse_hci_event(
    raw: bytes | bytearray | memoryview,
    *,
    has_h4: bool = True,
    strict: bool = True,
) -> HCIEvent:
    """
    Parse one HCI Event packet.

    Args:
        raw:
            HCI event bytes.
        has_h4:
            Whether the first byte must be H4 event type 0x04.
        strict:
            Reject trailing bytes after the declared parameter area.

    Returns:
        Generic HCIEvent.

    Raises:
        HCIEventFormatError:
            If the packet is truncated, has an invalid H4 type, or has
            unexpected trailing data in strict mode.
    """

    packet = _as_bytes("raw", raw)

    if not isinstance(has_h4, bool):
        raise TypeError("has_h4 must be a bool")

    if not isinstance(strict, bool):
        raise TypeError("strict must be a bool")

    offset = 0

    if has_h4:
        if not packet:
            raise HCIEventFormatError(
                "empty packet; expected H4 event packet type 0x04"
            )

        if packet[0] != H4_EVENT_PACKET_TYPE:
            raise HCIEventFormatError(
                "unexpected H4 packet type: "
                f"0x{packet[0]:02x}; expected "
                f"0x{H4_EVENT_PACKET_TYPE:02x}"
            )

        offset = 1

    if len(packet) - offset < HCI_EVENT_HEADER_LENGTH:
        raise HCIEventFormatError(
            "truncated HCI event header: "
            f"need {HCI_EVENT_HEADER_LENGTH} bytes"
        )

    event_code = packet[offset]
    declared_parameter_length = packet[offset + 1]

    parameter_start = offset + HCI_EVENT_HEADER_LENGTH
    expected_length = (
        parameter_start + declared_parameter_length
    )

    if len(packet) < expected_length:
        actual_length = len(packet) - parameter_start
        raise HCIEventFormatError(
            "truncated HCI event parameters: "
            f"header declares {declared_parameter_length} bytes, "
            f"but only {actual_length} bytes are present"
        )

    trailing_data = packet[expected_length:]

    if strict and trailing_data:
        raise HCIEventFormatError(
            "unexpected data after HCI event: "
            f"{len(trailing_data)} trailing bytes"
        )

    return HCIEvent(
        event_code=event_code,
        parameters=packet[
            parameter_start:expected_length
        ],
        declared_parameter_length=declared_parameter_length,
        raw=packet[:expected_length],
        has_h4=has_h4,
        trailing_data=trailing_data,
    )


def parse_known_hci_event(
    raw: bytes | bytearray | memoryview,
    *,
    has_h4: bool = True,
    strict: bool = True,
) -> HCIEvent | LEMetaEvent | LEConnectionComplete | (
    LEEnhancedConnectionComplete
) | DisconnectionComplete | CommandComplete | CommandStatus:
    """
    Parse an HCI event and decode supported event types.

    Unknown HCI event codes are returned as generic HCIEvent objects.
    Unknown LE Meta subevents are returned as LEMetaEvent objects.
    """

    event = parse_hci_event(
        raw,
        has_h4=has_h4,
        strict=strict,
    )

    if event.event_code == HCI_EVENT_LE_META:
        meta = parse_le_meta_event(
            event.parameters,
            strict=strict,
        )

        if (
            meta.subevent_code
            == LE_SUBEVENT_CONNECTION_COMPLETE
        ):
            return parse_le_connection_complete(
                meta,
                strict=strict,
            )

        if (
            meta.subevent_code
            == LE_SUBEVENT_ENHANCED_CONNECTION_COMPLETE
        ):
            return parse_le_enhanced_connection_complete(
                meta,
                strict=strict,
            )

        return meta

    if (
        event.event_code
        == HCI_EVENT_DISCONNECTION_COMPLETE
    ):
        return parse_disconnection_complete(
            event.parameters,
            strict=strict,
        )

    if event.event_code == HCI_EVENT_COMMAND_COMPLETE:
        return parse_command_complete(
            event.parameters,
            strict=strict,
        )

    if event.event_code == HCI_EVENT_COMMAND_STATUS:
        return parse_command_status(
            event.parameters,
            strict=strict,
        )

    return event


def parse_le_meta_event(
    parameters: bytes | bytearray | memoryview,
    *,
    strict: bool = True,
) -> LEMetaEvent:
    """
    Parse LE Meta Event parameters.

    The first byte is the LE subevent code. The remaining bytes are the
    subevent-specific data.
    """

    data = _as_bytes("parameters", parameters)

    if not data:
        raise HCIEventFormatError(
            "LE Meta Event has no subevent code"
        )

    return LEMetaEvent(
        subevent_code=data[0],
        data=data[1:],
        raw=data,
        declared_data_length=len(data) - 1,
        trailing_data=b"",
    )


def parse_le_connection_complete(
    event: LEMetaEvent | bytes | bytearray | memoryview,
    *,
    strict: bool = True,
) -> LEConnectionComplete:
    """
    Parse LE Connection Complete.

    The input may be:

    * an LEMetaEvent with subevent code 0x01; or
    * raw bytes beginning with subevent code 0x01; or
    * the event data after the subevent code.

    For an LEMetaEvent, the subevent code is checked explicitly.
    """

    data, raw = _normalise_le_subevent_input(
        event,
        expected_subevent=LE_SUBEVENT_CONNECTION_COMPLETE,
    )

    # LE Connection Complete data length is 18 bytes.
    _require_length(
        "LE Connection Complete",
        data,
        18,
    )

    status = data[0]
    connection_handle = _u16(data, 1)
    role = data[3]
    peer_address_type = data[4]
    peer_address = format_bd_addr(
        data[5:11]
    )
    connection_interval = _u16(data, 11)
    peripheral_latency = _u16(data, 13)
    supervision_timeout = _u16(data, 15)
    central_clock_accuracy = data[17]

    trailing_data = data[18:]

    if strict and trailing_data:
        raise HCIEventFormatError(
            "unexpected bytes after LE Connection Complete: "
            f"{len(trailing_data)}"
        )

    return LEConnectionComplete(
        status=status,
        connection_handle=connection_handle,
        role=role,
        peer_address_type=peer_address_type,
        peer_address=peer_address,
        connection_interval=connection_interval,
        peripheral_latency=peripheral_latency,
        supervision_timeout=supervision_timeout,
        central_clock_accuracy=central_clock_accuracy,
        raw=raw,
    )


def parse_le_enhanced_connection_complete(
    event: LEMetaEvent | bytes | bytearray | memoryview,
    *,
    strict: bool = True,
) -> LEEnhancedConnectionComplete:
    """
    Parse LE Enhanced Connection Complete.

    The data after the subevent code is 30 bytes.
    """

    data, raw = _normalise_le_subevent_input(
        event,
        expected_subevent=(
            LE_SUBEVENT_ENHANCED_CONNECTION_COMPLETE
        ),
    )

    # LE Enhanced Connection Complete data length is 30 bytes.
    _require_length(
        "LE Enhanced Connection Complete",
        data,
        30,
    )

    status = data[0]
    connection_handle = _u16(data, 1)
    role = data[3]
    peer_address_type = data[4]
    peer_address = format_bd_addr(
        data[5:11]
    )
    local_rpa = format_bd_addr(
        data[11:17]
    )
    peer_rpa = format_bd_addr(
        data[17:23]
    )
    connection_interval = _u16(data, 23)
    peripheral_latency = _u16(data, 25)
    supervision_timeout = _u16(data, 27)
    central_clock_accuracy = data[29]

    trailing_data = data[30:]

    if strict and trailing_data:
        raise HCIEventFormatError(
            "unexpected bytes after LE Enhanced "
            "Connection Complete: "
            f"{len(trailing_data)}"
        )

    return LEEnhancedConnectionComplete(
        status=status,
        connection_handle=connection_handle,
        role=role,
        peer_address_type=peer_address_type,
        peer_address=peer_address,
        local_resolvable_private_address=local_rpa,
        peer_resolvable_private_address=peer_rpa,
        connection_interval=connection_interval,
        peripheral_latency=peripheral_latency,
        supervision_timeout=supervision_timeout,
        central_clock_accuracy=central_clock_accuracy,
        raw=raw,
    )


def parse_disconnection_complete(
    parameters: bytes | bytearray | memoryview,
    *,
    strict: bool = True,
) -> DisconnectionComplete:
    """Parse HCI Disconnection Complete parameters."""

    data = _as_bytes("parameters", parameters)

    _require_length(
        "Disconnection Complete",
        data,
        4,
    )

    trailing_data = data[4:]

    if strict and trailing_data:
        raise HCIEventFormatError(
            "unexpected bytes after Disconnection Complete: "
            f"{len(trailing_data)}"
        )

    return DisconnectionComplete(
        status=data[0],
        connection_handle=_u16(data, 1),
        reason=data[3],
        raw=data[:4],
    )


def parse_command_complete(
    parameters: bytes | bytearray | memoryview,
    *,
    strict: bool = True,
) -> CommandComplete:
    """Parse HCI Command Complete parameters."""

    data = _as_bytes("parameters", parameters)

    _require_length(
        "Command Complete",
        data,
        3,
    )

    trailing_data = data[3:]

    if strict and not trailing_data:
        # No error: return parameters may legally be empty.
        pass

    return CommandComplete(
        num_hci_command_packets=data[0],
        opcode=_u16(data, 1),
        return_parameters=trailing_data,
        raw=data,
    )


def parse_command_status(
    parameters: bytes | bytearray | memoryview,
    *,
    strict: bool = True,
) -> CommandStatus:
    """Parse HCI Command Status parameters."""

    data = _as_bytes("parameters", parameters)

    _require_length(
        "Command Status",
        data,
        4,
    )

    trailing_data = data[4:]

    if strict and trailing_data:
        raise HCIEventFormatError(
            "unexpected bytes after Command Status: "
            f"{len(trailing_data)}"
        )

    return CommandStatus(
        status=data[0],
        num_hci_command_packets=data[1],
        opcode=_u16(data, 2),
        raw=data[:4],
    )


def format_bd_addr(
    address: bytes | bytearray | memoryview,
) -> str:
    """
    Format a six-byte Bluetooth address.

    Bluetooth addresses are transmitted least-significant octet first.
    For example, wire bytes ``06 05 04 03 02 01`` become:

        01:02:03:04:05:06
    """

    raw = _as_bytes("address", address)

    if len(raw) != BD_ADDR_LENGTH:
        raise ValueError(
            "Bluetooth address must contain exactly "
            f"{BD_ADDR_LENGTH} bytes; got {len(raw)}"
        )

    return ":".join(
        f"{octet:02X}"
        for octet in reversed(raw)
    )


def address_type_name(address_type: int) -> str:
    """Return a readable LE address type name."""

    names = {
        LE_ADDR_TYPE_PUBLIC: "public",
        LE_ADDR_TYPE_RANDOM: "random",
        LE_ADDR_TYPE_PUBLIC_IDENTITY: (
            "public_identity"
        ),
        LE_ADDR_TYPE_RANDOM_IDENTITY: (
            "random_identity"
        ),
        LE_ADDR_TYPE_ANONYMOUS: "anonymous",
    }

    return names.get(
        address_type,
        f"unknown_0x{address_type:02x}",
    )


def role_name(role: int) -> str:
    """Return a readable LE role name."""

    names = {
        LE_ROLE_CENTRAL: "central",
        LE_ROLE_PERIPHERAL: "peripheral",
    }

    return names.get(
        role,
        f"unknown_0x{role:02x}",
    )


def disconnection_reason_name(reason: int) -> str:
    """Return a common HCI disconnection reason name."""

    names = {
        0x05: "authentication_failure",
        0x08: "connection_timeout",
        0x13: "remote_user_terminated_connection",
        0x14: "remote_low_resources",
        0x15: "remote_powering_off",
        0x16: "local_host_terminated_connection",
        0x1A: "unsupported_remote_feature",
        0x22: "ll_response_timeout",
        0x3B: "sync_connection_limit_to_a_device_exceeded",
    }

    return names.get(
        reason,
        f"unknown_0x{reason:02x}",
    )


def event_to_dict(
    event: HCIEvent
    | LEMetaEvent
    | LEConnectionComplete
    | LEEnhancedConnectionComplete
    | DisconnectionComplete
    | CommandComplete
    | CommandStatus,
) -> dict[str, object]:
    """
    Convert a parsed event to a JSON-serialisable dictionary.

    This is intended for packets.jsonl or hci_events.jsonl output.
    """

    if isinstance(event, HCIEvent):
        return {
            "event_type": "hci_event",
            "event_code": event.event_code,
            "event_code_hex": (
                f"0x{event.event_code:02x}"
            ),
            "parameter_length": event.parameter_length,
            "parameters_hex": event.parameters.hex(),
            "raw_hex": event.raw.hex(),
            "has_h4": event.has_h4,
        }

    if isinstance(event, LEMetaEvent):
        return {
            "event_type": "le_meta",
            "subevent_code": event.subevent_code,
            "subevent_code_hex": (
                f"0x{event.subevent_code:02x}"
            ),
            "data_length": event.data_length,
            "data_hex": event.data.hex(),
            "raw_hex": event.raw.hex(),
        }

    if isinstance(event, LEConnectionComplete):
        return {
            "event_type": "le_connection_complete",
            "status": event.status,
            "status_hex": f"0x{event.status:02x}",
            "succeeded": event.succeeded,
            "connection_handle": event.connection_handle,
            "connection_handle_hex": (
                event.connection_handle_hex
            ),
            "role": event.role,
            "role_name": event.role_name,
            "peer_address_type": (
                event.peer_address_type
            ),
            "peer_address_type_name": (
                event.peer_address_type_name
            ),
            "peer_address": event.peer_address,
            "connection_interval": (
                event.connection_interval
            ),
            "connection_interval_ms": (
                event.connection_interval_ms
            ),
            "peripheral_latency": (
                event.peripheral_latency
            ),
            "supervision_timeout": (
                event.supervision_timeout
            ),
            "supervision_timeout_ms": (
                event.supervision_timeout_ms
            ),
            "central_clock_accuracy": (
                event.central_clock_accuracy
            ),
            "raw_hex": event.raw.hex(),
        }

    if isinstance(event, LEEnhancedConnectionComplete):
        return {
            "event_type": (
                "le_enhanced_connection_complete"
            ),
            "status": event.status,
            "status_hex": f"0x{event.status:02x}",
            "succeeded": event.succeeded,
            "connection_handle": event.connection_handle,
            "connection_handle_hex": (
                event.connection_handle_hex
            ),
            "role": event.role,
            "role_name": event.role_name,
            "peer_address_type": (
                event.peer_address_type
            ),
            "peer_address_type_name": (
                event.peer_address_type_name
            ),
            "peer_address": event.peer_address,
            "local_resolvable_private_address": (
                event.local_resolvable_private_address
            ),
            "peer_resolvable_private_address": (
                event.peer_resolvable_private_address
            ),
            "connection_interval": (
                event.connection_interval
            ),
            "connection_interval_ms": (
                event.connection_interval_ms
            ),
            "peripheral_latency": (
                event.peripheral_latency
            ),
            "supervision_timeout": (
                event.supervision_timeout
            ),
            "supervision_timeout_ms": (
                event.supervision_timeout_ms
            ),
            "central_clock_accuracy": (
                event.central_clock_accuracy
            ),
            "raw_hex": event.raw.hex(),
        }

    if isinstance(event, DisconnectionComplete):
        return {
            "event_type": "disconnection_complete",
            "status": event.status,
            "status_hex": f"0x{event.status:02x}",
            "succeeded": event.succeeded,
            "connection_handle": event.connection_handle,
            "connection_handle_hex": (
                event.connection_handle_hex
            ),
            "reason": event.reason,
            "reason_hex": f"0x{event.reason:02x}",
            "reason_name": event.reason_name,
            "raw_hex": event.raw.hex(),
        }

    if isinstance(event, CommandComplete):
        return {
            "event_type": "command_complete",
            "num_hci_command_packets": (
                event.num_hci_command_packets
            ),
            "opcode": event.opcode,
            "opcode_hex": f"0x{event.opcode:04x}",
            "return_parameters_hex": (
                event.return_parameters.hex()
            ),
            "raw_hex": event.raw.hex(),
        }

    if isinstance(event, CommandStatus):
        return {
            "event_type": "command_status",
            "status": event.status,
            "status_hex": f"0x{event.status:02x}",
            "num_hci_command_packets": (
                event.num_hci_command_packets
            ),
            "opcode": event.opcode,
            "opcode_hex": f"0x{event.opcode:04x}",
            "raw_hex": event.raw.hex(),
        }

    raise TypeError(
        f"unsupported event type: {type(event)!r}"
    )


def _normalise_le_subevent_input(
    event: LEMetaEvent | bytes | bytearray | memoryview,
    *,
    expected_subevent: int,
) -> tuple[bytes, bytes]:
    if isinstance(event, LEMetaEvent):
        if event.subevent_code != expected_subevent:
            raise HCIEventFormatError(
                "unexpected LE subevent code: "
                f"0x{event.subevent_code:02x}; expected "
                f"0x{expected_subevent:02x}"
            )

        return event.data, event.raw

    data = _as_bytes("event", event)

    if data and data[0] == expected_subevent:
        return data[1:], data

    # Also accept data after the subevent byte.
    return data, bytes((expected_subevent,)) + data


def _require_length(
    name: str,
    data: bytes,
    minimum: int,
) -> None:
    if len(data) < minimum:
        raise HCIEventFormatError(
            f"truncated {name}: "
            f"received {len(data)} bytes, "
            f"need at least {minimum}"
        )


def _u16(data: bytes, offset: int) -> int:
    end = offset + 2

    if end > len(data):
        raise HCIEventFormatError(
            f"cannot read uint16 at offset {offset}"
        )

    return int.from_bytes(
        data[offset:end],
        byteorder="little",
        signed=False,
    )


def _as_bytes(
    name: str,
    value: bytes | bytearray | memoryview,
) -> bytes:
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, memoryview):
        return value.tobytes()

    raise TypeError(
        f"{name} must be bytes, bytearray, or memoryview"
    )


__all__ = [
    "BD_ADDR_LENGTH",
    "CommandComplete",
    "CommandStatus",
    "DisconnectionComplete",
    "HCIEvent",
    "HCIEventFormatError",
    "HCI_EVENT_COMMAND_COMPLETE",
    "HCI_EVENT_COMMAND_STATUS",
    "HCI_EVENT_DISCONNECTION_COMPLETE",
    "HCI_EVENT_LE_META",
    "HCI_EVENT_HEADER_LENGTH",
    "H4_EVENT_PACKET_TYPE",
    "H4_EVENT_HEADER_LENGTH",
    "LEConnectionComplete",
    "LEEnhancedConnectionComplete",
    "LEMetaEvent",
    "LE_ADDR_TYPE_ANONYMOUS",
    "LE_ADDR_TYPE_PUBLIC",
    "LE_ADDR_TYPE_PUBLIC_IDENTITY",
    "LE_ADDR_TYPE_RANDOM",
    "LE_ADDR_TYPE_RANDOM_IDENTITY",
    "LE_ROLE_CENTRAL",
    "LE_ROLE_PERIPHERAL",
    "LE_SUBEVENT_CONNECTION_COMPLETE",
    "LE_SUBEVENT_ENHANCED_CONNECTION_COMPLETE",
    "address_type_name",
    "disconnection_reason_name",
    "event_to_dict",
    "format_bd_addr",
    "parse_command_complete",
    "parse_command_status",
    "parse_disconnection_complete",
    "parse_hci_event",
    "parse_known_hci_event",
    "parse_le_connection_complete",
    "parse_le_enhanced_connection_complete",
    "parse_le_meta_event",
    "role_name",
]
