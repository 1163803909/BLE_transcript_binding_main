# src/hci/acl_l2cap.py

"""
Encoding and decoding helpers for Bluetooth HCI ACL and L2CAP packets.

Packet layout used by this module:

    H4 ACL packet
    ├── packet type: 1 byte, 0x02
    ├── handle and flags: 2 bytes, little-endian
    ├── ACL data length: 2 bytes, little-endian
    └── ACL payload
        └── L2CAP Basic Frame
            ├── L2CAP payload length: 2 bytes, little-endian
            ├── channel ID: 2 bytes, little-endian
            └── L2CAP payload

For Bluetooth LE Security Manager Protocol traffic, the fixed L2CAP
channel ID is 0x0006.

This module only builds and parses individual packets. It does not:

* discover connection handles;
* perform ACL fragmentation;
* reassemble fragmented ACL packets;
* verify that a connection handle belongs to a particular peer;
* send packets to a controller.

Callers must obtain the connection handle from a successfully parsed
LE Connection Complete or LE Enhanced Connection Complete event.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


# H4 packet type for HCI ACL Data packets.
H4_ACL_PACKET_TYPE: Final[int] = 0x02

# HCI ACL header length, excluding the optional H4 packet type.
HCI_ACL_HEADER_LENGTH: Final[int] = 4

# H4 packet type plus HCI ACL header.
H4_ACL_HEADER_LENGTH: Final[int] = 5

# L2CAP Basic Frame header length.
L2CAP_HEADER_LENGTH: Final[int] = 4

# Fixed L2CAP Channel IDs.
L2CAP_CID_ATT: Final[int] = 0x0004
L2CAP_CID_LE_SIGNALING: Final[int] = 0x0005
L2CAP_CID_SMP: Final[int] = 0x0006
L2CAP_CID_SMP_BR_EDR: Final[int] = 0x0007

# ACL connection handle occupies 12 bits.
HCI_ACL_HANDLE_MASK: Final[int] = 0x0FFF

# Packet Boundary flag occupies bits 12 and 13.
HCI_ACL_PB_SHIFT: Final[int] = 12
HCI_ACL_PB_MASK: Final[int] = 0x03

# Broadcast flag occupies bits 14 and 15.
HCI_ACL_BC_SHIFT: Final[int] = 14
HCI_ACL_BC_MASK: Final[int] = 0x03

# Packet Boundary flag values.
#
# The precise interpretation and permitted values depend on packet
# direction and controller capabilities. These names describe their
# common use for host-to-controller ACL traffic.
PB_FIRST_NON_FLUSHABLE: Final[int] = 0b00
PB_CONTINUATION: Final[int] = 0b01
PB_FIRST_AUTOMATICALLY_FLUSHABLE: Final[int] = 0b10
PB_COMPLETE: Final[int] = 0b11

# Broadcast flag values.
BC_POINT_TO_POINT: Final[int] = 0b00
BC_ACTIVE_BROADCAST: Final[int] = 0b01
BC_PICONET_BROADCAST: Final[int] = 0b10

MAX_UINT16: Final[int] = 0xFFFF
MAX_CONNECTION_HANDLE: Final[int] = 0x0FFF

# A complete L2CAP frame carried in one ACL packet has a four-byte
# L2CAP header, so its payload cannot consume the entire uint16 ACL
# data-length range.
MAX_UNFRAGMENTED_L2CAP_PAYLOAD: Final[int] = (
    MAX_UINT16 - L2CAP_HEADER_LENGTH
)


class PacketFormatError(ValueError):
    """Base exception for malformed packet data."""


class HCIACLFormatError(PacketFormatError):
    """Raised when an HCI ACL packet is malformed."""


class L2CAPFormatError(PacketFormatError):
    """Raised when an L2CAP Basic Frame is malformed."""


class FragmentedPacketError(PacketFormatError):
    """
    Raised when an operation requires a complete L2CAP frame but receives
    an ACL fragment.
    """


@dataclass(frozen=True, slots=True)
class L2CAPFrame:
    """A parsed L2CAP Basic Frame."""

    cid: int
    payload: bytes
    declared_length: int
    raw: bytes
    trailing_data: bytes = b""

    @property
    def payload_length(self) -> int:
        """Return the actual payload length."""

        return len(self.payload)

    @property
    def is_smp(self) -> bool:
        """Return whether this frame uses the LE SMP fixed channel."""

        return self.cid == L2CAP_CID_SMP

    def to_bytes(self) -> bytes:
        """Return the frame bytes without ignored trailing data."""

        return self.raw

    def __bytes__(self) -> bytes:
        return self.to_bytes()


@dataclass(frozen=True, slots=True)
class HCIACLPacket:
    """A parsed HCI ACL Data packet."""

    handle: int
    pb_flag: int
    bc_flag: int
    payload: bytes
    declared_length: int
    raw: bytes
    has_h4: bool
    trailing_data: bytes = b""

    @property
    def connection_handle(self) -> int:
        """Alias for the 12-bit ACL connection handle."""

        return self.handle

    @property
    def data_length(self) -> int:
        """Return the actual ACL payload length."""

        return len(self.payload)

    @property
    def is_continuation(self) -> bool:
        """Return whether this is an ACL continuation fragment."""

        return self.pb_flag == PB_CONTINUATION

    @property
    def starts_l2cap_frame(self) -> bool:
        """
        Return whether the PB flag indicates the start of an L2CAP frame.

        PB_COMPLETE is included for completeness, though its exact use
        depends on the transport and packet direction.
        """

        return self.pb_flag in {
            PB_FIRST_NON_FLUSHABLE,
            PB_FIRST_AUTOMATICALLY_FLUSHABLE,
            PB_COMPLETE,
        }

    def to_bytes(self) -> bytes:
        """Return the parsed packet without ignored trailing data."""

        return self.raw

    def __bytes__(self) -> bytes:
        return self.to_bytes()


def build_l2cap_frame(
    cid: int,
    payload: bytes | bytearray | memoryview,
) -> bytes:
    """
    Build one L2CAP Basic Frame.

    The returned value contains the four-byte L2CAP header followed by the
    payload. It does not contain an HCI ACL header or H4 packet type.

    Args:
        cid:
            16-bit L2CAP Channel ID. SMP over LE uses ``0x0006``.
        payload:
            L2CAP channel payload.

    Raises:
        TypeError:
            If an argument has an unsupported type.
        ValueError:
            If the CID or payload length is outside the representable range.
    """

    cid_value = _validate_uint(
        "cid",
        cid,
        maximum=MAX_UINT16,
    )
    payload_bytes = _as_bytes(
        "payload",
        payload,
    )

    if len(payload_bytes) > MAX_UINT16:
        raise ValueError(
            "L2CAP payload is too large: "
            f"{len(payload_bytes)} bytes; maximum is {MAX_UINT16}"
        )

    return (
        len(payload_bytes).to_bytes(
            2,
            byteorder="little",
            signed=False,
        )
        + cid_value.to_bytes(
            2,
            byteorder="little",
            signed=False,
        )
        + payload_bytes
    )


def parse_l2cap_frame(
    raw: bytes | bytearray | memoryview,
    *,
    strict: bool = True,
) -> L2CAPFrame:
    """
    Parse one L2CAP Basic Frame.

    Args:
        raw:
            L2CAP header and payload, without an HCI ACL header.
        strict:
            If true, reject bytes after the declared L2CAP payload. If false,
            expose them through ``L2CAPFrame.trailing_data``.

    Raises:
        L2CAPFormatError:
            If the frame is truncated or has unexpected trailing data.
    """

    packet = _as_bytes("raw", raw)

    if len(packet) < L2CAP_HEADER_LENGTH:
        raise L2CAPFormatError(
            "truncated L2CAP header: "
            f"received {len(packet)} bytes, "
            f"need at least {L2CAP_HEADER_LENGTH}"
        )

    declared_length = int.from_bytes(
        packet[0:2],
        byteorder="little",
        signed=False,
    )
    cid = int.from_bytes(
        packet[2:4],
        byteorder="little",
        signed=False,
    )

    expected_length = L2CAP_HEADER_LENGTH + declared_length

    if len(packet) < expected_length:
        actual_payload_length = (
            len(packet) - L2CAP_HEADER_LENGTH
        )
        raise L2CAPFormatError(
            "truncated L2CAP payload: "
            f"header declares {declared_length} bytes, "
            f"but only {actual_payload_length} bytes are present"
        )

    trailing_data = packet[expected_length:]

    if strict and trailing_data:
        raise L2CAPFormatError(
            "unexpected data after L2CAP frame: "
            f"{len(trailing_data)} trailing bytes"
        )

    payload = packet[
        L2CAP_HEADER_LENGTH:expected_length
    ]

    return L2CAPFrame(
        cid=cid,
        payload=payload,
        declared_length=declared_length,
        raw=packet[:expected_length],
        trailing_data=trailing_data,
    )


def build_hci_acl_packet(
    connection_handle: int,
    payload: bytes | bytearray | memoryview,
    pb_flag: int = PB_FIRST_NON_FLUSHABLE,
    bc_flag: int = BC_POINT_TO_POINT,
    *,
    include_h4: bool = True,
) -> bytes:
    """
    Build one HCI ACL Data packet.

    Args:
        connection_handle:
            Active 12-bit HCI ACL connection handle.
        payload:
            ACL payload. For an initial SMP packet, this is normally a
            complete L2CAP Basic Frame.
        pb_flag:
            Two-bit Packet Boundary flag.
        bc_flag:
            Two-bit Broadcast flag.
        include_h4:
            Prefix the packet with H4 packet type ``0x02``. This is enabled
            by default because raw HCI user-channel and H4 logs commonly
            represent ACL packets with the packet type prefix.

    Returns:
        Encoded HCI ACL packet.

    Raises:
        TypeError:
            If an argument has an unsupported type.
        ValueError:
            If a field or payload is outside its permitted range.
    """

    handle = _validate_uint(
        "connection_handle",
        connection_handle,
        maximum=MAX_CONNECTION_HANDLE,
    )
    pb = _validate_uint(
        "pb_flag",
        pb_flag,
        maximum=HCI_ACL_PB_MASK,
    )
    bc = _validate_uint(
        "bc_flag",
        bc_flag,
        maximum=HCI_ACL_BC_MASK,
    )
    acl_payload = _as_bytes(
        "payload",
        payload,
    )

    if not isinstance(include_h4, bool):
        raise TypeError("include_h4 must be a bool")

    if len(acl_payload) > MAX_UINT16:
        raise ValueError(
            "HCI ACL payload is too large: "
            f"{len(acl_payload)} bytes; maximum is {MAX_UINT16}"
        )

    handle_and_flags = (
        handle
        | (pb << HCI_ACL_PB_SHIFT)
        | (bc << HCI_ACL_BC_SHIFT)
    )

    header = (
        handle_and_flags.to_bytes(
            2,
            byteorder="little",
            signed=False,
        )
        + len(acl_payload).to_bytes(
            2,
            byteorder="little",
            signed=False,
        )
    )

    if include_h4:
        return bytes((H4_ACL_PACKET_TYPE,)) + header + acl_payload

    return header + acl_payload


def parse_hci_acl_packet(
    raw: bytes | bytearray | memoryview,
    *,
    has_h4: bool = True,
    strict: bool = True,
) -> HCIACLPacket:
    """
    Parse one HCI ACL Data packet.

    Args:
        raw:
            HCI ACL packet bytes.
        has_h4:
            Whether ``raw`` starts with the H4 packet type byte. This argument
            is explicit because automatically detecting H4 is ambiguous when
            a non-H4 ACL packet's first handle byte happens to be ``0x02``.
        strict:
            If true, reject bytes after the declared ACL payload. If false,
            expose them through ``HCIACLPacket.trailing_data``.

    Raises:
        HCIACLFormatError:
            If the packet type is wrong, the header is truncated, the payload
            is truncated, or strict mode finds trailing bytes.
    """

    packet = _as_bytes("raw", raw)

    if not isinstance(has_h4, bool):
        raise TypeError("has_h4 must be a bool")

    if not isinstance(strict, bool):
        raise TypeError("strict must be a bool")

    offset = 0

    if has_h4:
        if not packet:
            raise HCIACLFormatError(
                "empty packet; expected H4 ACL packet type 0x02"
            )

        packet_type = packet[0]

        if packet_type != H4_ACL_PACKET_TYPE:
            raise HCIACLFormatError(
                "unexpected H4 packet type: "
                f"0x{packet_type:02x}; expected "
                f"0x{H4_ACL_PACKET_TYPE:02x}"
            )

        offset = 1

    available_header_bytes = len(packet) - offset

    if available_header_bytes < HCI_ACL_HEADER_LENGTH:
        raise HCIACLFormatError(
            "truncated HCI ACL header: "
            f"received {available_header_bytes} header/data bytes, "
            f"need at least {HCI_ACL_HEADER_LENGTH}"
        )

    handle_and_flags = int.from_bytes(
        packet[offset : offset + 2],
        byteorder="little",
        signed=False,
    )
    declared_length = int.from_bytes(
        packet[offset + 2 : offset + 4],
        byteorder="little",
        signed=False,
    )

    handle = handle_and_flags & HCI_ACL_HANDLE_MASK
    pb_flag = (
        handle_and_flags >> HCI_ACL_PB_SHIFT
    ) & HCI_ACL_PB_MASK
    bc_flag = (
        handle_and_flags >> HCI_ACL_BC_SHIFT
    ) & HCI_ACL_BC_MASK

    payload_start = offset + HCI_ACL_HEADER_LENGTH
    expected_length = payload_start + declared_length

    if len(packet) < expected_length:
        actual_payload_length = len(packet) - payload_start
        raise HCIACLFormatError(
            "truncated HCI ACL payload: "
            f"header declares {declared_length} bytes, "
            f"but only {actual_payload_length} bytes are present"
        )

    trailing_data = packet[expected_length:]

    if strict and trailing_data:
        raise HCIACLFormatError(
            "unexpected data after HCI ACL packet: "
            f"{len(trailing_data)} trailing bytes"
        )

    payload = packet[payload_start:expected_length]

    return HCIACLPacket(
        handle=handle,
        pb_flag=pb_flag,
        bc_flag=bc_flag,
        payload=payload,
        declared_length=declared_length,
        raw=packet[:expected_length],
        has_h4=has_h4,
        trailing_data=trailing_data,
    )


def build_smp_acl_packet(
    connection_handle: int,
    smp_pdu: bytes | bytearray | memoryview,
    *,
    pb_flag: int = PB_FIRST_NON_FLUSHABLE,
    bc_flag: int = BC_POINT_TO_POINT,
    include_h4: bool = True,
) -> bytes:
    """
    Wrap one SMP PDU in L2CAP and HCI ACL headers.

    The function only performs deterministic byte encoding. It does not verify
    that the handle is active or belongs to an authorised peer.

    SMP PDUs must contain at least a one-byte SMP command code. Fragmentation
    is intentionally unsupported; the whole L2CAP frame must fit in one ACL
    packet.
    """

    pdu = _as_bytes(
        "smp_pdu",
        smp_pdu,
    )

    if not pdu:
        raise ValueError(
            "smp_pdu must contain at least an SMP command code"
        )

    if len(pdu) > MAX_UNFRAGMENTED_L2CAP_PAYLOAD:
        raise ValueError(
            "SMP PDU is too large for one unfragmented HCI ACL packet: "
            f"{len(pdu)} bytes; maximum is "
            f"{MAX_UNFRAGMENTED_L2CAP_PAYLOAD}"
        )

    l2cap_frame = build_l2cap_frame(
        L2CAP_CID_SMP,
        pdu,
    )

    return build_hci_acl_packet(
        connection_handle,
        l2cap_frame,
        pb_flag=pb_flag,
        bc_flag=bc_flag,
        include_h4=include_h4,
    )


def extract_l2cap_frame(
    raw_hci_packet: bytes | bytearray | memoryview,
    *,
    has_h4: bool = True,
    strict: bool = True,
) -> L2CAPFrame:
    """
    Extract a complete L2CAP frame from one HCI ACL packet.

    ACL continuation packets cannot be decoded independently and cause
    ``FragmentedPacketError``. An initial packet containing only part of an
    L2CAP frame causes ``FragmentedPacketError`` as well.

    This function does not perform ACL reassembly.
    """

    acl_packet = parse_hci_acl_packet(
        raw_hci_packet,
        has_h4=has_h4,
        strict=strict,
    )

    if acl_packet.is_continuation:
        raise FragmentedPacketError(
            "ACL packet is a continuation fragment and cannot be "
            "decoded without reassembly"
        )

    try:
        return parse_l2cap_frame(
            acl_packet.payload,
            strict=strict,
        )
    except L2CAPFormatError as exc:
        if _looks_like_incomplete_l2cap_frame(
            acl_packet.payload
        ):
            raise FragmentedPacketError(
                "ACL packet contains only the beginning of an L2CAP "
                "frame; ACL reassembly is required"
            ) from exc

        raise


def extract_smp_pdu(
    raw_hci_packet: bytes | bytearray | memoryview,
    *,
    has_h4: bool = True,
    strict: bool = True,
) -> bytes | None:
    """
    Extract an SMP PDU from a complete HCI ACL packet.

    Returns:
        The SMP PDU if the L2CAP CID is ``0x0006``; otherwise ``None``.

    Raises:
        HCIACLFormatError:
            If the HCI ACL packet is malformed.
        L2CAPFormatError:
            If the L2CAP frame is malformed.
        FragmentedPacketError:
            If ACL fragmentation/reassembly is required.
    """

    l2cap_frame = extract_l2cap_frame(
        raw_hci_packet,
        has_h4=has_h4,
        strict=strict,
    )

    if l2cap_frame.cid != L2CAP_CID_SMP:
        return None

    return l2cap_frame.payload


def describe_hci_acl_packet(
    raw_hci_packet: bytes | bytearray | memoryview,
    *,
    has_h4: bool = True,
    strict: bool = True,
) -> dict[str, object]:
    """
    Parse an ACL packet and return a JSON-serialisable description.

    This is useful when writing exact injected packets to JSONL artifacts.
    """

    acl = parse_hci_acl_packet(
        raw_hci_packet,
        has_h4=has_h4,
        strict=strict,
    )

    result: dict[str, object] = {
        "has_h4": acl.has_h4,
        "connection_handle": acl.connection_handle,
        "connection_handle_hex": (
            f"0x{acl.connection_handle:03x}"
        ),
        "pb_flag": acl.pb_flag,
        "bc_flag": acl.bc_flag,
        "acl_data_length": acl.data_length,
        "acl_payload_hex": acl.payload.hex(),
        "raw_hex": acl.raw.hex(),
    }

    if acl.is_continuation:
        result["fragment"] = "continuation"
        result["l2cap"] = None
        return result

    try:
        l2cap = parse_l2cap_frame(
            acl.payload,
            strict=strict,
        )
    except L2CAPFormatError as exc:
        result["l2cap"] = None
        result["l2cap_error"] = str(exc)
        return result

    result["fragment"] = "start_or_complete"
    result["l2cap"] = {
        "cid": l2cap.cid,
        "cid_hex": f"0x{l2cap.cid:04x}",
        "payload_length": l2cap.payload_length,
        "payload_hex": l2cap.payload.hex(),
        "is_smp": l2cap.is_smp,
    }

    if l2cap.is_smp and l2cap.payload:
        result["smp"] = {
            "command_code": l2cap.payload[0],
            "command_code_hex": (
                f"0x{l2cap.payload[0]:02x}"
            ),
            "pdu_hex": l2cap.payload.hex(),
        }
    elif l2cap.is_smp:
        result["smp"] = {
            "command_code": None,
            "command_code_hex": None,
            "pdu_hex": "",
            "error": "empty SMP PDU",
        }

    return result


def _looks_like_incomplete_l2cap_frame(
    payload: bytes,
) -> bool:
    if len(payload) < L2CAP_HEADER_LENGTH:
        return True

    declared_length = int.from_bytes(
        payload[0:2],
        byteorder="little",
        signed=False,
    )
    expected_length = (
        L2CAP_HEADER_LENGTH + declared_length
    )

    return len(payload) < expected_length


def _validate_uint(
    name: str,
    value: int,
    *,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{name} must be an integer"
        )

    if value < 0 or value > maximum:
        raise ValueError(
            f"{name} must be between 0 and "
            f"{maximum} inclusive; received {value}"
        )

    return value


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
    "BC_ACTIVE_BROADCAST",
    "BC_PICONET_BROADCAST",
    "BC_POINT_TO_POINT",
    "FragmentedPacketError",
    "H4_ACL_HEADER_LENGTH",
    "H4_ACL_PACKET_TYPE",
    "HCIACLFormatError",
    "HCIACLPacket",
    "HCI_ACL_HEADER_LENGTH",
    "L2CAPFormatError",
    "L2CAPFrame",
    "L2CAP_CID_ATT",
    "L2CAP_CID_LE_SIGNALING",
    "L2CAP_CID_SMP",
    "L2CAP_CID_SMP_BR_EDR",
    "L2CAP_HEADER_LENGTH",
    "MAX_CONNECTION_HANDLE",
    "MAX_UNFRAGMENTED_L2CAP_PAYLOAD",
    "PB_COMPLETE",
    "PB_CONTINUATION",
    "PB_FIRST_AUTOMATICALLY_FLUSHABLE",
    "PB_FIRST_NON_FLUSHABLE",
    "PacketFormatError",
    "build_hci_acl_packet",
    "build_l2cap_frame",
    "build_smp_acl_packet",
    "describe_hci_acl_packet",
    "extract_l2cap_frame",
    "extract_smp_pdu",
    "parse_hci_acl_packet",
    "parse_l2cap_frame",
]
