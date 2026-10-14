# src/hci/raw_socket.py

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
import errno
import select
import socket
import struct
import time
from typing import Iterable


# Linux Bluetooth socket constants. Some Python builds do not expose all of
# them, so numeric Linux UAPI fallbacks are provided.
AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
BTPROTO_HCI = getattr(socket, "BTPROTO_HCI", 1)

SOL_HCI = 0
HCI_DATA_DIR = 1
HCI_FILTER = 2
HCI_TIME_STAMP = 3

HCI_CHANNEL_RAW = 0
HCI_CHANNEL_USER = 1
HCI_CHANNEL_MONITOR = 2
HCI_CHANNEL_CONTROL = 3
HCI_CHANNEL_LOGGING = 4

HCI_COMMAND_PKT = 0x01
HCI_ACLDATA_PKT = 0x02
HCI_SCODATA_PKT = 0x03
HCI_EVENT_PKT = 0x04
HCI_ISODATA_PKT = 0x05
HCI_VENDOR_PKT = 0xFF

# HCI event codes commonly needed by an experiment runner.
EVT_INQUIRY_COMPLETE = 0x01
EVT_CONN_COMPLETE = 0x03
EVT_DISCONN_COMPLETE = 0x05
EVT_ENCRYPT_CHANGE = 0x08
EVT_CMD_COMPLETE = 0x0E
EVT_CMD_STATUS = 0x0F
EVT_NUM_COMP_PKTS = 0x13
EVT_ENCRYPT_KEY_REFRESH_COMPLETE = 0x30
EVT_LE_META_EVENT = 0x3E

# HCI Filter is:
#
#     struct hci_filter {
#         uint32_t type_mask;
#         uint32_t event_mask[2];
#         uint16_t opcode;
#     };
#
# Linux normally exposes a 16-byte structure because of trailing alignment.
_HCI_FILTER_STRUCT = struct.Struct("<IIIH2x")

_HCI_EVENT_HEADER = struct.Struct("<BB")
_HCI_ACL_HEADER = struct.Struct("<HH")
_HCI_COMMAND_HEADER = struct.Struct("<HB")
_HCI_SCO_HEADER = struct.Struct("<HB")
_HCI_ISO_HEADER = struct.Struct("<HH")

_MAX_HCI_PACKET_SIZE = 65535
_DEFAULT_RECEIVE_SIZE = 4096

_VALID_PACKET_TYPES = frozenset(
    {
        HCI_COMMAND_PKT,
        HCI_ACLDATA_PKT,
        HCI_SCODATA_PKT,
        HCI_EVENT_PKT,
        HCI_ISODATA_PKT,
        HCI_VENDOR_PKT,
    }
)


class HCISocketError(RuntimeError):
    """Base exception raised by this module."""


class HCISocketTimeout(TimeoutError, HCISocketError):
    """No HCI packet was available before the timeout expired."""


class HCISocketClosed(HCISocketError):
    """An operation was attempted on a closed HCI socket."""


class InvalidHCIPacket(ValueError):
    """The supplied or received data is not a valid framed HCI packet."""


@dataclass(frozen=True)
class HCIFilter:
    """
    Linux HCI socket filter.

    ``packet_type_mask`` uses bit ``1 << packet_type``.

    ``event_mask_low`` covers event codes 0 through 31.
    ``event_mask_high`` covers event codes 32 through 63.

    ``opcode`` is zero to accept every command opcode.
    """

    packet_type_mask: int
    event_mask_low: int
    event_mask_high: int
    opcode: int = 0

    def __post_init__(self) -> None:
        _validate_uint32(
            "packet_type_mask",
            self.packet_type_mask,
        )
        _validate_uint32(
            "event_mask_low",
            self.event_mask_low,
        )
        _validate_uint32(
            "event_mask_high",
            self.event_mask_high,
        )
        _validate_uint16("opcode", self.opcode)

    @classmethod
    def all_packets(cls) -> "HCIFilter":
        """
        Accept all packet types and all filterable event codes.
        """
        return cls(
            packet_type_mask=0xFFFFFFFF,
            event_mask_low=0xFFFFFFFF,
            event_mask_high=0xFFFFFFFF,
            opcode=0,
        )

    @classmethod
    def events_only(
        cls,
        event_codes: Iterable[int] | None = None,
        *,
        opcode: int = 0,
    ) -> "HCIFilter":
        """
        Construct an event-only filter.

        If ``event_codes`` is None, all event codes are accepted.
        """
        packet_mask = hci_packet_type_bit(HCI_EVENT_PKT)

        if event_codes is None:
            low = 0xFFFFFFFF
            high = 0xFFFFFFFF
        else:
            low, high = hci_event_mask(event_codes)

        return cls(
            packet_type_mask=packet_mask,
            event_mask_low=low,
            event_mask_high=high,
            opcode=opcode,
        )

    @classmethod
    def events_and_acl(
        cls,
        event_codes: Iterable[int] | None = None,
        *,
        opcode: int = 0,
    ) -> "HCIFilter":
        """
        Accept controller events and ACL data packets.
        """
        packet_mask = (
            hci_packet_type_bit(HCI_EVENT_PKT)
            | hci_packet_type_bit(HCI_ACLDATA_PKT)
        )

        if event_codes is None:
            low = 0xFFFFFFFF
            high = 0xFFFFFFFF
        else:
            low, high = hci_event_mask(event_codes)

        return cls(
            packet_type_mask=packet_mask,
            event_mask_low=low,
            event_mask_high=high,
            opcode=opcode,
        )

    def to_bytes(self) -> bytes:
        return _HCI_FILTER_STRUCT.pack(
            self.packet_type_mask,
            self.event_mask_low,
            self.event_mask_high,
            self.opcode,
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> "HCIFilter":
        if len(value) < _HCI_FILTER_STRUCT.size:
            raise ValueError(
                "HCI filter requires at least "
                f"{_HCI_FILTER_STRUCT.size} bytes"
            )

        packet_mask, low, high, opcode = (
            _HCI_FILTER_STRUCT.unpack_from(value)
        )

        return cls(
            packet_type_mask=packet_mask,
            event_mask_low=low,
            event_mask_high=high,
            opcode=opcode,
        )


@dataclass(frozen=True)
class HCIPacket:
    """
    One H4-framed HCI packet.

    ``raw`` includes the one-byte H4 packet type. ``payload`` excludes it.
    ``monotonic_ns`` records when the process received the packet.
    """

    packet_type: int
    payload: bytes
    raw: bytes
    monotonic_ns: int

    def __post_init__(self) -> None:
        if not 0 <= self.packet_type <= 0xFF:
            raise ValueError("packet_type must fit in one byte")

        if not self.raw:
            raise InvalidHCIPacket("raw packet must not be empty")

        if self.raw[0] != self.packet_type:
            raise InvalidHCIPacket(
                "raw packet type does not match packet_type"
            )

        if self.raw[1:] != self.payload:
            raise InvalidHCIPacket(
                "raw packet payload does not match payload"
            )

    @property
    def event_code(self) -> int | None:
        """
        Return the HCI event code, or None for a non-event packet.
        """
        if (
            self.packet_type != HCI_EVENT_PKT
            or len(self.payload) < _HCI_EVENT_HEADER.size
        ):
            return None

        return self.payload[0]

    @property
    def acl_handle(self) -> int | None:
        """
        Return the 12-bit connection handle for an ACL packet.
        """
        if (
            self.packet_type != HCI_ACLDATA_PKT
            or len(self.payload) < _HCI_ACL_HEADER.size
        ):
            return None

        handle_and_flags, _ = _HCI_ACL_HEADER.unpack_from(
            self.payload
        )
        return handle_and_flags & 0x0FFF

    @property
    def hex(self) -> str:
        return self.raw.hex()


class RawHCISocket(AbstractContextManager["RawHCISocket"]):
    """
    Context-managed Linux Raw HCI socket.

    Example:

        with RawHCISocket("hci0") as hci:
            packet = hci.receive(timeout=5.0)
            print(packet.hex)

    Opening a raw HCI socket normally requires root or the appropriate
    Linux capabilities. The controller should be dedicated to the lab
    process; BlueZ and another raw controller owner can interfere with one
    another.
    """

    def __init__(
        self,
        controller: str | int = "hci0",
        *,
        channel: int = HCI_CHANNEL_RAW,
        receive_size: int = _DEFAULT_RECEIVE_SIZE,
        nonblocking: bool = False,
        hci_filter: HCIFilter | None = None,
        enable_data_direction: bool = False,
        enable_kernel_timestamp: bool = False,
    ) -> None:
        self.device_id = parse_controller_id(controller)
        self.channel = _validate_channel(channel)

        if not isinstance(receive_size, int):
            raise TypeError("receive_size must be an integer")

        if not 1 <= receive_size <= _MAX_HCI_PACKET_SIZE:
            raise ValueError(
                "receive_size must be between 1 and "
                f"{_MAX_HCI_PACKET_SIZE}"
            )

        self.receive_size = receive_size
        self.nonblocking = bool(nonblocking)
        self.initial_filter = hci_filter
        self.enable_data_direction = bool(
            enable_data_direction
        )
        self.enable_kernel_timestamp = bool(
            enable_kernel_timestamp
        )

        self._socket: socket.socket | None = None

    @property
    def is_open(self) -> bool:
        return self._socket is not None

    @property
    def file_descriptor(self) -> int:
        return self._require_socket().fileno()

    def open(self) -> "RawHCISocket":
        """
        Create and bind the Linux Bluetooth socket.
        """
        if self._socket is not None:
            return self

        socket_type = socket.SOCK_RAW

        if hasattr(socket, "SOCK_CLOEXEC"):
            socket_type |= socket.SOCK_CLOEXEC

        try:
            hci_socket = socket.socket(
                AF_BLUETOOTH,
                socket_type,
                BTPROTO_HCI,
            )
        except PermissionError as exc:
            raise HCISocketError(
                "permission denied while creating raw HCI socket; "
                "run in an isolated lab with the required Linux "
                "CAP_NET_RAW/CAP_NET_ADMIN capabilities"
            ) from exc
        except OSError as exc:
            raise HCISocketError(
                f"failed to create raw HCI socket: {exc}"
            ) from exc

        try:
            # Python's Linux Bluetooth address representation for HCI is
            # (device_id, channel).
            try:
                hci_socket.bind(
                    (self.device_id, self.channel)
                )
            except TypeError:
                # Compatibility with Python versions that accept only the
                # device identifier for HCI_CHANNEL_RAW.
                if self.channel != HCI_CHANNEL_RAW:
                    raise

                hci_socket.bind((self.device_id,))

            hci_socket.setblocking(
                not self.nonblocking
            )

            if self.initial_filter is not None:
                hci_socket.setsockopt(
                    SOL_HCI,
                    HCI_FILTER,
                    self.initial_filter.to_bytes(),
                )

            if self.enable_data_direction:
                hci_socket.setsockopt(
                    SOL_HCI,
                    HCI_DATA_DIR,
                    struct.pack("i", 1),
                )

            if self.enable_kernel_timestamp:
                hci_socket.setsockopt(
                    SOL_HCI,
                    HCI_TIME_STAMP,
                    struct.pack("i", 1),
                )

        except PermissionError as exc:
            hci_socket.close()
            raise HCISocketError(
                f"permission denied while binding hci{self.device_id}; "
                "verify capabilities and controller ownership"
            ) from exc
        except OSError as exc:
            hci_socket.close()
            raise HCISocketError(
                f"failed to bind hci{self.device_id} "
                f"on channel {self.channel}: {exc}"
            ) from exc

        self._socket = hci_socket
        return self

    def close(self) -> None:
        hci_socket = self._socket
        self._socket = None

        if hci_socket is not None:
            hci_socket.close()

    def __enter__(self) -> "RawHCISocket":
        return self.open()

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def set_filter(self, hci_filter: HCIFilter) -> None:
        """
        Replace the kernel HCI socket filter.
        """
        if not isinstance(hci_filter, HCIFilter):
            raise TypeError(
                "hci_filter must be an HCIFilter"
            )

        self._require_socket().setsockopt(
            SOL_HCI,
            HCI_FILTER,
            hci_filter.to_bytes(),
        )

    def get_filter(self) -> HCIFilter:
        """
        Read the current kernel HCI socket filter.
        """
        value = self._require_socket().getsockopt(
            SOL_HCI,
            HCI_FILTER,
            _HCI_FILTER_STRUCT.size,
        )
        return HCIFilter.from_bytes(value)

    def wait_readable(
        self,
        timeout: float | None = None,
    ) -> bool:
        """
        Wait until at least one packet can be received.

        Returns False when the timeout expires.
        """
        _validate_timeout(timeout)
        hci_socket = self._require_socket()

        try:
            readable, _, _ = select.select(
                [hci_socket],
                [],
                [],
                timeout,
            )
        except InterruptedError:
            return False
        except OSError as exc:
            raise HCISocketError(
                f"failed while waiting for HCI data: {exc}"
            ) from exc

        return bool(readable)

    def receive(
        self,
        *,
        timeout: float | None = None,
        validate: bool = True,
    ) -> HCIPacket:
        """
        Receive one H4-framed HCI packet.

        ``timeout=None`` follows normal blocking behavior. A finite timeout
        is implemented with select and does not permanently change the
        socket's blocking mode.
        """
        _validate_timeout(timeout)
        hci_socket = self._require_socket()

        if timeout is not None and not self.wait_readable(timeout):
            raise HCISocketTimeout(
                f"no HCI packet received within {timeout} seconds"
            )

        try:
            raw = hci_socket.recv(self.receive_size)
        except BlockingIOError as exc:
            raise HCISocketTimeout(
                "no HCI packet is currently available"
            ) from exc
        except InterruptedError as exc:
            raise HCISocketTimeout(
                "HCI receive was interrupted"
            ) from exc
        except OSError as exc:
            raise HCISocketError(
                f"failed to receive HCI packet: {exc}"
            ) from exc

        if not raw:
            raise HCISocketClosed(
                "raw HCI socket returned an empty read"
            )

        packet = parse_hci_packet(
            raw,
            monotonic_ns=time.monotonic_ns(),
        )

        if validate:
            validate_hci_packet_length(packet)

        return packet

    def receive_until(
        self,
        predicate,
        *,
        timeout: float,
        validate: bool = True,
    ) -> HCIPacket:
        """
        Receive packets until ``predicate(packet)`` is true.

        The timeout applies to the complete operation rather than to each
        individual receive.
        """
        _validate_timeout(timeout)

        if timeout is None:
            raise TypeError(
                "receive_until requires a finite timeout"
            )

        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                raise HCISocketTimeout(
                    "matching HCI packet was not received within "
                    f"{timeout} seconds"
                )

            packet = self.receive(
                timeout=remaining,
                validate=validate,
            )

            if predicate(packet):
                return packet

    def send_packet(
        self,
        packet: bytes | bytearray | memoryview,
        *,
        validate: bool = True,
    ) -> int:
        """
        Send one complete H4-framed HCI packet.

        The first byte must be the H4 packet type. The method deliberately
        does not construct commands or ACL/L2CAP/SMP payloads.
        """
        raw = bytes(packet)

        if not raw:
            raise InvalidHCIPacket(
                "HCI packet must not be empty"
            )

        if len(raw) > _MAX_HCI_PACKET_SIZE:
            raise InvalidHCIPacket(
                "HCI packet exceeds the maximum supported size"
            )

        parsed = parse_hci_packet(
            raw,
            monotonic_ns=time.monotonic_ns(),
        )

        if validate:
            validate_hci_packet_length(parsed)

        hci_socket = self._require_socket()

        try:
            written = hci_socket.send(raw)
        except BlockingIOError as exc:
            raise HCISocketTimeout(
                "raw HCI socket is not currently writable"
            ) from exc
        except PermissionError as exc:
            raise HCISocketError(
                "permission denied while sending HCI packet"
            ) from exc
        except OSError as exc:
            if exc.errno == errno.ENETDOWN:
                raise HCISocketError(
                    f"hci{self.device_id} is down"
                ) from exc

            raise HCISocketError(
                f"failed to send HCI packet: {exc}"
            ) from exc

        if written != len(raw):
            raise HCISocketError(
                "partial HCI packet write: "
                f"expected {len(raw)} bytes, wrote {written}"
            )

        return written

    def send(
        self,
        packet_type: int,
        payload: bytes | bytearray | memoryview,
        *,
        validate: bool = True,
    ) -> int:
        """
        Send a packet from a separate H4 type and payload.
        """
        _validate_packet_type(packet_type)

        return self.send_packet(
            bytes((packet_type,)) + bytes(payload),
            validate=validate,
        )

    def _require_socket(self) -> socket.socket:
        if self._socket is None:
            raise HCISocketClosed(
                "raw HCI socket is not open"
            )

        return self._socket


def parse_controller_id(
    controller: str | int,
) -> int:
    """
    Convert ``hci0`` or ``0`` to a Linux HCI device identifier.
    """
    if isinstance(controller, bool):
        raise TypeError(
            "controller must be an integer or hciN string"
        )

    if isinstance(controller, int):
        device_id = controller
    elif isinstance(controller, str):
        normalized = controller.strip().lower()

        if normalized.startswith("hci"):
            normalized = normalized[3:]

        if not normalized or not normalized.isdecimal():
            raise ValueError(
                "controller must have the form hciN or N"
            )

        device_id = int(normalized, 10)
    else:
        raise TypeError(
            "controller must be an integer or hciN string"
        )

    if not 0 <= device_id <= 0xFFFF:
        raise ValueError(
            "controller device identifier is out of range"
        )

    return device_id


def parse_hci_packet(
    raw: bytes | bytearray | memoryview,
    *,
    monotonic_ns: int | None = None,
) -> HCIPacket:
    """
    Parse the H4 packet type without interpreting its protocol payload.
    """
    value = bytes(raw)

    if not value:
        raise InvalidHCIPacket(
            "HCI packet must contain an H4 packet type"
        )

    packet_type = value[0]
    _validate_packet_type(packet_type)

    if monotonic_ns is None:
        monotonic_ns = time.monotonic_ns()

    return HCIPacket(
        packet_type=packet_type,
        payload=value[1:],
        raw=value,
        monotonic_ns=monotonic_ns,
    )


def validate_hci_packet_length(
    packet: HCIPacket,
) -> None:
    """
    Check the length encoded in the HCI transport header.

    Vendor packets are accepted without a generic length check because
    their framing is vendor-specific.
    """
    payload = packet.payload
    packet_type = packet.packet_type

    if packet_type == HCI_COMMAND_PKT:
        if len(payload) < _HCI_COMMAND_HEADER.size:
            raise InvalidHCIPacket(
                "truncated HCI command header"
            )

        _, parameter_length = _HCI_COMMAND_HEADER.unpack_from(
            payload
        )
        expected = _HCI_COMMAND_HEADER.size + parameter_length

    elif packet_type == HCI_ACLDATA_PKT:
        if len(payload) < _HCI_ACL_HEADER.size:
            raise InvalidHCIPacket(
                "truncated HCI ACL header"
            )

        _, data_length = _HCI_ACL_HEADER.unpack_from(
            payload
        )
        expected = _HCI_ACL_HEADER.size + data_length

    elif packet_type == HCI_SCODATA_PKT:
        if len(payload) < _HCI_SCO_HEADER.size:
            raise InvalidHCIPacket(
                "truncated HCI SCO header"
            )

        _, data_length = _HCI_SCO_HEADER.unpack_from(
            payload
        )
        expected = _HCI_SCO_HEADER.size + data_length

    elif packet_type == HCI_EVENT_PKT:
        if len(payload) < _HCI_EVENT_HEADER.size:
            raise InvalidHCIPacket(
                "truncated HCI event header"
            )

        _, parameter_length = _HCI_EVENT_HEADER.unpack_from(
            payload
        )
        expected = _HCI_EVENT_HEADER.size + parameter_length

    elif packet_type == HCI_ISODATA_PKT:
        if len(payload) < _HCI_ISO_HEADER.size:
            raise InvalidHCIPacket(
                "truncated HCI ISO header"
            )

        _, length_and_status = _HCI_ISO_HEADER.unpack_from(
            payload
        )
        data_length = length_and_status & 0x3FFF
        expected = _HCI_ISO_HEADER.size + data_length

    else:
        return

    if len(payload) != expected:
        raise InvalidHCIPacket(
            "HCI packet length mismatch: "
            f"type=0x{packet_type:02x}, "
            f"expected_payload={expected}, "
            f"actual_payload={len(payload)}"
        )


def hci_packet_type_bit(packet_type: int) -> int:
    """
    Return the Linux HCI filter bit for one H4 packet type.
    """
    _validate_packet_type(packet_type)

    # BlueZ's HCI_FLT_TYPE_BITS macro masks the shift count with 31.
    return 1 << (packet_type & 31)


def hci_event_mask(
    event_codes: Iterable[int],
) -> tuple[int, int]:
    """
    Build the two Linux HCI event-mask words.
    """
    low = 0
    high = 0

    for event_code in event_codes:
        if not isinstance(event_code, int):
            raise TypeError(
                "event code must be an integer"
            )

        if not 0 <= event_code <= 63:
            raise ValueError(
                "event code must be between 0 and 63"
            )

        if event_code < 32:
            low |= 1 << event_code
        else:
            high |= 1 << (event_code - 32)

    return low, high


def _validate_packet_type(packet_type: int) -> None:
    if not isinstance(packet_type, int):
        raise TypeError("packet_type must be an integer")

    if packet_type not in _VALID_PACKET_TYPES:
        raise InvalidHCIPacket(
            f"unsupported H4 packet type: 0x{packet_type:02x}"
        )


def _validate_channel(channel: int) -> int:
    if not isinstance(channel, int):
        raise TypeError("channel must be an integer")

    if channel not in {
        HCI_CHANNEL_RAW,
        HCI_CHANNEL_USER,
        HCI_CHANNEL_MONITOR,
        HCI_CHANNEL_CONTROL,
        HCI_CHANNEL_LOGGING,
    }:
        raise ValueError(
            f"unsupported HCI channel: {channel}"
        )

    return channel


def _validate_timeout(
    timeout: float | None,
) -> None:
    if timeout is None:
        return

    if isinstance(timeout, bool) or not isinstance(
        timeout,
        (int, float),
    ):
        raise TypeError(
            "timeout must be a number or None"
        )

    if timeout < 0:
        raise ValueError(
            "timeout must not be negative"
        )


def _validate_uint16(
    name: str,
    value: int,
) -> None:
    if not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")

    if not 0 <= value <= 0xFFFF:
        raise ValueError(
            f"{name} must fit in an unsigned 16-bit integer"
        )


def _validate_uint32(
    name: str,
    value: int,
) -> None:
    if not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")

    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(
            f"{name} must fit in an unsigned 32-bit integer"
        )
