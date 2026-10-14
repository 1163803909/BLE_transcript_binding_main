# src/hci/smp_packets.py

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar


SMP_CID = 0x0006
SMP_MAX_PDU_LENGTH = 65


class SMPError(ValueError):
    """Base exception for malformed or unsupported SMP packets."""


class SMPCode(IntEnum):
    PAIRING_REQUEST = 0x01
    PAIRING_RESPONSE = 0x02
    PAIRING_CONFIRM = 0x03
    PAIRING_RANDOM = 0x04
    PAIRING_FAILED = 0x05
    ENCRYPTION_INFORMATION = 0x06
    MASTER_IDENTIFICATION = 0x07
    IDENTITY_INFORMATION = 0x08
    IDENTITY_ADDRESS_INFORMATION = 0x09
    SIGNING_INFORMATION = 0x0A
    SECURITY_REQUEST = 0x0B
    PAIRING_PUBLIC_KEY = 0x0C
    PAIRING_DHKEY_CHECK = 0x0D
    PAIRING_KEYPRESS_NOTIFICATION = 0x0E


class IOCapability(IntEnum):
    DISPLAY_ONLY = 0x00
    DISPLAY_YES_NO = 0x01
    KEYBOARD_ONLY = 0x02
    NO_INPUT_NO_OUTPUT = 0x03
    KEYBOARD_DISPLAY = 0x04


class AuthReq:
    """
    Authentication Requirements bit definitions.

    The lower three bits encode bonding flags and key distribution support;
    the upper security-level bits are represented separately below.
    """

    BONDING_FLAG_MASK = 0x03
    BONDING_NOT_SUPPORTED = 0x00
    BONDING = 0x01

    MITM = 1 << 2
    SECURE_CONNECTIONS = 1 << 3
    KEYPRESS = 1 << 4
    CT2 = 1 << 5
    RFU_MASK = 0xC0


class KeyDistribution:
    """Pairing Request/Response key-distribution bit definitions."""

    ENC_KEY = 1 << 0
    ID_KEY = 1 << 1
    SIGN_KEY = 1 << 2
    LINK_KEY = 1 << 3
    RFU_MASK = 0xF0


@dataclass(frozen=True)
class SMPPacket:
    """
    Generic SMP packet.

    ``raw`` contains the SMP code byte followed by the PDU payload.
    It does not include the L2CAP header or an HCI transport header.
    """

    code: SMPCode
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.code, SMPCode):
            raise TypeError("code must be an SMPCode")

        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be bytes")

        if len(self.payload) > SMP_MAX_PDU_LENGTH - 1:
            raise SMPError("SMP payload is too large")

    @property
    def raw(self) -> bytes:
        return bytes((int(self.code),)) + self.payload

    @property
    def hex(self) -> str:
        return self.raw.hex()

    @property
    def length(self) -> int:
        return len(self.raw)

    @classmethod
    def parse(
        cls,
        raw: bytes | bytearray | memoryview,
    ) -> "SMPPacket":
        value = bytes(raw)

        if not value:
            raise SMPError("SMP PDU must not be empty")

        try:
            code = SMPCode(value[0])
        except ValueError as exc:
            raise SMPError(
                f"unsupported SMP code: 0x{value[0]:02x}"
            ) from exc

        packet = cls(code=code, payload=value[1:])
        _validate_smp_payload_length(packet)
        return packet


@dataclass(frozen=True)
class PairingRequest:
    """
    BLE SMP Pairing Request.

    Wire format:

        Code                  1 byte
        IO Capability         1 byte
        OOB Data Flag         1 byte
        AuthReq               1 byte
        Maximum Encryption Key Size
                              1 byte
        Initiator Key Distribution
                              1 byte
        Responder Key Distribution
                              1 byte

    The complete PDU is exactly seven bytes.
    """

    code: ClassVar[SMPCode] = SMPCode.PAIRING_REQUEST

    io_capability: int = int(
        IOCapability.NO_INPUT_NO_OUTPUT
    )
    oob_data_flag: int = 0
    auth_req: int = 0
    max_encryption_key_size: int = 16
    initiator_key_distribution: int = 0
    responder_key_distribution: int = 0

    def __post_init__(self) -> None:
        _validate_u8("io_capability", self.io_capability)
        _validate_u8("oob_data_flag", self.oob_data_flag)
        _validate_u8("auth_req", self.auth_req)
        _validate_u8(
            "max_encryption_key_size",
            self.max_encryption_key_size,
        )
        _validate_u8(
            "initiator_key_distribution",
            self.initiator_key_distribution,
        )
        _validate_u8(
            "responder_key_distribution",
            self.responder_key_distribution,
        )

        if self.io_capability > int(
            IOCapability.KEYBOARD_DISPLAY
        ):
            raise SMPError(
                "reserved IO capability value"
            )

        if self.oob_data_flag not in (0, 1):
            raise SMPError(
                "OOB data flag must be 0 or 1"
            )

        if not 7 <= self.max_encryption_key_size <= 16:
            raise SMPError(
                "maximum encryption key size must be between "
                "7 and 16"
            )

        if self.auth_req & AuthReq.RFU_MASK:
            raise SMPError(
                "reserved AuthReq bits must be zero"
            )

        if self.initiator_key_distribution & (
            KeyDistribution.RFU_MASK
        ):
            raise SMPError(
                "reserved initiator key-distribution bits "
                "must be zero"
            )

        if self.responder_key_distribution & (
            KeyDistribution.RFU_MASK
        ):
            raise SMPError(
                "reserved responder key-distribution bits "
                "must be zero"
            )

    @property
    def payload(self) -> bytes:
        return bytes(
            (
                self.io_capability,
                self.oob_data_flag,
                self.auth_req,
                self.max_encryption_key_size,
                self.initiator_key_distribution,
                self.responder_key_distribution,
            )
        )

    @property
    def raw(self) -> bytes:
        return bytes((int(self.code),)) + self.payload

    @property
    def hex(self) -> str:
        return self.raw.hex()

    @classmethod
    def parse(
        cls,
        raw: bytes | bytearray | memoryview,
    ) -> "PairingRequest":
        value = bytes(raw)

        if len(value) != 7:
            raise SMPError(
                "Pairing Request must be exactly 7 bytes"
            )

        if value[0] != int(SMPCode.PAIRING_REQUEST):
            raise SMPError(
                "PDU is not a Pairing Request"
            )

        return cls(
            io_capability=value[1],
            oob_data_flag=value[2],
            auth_req=value[3],
            max_encryption_key_size=value[4],
            initiator_key_distribution=value[5],
            responder_key_distribution=value[6],
        )

    def as_smp_packet(self) -> SMPPacket:
        return SMPPacket(
            code=self.code,
            payload=self.payload,
        )


@dataclass(frozen=True)
class PairingResponse:
    """
    BLE SMP Pairing Response.

    Its wire layout is identical to PairingRequest, except for the SMP code.
    """

    code: ClassVar[SMPCode] = SMPCode.PAIRING_RESPONSE

    io_capability: int = int(
        IOCapability.NO_INPUT_NO_OUTPUT
    )
    oob_data_flag: int = 0
    auth_req: int = 0
    max_encryption_key_size: int = 16
    initiator_key_distribution: int = 0
    responder_key_distribution: int = 0

    def __post_init__(self) -> None:
        _validate_pairing_fields(
            io_capability=self.io_capability,
            oob_data_flag=self.oob_data_flag,
            auth_req=self.auth_req,
            max_encryption_key_size=self.max_encryption_key_size,
            initiator_key_distribution=(
                self.initiator_key_distribution
            ),
            responder_key_distribution=(
                self.responder_key_distribution
            ),
        )

    @property
    def payload(self) -> bytes:
        return bytes(
            (
                self.io_capability,
                self.oob_data_flag,
                self.auth_req,
                self.max_encryption_key_size,
                self.initiator_key_distribution,
                self.responder_key_distribution,
            )
        )

    @property
    def raw(self) -> bytes:
        return bytes((int(self.code),)) + self.payload

    @property
    def hex(self) -> str:
        return self.raw.hex()

    @classmethod
    def parse(
        cls,
        raw: bytes | bytearray | memoryview,
    ) -> "PairingResponse":
        value = bytes(raw)

        if len(value) != 7:
            raise SMPError(
                "Pairing Response must be exactly 7 bytes"
            )

        if value[0] != int(SMPCode.PAIRING_RESPONSE):
            raise SMPError(
                "PDU is not a Pairing Response"
            )

        return cls(
            io_capability=value[1],
            oob_data_flag=value[2],
            auth_req=value[3],
            max_encryption_key_size=value[4],
            initiator_key_distribution=value[5],
            responder_key_distribution=value[6],
        )

    def as_smp_packet(self) -> SMPPacket:
        return SMPPacket(
            code=self.code,
            payload=self.payload,
        )


@dataclass(frozen=True)
class FixedLengthSMPPacket:
    """
    Base class for fixed-length SMP packets such as Confirm and Random.

    Subclasses define ``code`` and ``value_length``.
    """

    value: bytes
    code: ClassVar[SMPCode]
    value_length: ClassVar[int]

    def __post_init__(self) -> None:
        if not isinstance(self.value, bytes):
            raise TypeError("value must be bytes")

        if len(self.value) != self.value_length:
            raise SMPError(
                f"{self.code.name} value must be exactly "
                f"{self.value_length} bytes"
            )

    @property
    def payload(self) -> bytes:
        return self.value

    @property
    def raw(self) -> bytes:
        return bytes((int(self.code),)) + self.payload

    @property
    def hex(self) -> str:
        return self.raw.hex()

    def as_smp_packet(self) -> SMPPacket:
        return SMPPacket(
            code=self.code,
            payload=self.payload,
        )


@dataclass(frozen=True)
class PairingConfirm(FixedLengthSMPPacket):
    code: ClassVar[SMPCode] = SMPCode.PAIRING_CONFIRM
    value_length: ClassVar[int] = 16


@dataclass(frozen=True)
class PairingRandom(FixedLengthSMPPacket):
    code: ClassVar[SMPCode] = SMPCode.PAIRING_RANDOM
    value_length: ClassVar[int] = 16


@dataclass(frozen=True)
class PairingDHKeyCheck(FixedLengthSMPPacket):
    code: ClassVar[SMPCode] = SMPCode.PAIRING_DHKEY_CHECK
    value_length: ClassVar[int] = 16


@dataclass(frozen=True)
class PairingPublicKey:
    """
    BLE SMP Pairing Public Key.

    The public key contains X and Y coordinates, each encoded as 32 bytes
    in the Bluetooth LE wire representation.
    """

    x: bytes
    y: bytes

    code: ClassVar[SMPCode] = SMPCode.PAIRING_PUBLIC_KEY

    def __post_init__(self) -> None:
        if not isinstance(self.x, bytes):
            raise TypeError("x must be bytes")

        if not isinstance(self.y, bytes):
            raise TypeError("y must be bytes")

        if len(self.x) != 32:
            raise SMPError(
                "public-key X coordinate must be 32 bytes"
            )

        if len(self.y) != 32:
            raise SMPError(
                "public-key Y coordinate must be 32 bytes"
            )

    @property
    def payload(self) -> bytes:
        return self.x + self.y

    @property
    def raw(self) -> bytes:
        return bytes((int(self.code),)) + self.payload

    @property
    def hex(self) -> str:
        return self.raw.hex()

    def as_smp_packet(self) -> SMPPacket:
        return SMPPacket(
            code=self.code,
            payload=self.payload,
        )


@dataclass(frozen=True)
class PairingFailed:
    """BLE SMP Pairing Failed PDU."""

    reason: int

    code: ClassVar[SMPCode] = SMPCode.PAIRING_FAILED

    def __post_init__(self) -> None:
        _validate_u8("reason", self.reason)

    @property
    def payload(self) -> bytes:
        return bytes((self.reason,))

    @property
    def raw(self) -> bytes:
        return bytes((int(self.code), self.reason))

    @property
    def hex(self) -> str:
        return self.raw.hex()

    def as_smp_packet(self) -> SMPPacket:
        return SMPPacket(
            code=self.code,
            payload=self.payload,
        )


@dataclass(frozen=True)
class SecurityRequest:
    """BLE SMP Security Request PDU."""

    auth_req: int

    code: ClassVar[SMPCode] = SMPCode.SECURITY_REQUEST

    def __post_init__(self) -> None:
        _validate_u8("auth_req", self.auth_req)

        if self.auth_req & AuthReq.RFU_MASK:
            raise SMPError(
                "reserved AuthReq bits must be zero"
            )

    @property
    def payload(self) -> bytes:
        return bytes((self.auth_req,))

    @property
    def raw(self) -> bytes:
        return bytes((int(self.code), self.auth_req))

    @property
    def hex(self) -> str:
        return self.raw.hex()

    def as_smp_packet(self) -> SMPPacket:
        return SMPPacket(
            code=self.code,
            payload=self.payload,
        )


def parse_smp_packet(
    raw: bytes | bytearray | memoryview,
) -> (
    SMPPacket
    | PairingRequest
    | PairingResponse
    | PairingConfirm
    | PairingRandom
    | PairingFailed
    | SecurityRequest
    | PairingPublicKey
    | PairingDHKeyCheck
):
    """
    Parse a known SMP PDU into its typed representation.

    Unknown-but-valid SMP formats are returned as SMPPacket rather than
    being silently interpreted.
    """
    packet = SMPPacket.parse(raw)

    if packet.code == SMPCode.PAIRING_REQUEST:
        return PairingRequest.parse(packet.raw)

    if packet.code == SMPCode.PAIRING_RESPONSE:
        return PairingResponse.parse(packet.raw)

    if packet.code == SMPCode.PAIRING_CONFIRM:
        return PairingConfirm(packet.payload)

    if packet.code == SMPCode.PAIRING_RANDOM:
        return PairingRandom(packet.payload)

    if packet.code == SMPCode.PAIRING_FAILED:
        if len(packet.payload) != 1:
            raise SMPError(
                "Pairing Failed must contain exactly one reason byte"
            )
        return PairingFailed(packet.payload[0])

    if packet.code == SMPCode.SECURITY_REQUEST:
        if len(packet.payload) != 1:
            raise SMPError(
                "Security Request must contain exactly one "
                "AuthReq byte"
            )
        return SecurityRequest(packet.payload[0])

    if packet.code == SMPCode.PAIRING_PUBLIC_KEY:
        if len(packet.payload) != 64:
            raise SMPError(
                "Pairing Public Key must contain 64 payload bytes"
            )
        return PairingPublicKey(
            x=packet.payload[:32],
            y=packet.payload[32:],
        )

    if packet.code == SMPCode.PAIRING_DHKEY_CHECK:
        return PairingDHKeyCheck(packet.payload)

    return packet


def pairing_request_from_hex(
    value: str,
) -> PairingRequest:
    return PairingRequest.parse(_hex_to_bytes(value))


def pairing_response_from_hex(
    value: str,
) -> PairingResponse:
    return PairingResponse.parse(_hex_to_bytes(value))


def _validate_pairing_fields(
    *,
    io_capability: int,
    oob_data_flag: int,
    auth_req: int,
    max_encryption_key_size: int,
    initiator_key_distribution: int,
    responder_key_distribution: int,
) -> None:
    _validate_u8("io_capability", io_capability)
    _validate_u8("oob_data_flag", oob_data_flag)
    _validate_u8("auth_req", auth_req)
    _validate_u8(
        "max_encryption_key_size",
        max_encryption_key_size,
    )
    _validate_u8(
        "initiator_key_distribution",
        initiator_key_distribution,
    )
    _validate_u8(
        "responder_key_distribution",
        responder_key_distribution,
    )

    if io_capability > int(
        IOCapability.KEYBOARD_DISPLAY
    ):
        raise SMPError(
            "reserved IO capability value"
        )

    if oob_data_flag not in (0, 1):
        raise SMPError(
            "OOB data flag must be 0 or 1"
        )

    if not 7 <= max_encryption_key_size <= 16:
        raise SMPError(
            "maximum encryption key size must be between 7 and 16"
        )

    if auth_req & AuthReq.RFU_MASK:
        raise SMPError(
            "reserved AuthReq bits must be zero"
        )

    if initiator_key_distribution & KeyDistribution.RFU_MASK:
        raise SMPError(
            "reserved initiator key-distribution bits must be zero"
        )

    if responder_key_distribution & KeyDistribution.RFU_MASK:
        raise SMPError(
            "reserved responder key-distribution bits must be zero"
        )


def _validate_smp_payload_length(
    packet: SMPPacket,
) -> None:
    expected_lengths = {
        SMPCode.PAIRING_REQUEST: 6,
        SMPCode.PAIRING_RESPONSE: 6,
        SMPCode.PAIRING_CONFIRM: 16,
        SMPCode.PAIRING_RANDOM: 16,
        SMPCode.PAIRING_FAILED: 1,
        SMPCode.SECURITY_REQUEST: 1,
        SMPCode.PAIRING_PUBLIC_KEY: 64,
        SMPCode.PAIRING_DHKEY_CHECK: 16,
    }

    expected = expected_lengths.get(packet.code)

    if expected is not None and len(packet.payload) != expected:
        raise SMPError(
            f"{packet.code.name} payload must be exactly "
            f"{expected} bytes; got {len(packet.payload)}"
        )


def _validate_u8(
    name: str,
    value: int,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")

    if not 0 <= value <= 0xFF:
        raise ValueError(
            f"{name} must fit in one unsigned byte"
        )


def _hex_to_bytes(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("hex value must be a string")

    normalized = "".join(value.split())

    if not normalized:
        raise SMPError("hex value must not be empty")

    if len(normalized) % 2 != 0:
        raise SMPError(
            "hex value must contain a whole number of bytes"
        )

    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise SMPError(
            "invalid hexadecimal SMP value"
        ) from exc
