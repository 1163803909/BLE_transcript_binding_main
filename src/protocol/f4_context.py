# src/protocol/f4_context.py

from __future__ import annotations

from Crypto.Cipher import AES

from src.protocol.cmac_context import (
    build_context_input,
)
from src.protocol.transcript import PairingTranscript


F4_INPUT_LENGTH = 65
F4_OUTPUT_LENGTH = 16
AES_KEY_LENGTH = 16


def _validate_u256(name: str, value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")

    if len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")

    return value


def _validate_key(name: str, value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")

    if len(value) != AES_KEY_LENGTH:
        raise ValueError(
            f"{name} must be exactly {AES_KEY_LENGTH} bytes"
        )

    return value


def _aes_cmac(key: bytes, message: bytes) -> bytes:
    """
    AES-CMAC using the BLE AES-CMAC primitive.

    BLE f4 is defined using AES-CMAC with a 128-bit AES key.
    """
    cipher = AES.new(key, AES.MODE_ECB)

    zero = b"\x00" * 16
    l = cipher.encrypt(zero)

    const_rb = 0x87

    def left_shift_one_bit(value: bytes) -> bytes:
        result = bytearray(16)
        carry = 0

        for index in range(15, -1, -1):
            byte = value[index]
            result[index] = ((byte << 1) & 0xFF) | carry
            carry = (byte >> 7) & 0x01

        return bytes(result)

    def double(value: bytes) -> bytes:
        result = left_shift_one_bit(value)

        if value[0] & 0x80:
            result = bytes(
                byte ^ (const_rb if index == 15 else 0)
                for index, byte in enumerate(result)
            )

        return result

    k1 = double(l)
    k2 = double(k1)

    if len(message) == 0:
        block_count = 1
        last_block_complete = False
    else:
        block_count = (len(message) + 15) // 16
        last_block_complete = len(message) % 16 == 0

    if last_block_complete:
        last_block = bytes(
            message[(block_count - 1) * 16:block_count * 16][index]
            ^ k1[index]
            for index in range(16)
        )
    else:
        remaining = message[(block_count - 1) * 16:]
        padded = remaining + b"\x80"
        padded += b"\x00" * (15 - len(remaining))

        last_block = bytes(
            padded[index] ^ k2[index]
            for index in range(16)
        )

    state = b"\x00" * 16

    for block_index in range(block_count - 1):
        block = message[block_index * 16:(block_index + 1) * 16]
        state = cipher.encrypt(
            bytes(
                state[index] ^ block[index]
                for index in range(16)
            )
        )

    return cipher.encrypt(
        bytes(
            state[index] ^ last_block[index]
            for index in range(16)
        )
    )


def f4(
    u: bytes,
    v: bytes,
    x: bytes,
    z: int,
) -> bytes:
    """
    Standard Bluetooth LE Secure Connections f4 function.

    f4(U, V, X, Z) = AES-CMAC_X(U || V || Z)

    U and V are 256-bit public-key coordinates.
    X is a 128-bit key.
    Z is one octet.
    """
    _validate_u256("u", u)
    _validate_u256("v", v)
    _validate_key("x", x)

    if not isinstance(z, int):
        raise TypeError("z must be an integer")

    if not 0 <= z <= 0xFF:
        raise ValueError("z must fit in one octet")

    message = u + v + bytes([z])

    if len(message) != F4_INPUT_LENGTH:
        raise AssertionError(
            f"invalid f4 input length: {len(message)}"
        )

    return _aes_cmac(x, message)


def f4_context(
    u: bytes,
    v: bytes,
    x: bytes,
    z: int,
    transcript: PairingTranscript,
) -> bytes:
    """
    Experimental context-bound f4 function.

    The context-bound input is:

        U || V || Z || Pairing_Request || Pairing_Response

    Therefore:

        f4_context(U, V, X, Z, T)
        = AES-CMAC_X(U || V || Z || T)
    """
    _validate_u256("u", u)
    _validate_u256("v", v)
    _validate_key("x", x)

    if not isinstance(z, int):
        raise TypeError("z must be an integer")

    if not 0 <= z <= 0xFF:
        raise ValueError("z must fit in one octet")

    standard_input = u + v + bytes([z])

    if len(standard_input) != F4_INPUT_LENGTH:
        raise AssertionError(
            f"invalid f4 input length: {len(standard_input)}"
        )

    context_input = build_context_input(
        standard_input=standard_input,
        transcript=transcript,
    )

    return _aes_cmac(x, context_input)
def f4_hex(
    u: bytes,
    v: bytes,
    x: bytes,
    z: int,
) -> str:
    """Return standard f4 output as lowercase hexadecimal."""
    return f4(u=u, v=v, x=x, z=z).hex()


def f4_context_hex(
    u: bytes,
    v: bytes,
    x: bytes,
    z: int,
    transcript: PairingTranscript,
) -> str:
    """Return context-bound f4 output as lowercase hexadecimal."""
    return f4_context(
        u=u,
        v=v,
        x=x,
        z=z,
        transcript=transcript,
    ).hex()
