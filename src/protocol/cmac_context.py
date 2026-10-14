# src/protocol/cmac_context.py

from __future__ import annotations

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

from src.protocol.transcript import (
    PairingTranscript,
    TRANSCRIPT_LENGTH,
)


AES_BLOCK_SIZE = 16
AES_KEY_LENGTH = 16
CMAC_LENGTH = 16


def _validate_key(key: bytes) -> bytes:
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    if len(key) != AES_KEY_LENGTH:
        raise ValueError(
            f"key must be exactly {AES_KEY_LENGTH} bytes, got {len(key)}"
        )

    return key


def _validate_standard_input(standard_input: bytes) -> bytes:
    if not isinstance(standard_input, bytes):
        raise TypeError("standard_input must be bytes")

    if len(standard_input) == 0:
        raise ValueError("standard_input must not be empty")

    return standard_input


def build_context_input(
    standard_input: bytes,
    transcript: PairingTranscript,
) -> bytes:
    """
    Construct the CMAC input:

        standard_input || Pairing_Request || Pairing_Response
    """
    _validate_standard_input(standard_input)

    context = transcript.value

    if len(context) != TRANSCRIPT_LENGTH:
        raise ValueError(
            f"transcript must be exactly {TRANSCRIPT_LENGTH} bytes"
        )

    return standard_input + context


def calculate_context_cmac(
    key: bytes,
    standard_input: bytes,
    transcript: PairingTranscript,
) -> bytes:
    """
    Calculate AES-CMAC over the standard input bound to the pairing context.
    """
    _validate_key(key)

    cmac_input = build_context_input(
        standard_input=standard_input,
        transcript=transcript,
    )

    mac = CMAC.new(key, ciphermod=AES)
    mac.update(cmac_input)

    result = mac.digest()

    if len(result) != CMAC_LENGTH:
        raise AssertionError(
            f"invalid CMAC length: {len(result)}"
        )

    return result


def calculate_context_cmac_hex(
    key: bytes,
    standard_input: bytes,
    transcript: PairingTranscript,
) -> str:
    """
    Calculate the context-bound CMAC and return lowercase hexadecimal text.
    """
    return calculate_context_cmac(
        key=key,
        standard_input=standard_input,
        transcript=transcript,
    ).hex()
