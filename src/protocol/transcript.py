# src/protocol/transcript.py

from __future__ import annotations

from dataclasses import dataclass


SMP_PAIRING_PDU_LENGTH = 7
TRANSCRIPT_LENGTH = SMP_PAIRING_PDU_LENGTH * 2


def _validate_pairing_pdu(name: str, value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")

    if len(value) != SMP_PAIRING_PDU_LENGTH:
        raise ValueError(
            f"{name} must be exactly "
            f"{SMP_PAIRING_PDU_LENGTH} bytes, got {len(value)}"
        )

    return value


@dataclass(frozen=True)
class PairingTranscript:
    """
    Canonical BLE pairing transcript.

    The transcript order is always:

        Pairing Request || Pairing Response
    """

    pairing_request: bytes
    pairing_response: bytes

    def __post_init__(self) -> None:
        _validate_pairing_pdu(
            "pairing_request",
            self.pairing_request,
        )
        _validate_pairing_pdu(
            "pairing_response",
            self.pairing_response,
        )

    @property
    def value(self) -> bytes:
        """Return the canonical 14-byte transcript."""
        transcript = self.pairing_request + self.pairing_response

        if len(transcript) != TRANSCRIPT_LENGTH:
            raise AssertionError(
                f"invalid transcript length: {len(transcript)}"
            )

        return transcript

    @property
    def hex(self) -> str:
        """Return the transcript as lowercase hexadecimal text."""
        return self.value.hex()

    @classmethod
    def from_hex(
        cls,
        pairing_request_hex: str,
        pairing_response_hex: str,
    ) -> "PairingTranscript":
        """
        Construct a transcript from hexadecimal PDU strings.

        Whitespace is accepted to make captured packet data easier to use.
        """
        try:
            pairing_request = bytes.fromhex(pairing_request_hex)
            pairing_response = bytes.fromhex(pairing_response_hex)
        except ValueError as exc:
            raise ValueError("invalid hexadecimal SMP PDU") from exc

        return cls(
            pairing_request=pairing_request,
            pairing_response=pairing_response,
        )


def build_transcript(
    pairing_request: bytes,
    pairing_response: bytes,
) -> bytes:
    """
    Build a canonical Pairing Request || Pairing Response transcript.
    """
    return PairingTranscript(
        pairing_request=pairing_request,
        pairing_response=pairing_response,
    ).value
