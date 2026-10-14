# src/experiment/experiment_case.py

from __future__ import annotations

from dataclasses import dataclass

from src.protocol.f4_context import f4, f4_context
from src.protocol.transcript import PairingTranscript


@dataclass(frozen=True)
class F4Inputs:
    u: bytes
    v: bytes
    x: bytes
    z: int


@dataclass(frozen=True)
class ExperimentCase:
    name: str
    pairing_request: bytes
    pairing_response: bytes
    f4_inputs: F4Inputs

    @property
    def transcript(self) -> PairingTranscript:
        return PairingTranscript(
            pairing_request=self.pairing_request,
            pairing_response=self.pairing_response,
        )

    def run(self) -> "ExperimentResult":
        standard_result = f4(
            u=self.f4_inputs.u,
            v=self.f4_inputs.v,
            x=self.f4_inputs.x,
            z=self.f4_inputs.z,
        )
        context_result = f4_context(
            u=self.f4_inputs.u,
            v=self.f4_inputs.v,
            x=self.f4_inputs.x,
            z=self.f4_inputs.z,
            transcript=self.transcript,
        )

        return ExperimentResult(
            case_name=self.name,
            transcript=self.transcript.value,
            standard_f4=standard_result,
            context_f4=context_result,
        )


@dataclass(frozen=True)
class ExperimentResult:
    case_name: str
    transcript: bytes
    standard_f4: bytes
    context_f4: bytes

    @property
    def standard_f4_hex(self) -> str:
        return self.standard_f4.hex()

    @property
    def context_f4_hex(self) -> str:
        return self.context_f4.hex()


def _mutate_byte(value: bytes, offset: int) -> bytes:
    if not 0 <= offset < len(value):
        raise ValueError(
            f"offset must be between 0 and {len(value) - 1}"
        )

    mutated = bytearray(value)
    mutated[offset] ^= 0x01
    return bytes(mutated)


def default_f4_inputs() -> F4Inputs:
    return F4Inputs(
        u=bytes(range(32)),
        v=bytes(range(32, 64)),
        x=bytes(range(16)),
        z=0x00,
    )


def baseline_case() -> ExperimentCase:
    return ExperimentCase(
        name="baseline",
        pairing_request=bytes.fromhex("06010002100001"),
        pairing_response=bytes.fromhex("07010002100001"),
        f4_inputs=default_f4_inputs(),
    )


def request_mutation_case() -> ExperimentCase:
    baseline = baseline_case()

    return ExperimentCase(
        name="pairing-request-mutated",
        pairing_request=_mutate_byte(
            baseline.pairing_request,
            offset=6,
        ),
        pairing_response=baseline.pairing_response,
        f4_inputs=baseline.f4_inputs,
    )


def response_mutation_case() -> ExperimentCase:
    baseline = baseline_case()

    return ExperimentCase(
        name="pairing-response-mutated",
        pairing_request=baseline.pairing_request,
        pairing_response=_mutate_byte(
            baseline.pairing_response,
            offset=6,
        ),
        f4_inputs=baseline.f4_inputs,
    )


def default_experiment_cases() -> tuple[ExperimentCase, ...]:
    return (
        baseline_case(),
        request_mutation_case(),
        response_mutation_case(),
    )
