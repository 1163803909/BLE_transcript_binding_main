# src/experiment/experiment_config.py

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Mapping


_VALID_MODES = frozenset(
    {
        "standard",
        "context-bound",
        "both",
    }
)

_VALID_INJECTION_LAYERS = frozenset(
    {
        "none",
        "raw-hci",
        "scapy",
    }
)

_VALID_CAPTURE_BACKENDS = frozenset(
    {
        "none",
        "btmon",
        "tcpdump",
        "dumpcap",
    }
)

_CASE_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)

_BD_ADDR_PATTERN = re.compile(
    r"^[0-9A-Fa-f]{2}"
    r"(?::[0-9A-Fa-f]{2}){5}$"
)


@dataclass(frozen=True)
class TimeoutConfig:
    """
    Time limits used by one experiment execution.

    All values are seconds.
    """

    controller_setup: float = 10.0
    connection: float = 15.0
    pairing: float = 30.0
    packet_observation: float = 10.0
    disconnect: float = 10.0
    cleanup: float = 10.0

    def __post_init__(self) -> None:
        values = {
            "controller_setup": self.controller_setup,
            "connection": self.connection,
            "pairing": self.pairing,
            "packet_observation": self.packet_observation,
            "disconnect": self.disconnect,
            "cleanup": self.cleanup,
        }

        for name, value in values.items():
            if not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a number")

            if value <= 0:
                raise ValueError(
                    f"{name} must be greater than zero"
                )


@dataclass(frozen=True)
class CaptureConfig:
    """
    Packet and HCI capture configuration.

    The capture backend is selected by a later runner. This class does not
    start capture processes.
    """

    backend: str = "none"
    enabled: bool = False
    include_hci: bool = True
    include_smp: bool = True
    include_l2cap: bool = True
    output_subdirectory: str = "captures"

    def __post_init__(self) -> None:
        if self.backend not in _VALID_CAPTURE_BACKENDS:
            allowed = ", ".join(sorted(_VALID_CAPTURE_BACKENDS))
            raise ValueError(
                f"unsupported capture backend {self.backend!r}; "
                f"expected one of: {allowed}"
            )

        if not self.output_subdirectory:
            raise ValueError(
                "output_subdirectory must not be empty"
            )

        output_path = Path(self.output_subdirectory)

        if output_path.is_absolute():
            raise ValueError(
                "output_subdirectory must be relative"
            )

        if ".." in output_path.parts:
            raise ValueError(
                "output_subdirectory must not contain '..'"
            )

        if self.enabled and self.backend == "none":
            raise ValueError(
                "capture backend must not be 'none' when capture "
                "is enabled"
            )


@dataclass(frozen=True)
class InjectionConfig:
    """
    Packet-injection configuration.

    ``enabled`` is intentionally false by default. A raw-HCI or Scapy
    runner must require explicit opt-in before transmitting packets.
    """

    enabled: bool = False
    layer: str = "none"

    # Optional raw SMP PDU values. These are hexadecimal strings and must
    # contain exactly one seven-byte Pairing Request/Response PDU.
    pairing_request_hex: str | None = None
    pairing_response_hex: str | None = None

    # If true, the runner may replace the captured Pairing Request.
    mutate_pairing_request: bool = False

    # If true, the runner may replace the captured Pairing Response.
    mutate_pairing_response: bool = False

    # Prevent accidental use of a configuration against a non-lab device.
    require_lab_target: bool = True

    def __post_init__(self) -> None:
        if self.layer not in _VALID_INJECTION_LAYERS:
            allowed = ", ".join(sorted(_VALID_INJECTION_LAYERS))
            raise ValueError(
                f"unsupported injection layer {self.layer!r}; "
                f"expected one of: {allowed}"
            )

        if self.enabled and self.layer == "none":
            raise ValueError(
                "injection layer must not be 'none' when injection "
                "is enabled"
            )

        if not self.enabled and self.layer != "none":
            raise ValueError(
                "injection layer must be 'none' when injection "
                "is disabled"
            )

        if self.mutate_pairing_request and not self.enabled:
            raise ValueError(
                "request mutation requires injection to be enabled"
            )

        if self.mutate_pairing_response and not self.enabled:
            raise ValueError(
                "response mutation requires injection to be enabled"
            )

        if self.pairing_request_hex is not None:
            _validate_hex_pdu(
                "pairing_request_hex",
                self.pairing_request_hex,
            )

        if self.pairing_response_hex is not None:
            _validate_hex_pdu(
                "pairing_response_hex",
                self.pairing_response_hex,
            )

    @property
    def pairing_request(self) -> bytes | None:
        if self.pairing_request_hex is None:
            return None

        return bytes.fromhex(self.pairing_request_hex)

    @property
    def pairing_response(self) -> bytes | None:
        if self.pairing_response_hex is None:
            return None

        return bytes.fromhex(self.pairing_response_hex)


@dataclass(frozen=True)
class ExperimentConfig:
    """
    Static configuration for an experiment campaign.

    This object describes what a future runner should do. It does not
    perform setup, connect to a controller, capture traffic, or inject
    packets.
    """

    name: str = "ble-f4-experiment"

    # Linux Bluetooth controller, for example hci0.
    controller: str = "hci0"

    # Optional initiator and responder addresses.
    initiator_address: str | None = None
    responder_address: str | None = None

    # Experiment execution mode.
    mode: str = "both"

    # Names understood by the experiment-case registry.
    cases: tuple[str, ...] = (
        "baseline",
        "pairing-request-mutated",
        "pairing-response-mutated",
    )

    repetitions: int = 1

    output_directory: Path = Path("artifacts")
    result_directory_name: str = "results"

    timeouts: TimeoutConfig = field(
        default_factory=TimeoutConfig
    )
    capture: CaptureConfig = field(
        default_factory=CaptureConfig
    )
    injection: InjectionConfig = field(
        default_factory=InjectionConfig
    )

    # Additional metadata is copied into ExperimentRunRecord.metadata.
    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("name must not be empty")

        if not _CASE_NAME_PATTERN.fullmatch(self.name):
            raise ValueError(
                "name contains unsupported characters"
            )

        if not self.controller:
            raise ValueError(
                "controller must not be empty"
            )

        if self.mode not in _VALID_MODES:
            allowed = ", ".join(sorted(_VALID_MODES))
            raise ValueError(
                f"unsupported mode {self.mode!r}; "
                f"expected one of: {allowed}"
            )

        if not self.cases:
            raise ValueError("cases must not be empty")

        for case_name in self.cases:
            if not isinstance(case_name, str):
                raise TypeError("each case name must be a string")

            if not _CASE_NAME_PATTERN.fullmatch(case_name):
                raise ValueError(
                    f"invalid case name: {case_name!r}"
                )

        if not isinstance(self.repetitions, int):
            raise TypeError("repetitions must be an integer")

        if self.repetitions < 1:
            raise ValueError(
                "repetitions must be at least one"
            )

        _validate_optional_bd_addr(
            "initiator_address",
            self.initiator_address,
        )
        _validate_optional_bd_addr(
            "responder_address",
            self.responder_address,
        )

        _validate_relative_directory_name(
            "result_directory_name",
            self.result_directory_name,
        )

    @property
    def result_directory(self) -> Path:
        """
        Directory used by ResultStore for JSONL and per-run results.
        """
        return (
            self.output_directory
            / self.result_directory_name
        )

    @property
    def capture_directory(self) -> Path:
        """
        Directory intended for pcap and HCI capture artifacts.
        """
        return (
            self.output_directory
            / self.capture.output_subdirectory
        )

    def prepare_directories(self) -> None:
        """
        Create output directories.

        This method only creates local directories. It does not interact
        with Bluetooth hardware.
        """
        self.result_directory.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.capture_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-compatible configuration dictionary.
        """
        result = asdict(self)

        result["output_directory"] = str(
            self.output_directory
        )

        result["result_directory"] = str(
            self.result_directory
        )

        result["capture_directory"] = str(
            self.capture_directory
        )

        return result

    def to_json(self, *, indent: int | None = 2) -> str:
        """
        Serialize the configuration as JSON.
        """
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
        )

    def with_output_directory(
        self,
        output_directory: str | Path,
    ) -> "ExperimentConfig":
        """
        Return a copy using another artifact directory.
        """
        return ExperimentConfig(
            name=self.name,
            controller=self.controller,
            initiator_address=self.initiator_address,
            responder_address=self.responder_address,
            mode=self.mode,
            cases=self.cases,
            repetitions=self.repetitions,
            output_directory=Path(output_directory),
            result_directory_name=self.result_directory_name,
            timeouts=self.timeouts,
            capture=self.capture,
            injection=self.injection,
            metadata=dict(self.metadata),
        )


def default_experiment_config() -> ExperimentConfig:
    """
    Return the default offline-safe configuration.

    Packet injection and capture are disabled by default.
    """
    return ExperimentConfig()


def _validate_optional_bd_addr(
    name: str,
    value: str | None,
) -> None:
    if value is None:
        return

    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string or None")

    if not _BD_ADDR_PATTERN.fullmatch(value):
        raise ValueError(
            f"{name} must be a Bluetooth address in the form "
            "AA:BB:CC:DD:EE:FF"
        )


def _validate_hex_pdu(
    name: str,
    value: str,
) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a hexadecimal string")

    normalized = "".join(value.split())

    if len(normalized) != 14:
        raise ValueError(
            f"{name} must contain exactly 7 bytes"
        )

    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(
            f"{name} is not valid hexadecimal"
        ) from exc


def _validate_relative_directory_name(
    name: str,
    value: str,
) -> None:
    if not value:
        raise ValueError(f"{name} must not be empty")

    path = Path(value)

    if path.is_absolute():
        raise ValueError(
            f"{name} must be relative"
        )

    if ".." in path.parts:
        raise ValueError(
            f"{name} must not contain '..'"
        )
