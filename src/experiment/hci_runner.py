# src/experiment/hci_runner.py

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import time
import uuid
from typing import Any, Callable

from src.experiment.experiment_config import (
    ExperimentConfig,
    default_experiment_config,
)
from src.hci.raw_socket import (
    HCIFilter,
    HCIPacket,
    HCISocketError,
    HCISocketTimeout,
    RawHCISocket,
)


@dataclass
class RunSummary:
    """
    Serializable result of one HCI experiment run.
    """

    run_id: str
    experiment_name: str
    case_name: str
    repetition: int
    controller: str
    started_at: str
    finished_at: str
    duration_seconds: float
    packet_count: int
    packet_type_counts: dict[str, int]
    event_code_counts: dict[str, int]
    acl_handle_counts: dict[str, int]
    artifacts: dict[str, str]
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "experiment_name": self.experiment_name,
            "case_name": self.case_name,
            "repetition": self.repetition,
            "controller": self.controller,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "packet_count": self.packet_count,
            "packet_type_counts": self.packet_type_counts,
            "event_code_counts": self.event_code_counts,
            "acl_handle_counts": self.acl_handle_counts,
            "artifacts": self.artifacts,
            "errors": self.errors,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class RunContext:
    """
    Immutable identity of one experiment run.
    """

    run_id: str
    case_name: str
    repetition: int
    output_directory: Path


class HCIExperimentRunner:
    """
    Execute one observation-only HCI run.

    The runner deliberately does not inject SMP packets. A Pairing Request
    or Pairing Response is an L2CAP payload and cannot safely be sent directly
    through a raw HCI socket without knowing the current ACL connection
    handle, packet boundary flags, controller state, and peer direction.

    Packet injection can be added later as a separate, explicitly gated
    component.
    """

    def __init__(
        self,
        config: ExperimentConfig,
        *,
        packet_callback: Callable[
            [HCIPacket, RunContext],
            None
        ]
        | None = None,
    ) -> None:
        if not isinstance(config, ExperimentConfig):
            raise TypeError(
                "config must be an ExperimentConfig"
            )

        self.config = config
        self.packet_callback = packet_callback

    def run_once(
        self,
        *,
        case_name: str | None = None,
        repetition: int = 1,
        run_id: str | None = None,
    ) -> RunSummary:
        """
        Execute one HCI observation run.

        ``case_name`` must be one of config.cases. The run observes traffic
        for config.timeouts.packet_observation seconds.
        """
        selected_case = case_name or self.config.cases[0]

        if selected_case not in self.config.cases:
            raise ValueError(
                f"case {selected_case!r} is not present in config.cases"
            )

        if not isinstance(repetition, int):
            raise TypeError(
                "repetition must be an integer"
            )

        if repetition < 1:
            raise ValueError(
                "repetition must be at least one"
            )

        self._reject_unsupported_injection()

        if run_id is None:
            run_id = _new_run_id()

        context = RunContext(
            run_id=run_id,
            case_name=selected_case,
            repetition=repetition,
            output_directory=(
                self.config.result_directory / run_id
            ),
        )

        context.output_directory.mkdir(
            parents=True,
            exist_ok=False,
        )

        started_monotonic = time.monotonic()
        started_at = _utc_now()
        errors: list[str] = []

        packets_jsonl = (
            context.output_directory / "packets.jsonl"
        )
        raw_hci_path = (
            context.output_directory / "raw_hci.bin"
        )

        packet_type_counts: Counter[str] = Counter()
        event_code_counts: Counter[str] = Counter()
        acl_handle_counts: Counter[str] = Counter()
        packet_count = 0

        hci_filter = HCIFilter.events_and_acl()

        try:
            with (
                RawHCISocket(
                    self.config.controller,
                    hci_filter=hci_filter,
                    nonblocking=False,
                ) as hci,
                packets_jsonl.open(
                    "w",
                    encoding="utf-8",
                ) as packet_log,
                raw_hci_path.open("wb") as raw_hci,
            ):
                deadline = (
                    time.monotonic()
                    + self.config.timeouts.packet_observation
                )

                while True:
                    remaining = (
                        deadline - time.monotonic()
                    )

                    if remaining <= 0:
                        break

                    try:
                        packet = hci.receive(
                            timeout=remaining,
                            validate=True,
                        )
                    except HCISocketTimeout:
                        break

                    packet_count += 1
                    _update_counters(
                        packet,
                        packet_type_counts,
                        event_code_counts,
                        acl_handle_counts,
                    )

                    # Store one H4 packet per record, prefixed by its
                    # two-byte little-endian length. This makes raw_hci.bin
                    # unambiguous when concatenating variable-length HCI
                    # packets.
                    raw_hci.write(
                        len(packet.raw).to_bytes(
                            2,
                            byteorder="little",
                            signed=False,
                        )
                    )
                    raw_hci.write(packet.raw)
                    raw_hci.flush()

                    record = _packet_record(packet)
                    packet_log.write(
                        json.dumps(
                            record,
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    packet_log.flush()

                    if self.packet_callback is not None:
                        self.packet_callback(
                            packet,
                            context,
                        )

        except HCISocketError as exc:
            errors.append(str(exc))
        except PermissionError as exc:
            errors.append(
                "permission denied while writing experiment "
                f"artifacts: {exc}"
            )
        except OSError as exc:
            errors.append(
                f"filesystem or HCI I/O error: {exc}"
            )
        finally:
            finished_at = _utc_now()

        duration_seconds = (
            time.monotonic() - started_monotonic
        )

        summary = RunSummary(
            run_id=run_id,
            experiment_name=self.config.name,
            case_name=selected_case,
            repetition=repetition,
            controller=self.config.controller,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration_seconds,
            packet_count=packet_count,
            packet_type_counts=dict(
                sorted(packet_type_counts.items())
            ),
            event_code_counts=dict(
                sorted(event_code_counts.items())
            ),
            acl_handle_counts=dict(
                sorted(acl_handle_counts.items())
            ),
            artifacts={
                "packets_jsonl": str(
                    packets_jsonl
                ),
                "raw_hci": str(
                    raw_hci_path
                ),
            },
            errors=errors,
            metadata={
                **dict(self.config.metadata),
                "capture_backend": (
                    self.config.capture.backend
                ),
                "capture_enabled": (
                    self.config.capture.enabled
                ),
                "observation_only": True,
            },
        )

        summary_path = (
            context.output_directory / "summary.json"
        )
        _write_json(summary_path, summary.to_dict())

        return summary

    def run_campaign(self) -> list[RunSummary]:
        """
        Execute every configured case for the configured number of
        repetitions.
        """
        summaries: list[RunSummary] = []

        for repetition in range(
            1,
            self.config.repetitions + 1,
        ):
            for case_name in self.config.cases:
                summaries.append(
                    self.run_once(
                        case_name=case_name,
                        repetition=repetition,
                    )
                )

        campaign_summary = {
            "experiment_name": self.config.name,
            "controller": self.config.controller,
            "run_count": len(summaries),
            "runs": [
                summary.to_dict()
                for summary in summaries
            ],
        }

        campaign_path = (
            self.config.result_directory
            / "campaign_summary.json"
        )
        _write_json(
            campaign_path,
            campaign_summary,
        )

        return summaries

    def _reject_unsupported_injection(self) -> None:
        injection = self.config.injection

        if not injection.enabled:
            return

        raise RuntimeError(
            "packet injection is enabled in the configuration, "
            "but hci_runner.py is observation-only. "
            "Disable config.injection.enabled before running, "
            "or implement a separately reviewed ACL/L2CAP/SMP "
            "injection runner for an isolated lab controller."
        )


def _update_counters(
    packet: HCIPacket,
    packet_type_counts: Counter[str],
    event_code_counts: Counter[str],
    acl_handle_counts: Counter[str],
) -> None:
    packet_type_name = (
        f"0x{packet.packet_type:02x}"
    )
    packet_type_counts[packet_type_name] += 1

    if packet.event_code is not None:
        event_name = (
            f"0x{packet.event_code:02x}"
        )
        event_code_counts[event_name] += 1

    if packet.acl_handle is not None:
        handle_name = (
            f"0x{packet.acl_handle:03x}"
        )
        acl_handle_counts[handle_name] += 1


def _packet_record(packet: HCIPacket) -> dict[str, Any]:
    return {
        "monotonic_ns": packet.monotonic_ns,
        "packet_type": packet.packet_type,
        "packet_type_hex": (
            f"0x{packet.packet_type:02x}"
        ),
        "length": len(packet.raw),
        "event_code": packet.event_code,
        "event_code_hex": (
            None
            if packet.event_code is None
            else f"0x{packet.event_code:02x}"
        ),
        "acl_handle": packet.acl_handle,
        "acl_handle_hex": (
            None
            if packet.acl_handle is None
            else f"0x{packet.acl_handle:03x}"
        ),
        "raw_hex": packet.raw.hex(),
    }


def _write_json(
    path: Path,
    value: dict[str, Any],
) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _new_run_id() -> str:
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%S%fZ")

    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one observation-only raw HCI experiment"
        )
    )

    parser.add_argument(
        "--controller",
        default=None,
        help="Bluetooth controller, for example hci0",
    )
    parser.add_argument(
        "--case",
        default=None,
        help="Configured experiment case",
    )
    parser.add_argument(
        "--repetition",
        type=int,
        default=1,
        help="Repetition number",
    )
    parser.add_argument(
        "--output-directory",
        default=None,
        help="Override artifact output directory",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_cli()
    args = parser.parse_args(argv)

    config = default_experiment_config()

    if args.controller is not None:
        config = ExperimentConfig(
            name=config.name,
            controller=args.controller,
            initiator_address=config.initiator_address,
            responder_address=config.responder_address,
            mode=config.mode,
            cases=config.cases,
            repetitions=config.repetitions,
            output_directory=config.output_directory,
            result_directory_name=(
                config.result_directory_name
            ),
            timeouts=config.timeouts,
            capture=config.capture,
            injection=config.injection,
            metadata=dict(config.metadata),
        )

    if args.output_directory is not None:
        config = config.with_output_directory(
            args.output_directory
        )

    config.prepare_directories()

    runner = HCIExperimentRunner(config)

    summary = runner.run_once(
        case_name=args.case,
        repetition=args.repetition,
    )

    print(
        json.dumps(
            summary.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )

    return 1 if summary.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
