# src/experiment/aggregate.py

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import argparse
import csv
import json
from pathlib import Path
from typing import Any, Iterable


SUMMARY_FILENAME = "summary.json"
PACKETS_FILENAME = "packets.jsonl"


class AggregateError(RuntimeError):
    """Base exception for experiment aggregation errors."""


@dataclass
class RunCounts:
    """
    Counts reconstructed from one packets.jsonl file.
    """

    packet_count: int = 0
    packet_type_counts: Counter[str] = field(
        default_factory=Counter
    )
    event_code_counts: Counter[str] = field(
        default_factory=Counter
    )
    acl_handle_counts: Counter[str] = field(
        default_factory=Counter
    )
    malformed_records: int = 0

    def add_record(
        self,
        record: dict[str, Any],
    ) -> None:
        self.packet_count += 1

        packet_type = _first_present(
            record,
            "packet_type_hex",
            "packet_type",
        )

        if packet_type is not None:
            self.packet_type_counts[
                _normalise_hex_or_value(packet_type)
            ] += 1

        event_code = _first_present(
            record,
            "event_code_hex",
            "event_code",
        )

        if event_code is not None:
            self.event_code_counts[
                _normalise_hex_or_value(event_code)
            ] += 1

        acl_handle = _first_present(
            record,
            "acl_handle_hex",
            "acl_handle",
        )

        if acl_handle is not None:
            self.acl_handle_counts[
                _normalise_hex_or_value(
                    acl_handle,
                    width=3,
                )
            ] += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_count": self.packet_count,
            "packet_type_counts": dict(
                sorted(self.packet_type_counts.items())
            ),
            "event_code_counts": dict(
                sorted(self.event_code_counts.items())
            ),
            "acl_handle_counts": dict(
                sorted(self.acl_handle_counts.items())
            ),
            "malformed_records": self.malformed_records,
        }


@dataclass
class AggregateResult:
    """
    Complete aggregation result.
    """

    source_directory: str
    run_count: int
    successful_run_count: int
    failed_run_count: int
    timeout_run_count: int
    incomplete_run_count: int
    total_packet_count: int
    packet_type_counts: Counter[str]
    event_code_counts: Counter[str]
    acl_handle_counts: Counter[str]
    outcome_counts: Counter[str]
    case_counts: dict[str, dict[str, Any]]
    runs: list[dict[str, Any]]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_directory": self.source_directory,
            "run_count": self.run_count,
            "successful_run_count": (
                self.successful_run_count
            ),
            "failed_run_count": self.failed_run_count,
            "timeout_run_count": self.timeout_run_count,
            "incomplete_run_count": (
                self.incomplete_run_count
            ),
            "total_packet_count": self.total_packet_count,
            "packet_type_counts": dict(
                sorted(self.packet_type_counts.items())
            ),
            "event_code_counts": dict(
                sorted(self.event_code_counts.items())
            ),
            "acl_handle_counts": dict(
                sorted(self.acl_handle_counts.items())
            ),
            "outcome_counts": dict(
                sorted(self.outcome_counts.items())
            ),
            "case_counts": self.case_counts,
            "runs": self.runs,
            "warnings": self.warnings,
        }


def aggregate_directory(
    source_directory: str | Path,
    *,
    strict: bool = False,
    verify_packets: bool = True,
) -> AggregateResult:
    """
    Aggregate all run directories below source_directory.

    A run directory is identified by the presence of summary.json.
    campaign_summary.json is ignored.
    """
    root = Path(source_directory)

    if not root.exists():
        raise AggregateError(
            f"source directory does not exist: {root}"
        )

    if not root.is_dir():
        raise AggregateError(
            f"source path is not a directory: {root}"
        )

    summary_paths = sorted(
        path
        for path in root.rglob(SUMMARY_FILENAME)
        if path.is_file()
        and path.parent != root
    )

    if not summary_paths:
        raise AggregateError(
            f"no {SUMMARY_FILENAME} files found below {root}"
        )

    packet_type_counts: Counter[str] = Counter()
    event_code_counts: Counter[str] = Counter()
    acl_handle_counts: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter()

    case_accumulator: dict[
        str,
        dict[str, Any],
    ] = defaultdict(
        lambda: {
            "run_count": 0,
            "successful_run_count": 0,
            "failed_run_count": 0,
            "timeout_run_count": 0,
            "incomplete_run_count": 0,
            "total_packet_count": 0,
            "outcome_counts": Counter(),
            "packet_type_counts": Counter(),
            "event_code_counts": Counter(),
            "acl_handle_counts": Counter(),
        }
    )

    runs: list[dict[str, Any]] = []
    warnings: list[str] = []

    successful_run_count = 0
    failed_run_count = 0
    timeout_run_count = 0
    incomplete_run_count = 0
    total_packet_count = 0

    for summary_path in summary_paths:
        try:
            summary = _read_json_object(summary_path)
        except Exception as exc:
            message = (
                f"cannot read {summary_path}: {exc}"
            )

            if strict:
                raise AggregateError(message) from exc

            warnings.append(message)
            continue

        run_id = str(
            summary.get(
                "run_id",
                summary_path.parent.name,
            )
        )
        case_name = str(
            summary.get(
                "case_name",
                "unknown",
            )
        )

        declared_packet_count = _int_or_zero(
            summary.get("packet_count")
        )

        errors = summary.get("errors", [])
        if not isinstance(errors, list):
            errors = [str(errors)]

        outcome = classify_outcome(summary)

        reconstructed: RunCounts | None = None
        packets_path = (
            summary_path.parent / PACKETS_FILENAME
        )

        if verify_packets:
            if packets_path.exists():
                try:
                    reconstructed = read_packets_jsonl(
                        packets_path,
                        strict=strict,
                    )
                except Exception as exc:
                    message = (
                        f"cannot read {packets_path}: {exc}"
                    )

                    if strict:
                        raise AggregateError(
                            message
                        ) from exc

                    warnings.append(message)
            else:
                warnings.append(
                    f"missing packet log: {packets_path}"
                )

        if reconstructed is not None:
            if (
                declared_packet_count
                != reconstructed.packet_count
            ):
                warnings.append(
                    f"packet count mismatch in {run_id}: "
                    f"summary={declared_packet_count}, "
                    f"packets.jsonl="
                    f"{reconstructed.packet_count}"
                )

            run_packet_count = (
                reconstructed.packet_count
            )
            run_packet_type_counts = (
                reconstructed.packet_type_counts
            )
            run_event_code_counts = (
                reconstructed.event_code_counts
            )
            run_acl_handle_counts = (
                reconstructed.acl_handle_counts
            )
        else:
            run_packet_count = declared_packet_count
            run_packet_type_counts = Counter(
                _counter_from_summary(
                    summary,
                    "packet_type_counts",
                )
            )
            run_event_code_counts = Counter(
                _counter_from_summary(
                    summary,
                    "event_code_counts",
                )
            )
            run_acl_handle_counts = Counter(
                _counter_from_summary(
                    summary,
                    "acl_handle_counts",
                )
            )

        total_packet_count += run_packet_count
        packet_type_counts.update(
            run_packet_type_counts
        )
        event_code_counts.update(
            run_event_code_counts
        )
        acl_handle_counts.update(
            run_acl_handle_counts
        )
        outcome_counts[outcome] += 1

        if outcome == "success":
            successful_run_count += 1
        elif outcome == "failed":
            failed_run_count += 1
        elif outcome == "timeout":
            timeout_run_count += 1
        elif outcome == "incomplete":
            incomplete_run_count += 1

        case = case_accumulator[case_name]
        case["run_count"] += 1
        case["total_packet_count"] += run_packet_count
        case["outcome_counts"][outcome] += 1
        case["packet_type_counts"].update(
            run_packet_type_counts
        )
        case["event_code_counts"].update(
            run_event_code_counts
        )
        case["acl_handle_counts"].update(
            run_acl_handle_counts
        )

        if outcome == "success":
            case["successful_run_count"] += 1
        elif outcome == "failed":
            case["failed_run_count"] += 1
        elif outcome == "timeout":
            case["timeout_run_count"] += 1
        elif outcome == "incomplete":
            case["incomplete_run_count"] += 1

        run_record = {
            "run_id": run_id,
            "case_name": case_name,
            "repetition": summary.get(
                "repetition"
            ),
            "controller": summary.get(
                "controller"
            ),
            "outcome": outcome,
            "packet_count": run_packet_count,
            "declared_packet_count": (
                declared_packet_count
            ),
            "errors": errors,
            "summary_path": str(summary_path),
            "packets_path": str(packets_path),
        }

        if reconstructed is not None:
            run_record[
                "reconstructed_counts"
            ] = reconstructed.to_dict()

        runs.append(run_record)

    case_counts = {
        case_name: _serialise_case_counts(values)
        for case_name, values in sorted(
            case_accumulator.items()
        )
    }

    return AggregateResult(
        source_directory=str(root),
        run_count=len(runs),
        successful_run_count=successful_run_count,
        failed_run_count=failed_run_count,
        timeout_run_count=timeout_run_count,
        incomplete_run_count=incomplete_run_count,
        total_packet_count=total_packet_count,
        packet_type_counts=packet_type_counts,
        event_code_counts=event_code_counts,
        acl_handle_counts=acl_handle_counts,
        outcome_counts=outcome_counts,
        case_counts=case_counts,
        runs=sorted(
            runs,
            key=lambda item: (
                item["case_name"],
                item["repetition"]
                if item["repetition"] is not None
                else 0,
                item["run_id"],
            ),
        ),
        warnings=warnings,
    )


def read_packets_jsonl(
    path: str | Path,
    *,
    strict: bool = False,
) -> RunCounts:
    """
    Reconstruct counts from packets.jsonl.
    """
    packet_path = Path(path)
    result = RunCounts()

    with packet_path.open(
        "r",
        encoding="utf-8",
    ) as stream:
        for line_number, line in enumerate(
            stream,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

                if not isinstance(record, dict):
                    raise ValueError(
                        "record is not a JSON object"
                    )

                result.add_record(record)

            except Exception as exc:
                result.malformed_records += 1

                if strict:
                    raise AggregateError(
                        f"malformed record in "
                        f"{packet_path}:{line_number}: "
                        f"{exc}"
                    ) from exc

    return result


def classify_outcome(
    summary: dict[str, Any],
) -> str:
    """
    Classify the raw result of one run.

    Precedence:

    1. explicit summary["outcome"];
    2. errors;
    3. timeout-like metadata;
    4. missing artifact;
    5. success.
    """
    explicit = summary.get("outcome")

    if explicit is not None:
        value = str(explicit).strip().lower()

        if value in {
            "success",
            "failed",
            "timeout",
            "incomplete",
        }:
            return value

    errors = summary.get("errors", [])

    if isinstance(errors, list) and errors:
        text = " ".join(
            str(item).lower()
            for item in errors
        )

        if any(
            marker in text
            for marker in (
                "timeout",
                "timed out",
                "no hci packet",
            )
        ):
            return "timeout"

        return "failed"

    artifacts = summary.get("artifacts", {})

    if isinstance(artifacts, dict):
        packets_path = artifacts.get(
            "packets_jsonl"
        )

        if packets_path is not None:
            if not Path(str(packets_path)).exists():
                return "incomplete"

    return "success"


def write_aggregate_files(
    result: AggregateResult,
    output_directory: str | Path,
    *,
    write_csv: bool = True,
) -> dict[str, str]:
    """
    Write machine-readable aggregate artifacts.
    """
    output = Path(output_directory)
    output.mkdir(
        parents=True,
        exist_ok=True,
    )

    aggregate_path = output / "aggregate.json"
    outcome_path = (
        output / "raw_outcome_counts.json"
    )
    csv_path = (
        output / "raw_outcome_counts.csv"
    )

    _write_json(
        aggregate_path,
        result.to_dict(),
    )

    _write_json(
        outcome_path,
        {
            "source_directory": (
                result.source_directory
            ),
            "run_count": result.run_count,
            "successful_run_count": (
                result.successful_run_count
            ),
            "failed_run_count": (
                result.failed_run_count
            ),
            "timeout_run_count": (
                result.timeout_run_count
            ),
            "incomplete_run_count": (
                result.incomplete_run_count
            ),
            "total_packet_count": (
                result.total_packet_count
            ),
            "outcome_counts": dict(
                sorted(result.outcome_counts.items())
            ),
            "packet_type_counts": dict(
                sorted(
                    result.packet_type_counts.items()
                )
            ),
            "event_code_counts": dict(
                sorted(
                    result.event_code_counts.items()
                )
            ),
            "acl_handle_counts": dict(
                sorted(
                    result.acl_handle_counts.items()
                )
            ),
        },
    )

    paths = {
        "aggregate_json": str(aggregate_path),
        "raw_outcome_counts_json": str(
            outcome_path
        ),
    }

    if write_csv:
        _write_outcome_csv(
            csv_path,
            result,
        )
        paths["raw_outcome_counts_csv"] = str(
            csv_path
        )

    return paths


def _write_outcome_csv(
    path: Path,
    result: AggregateResult,
) -> None:
    rows: list[tuple[str, str, str, int]] = []

    for outcome, count in sorted(
        result.outcome_counts.items()
    ):
        rows.append(
            (
                "outcome",
                outcome,
                "",
                count,
            )
        )

    for packet_type, count in sorted(
        result.packet_type_counts.items()
    ):
        rows.append(
            (
                "packet_type",
                packet_type,
                "",
                count,
            )
        )

    for event_code, count in sorted(
        result.event_code_counts.items()
    ):
        rows.append(
            (
                "event_code",
                event_code,
                "",
                count,
            )
        )

    for acl_handle, count in sorted(
        result.acl_handle_counts.items()
    ):
        rows.append(
            (
                "acl_handle",
                acl_handle,
                "",
                count,
            )
        )

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "category",
                "key",
                "subkey",
                "count",
            ]
        )
        writer.writerows(rows)


def _serialise_case_counts(
    values: dict[str, Any],
) -> dict[str, Any]:
    return {
        "run_count": values["run_count"],
        "successful_run_count": (
            values["successful_run_count"]
        ),
        "failed_run_count": (
            values["failed_run_count"]
        ),
        "timeout_run_count": (
            values["timeout_run_count"]
        ),
        "incomplete_run_count": (
            values["incomplete_run_count"]
        ),
        "total_packet_count": (
            values["total_packet_count"]
        ),
        "outcome_counts": dict(
            sorted(values["outcome_counts"].items())
        ),
        "packet_type_counts": dict(
            sorted(
                values[
                    "packet_type_counts"
                ].items()
            )
        ),
        "event_code_counts": dict(
            sorted(
                values[
                    "event_code_counts"
                ].items()
            )
        ),
        "acl_handle_counts": dict(
            sorted(
                values[
                    "acl_handle_counts"
                ].items()
            )
        ),
    }


def _counter_from_summary(
    summary: dict[str, Any],
    key: str,
) -> dict[str, int]:
    value = summary.get(key, {})

    if not isinstance(value, dict):
        return {}

    result: dict[str, int] = {}

    for item_key, item_value in value.items():
        try:
            result[str(item_key)] = int(item_value)
        except (TypeError, ValueError):
            continue

    return result


def _read_json_object(
    path: Path,
) -> dict[str, Any]:
    with path.open(
        "r",
        encoding="utf-8",
    ) as stream:
        value = json.load(stream)

    if not isinstance(value, dict):
        raise ValueError(
            f"{path} does not contain a JSON object"
        )

    return value


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


def _first_present(
    record: dict[str, Any],
    *keys: str,
) -> Any:
    for key in keys:
        if key in record:
            return record[key]

    return None


def _normalise_hex_or_value(
    value: Any,
    *,
    width: int = 2,
) -> str:
    if isinstance(value, bool):
        return str(value)

    if isinstance(value, int):
        return f"0x{value:0{width}x}"

    text = str(value).strip().lower()

    if text.startswith("0x"):
        try:
            number = int(text, 16)
        except ValueError:
            return text

        return f"0x{number:0{width}x}"

    return text


def _int_or_zero(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0

    return max(parsed, 0)


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate raw outcome counts from HCI "
            "experiment run directories"
        )
    )

    parser.add_argument(
        "source_directory",
        help=(
            "Directory containing run subdirectories, "
            "for example artifacts/ble-observation/results"
        ),
    )
    parser.add_argument(
        "--output-directory",
        default=None,
        help=(
            "Directory for aggregate.json and "
            "raw_outcome_counts.json"
        ),
    )
    parser.add_argument(
        "--no-verify-packets",
        action="store_true",
        help=(
            "Do not reconstruct counts from packets.jsonl"
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Abort on malformed or incomplete input"
        ),
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Do not write raw_outcome_counts.csv",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_cli()
    args = parser.parse_args(argv)

    source_directory = Path(
        args.source_directory
    )

    result = aggregate_directory(
        source_directory,
        strict=args.strict,
        verify_packets=not args.no_verify_packets,
    )

    output_directory = (
        Path(args.output_directory)
        if args.output_directory is not None
        else source_directory
    )

    paths = write_aggregate_files(
        result,
        output_directory,
        write_csv=not args.no_csv,
    )

    output = {
        "summary": result.to_dict(),
        "artifacts": paths,
    }

    print(
        json.dumps(
            output,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )

    return 1 if result.warnings else 0


if __name__ == "__main__":
    raise SystemExit(main())
