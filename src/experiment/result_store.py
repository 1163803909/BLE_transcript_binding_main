# src/experiment/result_store.py

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Iterable, Iterator

from src.experiment.run_record import (
    ExperimentRunRecord,
)


_RUN_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
)


@dataclass(frozen=True)
class ResultStore:
    """
    Persistent storage for experiment run records.

    Directory layout:

        root/
        ├── results.jsonl
        └── runs/
            ├── <run_id>.json
            └── ...

    ``results.jsonl`` is append-only and is suitable for aggregate analysis.
    The individual JSON files provide convenient per-run artifacts.
    """

    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "root",
            Path(self.root),
        )

    @property
    def results_jsonl(self) -> Path:
        """
        Path to the append-only JSON Lines result file.
        """
        return self.root / "results.jsonl"

    @property
    def runs_directory(self) -> Path:
        """
        Directory containing one JSON file per completed run.
        """
        return self.root / "runs"

    def initialize(self) -> None:
        """
        Create the result directories if they do not already exist.
        """
        self.root.mkdir(parents=True, exist_ok=True)
        self.runs_directory.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        record: ExperimentRunRecord,
        *,
        write_individual: bool = True,
    ) -> None:
        """
        Persist one completed experiment record.

        The JSONL record is appended first. If ``write_individual`` is true,
        an individual JSON file is written afterwards.

        The append operation flushes and synchronizes the file descriptor
        before returning. This is intended for long-running experiments where
        a process or host may stop unexpectedly.

        Raises:
            ValueError:
                If the run identifier is not safe for use as a filename.
            FileExistsError:
                If the individual run file already exists.
        """
        self.initialize()
        _validate_run_id(record.run_id)

        line = record.to_json_line() + "\n"

        with self.results_jsonl.open(
            mode="a",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())

        if write_individual:
            self.write_individual(record)

    def write_individual(
        self,
        record: ExperimentRunRecord,
    ) -> Path:
        """
        Atomically write one record to ``runs/<run_id>.json``.

        A temporary file is written and synchronized first. It is then
        replaced into its final location using ``os.replace``.
        """
        self.initialize()
        _validate_run_id(record.run_id)

        destination = self.runs_directory / f"{record.run_id}.json"
        temporary = self.runs_directory / (
            f".{record.run_id}.json.tmp"
        )

        serialized = record.to_json(indent=2) + "\n"

        try:
            with temporary.open(
                mode="w",
                encoding="utf-8",
                newline="\n",
            ) as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temporary, destination)
            _fsync_directory(self.runs_directory)

        finally:
            if temporary.exists():
                temporary.unlink()

        return destination

    def contains_run(self, run_id: str) -> bool:
        """
        Return whether an individual run file exists.
        """
        _validate_run_id(run_id)

        return (
            self.runs_directory / f"{run_id}.json"
        ).is_file()

    def read_individual(
        self,
        run_id: str,
    ) -> dict[str, object]:
        """
        Read one individual JSON record as a dictionary.
        """
        _validate_run_id(run_id)

        path = self.runs_directory / f"{run_id}.json"

        with path.open(
            mode="r",
            encoding="utf-8",
        ) as handle:
            value = json.load(handle)

        if not isinstance(value, dict):
            raise ValueError(
                f"individual result is not a JSON object: {path}"
            )

        return value

    def iter_jsonl(
        self,
        *,
        skip_invalid: bool = False,
    ) -> Iterator[dict[str, object]]:
        """
        Iterate over records in ``results.jsonl``.

        Args:
            skip_invalid:
                If false, the first malformed line raises ``ValueError``.
                If true, malformed lines are ignored.

        This method reads the file line by line and does not load the entire
        result set into memory.
        """
        if not self.results_jsonl.exists():
            return

        with self.results_jsonl.open(
            mode="r",
            encoding="utf-8",
        ) as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()

                if not stripped:
                    continue

                try:
                    value = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    if skip_invalid:
                        continue

                    raise ValueError(
                        "invalid JSONL record at "
                        f"{self.results_jsonl}:{line_number}"
                    ) from exc

                if not isinstance(value, dict):
                    if skip_invalid:
                        continue

                    raise ValueError(
                        "JSONL record must be an object at "
                        f"{self.results_jsonl}:{line_number}"
                    )

                yield value

    def read_all(
        self,
        *,
        skip_invalid: bool = False,
    ) -> list[dict[str, object]]:
        """
        Read all JSONL records into a list.
        """
        return list(
            self.iter_jsonl(
                skip_invalid=skip_invalid,
            )
        )

    def count_outcomes(
        self,
        *,
        skip_invalid: bool = False,
    ) -> dict[str, int]:
        """
        Count records by their primary outcome.

        The result is suitable for the raw outcome-count report:

            {
                "paired": 10,
                "timeout": 2,
                "explicit_pairing_failed": 8
            }

        Records without a valid string ``outcome`` are rejected unless
        ``skip_invalid`` is true.
        """
        counts: dict[str, int] = {}

        for record in self.iter_jsonl(
            skip_invalid=skip_invalid,
        ):
            outcome = record.get("outcome")

            if not isinstance(outcome, str) or not outcome:
                if skip_invalid:
                    continue

                raise ValueError(
                    "result record contains no valid string outcome"
                )

            counts[outcome] = counts.get(outcome, 0) + 1

        return dict(sorted(counts.items()))

    def iter_run_files(self) -> Iterable[Path]:
        """
        Iterate over individual JSON run files in lexical order.
        """
        if not self.runs_directory.exists():
            return

        yield from sorted(
            self.runs_directory.glob("*.json")
        )


def _validate_run_id(run_id: str) -> None:
    """
    Prevent path traversal and unsafe individual result filenames.
    """
    if not isinstance(run_id, str):
        raise TypeError("run_id must be a string")

    if not run_id:
        raise ValueError("run_id must not be empty")

    if not _RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError(
            "run_id may contain only ASCII letters, digits, "
            "'.', '_' and '-' and must start with a letter or digit"
        )


def _fsync_directory(path: Path) -> None:
    """
    Synchronize directory metadata where supported.

    Some platforms do not allow opening directories for fsync. In that case,
    the file contents have already been synchronized and the directory fsync
    is skipped.
    """
    try:
        directory_fd = os.open(
            path,
            os.O_RDONLY,
        )
    except OSError:
        return

    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)
