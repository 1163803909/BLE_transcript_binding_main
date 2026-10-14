#!/usr/bin/env python3
"""
Experiment orchestration entry point.
This script is intentionally an orchestrator rather than an HCI injector.
It invokes configured commands, records their exact argv, captures output,
and creates a reproducible per-run artifact directory.
It does not:
  - implement a transparent OTA MITM;
  - fabricate outcome counts;
  - interpret a successful process exit as a successful pairing;
  - enable KeySize=7 or BR/EDR KNOB experiments;
  - store Bluetooth secrets or private keys.
Example:
    python3 scripts/run_experiment.py \
        --config config/experiment.example.yaml \
        --scenario normal_no_injection \
        --variant context_bound \
        --repetitions 1 \
        --dry-run
For an actual controlled run, commands must first be enabled in the YAML
configuration and reviewed locally.
"""
from __future__ import annotations
import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence
try:
    import yaml
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: PyYAML. Install it with: python3 -m pip install PyYAML"
    ) from exc
SCRIPT_VERSION = "0.1.0"
class RunnerError(RuntimeError):
    """Raised when experiment configuration or execution is invalid."""
def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()
def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RunnerError(f"Configuration file does not exist: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise RunnerError("Top-level YAML value must be a mapping")
    return data
  def write_json(path: Path, value: Any) -> None:
    """Atomically write a JSON document."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")

    with temporary.open("w", encoding="utf-8") as fh:
        json.dump(value, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())

    temporary.replace(path)


def write_yaml(path: Path, value: Any) -> None:
    """Atomically write a YAML document."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")

    with temporary.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(
            value,
            fh,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
        fh.flush()
        os.fsync(fh.fileno())

    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def sanitize_component(value: str) -> str:
    """Return a filesystem-safe run-ID component."""

    result = []
    for character in value:
        if character.isalnum() or character in ("-", "_", "."):
            result.append(character)
        else:
            result.append("_")

    sanitized = "".join(result).strip("._")
    return sanitized or "unnamed"


def get_git_revision(repository_root: Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    revision = result.stdout.strip()
    return revision or None


def get_git_dirty(repository_root: Path) -> Optional[bool]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository_root), "status", "--porcelain"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    return bool(result.stdout.strip())


def get_nested(
    mapping: Mapping[str, Any],
    keys: Sequence[str],
    default: Any = None,
) -> Any:
    current: Any = mapping

    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            return default
        current = current[key]

    return current


def require_mapping(value: Any, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RunnerError(f"{description} must be a mapping")
    return value


def require_positive_integer(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RunnerError(f"{description} must be a positive integer")
    return value


def validate_configuration(
    config: Mapping[str, Any],
    scenario_name: str,
    variant: str,
) -> Mapping[str, Any]:
    project = require_mapping(config.get("project"), "project")
    schema_version = project.get("schema_version")

    if schema_version != 1:
        raise RunnerError(
            f"Unsupported configuration schema_version: {schema_version!r}; "
            "expected 1"
        )

    scenarios = require_mapping(config.get("scenarios"), "scenarios")

    if scenario_name not in scenarios:
        available = ", ".join(sorted(str(name) for name in scenarios))
        raise RunnerError(
            f"Unknown scenario {scenario_name!r}. Available scenarios: {available}"
        )

    scenario = require_mapping(
        scenarios[scenario_name],
        f"scenarios.{scenario_name}",
    )

    allowed_variants = scenario.get("allowed_variants")
    if not isinstance(allowed_variants, list) or not all(
        isinstance(item, str) for item in allowed_variants
    ):
        raise RunnerError(
            f"scenarios.{scenario_name}.allowed_variants "
            "must be a list of strings"
        )

    if variant not in allowed_variants:
        raise RunnerError(
            f"Variant {variant!r} is not permitted for scenario "
            f"{scenario_name!r}; allowed variants: {allowed_variants}"
        )

    if variant not in {"standard", "context_bound"}:
        raise RunnerError(
            "Only the 'standard' and 'context_bound' variants are supported"
        )

    testbed = require_mapping(config.get("testbed"), "testbed")

    if testbed.get("injection_layer") != "host_hci":
        raise RunnerError(
            "This runner only supports the controlled host/HCI injection layer"
        )

    if testbed.get("transparent_ota_mitm") is not False:
        raise RunnerError(
            "transparent_ota_mitm must be false for this experiment"
        )

    injection = require_mapping(
        scenario.get("injection", {}),
        f"scenarios.{scenario_name}.injection",
    )

    if injection.get("enabled", False):
        injection_layer = injection.get("layer")
        if injection_layer != "host_hci":
            raise RunnerError(
                f"Scenario {scenario_name!r} requests unsupported injection "
                f"layer {injection_layer!r}"
            )

    # The paper does not experimentally establish a BLE KeySize=7 downgrade.
    fields = injection.get("fields", [])
    if not isinstance(fields, list):
        raise RunnerError(
            f"scenarios.{scenario_name}.injection.fields must be a list"
        )

    forbidden_fields = {
        "key_size",
        "keysize",
        "ltk",
        "effective_key_length",
    }
    normalized_fields = {
        str(field).strip().lower().replace("-", "_") for field in fields
    }

    if forbidden_fields.intersection(normalized_fields):
        raise RunnerError(
            "This experimental runner does not enable KeySize or effective "
            "key-length downgrade injection. The low-entropy case belongs to "
            "the parameterized symbolic model, not the reported HCI experiment."
        )

    return scenario


class StrictFormatMap(dict):
    """Fail clearly when a command uses an unknown placeholder."""

    def __missing__(self, key: str) -> str:
        raise RunnerError(f"Unknown command placeholder: {{{key}}}")


def expand_command(
    command: Any,
    placeholders: Mapping[str, str],
    description: str,
) -> List[str]:
    if not isinstance(command, list):
        raise RunnerError(f"{description}.command must be an argv list")

    if not all(isinstance(item, str) for item in command):
        raise RunnerError(
            f"{description}.command must contain strings only"
        )

    formatter = StrictFormatMap(placeholders)

    try:
        return [item.format_map(formatter) for item in command]
    except ValueError as exc:
        raise RunnerError(
            f"Invalid placeholder syntax in {description}.command: {exc}"
        ) from exc


def command_spec(
    config: Mapping[str, Any],
    stage: str,
) -> Mapping[str, Any]:
    commands = require_mapping(config.get("commands", {}), "commands")
    raw_spec = commands.get(stage, {})

    if raw_spec is None:
        return {"enabled": False, "command": []}

    return require_mapping(raw_spec, f"commands.{stage}")


def write_command_record(
    run_dir: Path,
    stage: str,
    record: Mapping[str, Any],
) -> Path:
    command_dir = run_dir / "commands"
    command_dir.mkdir(parents=True, exist_ok=True)

    path = command_dir / f"{stage}.json"
    write_json(path, dict(record))
    return path


def run_synchronous_command(
    *,
    stage: str,
    argv: Sequence[str],
    run_dir: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    dry_run: bool,
) -> Dict[str, Any]:
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    stdout_path = logs_dir / f"{stage}.stdout.log"
    stderr_path = logs_dir / f"{stage}.stderr.log"

    record: Dict[str, Any] = {
        "stage": stage,
        "mode": "synchronous",
        "argv": list(argv),
        "argv_display": shlex.join(argv),
        "cwd": str(Path.cwd()),
        "started_at": utc_now(),
        "ended_at": None,
        "timeout_seconds": timeout_seconds,
        "dry_run": dry_run,
        "status": "planned" if dry_run else "running",
        "returncode": None,
        "stdout": str(stdout_path.relative_to(run_dir)),
        "stderr": str(stderr_path.relative_to(run_dir)),
    }

    write_command_record(run_dir, stage, record)

    if dry_run:
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        record["ended_at"] = utc_now()
        record["status"] = "not_executed"
        write_command_record(run_dir, stage, record)
        return record

    try:
        with stdout_path.open("wb") as stdout_fh, stderr_path.open(
            "wb"
        ) as stderr_fh:
            completed = subprocess.run(
                list(argv),
                cwd=Path.cwd(),
                env=dict(environment),
                stdout=stdout_fh,
                stderr=stderr_fh,
                timeout=timeout_seconds,
                check=False,
            )

        record["returncode"] = completed.returncode
        record["status"] = (
            "completed" if completed.returncode == 0 else "failed"
        )

    except subprocess.TimeoutExpired:
        record["status"] = "timeout"
        record["returncode"] = None

    except OSError as exc:
        record["status"] = "start_failed"
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["returncode"] = None

    finally:
        record["ended_at"] = utc_now()
        write_command_record(run_dir, stage, record)

    return record


def start_background_command(
    *,
    stage: str,
    argv: Sequence[str],
    run_dir: Path,
    environment: Mapping[str, str],
    dry_run: bool,
) -> Dict[str, Any]:
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    stdout_path = logs_dir / f"{stage}.stdout.log"
    stderr_path = logs_dir / f"{stage}.stderr.log"

    record: Dict[str, Any] = {
        "stage": stage,
        "mode": "background",
        "argv": list(argv),
        "argv_display": shlex.join(argv),
        "cwd": str(Path.cwd()),
        "started_at": utc_now(),
        "ended_at": None,
        "dry_run": dry_run,
        "status": "planned" if dry_run else "starting",
        "pid": None,
        "returncode": None,
        "stdout": str(stdout_path.relative_to(run_dir)),
        "stderr": str(stderr_path.relative_to(run_dir)),
        "_process": None,
        "_stdout_handle": None,
        "_stderr_handle": None,
    }

    serializable = {
        key: value
        for key, value in record.items()
        if not key.startswith("_")
    }
    write_command_record(run_dir, stage, serializable)

    if dry_run:
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        record["status"] = "not_executed"
        record["ended_at"] = utc_now()
        serializable = {
            key: value
            for key, value in record.items()
            if not key.startswith("_")
        }
        write_command_record(run_dir, stage, serializable)
        return record

    stdout_fh = stdout_path.open("wb")
    stderr_fh = stderr_path.open("wb")

    try:
        process = subprocess.Popen(
            list(argv),
            cwd=Path.cwd(),
            env=dict(environment),
            stdout=stdout_fh,
            stderr=stderr_fh,
            start_new_session=True,
        )
    except OSError as exc:
        stdout_fh.close()
        stderr_fh.close()

        record["status"] = "start_failed"
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["ended_at"] = utc_now()

        serializable = {
            key: value
            for key, value in record.items()
            if not key.startswith("_")
        }
        write_command_record(run_dir, stage, serializable)
        return record

    record["_process"] = process
    record["_stdout_handle"] = stdout_fh
    record["_stderr_handle"] = stderr_fh
    record["pid"] = process.pid
    record["status"] = "running"

    serializable = {
        key: value
        for key, value in record.items()
        if not key.startswith("_")
    }
    write_command_record(run_dir, stage, serializable)

    return record


def stop_background_command(
    *,
    stage: str,
    background: Dict[str, Any],
    run_dir: Path,
    grace_seconds: float = 5.0,
) -> Dict[str, Any]:
    process = background.get("_process")

    if process is None:
        return background

    returncode = process.poll()

    if returncode is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.terminate()
            except OSError:
                pass

        try:
            returncode = process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    process.kill()
                except OSError:
                    pass
            returncode = process.wait()

    stdout_fh = background.get("_stdout_handle")
    stderr_fh = background.get("_stderr_handle")

    if stdout_fh is not None:
        stdout_fh.close()
    if stderr_fh is not None:
        stderr_fh.close()

    background["returncode"] = returncode
    background["ended_at"] = utc_now()

    # Capture tools are commonly terminated deliberately after the experiment.
    if returncode in (0, -signal.SIGTERM, 128 + signal.SIGTERM):
        background["status"] = "stopped"
    else:
        background["status"] = "failed"

    serializable = {
        key: value
        for key, value in background.items()
        if not key.startswith("_")
    }
    write_command_record(run_dir, stage, serializable)

    return background


def create_run_id(
    scenario: str,
    variant: str,
    repetition: int,
) -> str:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    suffix = uuid.uuid4().hex[:8]

    return "-".join(
        [
            timestamp,
            sanitize_component(scenario),
            sanitize_component(variant),
            f"{repetition:04d}",
            suffix,
        ]
    )


def create_artifact_directories(
    run_dir: Path,
    config: Mapping[str, Any],
) -> None:
    run_dir.mkdir(parents=True, exist_ok=False)

    configured = get_nested(
        config,
        ("artifacts", "directories"),
        default=[],
    )

    if not isinstance(configured, list) or not all(
        isinstance(item, str) for item in configured
    ):
        raise RunnerError("artifacts.directories must be a list of strings")

    required = {
        "hci",
        "pcap",
        "injected",
        "analysis",
        "logs",
        "commands",
    }

    for directory in sorted(required.union(configured)):
        relative = Path(directory)

        if relative.is_absolute() or ".." in relative.parts:
            raise RunnerError(
                f"Unsafe artifact directory path: {directory!r}"
            )

        (run_dir / relative).mkdir(parents=True, exist_ok=True)


def build_environment(
    run_dir: Path,
    scenario: str,
    variant: str,
    run_id: str,
) -> Dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "BLE_EXPERIMENT_RUN_DIR": str(run_dir),
            "BLE_EXPERIMENT_RUN_ID": run_id,
            "BLE_EXPERIMENT_SCENARIO": scenario,
            "BLE_EXPERIMENT_VARIANT": variant,
            "PYTHONUNBUFFERED": "1",
        }
    )
    return environment


def build_placeholders(
    *,
    run_dir: Path,
    run_id: str,
    scenario: str,
    variant: str,
    config_snapshot: Path,
    config: Mapping[str, Any],
) -> Dict[str, str]:
    controller = str(
        get_nested(
            config,
            ("capture", "hci", "controller"),
            default=get_nested(
                config,
                ("testbed", "responder_controller"),
                default="",
            ),
        )
    )

    return {
        "run_dir": str(run_dir.resolve()),
        "run_id": run_id,
        "scenario": scenario,
        "variant": variant,
        "config_snapshot": str(config_snapshot.resolve()),
        "hci_controller": controller,
        "initiator_controller": str(
            get_nested(
                config,
                ("testbed", "initiator_controller"),
                default="",
            )
        ),
        "responder_controller": str(
            get_nested(
                config,
                ("testbed", "responder_controller"),
                default="",
            )
        ),
        "initiator_address": str(
            get_nested(
                config,
                ("testbed", "initiator_address"),
                default="",
            )
        ),
        "responder_address": str(
            get_nested(
                config,
                ("testbed", "responder_address"),
                default="",
            )
        ),
    }


def execute_configured_stage(
    *,
    config: Mapping[str, Any],
    stage: str,
    run_dir: Path,
    placeholders: Mapping[str, str],
    environment: Mapping[str, str],
    timeout_seconds: int,
    dry_run: bool,
    required: bool = False,
) -> Optional[Dict[str, Any]]:
    spec = command_spec(config, stage)
    enabled = spec.get("enabled", False)

    if not isinstance(enabled, bool):
        raise RunnerError(f"commands.{stage}.enabled must be boolean")

    raw_command = spec.get("command", [])

    if not enabled:
        record = {
            "stage": stage,
            "mode": "synchronous",
            "argv": raw_command if isinstance(raw_command, list) else [],
            "started_at": utc_now(),
            "ended_at": utc_now(),
            "dry_run": dry_run,
            "status": "disabled",
            "returncode": None,
        }
        write_command_record(run_dir, stage, record)

        if required and not dry_run:
            raise RunnerError(
                f"Required command stage {stage!r} is disabled"
            )

        return None

    argv = expand_command(
        raw_command,
        placeholders,
        f"commands.{stage}",
    )

    if not argv:
        raise RunnerError(
            f"commands.{stage} is enabled but has an empty command"
        )

    return run_synchronous_command(
        stage=stage,
        argv=argv,
        run_dir=run_dir,
        environment=environment,
        timeout_seconds=timeout_seconds,
        dry_run=dry_run,
    )


def start_configured_capture(
    *,
    config: Mapping[str, Any],
    run_dir: Path,
    placeholders: Mapping[str, str],
    environment: Mapping[str, str],
    dry_run: bool,
) -> Optional[Dict[str, Any]]:
    spec = command_spec(config, "capture_start")
    enabled = spec.get("enabled", False)

    if not isinstance(enabled, bool):
        raise RunnerError("commands.capture_start.enabled must be boolean")

    raw_command = spec.get("command", [])

    if not enabled:
        record = {
            "stage": "capture_start",
            "mode": "background",
            "argv": raw_command if isinstance(raw_command, list) else [],
            "started_at": utc_now(),
            "ended_at": utc_now(),
            "dry_run": dry_run,
            "status": "disabled",
            "returncode": None,
        }
        write_command_record(run_dir, "capture_start", record)
        return None

    argv = expand_command(
        raw_command,
        placeholders,
        "commands.capture_start",
    )

    if not argv:
        raise RunnerError(
            "commands.capture_start is enabled but has an empty command"
        )

    return start_background_command(
        stage="capture_start",
        argv=argv,
        run_dir=run_dir,
        environment=environment,
        dry_run=dry_run,
    )


def inventory_artifacts(run_dir: Path) -> List[Dict[str, Any]]:
    inventory: List[Dict[str, Any]] = []

    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue

        relative = path.relative_to(run_dir)

        # Avoid a recursive manifest digest.
        if relative.as_posix() == "manifest.json":
            continue

        try:
            size = path.stat().st_size
            digest = sha256_file(path)
        except OSError as exc:
            inventory.append(
                {
                    "path": relative.as_posix(),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        inventory.append(
            {
                "path": relative.as_posix(),
                "size_bytes": size,
                "sha256": digest,
            }
        )

    return inventory


def determine_run_status(
    stage_records: Mapping[str, Optional[Mapping[str, Any]]],
    outcome_exists: bool,
    require_outcome: bool,
    dry_run: bool,
) -> str:
    if dry_run:
        return "dry_run"

    failure_states = {"failed", "timeout", "start_failed"}

    for record in stage_records.values():
        if record is not None and record.get("status") in failure_states:
            return "failed"

    if require_outcome and not outcome_exists:
        return "failed_missing_outcome"

    return "completed"


def execute_one_run(
    *,
    repository_root: Path,
    source_config_path: Path,
    config: Dict[str, Any],
    scenario: str,
    variant: str,
    repetition: int,
    artifact_root: Path,
    timeout_seconds: int,
    dry_run: bool,
) -> Dict[str, Any]:
    scenario_config = validate_configuration(config, scenario, variant)

    run_id = create_run_id(scenario, variant, repetition)
    run_dir = artifact_root / run_id
    create_artifact_directories(run_dir, config)

    effective_config = copy.deepcopy(config)
    effective_config["execution"] = {
        "run_id": run_id,
        "scenario": scenario,
        "variant": variant,
        "repetition": repetition,
        "timeout_seconds": timeout_seconds,
        "dry_run": dry_run,
        "injection_layer": "host_hci",
        "created_at": utc_now(),
    }

    config_snapshot = run_dir / "config.snapshot.yaml"
    write_yaml(config_snapshot, effective_config)

    placeholders = build_placeholders(
        run_dir=run_dir,
        run_id=run_id,
        scenario=scenario,
        variant=variant,
        config_snapshot=config_snapshot,
        config=effective_config,
    )

    environment = build_environment(
        run_dir=run_dir.resolve(),
        scenario=scenario,
        variant=variant,
        run_id=run_id,
    )

    manifest_path = run_dir / str(
        get_nested(
            config,
            ("analysis", "manifest_file"),
            default="manifest.json",
        )
    )

    outcome_relative = str(
        get_nested(
            config,
            ("analysis", "outcome_file"),
            default="raw_outcome_counts.json",
        )
    )
    outcome_path = run_dir / outcome_relative

    require_outcome = bool(
        get_nested(
            config,
            ("analysis", "require_observed_outcome_file"),
            default=False,
        )
    )

    manifest: Dict[str, Any] = {
        "schema_version": 1,
        "runner_version": SCRIPT_VERSION,
        "run_id": run_id,
        "scenario": scenario,
        "variant": variant,
        "repetition": repetition,
        "status": "initializing",
        "source": "observed" if not dry_run else "not_run",
        "started_at": utc_now(),
        "ended_at": None,
        "dry_run": dry_run,
        "injection_layer": "host_hci",
        "transparent_ota_mitm": False,
        "passive_observer": get_nested(
            config,
            ("testbed", "passive_observer"),
            default=None,
        ),
        "scenario_description": scenario_config.get("description"),
        "source_config": str(source_config_path),
        "config_snapshot": str(config_snapshot.relative_to(run_dir)),
        "repository": {
            "root": str(repository_root),
            "revision": get_git_revision(repository_root),
            "dirty": get_git_dirty(repository_root),
        },
        "runtime": {
            "python": sys.version,
            "executable": sys.executable,
            "platform": platform.platform(),
            "hostname": platform.node(),
            "kernel": platform.release(),
        },
        "testbed": copy.deepcopy(config.get("testbed", {})),
        "stages": {},
        "outcome": {
            "path": outcome_relative,
            "exists": False,
            "sha256": None,
        },
        "artifacts": [],
        "errors": [],
    }
    write_json(manifest_path, manifest)

    stage_records: Dict[str, Optional[Dict[str, Any]]] = {
        "prepare": None,
        "capture_start": None,
        "experiment": None,
        "analyze": None,
        "capture_stop": None,
        "cleanup": None,
    }

    background_capture: Optional[Dict[str, Any]] = None

    try:
        stage_records["prepare"] = execute_configured_stage(
            config=config,
            stage="prepare",
            run_dir=run_dir,
            placeholders=placeholders,
            environment=environment,
            timeout_seconds=timeout_seconds,
            dry_run=dry_run,
        )

        if (
            stage_records["prepare"] is not None
            and stage_records["prepare"].get("status")
            in {"failed", "timeout", "start_failed"}
        ):
            raise RunnerError("Prepare stage failed")

        background_capture = start_configured_capture(
            config=config,
            run_dir=run_dir,
            placeholders=placeholders,
            environment=environment,
            dry_run=dry_run,
        )
        stage_records["capture_start"] = background_capture

        if (
            background_capture is not None
            and background_capture.get("status") == "start_failed"
        ):
            raise RunnerError("Capture process failed to start")

        # Give a real capture process a short initialization interval.
        if (
            not dry_run
            and background_capture is not None
            and background_capture.get("status") == "running"
        ):
            time.sleep(1.0)

            process = background_capture.get("_process")
            if process is not None and process.poll() is not None:
                background_capture["returncode"] = process.returncode
                background_capture["status"] = "failed"
                raise RunnerError(
                    "Capture process exited before experiment execution"
                )

        stage_records["experiment"] = execute_configured_stage(
            config=config,
            stage="experiment",
            run_dir=run_dir,
            placeholders=placeholders,
            environment=environment,
            timeout_seconds=timeout_seconds,
            dry_run=dry_run,
            required=True,
        )

        if (
            stage_records["experiment"] is not None
            and stage_records["experiment"].get("status")
            in {"failed", "timeout", "start_failed"}
        ):
            raise RunnerError("Experiment command failed")

        stage_records["analyze"] = execute_configured_stage(
            config=config,
            stage="analyze",
            run_dir=run_dir,
            placeholders=placeholders,
            environment=environment,
            timeout_seconds=timeout_seconds,
            dry_run=dry_run,
        )

        if (
            stage_records["analyze"] is not None
            and stage_records["analyze"].get("status")
            in {"failed", "timeout", "start_failed"}
        ):
            raise RunnerError("Analysis command failed")

    except Exception as exc:
        manifest["errors"].append(
            {
                "time": utc_now(),
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )

    finally:
        try:
            # An optional explicit stop command may flush or finalize a capture
            # tool before the runner terminates the background process.
            stage_records["capture_stop"] = execute_configured_stage(
                config=config,
                stage="capture_stop",
                run_dir=run_dir,
                placeholders=placeholders,
                environment=environment,
                timeout_seconds=timeout_seconds,
                dry_run=dry_run,
            )
        except Exception as exc:
            manifest["errors"].append(
                {
                    "time": utc_now(),
                    "type": type(exc).__name__,
                    "message": f"capture_stop: {exc}",
                }
            )

        if background_capture is not None:
            try:
                stage_records["capture_start"] = stop_background_command(
                    stage="capture_start",
                    background=background_capture,
                    run_dir=run_dir,
                )
            except Exception as exc:
                manifest["errors"].append(
                    {
                        "time": utc_now(),
                        "type": type(exc).__name__,
                        "message": f"capture termination: {exc}",
                    }
                )

        try:
            stage_records["cleanup"] = execute_configured_stage(
                config=config,
                stage="cleanup",
                run_dir=run_dir,
                placeholders=placeholders,
                environment=environment,
                timeout_seconds=timeout_seconds,
                dry_run=dry_run,
            )
        except Exception as exc:
            manifest["errors"].append(
                {
                    "time": utc_now(),
                    "type": type(exc).__name__,
                    "message": f"cleanup: {exc}",
                }
            )

    outcome_exists = outcome_path.is_file()
    manifest["outcome"]["exists"] = outcome_exists

    if outcome_exists:
        manifest["outcome"]["sha256"] = sha256_file(outcome_path)

    serializable_stages: Dict[str, Any] = {}
    for stage, record in stage_records.items():
        if record is None:
            serializable_stages[stage] = None
            continue

        serializable_stages[stage] = {
            key: value
            for key, value in record.items()
            if not key.startswith("_")
        }

    manifest["stages"] = serializable_stages
    manifest["status"] = determine_run_status(
        stage_records=serializable_stages,
        outcome_exists=outcome_exists,
        require_outcome=require_outcome,
        dry_run=dry_run,
    )

    if manifest["errors"] and manifest["status"] == "completed":
        manifest["status"] = "failed"

    manifest["ended_at"] = utc_now()
    manifest["artifacts"] = inventory_artifacts(run_dir)
    write_json(manifest_path, manifest)

    return {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "manifest": str(manifest_path),
        "status": manifest["status"],
    }


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run controlled BLE SMP Passkey Entry HCI experiments and "
            "preserve per-run artifacts."
        )
    )

    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="YAML experiment configuration",
    )
    parser.add_argument(
        "--scenario",
        help=(
            "Scenario name. Defaults to defaults.scenario in the "
            "configuration."
        ),
    )
    parser.add_argument(
        "--variant",
        choices=("standard", "context_bound"),
        help=(
            "Protocol variant. Defaults to defaults.variant in the "
            "configuration."
        ),
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        help=(
            "Number of runs. Defaults to defaults.repetitions in the "
            "configuration."
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        help=(
            "Timeout for each synchronous command. Defaults to "
            "defaults.timeout_seconds."
        ),
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        help=(
            "Artifact root directory. Defaults to defaults.artifact_root."
        ),
    )

    dry_run_group = parser.add_mutually_exclusive_group()
    dry_run_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Create the plan and artifacts without executing commands",
    )
    dry_run_group.add_argument(
        "--execute",
        action="store_true",
        help="Execute commands enabled in the configuration",
    )

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_arguments(argv)

    try:
        config_path = args.config.expanduser().resolve()
        config = load_yaml(config_path)
        defaults = require_mapping(config.get("defaults", {}), "defaults")

        scenario = args.scenario or defaults.get("scenario")
        variant = args.variant or defaults.get("variant")

        if not isinstance(scenario, str) or not scenario:
            raise RunnerError(
                "Scenario must be supplied by --scenario or defaults.scenario"
            )

        if not isinstance(variant, str) or not variant:
            raise RunnerError(
                "Variant must be supplied by --variant or defaults.variant"
            )

        repetitions_raw = (
            args.repetitions
            if args.repetitions is not None
            else defaults.get("repetitions", 1)
        )
        repetitions = require_positive_integer(
            repetitions_raw,
            "repetitions",
        )

        timeout_raw = (
            args.timeout_seconds
            if args.timeout_seconds is not None
            else defaults.get("timeout_seconds", 120)
        )
        timeout_seconds = require_positive_integer(
            timeout_raw,
            "timeout_seconds",
        )

        configured_dry_run = defaults.get("dry_run", True)
        if not isinstance(configured_dry_run, bool):
            raise RunnerError("defaults.dry_run must be boolean")

        if args.execute:
            dry_run = False
        elif args.dry_run:
            dry_run = True
        else:
            dry_run = configured_dry_run

        artifact_root_raw: Any
        if args.artifact_root is not None:
            artifact_root_raw = args.artifact_root
        else:
            artifact_root_raw = defaults.get("artifact_root", "artifacts")

        artifact_root = Path(artifact_root_raw).expanduser()
        if not artifact_root.is_absolute():
            artifact_root = Path.cwd() / artifact_root
        artifact_root = artifact_root.resolve()
        artifact_root.mkdir(parents=True, exist_ok=True)

        repository_root = Path(__file__).resolve().parents[1]

        # Validate before creating any per-run directory.
        validate_configuration(config, scenario, variant)

        results: List[Dict[str, Any]] = []

        for repetition in range(1, repetitions + 1):
            result = execute_one_run(
                repository_root=repository_root,
                source_config_path=config_path,
                config=config,
                scenario=scenario,
                variant=variant,
                repetition=repetition,
                artifact_root=artifact_root,
                timeout_seconds=timeout_seconds,
                dry_run=dry_run,
            )
            results.append(result)

            print(
                f"[{result['status']}] "
                f"{result['run_id']} -> {result['run_dir']}",
                flush=True,
            )

        summary = {
            "schema_version": 1,
            "created_at": utc_now(),
            "config": str(config_path),
            "scenario": scenario,
            "variant": variant,
            "repetitions": repetitions,
            "dry_run": dry_run,
            "runs": results,
        }

        summary_name = (
            "batch-"
            + dt.datetime.now(dt.timezone.utc).strftime(
                "%Y%m%dT%H%M%S.%fZ"
            )
            + "-"
            + uuid.uuid4().hex[:8]
            + ".json"
        )
        summary_path = artifact_root / summary_name
        write_json(summary_path, summary)

        print(f"Batch summary: {summary_path}", flush=True)

        failed_statuses = {
            "failed",
            "failed_missing_outcome",
        }
        return 1 if any(
            result["status"] in failed_statuses for result in results
        ) else 0

    except RunnerError as exc:
        print(f"configuration/execution error: {exc}", file=sys.stderr)
        return 2

    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
