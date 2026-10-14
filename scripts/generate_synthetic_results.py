#!/usr/bin/env python3

from __future__ import annotations

import csv
import hashlib
import json
import random
from pathlib import Path


SEED = 20260515
RUNS_PER_CELL = 1000
OUT = Path("artifacts")


CELLS = [
    {
        "scenario_id": "normal",
        "variant": "standard",
        "counts": {"pair": 987, "block": 0, "timeout": 13},
        "packet_id": None,
        "packet_hex": None,
        "expected": "pair",
        "timeout_reasons": {
            "link_loss": 4,
            "smp_timer": 5,
            "injector_timeout": 3,
            "controller_reset": 1,
        },
    },
    {
        "scenario_id": "normal",
        "variant": "context_bound",
        "counts": {"pair": 985, "block": 0, "timeout": 15},
        "packet_id": None,
        "packet_hex": None,
        "expected": "pair",
        "timeout_reasons": {
            "link_loss": 5,
            "smp_timer": 5,
            "injector_timeout": 4,
            "controller_reset": 1,
        },
    },
    {
        "scenario_id": "iocap_tampered",
        "variant": "standard",
        "counts": {"pair": 974, "block": 0, "timeout": 26},
        "packet_id": "pairing_request_iocap_tampered",
        "packet_hex": "0102000d100101",
        "expected": "pair",
        "timeout_reasons": {
            "link_loss": 9,
            "smp_timer": 9,
            "injector_timeout": 6,
            "controller_reset": 2,
        },
    },
    {
        "scenario_id": "iocap_tampered",
        "variant": "context_bound",
        "counts": {"pair": 0, "block": 981, "timeout": 19},
        "packet_id": "pairing_request_iocap_tampered",
        "packet_hex": "0102000d100101",
        "expected": "block",
        "timeout_reasons": {
            "link_loss": 6,
            "smp_timer": 7,
            "injector_timeout": 5,
            "controller_reset": 1,
        },
    },
    {
        "scenario_id": "authreq_tampered",
        "variant": "standard",
        "counts": {"pair": 982, "block": 0, "timeout": 18},
        "packet_id": "pairing_request_authreq_tampered",
        "packet_hex": "01030009100101",
        "expected": "pair",
        "timeout_reasons": {
            "link_loss": 6,
            "smp_timer": 6,
            "injector_timeout": 5,
            "controller_reset": 1,
        },
    },
    {
        "scenario_id": "authreq_tampered",
        "variant": "context_bound",
        "counts": {"pair": 0, "block": 978, "timeout": 22},
        "packet_id": "pairing_request_authreq_tampered",
        "packet_hex": "01030009100101",
        "expected": "block",
        "timeout_reasons": {
            "link_loss": 7,
            "smp_timer": 8,
            "injector_timeout": 6,
            "controller_reset": 1,
        },
    },
]


def weighted_items(mapping: dict[str, int]) -> list[str]:
    result = []
    for key, count in mapping.items():
        result.extend([key] * count)
    return result


def deterministic_duration_ms(outcome: str, reason: str | None,
                              rng: random.Random) -> int:
    if outcome == "pair":
        return rng.randint(650, 1450)

    if outcome == "block":
        return rng.randint(500, 1800)

    if reason == "smp_timer":
        return rng.randint(30000, 30500)

    if reason == "injector_timeout":
        return rng.randint(10000, 15000)

    if reason == "controller_reset":
        return rng.randint(2000, 7000)

    return rng.randint(1000, 8000)


def make_cell_records(cell: dict, rng: random.Random) -> list[dict]:
    counts = cell["counts"]

    outcomes = (
        ["pair"] * counts["pair"]
        + ["block"] * counts["block"]
        + ["timeout"] * counts["timeout"]
    )
    rng.shuffle(outcomes)

    timeout_reasons = weighted_items(cell["timeout_reasons"])
    rng.shuffle(timeout_reasons)

    records = []
    timeout_index = 0

    for index, outcome in enumerate(outcomes, start=1):
        reason = None
        if outcome == "timeout":
            reason = timeout_reasons[timeout_index]
            timeout_index += 1

        run_id = (
            f"{cell['scenario_id']}-"
            f"{cell['variant']}-"
            f"{index:06d}"
        )

        record = {
            "run_id": run_id,
            "run_index": index,
            "scenario_id": cell["scenario_id"],
            "variant": cell["variant"],
            "seed": SEED,
            "injected_packet_id": cell["packet_id"],
            "injected_packet_hex": cell["packet_hex"],
            "expected_outcome": cell["expected"],
            "observed_outcome": outcome,
            "timeout_reason": reason,
            "duration_ms": deterministic_duration_ms(
                outcome, reason, rng
            ),
            "hci_log": (
                f"hci/{run_id}.btsnoop"
            ),
            "pcap": (
                f"pcap/{run_id}.pcapng"
            ),
            "synthetic": True,
            "evidence_status": "simulated_not_measured",
        }

        records.append(record)

    return records


def main() -> None:
    rng = random.Random(SEED)
    records = []

    for cell in CELLS:
        records.extend(make_cell_records(cell, rng))

    OUT.mkdir(parents=True, exist_ok=True)

    jsonl_path = OUT / "runs.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fp:
        for record in records:
            fp.write(json.dumps(record, sort_keys=True) + "\n")

    csv_path = OUT / "outcomes.csv"
    fields = list(records[0].keys())
    with csv_path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)

    summary = []
    for cell in CELLS:
        subset = [
            r for r in records
            if r["scenario_id"] == cell["scenario_id"]
            and r["variant"] == cell["variant"]
        ]

        row = {
            "scenario_id": cell["scenario_id"],
            "variant": cell["variant"],
            "total": len(subset),
            "pair": sum(
                r["observed_outcome"] == "pair" for r in subset
            ),
            "block": sum(
                r["observed_outcome"] == "block" for r in subset
            ),
            "timeout": sum(
                r["observed_outcome"] == "timeout" for r in subset
            ),
            "synthetic": True,
        }
        summary.append(row)

    summary_path = OUT / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "format_version": 1,
        "data_status": "synthetic",
        "source": "deterministic_simulation",
        "not_measured": True,
        "seed": SEED,
        "runs_per_cell": RUNS_PER_CELL,
        "total_runs": len(records),
        "files": {},
    }

    for path in [jsonl_path, csv_path, summary_path]:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest["files"][str(path.relative_to(OUT))] = {
            "sha256": digest,
            "bytes": path.stat().st_size,
        }

    (OUT / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"generated {len(records)} synthetic runs")
    print(f"output: {OUT}")


if __name__ == "__main__":
    main()
