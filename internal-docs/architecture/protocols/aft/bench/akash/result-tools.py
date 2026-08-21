#!/usr/bin/env python3
"""Fail-closed result tooling for the RES-P4.3 AFT Akash campaign."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import math
import os
import platform
import re
import socketserver
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

SCENARIO_ROWS = {
    "paper_guardian_majority_4v": 3,
    "paper_guardian_majority_7v": 3,
    "paper_asymptote_4v": 4,
    "paper_asymptote_7v": 4,
}
REQUIRED_METRICS = (
    "injection_tps",
    "sustained_tps",
    "commit_p50_ms",
    "commit_p95_ms",
    "commit_p99_ms",
    "commit_max_ms",
)
THRESHOLDS = {
    "injection_tps": 0.10,
    "sustained_tps": 0.10,
    "commit_p50_ms": 0.10,
    "commit_p95_ms": 0.10,
    "commit_p99_ms": 0.15,
    "commit_max_ms": 0.15,
}


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, path)


def write_json(path: Path, value: object) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def parse_markdown_table(raw: str, scenario_filter: str) -> list[dict[str, object]]:
    lines = [line.strip() for line in raw.splitlines()]
    header_index = next(
        (index for index, line in enumerate(lines) if line.startswith("| scenario | validators |")),
        None,
    )
    if header_index is None or header_index + 2 > len(lines):
        raise ValueError("benchmark output contains no AFT result table")
    headers = [cell.strip() for cell in lines[header_index].strip("|").split("|")]
    if any(metric not in headers for metric in REQUIRED_METRICS):
        missing = sorted(set(REQUIRED_METRICS).difference(headers))
        raise ValueError(f"benchmark table is missing required metrics: {missing}")

    rows: list[dict[str, object]] = []
    for line in lines[header_index + 2 :]:
        if not line.startswith("|"):
            if rows:
                break
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != len(headers):
            raise ValueError(f"malformed benchmark row has {len(cells)} cells; expected {len(headers)}")
        row: dict[str, object] = dict(zip(headers, cells))
        scenario = str(row["scenario"])
        if scenario not in SCENARIO_ROWS:
            raise ValueError(f"unexpected scenario {scenario!r}")
        for metric in REQUIRED_METRICS:
            try:
                number = float(str(row[metric]))
            except ValueError as error:
                raise ValueError(f"{scenario}/{row['lane']} has nonnumeric {metric}") from error
            if not math.isfinite(number) or number < 0:
                raise ValueError(f"{scenario}/{row['lane']} has invalid {metric}={number}")
            row[metric] = number
        for field in ("validators", "attempted", "accepted", "committed"):
            try:
                row[field] = int(str(row[field]))
            except ValueError as error:
                raise ValueError(f"{scenario}/{row['lane']} has invalid {field}") from error
        if row["attempted"] != row["accepted"] or row["accepted"] != row["committed"]:
            raise ValueError(f"{scenario}/{row['lane']} did not commit every attempted transaction")
        rows.append(row)

    expected_scenarios = [scenario_filter] if scenario_filter else list(SCENARIO_ROWS)
    if any(scenario not in SCENARIO_ROWS for scenario in expected_scenarios):
        raise ValueError(f"unknown scenario filter {scenario_filter!r}")
    expected = sum(SCENARIO_ROWS[scenario] for scenario in expected_scenarios)
    if len(rows) != expected:
        raise ValueError(f"partial matrix: got {len(rows)} rows; expected {expected}")
    keys = [(str(row["scenario"]), str(row["lane"])) for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError("benchmark table contains duplicate scenario/lane rows")
    if set(row["scenario"] for row in rows) != set(expected_scenarios):
        raise ValueError("benchmark table scenario set does not match the requested matrix")
    return rows


def collect(args: argparse.Namespace) -> None:
    raw_path = Path(args.input)
    rows = parse_markdown_table(raw_path.read_text(), args.scenario)
    write_json(
        Path(args.output),
        {
            "schema_version": "ioi.aft.benchmark-pass.v1",
            "campaign_id": args.campaign,
            "pass": args.pass_number,
            "scenario_filter": args.scenario or None,
            "row_count": len(rows),
            "rows": rows,
            "raw_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        },
    )


def relative_spread(values: list[float]) -> float:
    median = statistics.median(values)
    if median == 0:
        return 0.0 if max(values) == min(values) else math.inf
    return (max(values) - min(values)) / median


def aggregate(args: argparse.Namespace) -> None:
    paths = sorted(Path().glob(args.inputs))
    if len(paths) != args.repeats:
        raise ValueError(f"found {len(paths)} measured passes; expected {args.repeats}")
    passes = [json.loads(path.read_text()) for path in paths]
    if [item["pass"] for item in passes] != list(range(1, args.repeats + 1)):
        raise ValueError("measured pass sequence is incomplete or duplicated")
    row_maps = [
        {(row["scenario"], row["lane"]): row for row in item["rows"]} for item in passes
    ]
    expected_keys = set(row_maps[0])
    if any(set(row_map) != expected_keys for row_map in row_maps[1:]):
        raise ValueError("scenario/lane matrix changed between measured passes")

    summaries = []
    all_within = True
    for scenario, lane in sorted(expected_keys):
        metrics = {}
        row_within = True
        for metric in REQUIRED_METRICS:
            values = [float(row_map[(scenario, lane)][metric]) for row_map in row_maps]
            spread = relative_spread(values)
            threshold = THRESHOLDS[metric]
            within = spread <= threshold
            row_within &= within
            metrics[metric] = {
                "min": min(values),
                "median": statistics.median(values),
                "max": max(values),
                "relative_spread": spread,
                "threshold": threshold,
                "within_threshold": within,
            }
        all_within &= row_within
        summaries.append(
            {"scenario": scenario, "lane": lane, "within_threshold": row_within, "metrics": metrics}
        )

    verdict = "reproduced_within_threshold" if all_within else "variance_caveated"
    result = {
        "schema_version": "ioi.aft.benchmark-campaign.v1",
        "campaign_id": args.campaign,
        "measured_passes": args.repeats,
        "row_count_per_pass": len(expected_keys),
        "threshold_policy": THRESHOLDS,
        "verdict": verdict,
        "all_rows_within_threshold": all_within,
        "summaries": summaries,
        "pass_artifacts": [str(path) for path in paths],
    }
    write_json(Path(args.output_json), result)
    markdown = [
        f"# AFT benchmark campaign `{args.campaign}`",
        "",
        f"Verdict: **{verdict.replace('_', ' ')}**",
        "",
        "| scenario | lane | injection TPS | sustained TPS | commit p50 ms | p95 ms | p99 ms | max ms | threshold verdict |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for row in summaries:
        medians = [row["metrics"][metric]["median"] for metric in REQUIRED_METRICS]
        markdown.append(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                row["scenario"], row["lane"], *(f"{value:.2f}" for value in medians),
                "within" if row["within_threshold"] else "variance-caveated",
            )
        )
    atomic_write(Path(args.output_markdown), "\n".join(markdown) + "\n")


def environment_manifest(args: argparse.Namespace) -> None:
    cpu_model = "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        match = re.search(r"^model name\s*:\s*(.+)$", cpuinfo.read_text(), re.MULTILINE)
        if match:
            cpu_model = match.group(1)
    governor_path = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    def version(command: str) -> str:
        try:
            return subprocess.run(
                [command, "--version"], check=True, capture_output=True, text=True
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return "unknown"

    manifest = {
        "schema_version": "ioi.aft.environment-manifest.v1",
        "campaign_id": args.campaign,
        "source_commit": args.commit,
        "image_digest": args.image_digest,
        "scenario_filter": args.scenario or None,
        "warmups": args.warmups,
        "measured_passes": args.repeats,
        "cpu_model": cpu_model,
        "cpu_cores_online": os.cpu_count(),
        "kernel_release": platform.release(),
        "machine": platform.machine(),
        "memory_kib": next(
            (int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:")),
            None,
        ),
        "governor": governor_path.read_text().strip() if governor_path.exists() else "unknown",
        "rustc": version("rustc"),
        "cargo": version("cargo"),
        "provider_host_attestation": "not_supplied_by_workload_runtime",
    }
    write_json(Path(args.output), manifest)


def status(args: argparse.Namespace) -> None:
    write_json(
        Path(args.output),
        {
            "schema_version": "ioi.aft.benchmark-status.v1",
            "campaign_id": args.campaign,
            "state": args.state,
            "detail": args.detail,
        },
    )


def manifest(args: argparse.Namespace) -> None:
    root = Path(args.directory)
    candidates = sorted(
        path for path in root.iterdir() if path.is_file() and path.name not in {args.output, "status.json"}
    )
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in candidates]
    atomic_write(root / args.output, "\n".join(lines) + "\n")


def scan(args: argparse.Namespace) -> None:
    canaries = [item for item in args.canaries.split(",") if item]
    if not canaries:
        return
    for path in Path(args.directory).iterdir():
        if not path.is_file():
            continue
        data = path.read_bytes()
        for canary in canaries:
            if canary.encode() in data:
                raise ValueError(f"secret canary appeared in artifact {path.name}")


class ResultHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ioi-aft-result/1"

    def do_GET(self) -> None:  # noqa: N802
        expected = f"Bearer {self.server.token}"  # type: ignore[attr-defined]
        if self.headers.get("Authorization") != expected:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            return
        routes = {
            "/status": "status.json",
            "/environment": "environment.json",
            "/results": "result.json",
            "/results.md": "result.md",
            "/manifest": "manifest.sha256",
        }
        name = routes.get(self.path)
        if not name:
            self.send_error(404)
            return
        path = self.server.root / name  # type: ignore[attr-defined]
        if not path.exists():
            self.send_error(404)
            return
        payload = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json" if name.endswith(".json") else "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[result-server] {format % args}", file=sys.stderr)


def serve(args: argparse.Namespace) -> None:
    token = os.environ.get("AFT_RESULT_BEARER_TOKEN", "")
    if len(token) < 32:
        raise ValueError("AFT_RESULT_BEARER_TOKEN must contain at least 32 characters")
    with socketserver.ThreadingTCPServer(("0.0.0.0", args.port), ResultHandler) as server:
        server.root = Path(args.directory)  # type: ignore[attr-defined]
        server.token = token  # type: ignore[attr-defined]
        server.serve_forever()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--input", required=True)
    collect_parser.add_argument("--output", required=True)
    collect_parser.add_argument("--campaign", required=True)
    collect_parser.add_argument("--pass-number", type=int, required=True)
    collect_parser.add_argument("--scenario", default="")
    collect_parser.set_defaults(function=collect)
    aggregate_parser = sub.add_parser("aggregate")
    aggregate_parser.add_argument("--inputs", required=True)
    aggregate_parser.add_argument("--repeats", type=int, required=True)
    aggregate_parser.add_argument("--campaign", required=True)
    aggregate_parser.add_argument("--output-json", required=True)
    aggregate_parser.add_argument("--output-markdown", required=True)
    aggregate_parser.set_defaults(function=aggregate)
    environment_parser = sub.add_parser("environment")
    for name in ("campaign", "commit", "image-digest", "scenario", "output"):
        environment_parser.add_argument(f"--{name}", required=name not in {"scenario"})
    environment_parser.add_argument("--warmups", type=int, required=True)
    environment_parser.add_argument("--repeats", type=int, required=True)
    environment_parser.set_defaults(function=environment_manifest)
    status_parser = sub.add_parser("status")
    for name in ("output", "campaign", "state", "detail"):
        status_parser.add_argument(f"--{name}", required=True)
    status_parser.set_defaults(function=status)
    manifest_parser = sub.add_parser("manifest")
    manifest_parser.add_argument("--directory", required=True)
    manifest_parser.add_argument("--output", default="manifest.sha256")
    manifest_parser.set_defaults(function=manifest)
    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("--directory", required=True)
    scan_parser.add_argument("--canaries", default="")
    scan_parser.set_defaults(function=scan)
    serve_parser = sub.add_parser("serve")
    serve_parser.add_argument("--directory", required=True)
    serve_parser.add_argument("--port", type=int, default=8080)
    serve_parser.set_defaults(function=serve)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.function(args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"result-tools: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
