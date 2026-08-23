#!/usr/bin/env python3
"""Fail-closed result tooling for the RES-P4.3 AFT Akash campaign."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import itertools
import json
import math
import os
import platform
import re
import socketserver
import ssl
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

SCENARIO_LANES = {
    "paper_guardian_majority_4v": ("base_final",),
    "paper_guardian_majority_7v": ("base_final",),
    "paper_asymptote_4v": (
        "base_final", "canonical_ordering", "durable_collapse", "sealed_final"
    ),
    "paper_asymptote_7v": (
        "base_final", "canonical_ordering", "durable_collapse", "sealed_final"
    ),
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
ALLOWED_STATES = {"starting", "warmup", "measuring", "complete", "failed"}
MODE_ALIASES = {
    "GuardianMajority": "guardian_majority",
    "guardian_majority": "guardian_majority",
    "Asymptote": "asymptote",
    "asymptote": "asymptote",
}
ENVIRONMENT_MATCH_FIELDS = (
    "source_commit",
    "image_digest",
    "protocol_version",
    "cpu_model",
    "cpu_cores_online",
    "kernel_release",
    "machine",
    "memory_kib",
    "governor",
)


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
        if scenario not in SCENARIO_LANES:
            raise ValueError(f"unexpected scenario {scenario!r}")
        mode = MODE_ALIASES.get(str(row["mode"]))
        if mode is None:
            raise ValueError(f"{scenario}/{row['lane']} has unsupported mode {row['mode']!r}")
        row["mode"] = mode
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

    expected_scenarios = [scenario_filter] if scenario_filter else list(SCENARIO_LANES)
    if any(scenario not in SCENARIO_LANES for scenario in expected_scenarios):
        raise ValueError(f"unknown scenario filter {scenario_filter!r}")
    expected = sum(len(SCENARIO_LANES[scenario]) for scenario in expected_scenarios)
    if len(rows) != expected:
        raise ValueError(f"partial matrix: got {len(rows)} rows; expected {expected}")
    keys = [(str(row["scenario"]), str(row["lane"])) for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError("benchmark table contains duplicate scenario/lane rows")
    if set(row["scenario"] for row in rows) != set(expected_scenarios):
        raise ValueError("benchmark table scenario set does not match the requested matrix")
    expected_keys = {
        (scenario, lane)
        for scenario in expected_scenarios
        for lane in SCENARIO_LANES[scenario]
    }
    if set(keys) != expected_keys:
        raise ValueError("benchmark table lane set does not match the canonical matrix")
    for row in rows:
        scenario = str(row["scenario"])
        expected_validators = 4 if scenario.endswith("_4v") else 7
        expected_mode = "asymptote" if "asymptote" in scenario else "guardian_majority"
        if row["validators"] != expected_validators or row["mode"] != expected_mode:
            raise ValueError(f"{scenario}/{row['lane']} has inconsistent scenario metadata")
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


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot compute a percentile over no values")
    position = quantile * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def exact_bootstrap_median_interval(values: list[float]) -> dict[str, object] | None:
    # The protocol fixes five measured passes. Enumerating 5^5 resamples makes
    # this deterministic and avoids publishing a seed-dependent interval.
    if len(values) < 5 or len(values) > 7:
        return None
    medians = [statistics.median(sample) for sample in itertools.product(values, repeat=len(values))]
    return {
        "confidence": 0.95,
        "lower": percentile(medians, 0.025),
        "upper": percentile(medians, 0.975),
        "method": "exact_bootstrap_median",
        "resamples": len(medians),
    }


def summarize_metric(values: list[float], threshold: float) -> dict[str, object]:
    median = statistics.median(values)
    mean = statistics.fmean(values)
    spread = relative_spread(values)
    mad = statistics.median(abs(value - median) for value in values)
    coefficient_of_variation = (
        statistics.stdev(values) / mean
        if len(values) > 1 and mean != 0
        else (0.0 if max(values) == min(values) else math.inf)
    )
    return {
        "count": len(values),
        "min": min(values),
        "median": median,
        "max": max(values),
        "median_absolute_deviation": mad,
        "coefficient_of_variation": coefficient_of_variation,
        "bootstrap_median_95": exact_bootstrap_median_interval(values),
        "relative_spread": spread,
        "threshold": threshold,
        "within_threshold": spread <= threshold,
    }


def aggregate(args: argparse.Namespace) -> None:
    paths = sorted(Path().glob(args.inputs))
    if len(paths) != args.repeats:
        raise ValueError(f"found {len(paths)} measured passes; expected {args.repeats}")
    passes = [json.loads(path.read_text()) for path in paths]
    if any(item.get("schema_version") != "ioi.aft.benchmark-pass.v1" for item in passes):
        raise ValueError("measured pass schema is unsupported")
    if any(item.get("campaign_id") != args.campaign for item in passes):
        raise ValueError("measured pass campaign identity does not match the aggregate")
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
            threshold = THRESHOLDS[metric]
            summary = summarize_metric(values, threshold)
            within = bool(summary["within_threshold"])
            row_within &= within
            metrics[metric] = summary
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


def compare_campaigns(args: argparse.Namespace) -> None:
    campaign_paths = [Path(args.campaign_a), Path(args.campaign_b)]
    campaigns = [json.loads(path.read_text()) for path in campaign_paths]
    environment_paths = [Path(args.environment_a), Path(args.environment_b)]
    environments = [json.loads(path.read_text()) for path in environment_paths]
    if any(item.get("schema_version") != "ioi.aft.benchmark-campaign.v1" for item in campaigns):
        raise ValueError("campaign comparison input schema is unsupported")
    campaign_ids = [str(item.get("campaign_id", "")) for item in campaigns]
    if not all(campaign_ids) or campaign_ids[0] == campaign_ids[1]:
        raise ValueError("campaign comparison requires two distinct campaign identities")
    if any(item.get("threshold_policy") != THRESHOLDS for item in campaigns):
        raise ValueError("campaign threshold policy differs from the fixed protocol")
    if any(
        item.get("schema_version") != "ioi.aft.environment-manifest.v1"
        for item in environments
    ):
        raise ValueError("campaign environment manifest schema is unsupported")
    if any(
        environments[index].get("campaign_id") != campaign_ids[index]
        for index in range(2)
    ):
        raise ValueError("environment manifest campaign identity differs from its campaign")
    missing_environment_fields = [
        field
        for field in ENVIRONMENT_MATCH_FIELDS
        if any(environment.get(field) in (None, "") for environment in environments)
    ]
    if missing_environment_fields:
        raise ValueError(
            f"environment manifests are missing comparison fields: {missing_environment_fields}"
        )
    environment_comparison = {
        field: {
            "campaign_a": environments[0][field],
            "campaign_b": environments[1][field],
            "matches": environments[0][field] == environments[1][field],
        }
        for field in ENVIRONMENT_MATCH_FIELDS
    }
    environment_compatible = all(
        comparison["matches"] for comparison in environment_comparison.values()
    )

    summary_maps = [
        {(row["scenario"], row["lane"]): row for row in item["summaries"]}
        for item in campaigns
    ]
    expected_keys = set(summary_maps[0])
    if not expected_keys or set(summary_maps[1]) != expected_keys:
        raise ValueError("campaign scenario/lane matrices differ")

    comparisons = []
    all_within = True
    for scenario, lane in sorted(expected_keys):
        metrics = {}
        row_within = True
        for metric in REQUIRED_METRICS:
            values = [
                float(summary_map[(scenario, lane)]["metrics"][metric]["median"])
                for summary_map in summary_maps
            ]
            spread = relative_spread(values)
            threshold = THRESHOLDS[metric]
            within = spread <= threshold
            row_within &= within
            metrics[metric] = {
                "campaign_a_median": values[0],
                "campaign_b_median": values[1],
                "relative_spread": spread,
                "threshold": threshold,
                "within_threshold": within,
            }
        all_within &= row_within
        comparisons.append(
            {"scenario": scenario, "lane": lane, "within_threshold": row_within, "metrics": metrics}
        )

    verdict = (
        "reproduced_within_threshold"
        if all_within and environment_compatible
        else "variance_caveated"
    )
    result = {
        "schema_version": "ioi.aft.benchmark-campaign-comparison.v1",
        "campaign_ids": campaign_ids,
        "campaign_artifacts": [str(path) for path in campaign_paths],
        "environment_artifacts": [str(path) for path in environment_paths],
        "environment_compatible": environment_compatible,
        "environment_comparison": environment_comparison,
        "threshold_policy": THRESHOLDS,
        "verdict": verdict,
        "all_rows_within_threshold": all_within,
        "comparisons": comparisons,
    }
    write_json(Path(args.output_json), result)
    markdown = [
        "# AFT cross-campaign comparison",
        "",
        f"Campaigns: `{campaign_ids[0]}` and `{campaign_ids[1]}`",
        "",
        f"Verdict: **{verdict.replace('_', ' ')}**",
        "",
        f"Environment compatible: **{'yes' if environment_compatible else 'no'}**",
        "",
        "| scenario | lane | threshold verdict |",
        "|---|---|---|",
    ]
    markdown.extend(
        f"| {row['scenario']} | {row['lane']} | "
        f"{'within' if row['within_threshold'] else 'variance-caveated'} |"
        for row in comparisons
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
        "protocol_version": args.protocol_version,
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
    if args.state not in ALLOWED_STATES:
        raise ValueError(f"invalid campaign state {args.state!r}")
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
    excluded = {args.output, args.json_output, "status.json"}
    candidates = sorted(
        path for path in root.iterdir() if path.is_file() and path.name not in excluded
    )
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in candidates]
    atomic_write(root / args.output, "\n".join(lines) + "\n")
    status_record = json.loads((root / "status.json").read_text())
    write_json(
        root / args.json_output,
        {
            "schema_version": "ioi.aft.artifact-manifest.v1",
            "campaign_id": status_record["campaign_id"],
            "artifacts": [
                {
                    "name": path.name,
                    "bytes": path.stat().st_size,
                    "sha256": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
                }
                for path in candidates
            ],
        },
    )


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
            "/manifest": "artifact-manifest.json",
        }
        name = routes.get(self.path)
        if not name:
            self.send_error(404)
            return
        path = self.server.root / name  # type: ignore[attr-defined]
        if not path.exists():
            self.send_error(404)
            return
        try:
            status_record = json.loads((self.server.root / "status.json").read_text())  # type: ignore[attr-defined]
            if status_record.get("state") not in ALLOWED_STATES:
                raise ValueError("invalid status state")
            if self.path in {"/results", "/results.md", "/manifest"}:
                if status_record.get("state") != "complete":
                    self.send_error(409, "campaign is not complete")
                    return
                manifest_record = json.loads(
                    (self.server.root / "artifact-manifest.json").read_text()  # type: ignore[attr-defined]
                )
                if manifest_record.get("campaign_id") != status_record.get("campaign_id"):
                    raise ValueError("manifest campaign identity mismatch")
                artifact = next(
                    (item for item in manifest_record.get("artifacts", []) if item.get("name") == name),
                    None,
                )
                if self.path != "/manifest" and artifact is None:
                    raise ValueError(f"{name} is absent from the artifact manifest")
                if artifact is not None:
                    digest = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
                    if digest != artifact.get("sha256") or path.stat().st_size != artifact.get("bytes"):
                        raise ValueError(f"{name} does not match the artifact manifest")
                if self.path == "/results":
                    result_record = json.loads(path.read_text())
                    if result_record.get("campaign_id") != status_record.get("campaign_id"):
                        raise ValueError("result campaign identity mismatch")
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            self.send_error(409, str(error))
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
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
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
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("--campaign-a", required=True)
    compare_parser.add_argument("--campaign-b", required=True)
    compare_parser.add_argument("--environment-a", required=True)
    compare_parser.add_argument("--environment-b", required=True)
    compare_parser.add_argument("--output-json", required=True)
    compare_parser.add_argument("--output-markdown", required=True)
    compare_parser.set_defaults(function=compare_campaigns)
    environment_parser = sub.add_parser("environment")
    for name in ("campaign", "commit", "image-digest", "protocol-version", "scenario", "output"):
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
    manifest_parser.add_argument("--json-output", default="artifact-manifest.json")
    manifest_parser.set_defaults(function=manifest)
    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("--directory", required=True)
    scan_parser.add_argument("--canaries", default="")
    scan_parser.set_defaults(function=scan)
    serve_parser = sub.add_parser("serve")
    serve_parser.add_argument("--directory", required=True)
    serve_parser.add_argument("--port", type=int, default=8080)
    serve_parser.add_argument("--tls-cert", required=True)
    serve_parser.add_argument("--tls-key", required=True)
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
