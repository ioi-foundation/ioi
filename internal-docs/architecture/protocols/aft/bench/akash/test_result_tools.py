#!/usr/bin/env python3

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "result-tools.py"
SCENARIOS = (
    ("paper_guardian_majority_4v", ("base_final", "canonical_ordering", "durable_collapse")),
    ("paper_guardian_majority_7v", ("base_final", "canonical_ordering", "durable_collapse")),
    ("paper_asymptote_4v", ("base_final", "canonical_ordering", "durable_collapse", "sealed_final")),
    ("paper_asymptote_7v", ("base_final", "canonical_ordering", "durable_collapse", "sealed_final")),
)
HEADER = (
    "| scenario | validators | mode | lane | attempted | accepted | committed | "
    "injection_tps | sustained_tps | commit_p50_ms | commit_p95_ms | commit_p99_ms | commit_max_ms |"
)


def table(multiplier=1.0, truncate=False):
    lines = [HEADER, "|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    rows = []
    for scenario, lanes in SCENARIOS:
        validators = 4 if "4v" in scenario else 7
        mode = "asymptote" if "asymptote" in scenario else "guardian_majority"
        for lane in lanes:
            values = [1000, 900, 2, 4, 6, 8]
            values = [value * multiplier for value in values]
            rows.append(
                f"| {scenario} | {validators} | {mode} | {lane} | 512 | 512 | 512 | "
                + " | ".join(f"{value:.2f}" for value in values)
                + " |"
            )
    if truncate:
        rows.pop()
    return "\n".join(lines + rows) + "\n"


class ResultToolsTests(unittest.TestCase):
    def run_tool(self, *args, cwd=None):
        return subprocess.run(
            [str(TOOL), *args], cwd=cwd, text=True, capture_output=True, check=False
        )

    def test_collect_accepts_exact_fourteen_row_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run.raw").write_text(table())
            result = self.run_tool(
                "collect", "--input", str(root / "run.raw"), "--output", str(root / "run.json"),
                "--campaign", "campaign-1", "--pass-number", "1",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((root / "run.json").read_text())["row_count"], 14)

    def test_collect_rejects_partial_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run.raw").write_text(table(truncate=True))
            result = self.run_tool(
                "collect", "--input", str(root / "run.raw"), "--output", str(root / "run.json"),
                "--campaign", "campaign-1", "--pass-number", "1",
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("partial matrix", result.stderr)

    def test_aggregate_emits_reproducibility_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, multiplier in enumerate((1.0, 1.04), start=1):
                raw = root / f"raw-{index}"
                raw.write_text(table(multiplier))
                result = self.run_tool(
                    "collect", "--input", str(raw), "--output", str(root / f"run-{index}.json"),
                    "--campaign", "campaign-1", "--pass-number", str(index),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            result = self.run_tool(
                "aggregate", "--inputs", "run-*.json", "--repeats", "2", "--campaign", "campaign-1",
                "--output-json", "result.json", "--output-markdown", "result.md", cwd=root,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((root / "result.json").read_text())["verdict"], "reproduced_within_threshold")

    def test_secret_canary_refuses_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "result.json").write_text('{"oops":"seeded-secret-123"}')
            result = self.run_tool(
                "scan", "--directory", str(root), "--canaries", "seeded-secret-123"
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("secret canary", result.stderr)


if __name__ == "__main__":
    unittest.main()
