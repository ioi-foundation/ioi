#!/usr/bin/env python3

import json
import socketserver
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import importlib.util

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "result-tools.py"
SPEC = importlib.util.spec_from_file_location("aft_result_tools", TOOL)
RESULT_TOOLS = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(RESULT_TOOLS)
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

    def collect(self, root, raw_name, output_name, campaign, pass_number):
        return self.run_tool(
            "collect", "--input", str(root / raw_name), "--output", str(root / output_name),
            "--campaign", campaign, "--pass-number", str(pass_number),
        )

    def write_campaign(self, root, campaign, multipliers):
        root.mkdir(parents=True, exist_ok=True)
        for index, multiplier in enumerate(multipliers, start=1):
            raw = root / f"raw-{index}"
            raw.write_text(table(multiplier))
            result = self.collect(root, raw.name, f"run-{index}.json", campaign, index)
            self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_tool(
            "aggregate", "--inputs", "run-*.json", "--repeats", str(len(multipliers)),
            "--campaign", campaign, "--output-json", "result.json",
            "--output-markdown", "result.md", cwd=root,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads((root / "result.json").read_text())

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

    def test_collect_rejects_duplicate_wrong_lane_and_nonfinite_metric(self):
        mutations = {
            "duplicate": lambda raw: raw.replace(
                "| paper_asymptote_7v | 7 | asymptote | sealed_final |",
                "| paper_asymptote_7v | 7 | asymptote | base_final |",
            ),
            "lane set": lambda raw: raw.replace("| base_final |", "| sealed_final |", 1),
            "invalid": lambda raw: raw.replace("1000.00", "nan", 1),
        }
        for expected, mutate in mutations.items():
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "run.raw").write_text(mutate(table()))
                result = self.collect(root, "run.raw", "run.json", "campaign-1", 1)
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)

    def test_aggregate_emits_reproducibility_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aggregate = self.write_campaign(root, "campaign-1", (1.0, 1.01, 1.02, 1.03, 1.04))
            self.assertEqual(aggregate["verdict"], "reproduced_within_threshold")
            metric = aggregate["summaries"][0]["metrics"]["sustained_tps"]
            self.assertEqual(metric["count"], 5)
            self.assertIn("median_absolute_deviation", metric)
            self.assertIn("coefficient_of_variation", metric)
            self.assertEqual(metric["bootstrap_median_95"]["resamples"], 3125)

    def test_aggregate_rejects_wrong_campaign_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, campaign in enumerate(("campaign-1", "campaign-2"), start=1):
                raw = root / f"raw-{index}"
                raw.write_text(table())
                result = self.collect(root, raw.name, f"run-{index}.json", campaign, index)
                self.assertEqual(result.returncode, 0, result.stderr)
            result = self.run_tool(
                "aggregate", "--inputs", "run-*.json", "--repeats", "2",
                "--campaign", "campaign-1", "--output-json", "result.json",
                "--output-markdown", "result.md", cwd=root,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("campaign identity", result.stderr)

    def test_compare_campaigns_applies_fixed_threshold_to_campaign_medians(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign_a = root / "a"
            campaign_b = root / "b"
            self.write_campaign(campaign_a, "campaign-a", (1.0,) * 5)
            self.write_campaign(campaign_b, "campaign-b", (1.20,) * 5)
            environment = {
                "schema_version": "ioi.aft.environment-manifest.v1",
                "source_commit": "a" * 40,
                "image_digest": f"sha256:{'b' * 64}",
                "protocol_version": "res-p4.3.v1",
                "cpu_model": "fixture",
                "cpu_cores_online": 8,
                "kernel_release": "fixture",
                "machine": "x86_64",
                "memory_kib": 16_777_216,
                "governor": "performance",
            }
            for campaign, campaign_id in ((campaign_a, "campaign-a"), (campaign_b, "campaign-b")):
                (campaign / "environment.json").write_text(
                    json.dumps({**environment, "campaign_id": campaign_id})
                )
            result = self.run_tool(
                "compare", "--campaign-a", str(campaign_a / "result.json"),
                "--campaign-b", str(campaign_b / "result.json"),
                "--environment-a", str(campaign_a / "environment.json"),
                "--environment-b", str(campaign_b / "environment.json"),
                "--output-json", str(root / "comparison.json"),
                "--output-markdown", str(root / "comparison.md"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            comparison = json.loads((root / "comparison.json").read_text())
            self.assertEqual(comparison["verdict"], "variance_caveated")
            self.assertFalse(comparison["all_rows_within_threshold"])
            self.assertTrue(comparison["environment_compatible"])

    def test_compare_campaigns_caveats_environment_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign_a = root / "a"
            campaign_b = root / "b"
            self.write_campaign(campaign_a, "campaign-a", (1.0,) * 5)
            self.write_campaign(campaign_b, "campaign-b", (1.0,) * 5)
            base = {
                "schema_version": "ioi.aft.environment-manifest.v1",
                "source_commit": "a" * 40,
                "image_digest": f"sha256:{'b' * 64}",
                "protocol_version": "res-p4.3.v1",
                "cpu_model": "fixture",
                "cpu_cores_online": 8,
                "kernel_release": "fixture",
                "machine": "x86_64",
                "memory_kib": 16_777_216,
                "governor": "performance",
            }
            (campaign_a / "environment.json").write_text(json.dumps({**base, "campaign_id": "campaign-a"}))
            (campaign_b / "environment.json").write_text(json.dumps({**base, "campaign_id": "campaign-b", "cpu_model": "different"}))
            result = self.run_tool(
                "compare", "--campaign-a", str(campaign_a / "result.json"),
                "--campaign-b", str(campaign_b / "result.json"),
                "--environment-a", str(campaign_a / "environment.json"),
                "--environment-b", str(campaign_b / "environment.json"),
                "--output-json", str(root / "comparison.json"),
                "--output-markdown", str(root / "comparison.md"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            comparison = json.loads((root / "comparison.json").read_text())
            self.assertEqual(comparison["verdict"], "variance_caveated")
            self.assertFalse(comparison["environment_compatible"])

    def test_secret_canary_refuses_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "result.json").write_text('{"oops":"seeded-secret-123"}')
            result = self.run_tool(
                "scan", "--directory", str(root), "--canaries", "seeded-secret-123"
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("secret canary", result.stderr)

    def test_status_rejects_noncanonical_state(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_tool(
                "status", "--output", str(Path(directory) / "status.json"),
                "--campaign", "campaign-1", "--state", "warming_up", "--detail", "bad",
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid campaign state", result.stderr)

    def test_manifest_is_machine_readable_and_hashes_regular_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "status.json").write_text(
                json.dumps({"campaign_id": "campaign-1", "state": "measuring"})
            )
            (root / "result.json").write_text('{"campaign_id":"campaign-1"}')
            result = self.run_tool("manifest", "--directory", str(root))
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((root / "artifact-manifest.json").read_text())
            self.assertEqual(manifest["campaign_id"], "campaign-1")
            self.assertEqual([item["name"] for item in manifest["artifacts"]], ["result.json"])
            self.assertRegex(manifest["artifacts"][0]["sha256"], r"^sha256:[0-9a-f]{64}$")

    def test_result_server_requires_auth_completion_identity_and_untampered_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "t" * 32
            status_path = root / "status.json"
            status_path.write_text(json.dumps({"campaign_id": "campaign-1", "state": "measuring"}))
            (root / "result.json").write_text(
                json.dumps({"schema_version": "ioi.aft.benchmark-campaign.v1", "campaign_id": "campaign-1"})
            )
            (root / "result.md").write_text("result\n")
            self.assertEqual(
                self.run_tool("manifest", "--directory", str(root)).returncode, 0
            )
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), RESULT_TOOLS.ResultHandler)
            server.root = root
            server.token = token
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"

            def fetch(path, supplied_token=token):
                headers = {"Authorization": f"Bearer {supplied_token}"} if supplied_token else {}
                return urllib.request.urlopen(urllib.request.Request(base + path, headers=headers))

            try:
                with self.assertRaises(urllib.error.HTTPError) as unauthenticated:
                    fetch("/status", "")
                self.assertEqual(unauthenticated.exception.code, 401)
                with self.assertRaises(urllib.error.HTTPError) as incomplete:
                    fetch("/results")
                self.assertEqual(incomplete.exception.code, 409)

                status_path.write_text(json.dumps({"campaign_id": "campaign-1", "state": "complete"}))
                first = fetch("/results").read()
                second = fetch("/results").read()
                self.assertEqual(first, second)
                self.assertEqual(fetch("/manifest").status, 200)

                (root / "result.json").write_text('{"campaign_id":"campaign-1","tampered":true}')
                with self.assertRaises(urllib.error.HTTPError) as tampered:
                    fetch("/results")
                self.assertEqual(tampered.exception.code, 409)

                (root / "result.json").write_text(
                    json.dumps({"schema_version": "ioi.aft.benchmark-campaign.v1", "campaign_id": "campaign-2"})
                )
                self.assertEqual(
                    self.run_tool("manifest", "--directory", str(root)).returncode, 0
                )
                with self.assertRaises(urllib.error.HTTPError) as wrong_campaign:
                    fetch("/results")
                self.assertEqual(wrong_campaign.exception.code, 409)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
