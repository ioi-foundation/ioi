#!/usr/bin/env python3

import json
import os
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import importlib.util

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "result-tools.py"
RUNNER = ROOT / "run-bench.sh"
SPEC = importlib.util.spec_from_file_location("aft_result_tools", TOOL)
RESULT_TOOLS = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(RESULT_TOOLS)
SCENARIOS = (
    ("paper_guardian_majority_4v", ("base_final",)),
    ("paper_guardian_majority_7v", ("base_final",)),
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
    @staticmethod
    def free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]

    @staticmethod
    def tls_identity(root):
        certificate = root / "tls.crt"
        key = root / "tls.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                "-nodes", "-days", "1", "-keyout", str(key), "-out", str(certificate),
                "-subj", "/CN=ioi-aft-result",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "subjectAltName=DNS:ioi-aft-result",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return certificate, key

    def test_runner_serves_authenticated_status_while_benchmark_is_running(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, key = self.tls_identity(root)
            binary = root / "bin"
            binary.mkdir()
            cargo = binary / "cargo"
            cargo.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == --version ]]; then echo 'cargo 1.0.0-test'; exit 0; fi\n"
                "touch \"$AFT_TEST_STARTED\"\n"
                "while [[ ! -f \"$AFT_TEST_RELEASE\" ]]; do sleep 0.05; done\n"
                "echo 'simulated benchmark failure after startup' >&2\n"
                "exit 17\n"
            )
            cargo.chmod(0o755)
            token = "u1-progress-token-abcdefghijklmnopqrstuvwxyz"
            port = self.free_port()
            environment = {
                **os.environ,
                "PATH": f"{binary}:{os.environ['PATH']}",
                "AFT_RESULT_TOOLS": str(TOOL),
                "AFT_RESULT_BEARER_TOKEN": token,
                "AFT_RESULT_PORT": str(port),
                "AFT_RESULT_TLS_CERT": str(certificate),
                "AFT_RESULT_TLS_KEY": str(key),
                "AFT_BENCH_OUTDIR": str(root / "output"),
                "AFT_BENCH_CAMPAIGN_ID": "campaign-progress",
                "IOI_BENCH_COMMIT": "a" * 40,
                "IOI_BENCH_IMAGE_DIGEST": f"sha256:{'b' * 64}",
                "AFT_BENCH_PROTOCOL_VERSION": "res-p4.3.v2",
                "AFT_TEST_RELEASE": str(root / "release"),
                "AFT_TEST_STARTED": str(root / "started"),
                "AFT_BENCH_WARMUPS": "1",
                "AFT_BENCH_REPEATS": "5",
            }
            process = subprocess.Popen(
                [str(RUNNER)],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 10
                status = None
                while time.monotonic() < deadline:
                    try:
                        request = urllib.request.Request(
                            f"https://127.0.0.1:{port}/status",
                            headers={"Authorization": f"Bearer {token}"},
                        )
                        context = ssl.create_default_context(cafile=str(certificate))
                        context.check_hostname = False
                        with urllib.request.urlopen(request, timeout=1, context=context) as response:
                            status = json.loads(response.read())
                        if (Path(environment["AFT_TEST_STARTED"]).exists()
                                and status.get("state") in {"starting", "warmup", "measuring"}):
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    time.sleep(0.05)
                if (status is None
                        or not Path(environment["AFT_TEST_STARTED"]).exists()
                        or status.get("state") not in {"starting", "warmup", "measuring"}):
                    Path(environment["AFT_TEST_RELEASE"]).touch()
                    time.sleep(0.2)
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=10)
                    self.fail(
                        f"runner did not reach warmup; status={status!r}, "
                        f"benchmark_started={Path(environment['AFT_TEST_STARTED']).exists()}, "
                        f"stdout={stdout!r}, stderr={stderr!r}"
                    )
                self.assertEqual(status["campaign_id"], "campaign-progress")
                Path(environment["AFT_TEST_RELEASE"]).touch()
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        request = urllib.request.Request(
                            f"https://127.0.0.1:{port}/status",
                            headers={"Authorization": f"Bearer {token}"},
                        )
                        with urllib.request.urlopen(request, timeout=1, context=context) as response:
                            status = json.loads(response.read())
                        if status.get("state") == "failed":
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    time.sleep(0.05)
                self.assertEqual(status.get("state"), "failed")
                self.assertIn("warmup 1 of 1 failed with exit code 17", status["detail"])
                self.assertIn("simulated benchmark failure", status["detail"])
                failure = json.loads((root / "output" / "failure.json").read_text())
                self.assertEqual(failure["phase"], "warmup 1 of 1")
                self.assertEqual(failure["exit_code"], 17)
                self.assertEqual(failure["diagnostic_source"], "warmup-1.raw")
            finally:
                Path(environment["AFT_TEST_RELEASE"]).touch()
                time.sleep(0.2)
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=10)

    def test_cli_result_server_requires_tls_before_bearer_authentication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, key = self.tls_identity(root)
            (root / "status.json").write_text(
                json.dumps({"campaign_id": "campaign-tls", "state": "measuring"})
            )
            token = "u1-tls-token-abcdefghijklmnopqrstuvwxyz"
            port = self.free_port()
            process = subprocess.Popen(
                [
                    str(TOOL), "serve", "--directory", str(root), "--port", str(port),
                    "--tls-cert", str(certificate), "--tls-key", str(key),
                ],
                env={**os.environ, "AFT_RESULT_BEARER_TOKEN": token},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 10
                response = None
                while time.monotonic() < deadline:
                    try:
                        context = ssl.create_default_context(cafile=str(certificate))
                        context.check_hostname = False
                        request = urllib.request.Request(
                            f"https://127.0.0.1:{port}/status",
                            headers={"Authorization": f"Bearer {token}"},
                        )
                        response = urllib.request.urlopen(request, context=context, timeout=1)
                        break
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.05)
                self.assertIsNotNone(response)
                self.assertEqual(json.loads(response.read())["campaign_id"], "campaign-tls")

                with self.assertRaises((OSError, urllib.error.URLError, ssl.SSLError)):
                    urllib.request.urlopen(
                        urllib.request.Request(
                            f"http://127.0.0.1:{port}/status",
                            headers={"Authorization": f"Bearer {token}"},
                        ),
                        timeout=2,
                    )
            finally:
                process.terminate()
                process.wait(timeout=10)

    def run_tool(self, *args, cwd=None, env=None):
        return subprocess.run(
            [str(TOOL), *args], cwd=cwd, env=env, text=True, capture_output=True, check=False
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

    def test_collect_accepts_exact_ten_row_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run.raw").write_text(table())
            result = self.run_tool(
                "collect", "--input", str(root / "run.raw"), "--output", str(root / "run.json"),
                "--campaign", "campaign-1", "--pass-number", "1",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((root / "run.json").read_text())["row_count"], 10)

    def test_collect_accepts_and_normalizes_real_rust_mode_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rust_output = table().replace(
                "| guardian_majority |", "| GuardianMajority |"
            ).replace("| asymptote |", "| Asymptote |")
            (root / "run.raw").write_text(rust_output)
            result = self.run_tool(
                "collect", "--input", str(root / "run.raw"),
                "--output", str(root / "run.json"), "--campaign", "campaign-real-output",
                "--pass-number", "1",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            modes = {row["mode"] for row in json.loads((root / "run.json").read_text())["rows"]}
            self.assertEqual(modes, {"guardian_majority", "asymptote"})

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
            self.assertEqual(metric["values"], [900.0, 909.0, 918.0, 927.0, 936.0])
            self.assertIn("median_absolute_deviation", metric)
            self.assertIn("coefficient_of_variation", metric)
            self.assertEqual(len(metric["bootstrap_median_95"]), 2)
            self.assertEqual(
                set(metric),
                {
                    "values", "min", "median", "max", "median_absolute_deviation",
                    "coefficient_of_variation", "bootstrap_median_95", "relative_spread",
                    "threshold", "within_threshold",
                },
            )

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
                "protocol_version": "res-p4.3.v2",
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
                "protocol_version": "res-p4.3.v2",
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

    def test_failure_status_names_phase_and_bounds_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "status.json").write_text(json.dumps({
                "campaign_id": "campaign-1",
                "state": "measuring",
                "detail": "measured pass 3 of 5",
            }))
            (root / "run-3.raw").write_text("older\nprecise benchmark failure\n")
            result = self.run_tool(
                "failure-status", "--directory", str(root),
                "--campaign", "campaign-1", "--exit-code", "101",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            failure = json.loads((root / "failure.json").read_text())
            status = json.loads((root / "status.json").read_text())
            self.assertEqual(failure["phase"], "measured pass 3 of 5")
            self.assertEqual(failure["exit_code"], 101)
            self.assertIn("precise benchmark failure", failure["bounded_diagnostic"])
            self.assertEqual(status["state"], "failed")
            self.assertIn("measured pass 3 of 5 failed", status["detail"])

    def test_failure_status_never_echoes_secret_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "status.json").write_text(json.dumps({
                "campaign_id": "campaign-1", "state": "warmup", "detail": "warmup 1 of 1",
            }))
            (root / "warmup-1.raw").write_text("seeded-secret-123\n")
            result = self.run_tool(
                "failure-status", "--directory", str(root),
                "--campaign", "campaign-1", "--exit-code", "17",
                "--canaries", "seeded-secret-123",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            serialized = (root / "failure.json").read_text() + (root / "status.json").read_text()
            self.assertNotIn("seeded-secret-123", serialized)
            self.assertIn("credential-like material was detected", serialized)

    def test_failure_status_never_echoes_result_bearer_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "u1-result-secret-token-abcdefghijklmnopqrstuvwxyz"
            (root / "status.json").write_text(json.dumps({
                "campaign_id": "campaign-1", "state": "measuring", "detail": "measured pass 1 of 5",
            }))
            (root / "run-1.raw").write_text(f"request failed bearer={token}\n")
            result = self.run_tool(
                "failure-status", "--directory", str(root),
                "--campaign", "campaign-1", "--exit-code", "17",
                env={**os.environ, "AFT_RESULT_BEARER_TOKEN": token},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            serialized = (root / "failure.json").read_text() + (root / "status.json").read_text()
            self.assertNotIn(token, serialized)
            self.assertIn("credential-like material was detected", serialized)

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
