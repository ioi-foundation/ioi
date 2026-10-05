"""Tests for fork_check per_node_root_agreement.v1 in result-tools (collect + aggregate + environment)."""
import json, subprocess, tempfile, unittest
from pathlib import Path
from test_result_tools import TOOL, table

def run(*args, cwd=None):
    return subprocess.run([str(TOOL), *args], cwd=cwd, text=True, capture_output=True, check=False)

def campaign(root, raws, campaign_id="c-1"):
    for i, raw in enumerate(raws, start=1):
        (root / f"raw-{i}").write_text(raw)
        r = run("collect", "--input", str(root / f"raw-{i}"), "--output", str(root / f"run-{i}.json"),
                "--campaign", campaign_id, "--pass-number", str(i))
        if r.returncode != 0:
            return r
    return None

def aggregate(root, n, *extra, campaign_id="c-1"):
    return run("aggregate", "--inputs", "run-*.json", "--repeats", str(n), "--campaign", campaign_id,
               "--output-json", "result.json", "--output-markdown", "result.md", *extra, cwd=root)

class ForkCheckTools(unittest.TestCase):
    def test_all_agree_aggregates_with_the_policy_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.assertIsNone(campaign(root, [table()] * 2))
            r = aggregate(root, 2); self.assertEqual(r.returncode, 0, r.stderr)
            res = json.loads((root / "result.json").read_text())
            self.assertEqual(res["fork_check"], "per_node_root_agreement.v1")
            self.assertNotIn("legacy", res["verdict"])
            p1 = json.loads((root / "run-1.json").read_text())
            self.assertTrue(all(row["fork_check"] == "agree" for row in p1["rows"]))
            self.assertEqual(len(p1["fork_checks"]), len(p1["rows"]))

    def test_one_forked_row_refuses_the_whole_campaign(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            forked = table(fork_check="forked", fork_only=("paper_asymptote_4v", "base_final"))
            self.assertIsNone(campaign(root, [table(), forked]))
            r = aggregate(root, 2); self.assertNotEqual(r.returncode, 0)
            self.assertIn("fork_check=forked", r.stderr); self.assertFalse((root / "result.json").exists())

    def test_degraded_row_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.assertIsNone(campaign(root, [table(fork_check="degraded", fork_only=("paper_asymptote_7v", "sealed_final")), table()]))
            r = aggregate(root, 2); self.assertNotEqual(r.returncode, 0); self.assertIn("fork_check=degraded", r.stderr)

    def test_missing_fork_check_refuses_unless_labelled_legacy(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.assertIsNone(campaign(root, [table(fork_check=None)] * 2))
            r = aggregate(root, 2); self.assertNotEqual(r.returncode, 0); self.assertIn("has no fork check", r.stderr)
            r2 = aggregate(root, 2, "--allow-missing-fork-check"); self.assertEqual(r2.returncode, 0, r2.stderr)
            res = json.loads((root / "result.json").read_text())
            self.assertTrue(res["verdict"].endswith("_fork_check_missing_legacy")); self.assertEqual(res["fork_check"], "missing_legacy")

    def test_worst_verdict_wins_when_a_key_is_checked_twice(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            raw = table() + 'FORK_CHECK {"schema":"ioi.aft.fork-check.v1","scenario":"paper_asymptote_4v","lane":"base_final","verdict":"forked","common_tip":11,"nodes":[],"first_divergence":{"height":11,"per_node":[]}}\n'
            self.assertIsNone(campaign(root, [raw]))
            p = json.loads((root / "run-1.json").read_text())
            row = [x for x in p["rows"] if (x["scenario"], x["lane"]) == ("paper_asymptote_4v", "base_final")][0]
            self.assertEqual(row["fork_check"], "forked")

    def test_malformed_fork_check_line_fails_collect(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            r = campaign(root, [table() + 'FORK_CHECK {"schema":"wrong","verdict":"agree"}\n'])
            self.assertIsNotNone(r); self.assertNotEqual(r.returncode, 0)
            r2 = campaign(root, [table() + 'FORK_CHECK {"schema":"ioi.aft.fork-check.v1","verdict":"maybe"}\n'])
            self.assertIsNotNone(r2); self.assertNotEqual(r2.returncode, 0)

if __name__ == "__main__":
    unittest.main()
