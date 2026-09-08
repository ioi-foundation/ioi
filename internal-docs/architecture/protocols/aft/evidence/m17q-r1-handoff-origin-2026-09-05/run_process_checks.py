from pathlib import Path
import datetime, hashlib, json, os, subprocess
base = Path(__file__).resolve().parent / "process"
base.mkdir(exist_ok=True)
prior = json.loads(Path("internal-docs/architecture/protocols/aft/evidence/m17q-r1-expired-result-process-2026-09-05/started.json").read_text())
sources = set(prior["sources"])
sources.update([".github/scripts/check_aft_quv_handoff_evidence.py", "crates/validator/src/standard/orchestration/lifecycle.rs", "crates/validator/src/standard/orchestration/consensus.rs", "crates/types/src/app/query_unanimity.rs", "crates/types/src/config/mod.rs", "crates/types/src/config/tests.rs", "crates/cli/src/testing/cluster.rs"])
hashes = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sorted(sources)}
plan = [
 ("disjoint-handoff", "test_aft_quv_disjoint_successors_install_live_handoff_before_activation"),
 ("overlap-handoff", "test_aft_quv_overlapping_member_installs_and_recovers_the_same_live_handoff"),
 ("correct-member-campaign", "test_aft_quv_m16q_each_single_correct_member_and_conflict_isolation"),
]
results = []
for label, test in plan:
    directory = base / label
    directory.mkdir(exist_ok=False)
    components = directory / "components"
    components.mkdir()
    command = ["cargo", "test", "--locked", "-p", "ioi-cli", "--test", "aft_e2e", "--features", "consensus-aft,vm-wasm,state-iavl", test, "--", "--exact", "--nocapture"]
    overrides = {"IOI_TEST_ORCH_RUST_LOG": "info,quv=debug,network=debug", "IOI_AFT_BENCH_TRACE_DIR": str(components)}
    started = {"base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "tree_dirty": True, "command": command, "environment_overrides": overrides, "sources": hashes}
    (directory / "started.json").write_text(json.dumps(started, indent=2) + "\n")
    env = dict(os.environ); env.update(overrides)
    with (directory / "process.log").open("w") as log:
        run = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    changed = [p for p, h in hashes.items() if hashlib.sha256(Path(p).read_bytes()).hexdigest() != h]
    result = {"case": label, "exit_code": run.returncode, "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "changed_sources": changed}
    if run.returncode == 0:
        text = (directory / "process.log").read_text()
        if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in text:
            result["evidence_error"] = "missing exact one nonignored passing test"
        if label in ("disjoint-handoff", "overlap-handoff", "correct-member-campaign"):
            checker_script = ".github/scripts/check_aft_m16q_process_evidence.py" if label == "correct-member-campaign" else ".github/scripts/check_aft_quv_handoff_evidence.py"
            checker = ["python3", checker_script, str(directory / "process.log"), "--components", str(components)]
            with (directory / "evidence-check.log").open("w") as out:
                checked = subprocess.run(checker, stdout=out, stderr=subprocess.STDOUT)
            result["checker_exit_code"] = checked.returncode
    results.append(result)
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    (base / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    if run.returncode or changed or result.get("evidence_error") or result.get("checker_exit_code", 0):
        raise SystemExit(1)
