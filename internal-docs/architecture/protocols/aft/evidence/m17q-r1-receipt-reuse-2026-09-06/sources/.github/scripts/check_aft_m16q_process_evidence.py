#!/usr/bin/env python3
"""Check completeness of the fixed four-member M16Q development campaign log."""

import argparse
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
import tempfile


def validate_overlap(text: str, directory: Path) -> dict:
    """Require observed overlap on this test host; not a protocol timing proof."""
    rows = [line for line in text.splitlines()
            if line.startswith("[M16Q-QUV] case=authenticated_saturation ")]
    if len(rows) != 1:
        raise ValueError("expected one workload nonce row")
    fields = dict(re.findall(r"(\w+)=([^ ]+)", rows[0]))
    nonces = fields.get("verifier_nonces", "").split(",")
    if len(nonces) != 4 or len(set(nonces)) != 4 or any(
            not re.fullmatch(r"[0-9a-f]{64}", nonce) for nonce in nonces):
        raise ValueError("expected four distinct receipt-bound workload nonces")
    events = {nonce: {} for nonce in nonces}
    sources = {}
    completed_operations, released_operations = set(), set()
    paths = sorted(directory.glob("*-orch.log"))
    if len(paths) != 4:
        raise ValueError("expected four orchestration component logs")
    for path in paths:
        raw = path.read_bytes()
        if not raw:
            raise ValueError("empty component log")
        sources[path.name] = hashlib.sha256(raw).hexdigest()
        for line in raw.decode("utf-8").splitlines():
            if "HARNESS_DIAGNOSTIC_WRITE_FAILURE" in line:
                raise ValueError("component capture failed")
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                if line.lstrip().startswith("{"):
                    raise ValueError("malformed JSON component record")
                continue  # Child startup output may be plain text.
            if not isinstance(record, dict):
                continue
            entry = record.get("fields", {})
            if not isinstance(entry, dict):
                continue
            nonce, event = entry.get("nonce"), entry.get("event")
            if event in {"push_admission_overflow", "push_admission_worker_stopped", "preparation_service_expired", "operation_service_expired"}:
                raise ValueError("QUV scheduling/service failure invalidates process timing qualification")
            if event in {"operation_finished", "operation_admission_released"} and (entry.get("service_budgeted") is not True or entry.get("service_budget_met") is not True):
                raise ValueError("operation completion lacks a successful rooted active-service check")
            if event in {"operation_finished", "operation_admission_released"}:
                if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce):
                    raise ValueError("invalid completed/released operation nonce")
                target = completed_operations if event == "operation_finished" else released_operations
                key = (path.name, nonce)
                if key in target:
                    raise ValueError("duplicate completed/released operation")
                target.add(key)
            if nonce not in events or event not in {"operation_started", "operation_finished", "operation_admission_released"}:
                continue
            if event in events[nonce]:
                raise ValueError("duplicate workload lifecycle event")
            timestamp = record.get("timestamp")
            if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
                raise ValueError("missing UTC lifecycle timestamp")
            time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if event == "operation_started" and entry.get("decision_millis") != 5000:
                raise ValueError("unexpected workload decision interval")
            if event == "operation_finished" and entry.get("accepted") is not True:
                raise ValueError("workload lifecycle did not accept")
            events[nonce][event] = (time, path.name)
    if not completed_operations <= released_operations:
        raise ValueError("completed operation lacks final admission release")
    intervals = []
    for lifecycle in events.values():
        if set(lifecycle) != {"operation_started", "operation_finished", "operation_admission_released"}:
            raise ValueError("missing workload lifecycle event")
        start, start_node = lifecycle["operation_started"]
        end, end_node = lifecycle["operation_finished"]
        released, released_node = lifecycle["operation_admission_released"]
        if released_node != start_node or released < start:
            raise ValueError("inconsistent admission release")
        if start_node != end_node or end <= start:
            raise ValueError("inconsistent workload lifecycle")
        # A delayed completion log must not manufacture overlap after the
        # rooted decision interval has expired. These remain wall-clock
        # observations, separate from runtime monotonic-clock enforcement.
        intervals.append((start, min(end, start + timedelta(milliseconds=5000))))
    latest_start = max(start for start, _ in intervals)
    earliest_end = min(end for _, end in intervals)
    if latest_start >= earliest_end:
        raise ValueError("four-way verifier overlap was not observed")
    return {"scope": "same-host wall-clock workload observation, not protocol deadline proof",
            "verifier_nonces": nonces, "component_sha256": sources,
            "four_way_overlap_observed": True,
            "start_span_millis": round((latest_start - min(s for s, _ in intervals)).total_seconds() * 1000, 3),
            "common_overlap_millis": round((earliest_end - latest_start).total_seconds() * 1000, 3)}


def validate(text: str) -> dict:
    rows = {}
    case_order = []
    for line in text.splitlines():
        if line.startswith("[M16Q-QUV] "):
            fields = dict(re.findall(r"(\w+)=([^ ]+)", line))
            case = fields.get("case")
            if case not in {
                "initial_manifest_admission", "invalid_signature_preparation", "recovered_results",
                "sole_correct", "authenticated_saturation",
                "concurrent_valid_conflict", "unrelated_after_conflict", "expired_result",
            }:
                raise ValueError("unknown or missing campaign case")
            rows.setdefault(case, []).append(fields)
            case_order.append(case)

    def number(row, field):
        value = row.get(field, "")
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError(f"invalid numeric field {field}")
        return int(value)

    def single(case):
        values = rows.get(case, [])
        if len(values) != 1:
            raise ValueError(f"expected exactly one {case} case")
        return values[0]

    def executed(row):
        if row.get("result") != "executed":
            raise ValueError("case did not execute")
        number(row, "elapsed_ms")

    def bounded(row):
        if number(row, "qualified_envelope_ms") != 4000:
            raise ValueError("unexpected qualified reply envelope")
        if number(row, "max_valid_reply_elapsed_ms") > 4000:
            raise ValueError("reply exceeded qualified envelope")

    expected_order = (["initial_manifest_admission"] * 4
                      + ["invalid_signature_preparation", "sole_correct"] * 4
                      + ["recovered_results", "authenticated_saturation",
                         "concurrent_valid_conflict", "unrelated_after_conflict", "expired_result"])
    if case_order != expected_order:
        raise ValueError("missing, duplicate or reordered campaign phases")
    for case, expected_result in [("initial_manifest_admission", "exact_signature_refusal"),
                                  ("invalid_signature_preparation", "rejected")]:
        probes = rows.get(case, [])
        if [number(row, "member_position") for row in probes] != list(range(4)):
            raise ValueError("missing or reordered per-member admission probes")
        for row in probes:
            if row.get("result") != expected_result:
                raise ValueError("admission probe lacks exact refusal result")
            if case == "invalid_signature_preparation" and row.get("per_effect_storage_unchanged") != "true":
                raise ValueError("rejected preparation changed per-effect storage")
    recovered = single("recovered_results")
    if number(recovered, "exact_nonportable_results") != 4 or recovered.get("result") != "recorded":
        raise ValueError("missing exact nonportable recovery results")

    solo = rows.get("sole_correct", [])
    if len(solo) != 4:
        raise ValueError("expected four sole-correct placements")
    if {number(row, "member_position") for row in solo} != set(range(4)):
        raise ValueError("missing or duplicate sole-correct member placement")
    if {number(row, "process_index") for row in solo} != set(range(4)):
        raise ValueError("missing or duplicate sole-correct process placement")
    for row in solo:
        if number(row, "terminal_replays") != 1:
            raise ValueError("missing same-effect terminal replay")
        number(row, "replay_elapsed_ms")
        executed(row)
        bounded(row)

    saturation = single("authenticated_saturation")
    executed(saturation)
    if number(saturation, "operations") != 4:
        raise ValueError("incomplete saturation operations")
    # Rust prints Option<u64> for this maximum, unlike the solo cases.
    maximum = re.fullmatch(r"Some\(([0-9]+)\)", saturation.get("max_valid_reply_elapsed_ms", ""))
    if maximum is None:
        raise ValueError("missing saturation reply maximum")
    bounded({**saturation, "max_valid_reply_elapsed_ms": maximum[1]})

    conflict = single("concurrent_valid_conflict")
    accepts = number(conflict, "accepts")
    if accepts > 1 or number(conflict, "conflict_rejections") != 2 - accepts:
        raise ValueError("incomplete or unsafe conflict outcomes")
    if (number(conflict, "durable_records") != accepts
            or conflict.get("rejected_resources_unchanged") != "true"
            or conflict.get("result") != "safe"):
        raise ValueError("missing conflict resource assertions")
    number(conflict, "elapsed_ms")
    executed(single("unrelated_after_conflict"))
    expired = single("expired_result")
    if (number(expired, "observed_height") <= number(expired, "expiry_height")
            or expired.get("receipt_unchanged") != "true"
            or expired.get("result") != "recorded"):
        raise ValueError("missing unchanged result beyond committed expiry")
    number(expired, "elapsed_ms")
    if len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", text, re.MULTILINE)) != 1:
        raise ValueError("expected one completed, non-ignored process test")
    return {"initial_admissions": 4, "signature_storage_refusals": 4, "recovered_results": 4,
            "sole_correct_placements": 4, "saturation_operations": 4,
            "conflict_accepts": accepts, "unrelated_executed": True,
            "expired_result_recorded": True}


def overlap_self_test():
    nonces = [f"{i:064x}" for i in range(4)]
    row = "[M16Q-QUV] case=authenticated_saturation verifier_nonces=" + ",".join(nonces)

    def record(nonce, event, second, **extra):
        return json.dumps({"timestamp": f"2026-09-05T00:00:{second:02d}Z",
                           "fields": {"nonce": nonce, "event": event, **extra}})

    valid = [[record(n, "operation_started", i, decision_millis=5000),
              record(n, "operation_finished", i + 5, accepted=True, service_budgeted=True, service_budget_met=True),
              record(n, "operation_admission_released", i + 5, service_budgeted=True, service_budget_met=True)]
             for i, n in enumerate(nonces)]
    cases = []
    for index in range(4):
        for event_index in range(3):
            missing = [list(lines) for lines in valid]
            missing[index].pop(event_index)
            cases.append((row, missing))
    for before, after in [("decision_millis\": 5000", "decision_millis\": 6000"),
                          ("accepted\": true", "accepted\": false"),
                          ("00:00:03Z", "00:00:05Z"),
                          ("00:00:05Z", "00:00:00Z"),
                          ("00:00:03Z", "invalid")]:
        cases.append((row, [[line.replace(before, after) for line in lines] for lines in valid]))
    for field in ["service_budgeted", "service_budget_met"]:
        for replacement in [False, None]:
            changed = [list(lines) for lines in valid]
            value = json.loads(changed[0][1])
            if replacement is None:
                del value["fields"][field]
            else:
                value["fields"][field] = replacement
            changed[0][1] = json.dumps(value)
            cases.append((row, changed))
    for field in ["service_budgeted", "service_budget_met"]:
        changed = [list(lines) for lines in valid]
        value = json.loads(changed[0][2]); value["fields"][field] = False
        changed[0][2] = json.dumps(value); cases.append((row, changed))
    cases.append((row, [valid[0] + [record("ff" * 32, "operation_finished", 9, accepted=False, service_budgeted=True, service_budget_met=True)], *valid[1:]]))
    cases.append((row, [valid[0] + [valid[0][0]], *valid[1:]]))
    cases.append((row, [valid[0] + ["{broken"], *valid[1:]]))
    cases.append((row, [valid[0] + ["HARNESS_DIAGNOSTIC_WRITE_FAILURE"], *valid[1:]]))
    cases.append((row, [valid[0] + [record("ff" * 32, "push_admission_overflow", 1)], *valid[1:]]))
    cases.append((row, [valid[0] + [record("ff" * 32, "push_admission_worker_stopped", 1)], *valid[1:]]))
    cases.append((row, [valid[0] + [record("ff" * 32, "preparation_service_expired", 1)], *valid[1:]]))
    cases.append((row, [valid[0] + [record("ff" * 32, "operation_service_expired", 1)], *valid[1:]]))
    cases.append((row.replace(nonces[3], nonces[2]), valid))
    cases.append((row.replace(nonces[3], "bad"), valid))
    cases.append((row, valid[:3]))
    cases.append((row, [[], *valid[1:]]))
    cases.append((row, [[valid[0][0]], [*valid[1], valid[0][1]], *valid[2:]]))
    cases.append((row, [valid[0], valid[1], valid[2], [
        record(nonces[3], "operation_started", 6, decision_millis=5000),
        record(nonces[3], "operation_finished", 11, accepted=True)]]))
    cases.append((row, [[record(n, "operation_started", i * 2, decision_millis=5000),
                         record(n, "operation_finished", 20, accepted=True)]
                        for i, n in enumerate(nonces)]))
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)

        def check(sample_row, logs):
            for path in directory.glob("*.log"):
                path.unlink()
            for i, lines in enumerate(logs):
                (directory / f"validator-{i}-orch.log").write_text("\n".join(lines))
            return validate_overlap(sample_row, directory)

        assert check(row, valid)["common_overlap_millis"] == 2000
        for index, (sample_row, logs) in enumerate(cases):
            try:
                check(sample_row, logs)
            except ValueError:
                continue
            raise AssertionError(f"invalid overlap evidence sample {index} was accepted")
    return {"positive_cases": 1, "negative_cases": len(cases)}


def self_test():
    lines = [f"[M16Q-QUV] case=initial_manifest_admission member_position={i} result=exact_signature_refusal" for i in range(4)]
    for i in range(4):
        lines += [f"[M16Q-QUV] case=invalid_signature_preparation member_position={i} per_effect_storage_unchanged=true result=rejected",
                  f"[M16Q-QUV] case=sole_correct member_position={i} process_index={i} terminal_replays=1 replay_elapsed_ms=1 elapsed_ms=5000 max_valid_reply_elapsed_ms=3999 qualified_envelope_ms=4000 result=executed"]
    lines += [
        "[M16Q-QUV] case=recovered_results exact_nonportable_results=4 result=recorded",
        "[M16Q-QUV] case=authenticated_saturation operations=4 elapsed_ms=5000 max_valid_reply_elapsed_ms=Some(4000) qualified_envelope_ms=4000 result=executed",
        "[M16Q-QUV] case=concurrent_valid_conflict accepts=1 conflict_rejections=1 durable_records=1 rejected_resources_unchanged=true elapsed_ms=5000 result=safe",
        "[M16Q-QUV] case=unrelated_after_conflict elapsed_ms=5000 result=executed",
        "[M16Q-QUV] case=expired_result expiry_height=64 observed_height=65 elapsed_ms=15 receipt_unchanged=true result=recorded",
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;",
    ]
    valid = "\n".join(lines)
    validate(valid)
    validate(valid.replace("accepts=1 conflict_rejections=1 durable_records=1", "accepts=0 conflict_rejections=2 durable_records=0"))
    invalid = ["\n".join(lines[:i] + lines[i + 1:]) for i in range(len(lines))]
    invalid += [valid + "\n" + lines[0], valid + "\n" + lines[4],
                "\n".join([lines[4]] + lines[:4] + lines[5:])]
    for before, after in [
        ("result=exact_signature_refusal", "result=unavailable"),
        ("per_effect_storage_unchanged=true", "per_effect_storage_unchanged=false"),
        ("exact_nonportable_results=4", "exact_nonportable_results=3"),
        ("member_position=3", "member_position=2"),
        ("process_index=3", "process_index=2"),
        ("operations=4", "operations=3"),
        ("terminal_replays=1", "terminal_replays=0"),
        ("observed_height=65", "observed_height=64"),
        ("receipt_unchanged=true", "receipt_unchanged=false"),
        ("result=recorded", "result=executed"),
        ("3999", "4001"), ("Some(4000)", "Some(4001)"),
        ("Some(4000)", "None"), ("conflict_rejections=1", "conflict_rejections=0"),
        ("accepts=1", "accepts=2"), ("durable_records=1", "durable_records=0"),
        ("unchanged=true", "unchanged=false"), ("0 ignored;", "1 ignored;"),
    ]:
        invalid.append(valid.replace(before, after))
    for index, sample in enumerate(invalid):
        try:
            validate(sample)
        except ValueError:
            continue
        raise AssertionError(f"incomplete evidence sample {index} was accepted")
    return {"positive_cases": 2, "negative_cases": len(invalid),
            "overlap": overlap_self_test()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--components", type=Path,
                        help="require receipt-bound four-way overlap in retained component logs")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), sort_keys=True))
    elif args.log is not None:
        raw = args.log.read_bytes()
        result = validate(raw.decode("utf-8"))
        if args.components is not None:
            result["workload_overlap"] = validate_overlap(raw.decode("utf-8"), args.components)
        print(json.dumps({"log_sha256": hashlib.sha256(raw).hexdigest(), **result}, sort_keys=True))
    else:
        parser.error("provide a log or --self-test")
