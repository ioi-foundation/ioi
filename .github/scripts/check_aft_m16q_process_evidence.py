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


DELTA_RT_MS = 5000
# Post-decision allowance for a singleton racing terminal replay or flood on
# the same host; must equal M16Q_CONCURRENT_REPLAY_SLACK_MS in the fixture.
QUALIFIED_ENVELOPE_MS = 4500
CONCURRENT_SLACK_MS = 10000
# Flood-phase slack: two extra rooted decision intervals end to end; must equal
# SLACK_MS in aft_e2e_parts/quv_flood.rs.
FLOOD_SLACK_MS = 10000
FORK_CASES = ("owned-ab", "owned-ba", "unowned-ab", "unowned-ba")
QUOTA_DROP_MESSAGE = "Dropped QUV PUSHQUERY beyond the rooted per-identity admission quota"
SCHEDULING_FAILURES = {"push_admission_overflow", "push_admission_worker_stopped",
                       "preparation_service_expired", "operation_service_expired"}


def prefixed_rows(text: str, prefix: str) -> list:
    return [dict(re.findall(r"(\w+)=([^ ]+)", line)) for line in text.splitlines()
            if line.startswith(prefix + " ")]


def decimal(row, field):
    value = row.get(field, "")
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError(f"invalid numeric field {field}")
    return int(value)


def hash_field(row, field):
    value = row.get(field, "")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"invalid hash field {field}")
    return value


def validate_predecessor_fork(text: str) -> dict:
    """Each order/mode: B refused before any push, A executed once, one record."""
    rows = prefixed_rows(text, "[M16Q-PREDECESSOR-FORK]")
    if [row.get("case") for row in rows] != list(FORK_CASES):
        raise ValueError("missing, duplicate or reordered predecessor-fork cases")
    payloads = {}
    for row in rows:
        mode, order = row["case"].split("-")
        if row.get("mode") != mode or row.get("order") != order:
            raise ValueError("fork case does not match its mode/order")
        if (row.get("refused_before_push") != "true" or decimal(row, "accepts") != 1
                or decimal(row, "durable_records") != 1 or decimal(row, "refusals") < 1
                or row.get("result") != "safe"):
            raise ValueError("fork case lacks refusal-before-push with one accept and one record")
        if order == "ba" and decimal(row, "refusals") < 2:
            raise ValueError("B-then-A order must refuse B both before and after A")
        same_executor = row.get("same_executor")
        if same_executor not in ("true", "false"):
            raise ValueError("fork case does not state whether B used A's executor")
        after_a = "claim_index" if same_executor == "true" else "expected_head"
        expected_rules = {"ab": after_a, "ba": "expected_head," + after_a}[order]
        if row.get("refusal_rules") != expected_rules:
            raise ValueError("fork case refusal rules do not match the exact expected sequence")
        if row.get("predecessor_a") != "4d" * 32 or row.get("predecessor_b") != "4e" * 32:
            raise ValueError("fork case does not use the distinct rooted/forked predecessors")
        accepted, refused = hash_field(row, "accepted_payload"), hash_field(row, "refused_payload")
        if accepted == refused or accepted in payloads or refused in payloads:
            raise ValueError("fork payloads are not distinct")
        payloads[accepted] = ("accepted", row["case"])
        payloads[refused] = ("refused", row["case"])
    return {"cases": list(FORK_CASES), "payloads": payloads}


def validate_concurrent_replay(text: str) -> dict:
    rows = prefixed_rows(text, "[M16Q-CONCURRENT-REPLAY]")
    if len(rows) != 1:
        raise ValueError("expected exactly one concurrent terminal replay row")
    row = rows[0]
    if decimal(row, "delta_rt_ms") != DELTA_RT_MS or decimal(row, "slack_ms") != CONCURRENT_SLACK_MS:
        raise ValueError("unexpected concurrent replay timing profile")
    elapsed = decimal(row, "unrelated_elapsed_ms")
    if elapsed > DELTA_RT_MS + CONCURRENT_SLACK_MS:
        raise ValueError("unrelated singleton exceeded delta_rt + slack during terminal replay")
    if decimal(row, "replay_count") < 2 or row.get("lookup_only") != "true":
        raise ValueError("terminal replay pressure was absent or not lookup-only")
    decimal(row, "replay_span_ms")
    replay, unrelated = hash_field(row, "replay_payload"), hash_field(row, "unrelated_payload")
    if replay == unrelated:
        raise ValueError("replay and unrelated payloads coincide")
    return {"unrelated_elapsed_ms": elapsed, "replay_count": decimal(row, "replay_count"),
            "replay_payload": replay, "unrelated_payload": unrelated}


def component_records(directory: Path, expected_logs: int = 4):
    paths = sorted(directory.glob("*-orch.log"))
    if len(paths) != expected_logs:
        raise ValueError(f"expected {expected_logs} orchestration component logs")
    for path in paths:
        raw = path.read_bytes()
        if not raw:
            raise ValueError("empty component log")
        for line in raw.decode("utf-8").splitlines():
            if "HARNESS_DIAGNOSTIC_WRITE_FAILURE" in line:
                raise ValueError("component capture failed")
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                if line.lstrip().startswith("{"):
                    raise ValueError("malformed JSON component record")
                continue
            if isinstance(record, dict) and isinstance(record.get("fields"), dict):
                yield path.name, record


def operation_starts(directory: Path, expected_logs: int = 4) -> list:
    """(log, payload, independent_preparation) for every retained operation start."""
    starts = []
    for name, record in component_records(directory, expected_logs):
        fields = record["fields"]
        if record.get("target") != "quv" or fields.get("event") != "operation_started":
            continue
        payload = fields.get("payload")
        if not isinstance(payload, str) or not re.fullmatch(r"[0-9a-f]{64}", payload):
            raise ValueError("operation start lacks its payload hash")
        if not isinstance(fields.get("independent_preparation"), bool):
            raise ValueError("operation start lacks its preparation flag")
        starts.append((name, payload, fields["independent_preparation"]))
    return starts


def validate_no_push_evidence(text: str, directory: Path) -> dict:
    """Refused payloads never start an executor operation on any process;
    each accepted fork payload and the concurrent unrelated payload start
    exactly one non-preparation operation; the replayed terminal payload
    starts exactly one (its original sole-correct placement)."""
    fork = validate_predecessor_fork(text)
    replay = validate_concurrent_replay(text)
    starts = operation_starts(directory)
    executor = {}
    any_start = {}
    for _, payload, preparation in starts:
        any_start[payload] = any_start.get(payload, 0) + 1
        if not preparation:
            executor[payload] = executor.get(payload, 0) + 1
    for payload, (kind, case) in fork["payloads"].items():
        if kind == "refused" and any_start.get(payload, 0) != 0:
            raise ValueError(f"refused fork payload started an operation in {case}")
        if kind == "accepted" and executor.get(payload, 0) != 1:
            raise ValueError(f"accepted fork payload did not start exactly one operation in {case}")
    # Other members may independently prepare the replayed payload; only a
    # fresh executor (non-preparation) operation would show a live replay.
    if executor.get(replay["replay_payload"], 0) != 1:
        raise ValueError("terminal replay payload started more than its original operation")
    if executor.get(replay["unrelated_payload"], 0) != 1:
        raise ValueError("concurrent unrelated payload did not start exactly one operation")
    return {"operation_starts": len(starts), "refused_payload_starts": 0,
            "replay_payload_starts": 1}


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
                "byzantine_status_claim",
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
        if number(row, "qualified_envelope_ms") != QUALIFIED_ENVELOPE_MS:
            raise ValueError("unexpected qualified reply envelope")
        if number(row, "max_valid_reply_elapsed_ms") > QUALIFIED_ENVELOPE_MS:
            raise ValueError("reply exceeded qualified envelope")

    expected_order = (["initial_manifest_admission"] * 4
                      + ["invalid_signature_preparation", "sole_correct"] * 4
                      + ["recovered_results", "authenticated_saturation",
                         "concurrent_valid_conflict", "unrelated_after_conflict", "expired_result",
                         "byzantine_status_claim"])
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
    # The register evidence is measured, so it must also be consistent with
    # the outcome counts: records exist only for accepted effects.
    if number(conflict, "durable_records") > accepts:
        raise ValueError("measured durable records exceed accepted effects")
    unrelated = single("unrelated_after_conflict")
    executed(unrelated)
    fork = validate_predecessor_fork(text)
    replay = validate_concurrent_replay(text)
    if replay["unrelated_elapsed_ms"] != number(unrelated, "elapsed_ms"):
        raise ValueError("concurrent replay row does not report the unrelated case elapsed time")
    expired = single("expired_result")
    if (number(expired, "observed_height") <= number(expired, "expiry_height")
            or expired.get("receipt_unchanged") != "true"
            or expired.get("result") != "recorded"):
        raise ValueError("missing unchanged result beyond committed expiry")
    number(expired, "elapsed_ms")
    claim = validate_status_claim(text, solo)
    if len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", text, re.MULTILINE)) != 1:
        raise ValueError("expected one completed, non-ignored process test")
    return {"initial_admissions": 4, "signature_storage_refusals": 4, "recovered_results": 4,
            "sole_correct_placements": 4, "saturation_operations": 4,
            "conflict_accepts": accepts, "unrelated_executed": True,
            "expired_result_recorded": True, "predecessor_fork_cases": fork["cases"],
            "concurrent_replay": {"unrelated_elapsed_ms": replay["unrelated_elapsed_ms"],
                                  "replay_count": replay["replay_count"]},
            "byzantine_status_claim": claim}


PEER_ID_PATTERN = r"[1-9A-HJ-NP-Za-km-z]{40,}"


def validate_status_claim(text: str, solo: list) -> dict:
    """R1 007 (process level): exactly one byzantine_status_claim row in which a
    Byzantine process B, claiming member position 0's account C in every status
    response, still leaves all four configured replies routed (members_valid=4,
    result=executed). The claimed account is cross-checked against the
    fixture's [M16Q-STATUS-CLAIM-EXPECT] line, which names position 0's account
    and the claimant, and against the sole_correct member_position=0 row's
    process (the claimant must be a different process)."""
    rows = prefixed_rows(text, "[M16Q-QUV] case=byzantine_status_claim")
    if len(rows) != 1:
        raise ValueError("expected exactly one byzantine_status_claim case")
    row = rows[0]
    expect = prefixed_rows(text, "[M16Q-STATUS-CLAIM-EXPECT]")
    if len(expect) != 1:
        raise ValueError("expected exactly one status-claim expectation row")
    expect = expect[0]
    if row.get("result") != "executed" or decimal(row, "members_valid") != 4:
        raise ValueError("status claim did not leave all four configured replies routed")
    decimal(row, "elapsed_ms")
    decimal(row, "max_valid_reply_elapsed_ms")
    if decimal(row, "qualified_envelope_ms") != QUALIFIED_ENVELOPE_MS:
        raise ValueError("unexpected qualified reply envelope in status-claim row")
    claimed = hash_field(row, "claimed_account")
    if decimal(expect, "member_position") != 0 or hash_field(expect, "account") != claimed:
        raise ValueError("claimed account is not member position 0's account")
    claimant_account = hash_field(expect, "claimant_account")
    if claimant_account == claimed or decimal(expect, "claimant_position") == 0:
        raise ValueError("claimant must be a distinct member from the claimed account")
    claimant_process = decimal(row, "claimant_process")
    if claimant_process != decimal(expect, "claimant_process") or claimant_process > 3:
        raise ValueError("claimant process differs from the fixture expectation")
    position_zero = [solo_row for solo_row in solo if decimal(solo_row, "member_position") == 0]
    if len(position_zero) != 1 or decimal(position_zero[0], "process_index") == claimant_process:
        raise ValueError("claimant process is member position 0's own process")
    peer = row.get("claimant_peer", "")
    if not re.fullmatch(PEER_ID_PATTERN, peer) or expect.get("claimant_peer") != peer:
        raise ValueError("claimant peer id is missing or differs from the fixture expectation")
    if decimal(row, "override_warnings") < 1 or decimal(row, "claim_refusals") < 1:
        raise ValueError("status claim was not observed as advertised and refused")
    return {"claimed_account": claimed, "claimant_account": claimant_account,
            "claimant_process": claimant_process, "claimant_peer": peer,
            "members_valid": 4, "override_warnings": decimal(row, "override_warnings"),
            "claim_refusals": decimal(row, "claim_refusals")}


def validate_status_claim_components(text: str, directory: Path) -> dict:
    """The test-only override warning appears in exactly one component log (the
    claimant's, by local peer id) naming the claimed account; no process ever
    reports a malformed override; and at least one OTHER process retained a
    pq_peer_enrollment_refused record for the claimant's peer id."""
    solo = [dict(re.findall(r"(\w+)=([^ ]+)", line)) for line in text.splitlines()
            if line.startswith("[M16Q-QUV] case=sole_correct ")]
    summary = validate_status_claim(text, solo)
    override_logs = {}
    refusal_logs = set()
    sources = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
               for path in sorted(directory.glob("*-orch.log"))}
    for name, record in component_records(directory):
        fields = record["fields"]
        if record.get("target") != "network":
            continue
        event = fields.get("event")
        if event == "testing_status_account_override_invalid":
            raise ValueError("a process reported a malformed status override")
        if event == "testing_status_account_override":
            if record.get("level") != "WARN":
                raise ValueError("status override was not logged at WARN")
            if (fields.get("claimed_account") != summary["claimed_account"]
                    or fields.get("local_peer") != summary["claimant_peer"]):
                raise ValueError("status override names another account or carrier")
            override_logs[name] = override_logs.get(name, 0) + 1
        if event == "pq_peer_enrollment_refused" and fields.get("peer") == summary["claimant_peer"]:
            refusal_logs.add(name)
    if len(override_logs) != 1:
        raise ValueError("status override must appear in exactly one component log")
    claimant_log, overrides = next(iter(override_logs.items()))
    if overrides < summary["override_warnings"]:
        raise ValueError("component log retains fewer override warnings than the case reported")
    if not (refusal_logs - {claimant_log}):
        raise ValueError("no genuine process retained a refusal of the claimant's enrollment")
    return {"claimant_log": claimant_log, "override_warnings_in_components": overrides,
            "refusal_logs": sorted(refusal_logs - {claimant_log}), "component_sha256": sources,
            "scope": "same-host diagnostics; the refusal records show the claim reached genuine carriers, the receipt shows routing survived it"}


def validate_flood(text: str) -> dict:
    """Sustained serial Byzantine traffic, unrelated progress, horizon, restart."""
    expect = prefixed_rows(text, "[M16Q-FLOOD-EXPECT]")
    rows = prefixed_rows(text, "[M16Q-FLOOD]")
    order = ["saturate", "flood", "unrelated_during_flood", "horizon",
             "high_water_restart", "post_restart_unrelated"]
    if len(expect) != 1 or [row.get("case") for row in rows] != order:
        raise ValueError("missing, duplicate or reordered flood phases")
    expect = expect[0]
    cases = dict(zip(order, rows))
    if (decimal(expect, "delta_rt_ms") != DELTA_RT_MS or decimal(expect, "slack_ms") != FLOOD_SLACK_MS
            or decimal(expect, "authority_slots") != 6 or decimal(expect, "quota_max_requests") != 2
            or decimal(expect, "quota_window_ms") < DELTA_RT_MS):
        raise ValueError("unexpected flood fixture profile")
    for field in ("flooder", "correct_executor", "flood_domain", "unrelated_domain",
                  "horizon_domain", "post_restart_domain", "configuration", "network"):
        hash_field(expect, field)
    if expect["flooder"] == expect["correct_executor"] or len({expect[d] for d in (
            "flood_domain", "unrelated_domain", "horizon_domain", "post_restart_domain")}) != 4:
        raise ValueError("flood fixture scope is not distinct")
    saturate = cases["saturate"]
    if (decimal(saturate, "accepts") != 1 or decimal(saturate, "typed_conflicts") != 1
            or decimal(saturate, "durable_records") != 1 or saturate.get("result") != "safe"
            or decimal(saturate, "max_valid_reply_elapsed_ms") > QUALIFIED_ENVELOPE_MS):
        raise ValueError("saturated slot was not established by one accept and one typed conflict")
    flood = cases["flood"]
    live = decimal(flood, "saturated_live_requests")
    if (decimal(flood, "elapsed_ms") < 2 * DELTA_RT_MS or decimal(flood, "min_millis") != 2 * DELTA_RT_MS
            or live < 2 or decimal(flood, "typed_conflicts") != live
            or decimal(flood, "executor_operations") != live
            or decimal(flood, "wrong_slot_refusals") < 1 or decimal(flood, "wrong_predecessor_refusals") < 1
            or decimal(flood, "quota_drops") < 1 or decimal(flood, "accepts") != 0
            or decimal(flood, "durable_records") != 0 or flood.get("result") != "safe"):
        raise ValueError("flood lacks sustained typed refusals with zero mutation")
    if hash_field(flood, "requester") != expect["flooder"] or hash_field(flood, "domain") != expect["flood_domain"]:
        raise ValueError("flood identity does not match the fixture scope")
    refused = flood.get("refused_payloads", "").split(",")
    if len(refused) != 2 or len(set(refused)) != 2 or any(not re.fullmatch(r"[0-9a-f]{64}", p) for p in refused):
        raise ValueError("flood lacks two distinct refused payloads")
    for name in ("unrelated_during_flood", "post_restart_unrelated"):
        row = cases[name]
        if (row.get("result") != "executed" or decimal(row, "delta_rt_ms") != DELTA_RT_MS
                or decimal(row, "slack_ms") != FLOOD_SLACK_MS
                or decimal(row, "elapsed_ms") > DELTA_RT_MS + FLOOD_SLACK_MS
                or decimal(row, "max_valid_reply_elapsed_ms") > QUALIFIED_ENVELOPE_MS):
            raise ValueError(f"{name} missed delta_rt + slack or its reply envelope")
    horizon = cases["horizon"]
    slots = re.fullmatch(r"\[([0-9]+(?:,[0-9]+)*)\]", horizon.get("slot_elapsed_ms", ""))
    if (slots is None or len(slots[1].split(",")) != 6 or decimal(horizon, "authority_slots") != 6
            or decimal(horizon, "filled") != 6 or horizon.get("beyond_horizon_refused") != "true"
            or decimal(horizon, "historical_replays") != 6 or horizon.get("result") != "safe"):
        raise ValueError("horizon was not filled, refused beyond, and historically replayed")
    restart = cases["high_water_restart"]
    if (restart.get("durable_store_holds_both_candidates") != "true"
            or restart.get("durable_store_holds_horizon_head") != "true"
            or decimal(restart, "recovery_elapsed_ms") > decimal(restart, "recovery_budget_ms")
            or restart.get("beyond_horizon_refused") != "true"
            or decimal(restart, "historical_replays") != 6
            or decimal(restart, "sole_member_conflict_refusals") != 2
            or restart.get("sole_member_refusal_kinds") != "live_conflict,durable_claim"
            or restart.get("result") != "recovered"):
        raise ValueError("high-water restart lacks bounded recovery with retained knowledge")
    live_refusals = restart.get("sole_member_refusal_kinds", "").split(",").count("live_conflict")
    post = cases["post_restart_unrelated"]
    if (decimal(post, "live_sole_member_refusals") != live_refusals
            or decimal(post, "executor_operations_since_restart") != 1 + live_refusals):
        raise ValueError("post-restart executor operation count differs from the two conflict queries and one singleton")
    if len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", text, re.MULTILINE)) != 1:
        raise ValueError("expected one completed, non-ignored process test")
    return {"flood_elapsed_ms": decimal(flood, "elapsed_ms"), "saturated_live_requests": live,
            "quota_drops": decimal(flood, "quota_drops"),
            "wrong_slot_refusals": decimal(flood, "wrong_slot_refusals"),
            "wrong_predecessor_refusals": decimal(flood, "wrong_predecessor_refusals"),
            "unrelated_elapsed_ms": decimal(cases["unrelated_during_flood"], "elapsed_ms"),
            "recovery_elapsed_ms": decimal(restart, "recovery_elapsed_ms"),
            "post_restart_elapsed_ms": decimal(cases["post_restart_unrelated"], "elapsed_ms"),
            "requester": expect["flooder"], "domain": expect["flood_domain"],
            "refused_payloads": refused}


def validate_flood_components(text: str, directory: Path) -> dict:
    """Member-side quota drops, no operation start for refused payloads, no
    scheduling failure, and every completed member write is published
    (member_work_returned) only after its durable completion on that process."""
    summary = validate_flood(text)
    drops = 0
    lifecycle = {}
    sources = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
               for path in sorted(directory.glob("*-orch.log"))}
    for name, record in component_records(directory):
        fields = record["fields"]
        event = fields.get("event")
        if event in SCHEDULING_FAILURES:
            raise ValueError("QUV scheduling/service failure invalidates flood qualification")
        if record.get("target") != "quv":
            continue
        if (fields.get("message") == QUOTA_DROP_MESSAGE and fields.get("domain") == summary["domain"]
                and fields.get("requester") == summary["requester"]):
            drops += 1
        if event in {"member_work_queued", "member_work_completed", "member_work_returned"}:
            nonce = fields.get("nonce")
            if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce):
                raise ValueError("member work event lacks its nonce")
            lifecycle.setdefault((name, nonce), []).append((event, fields.get("succeeded")))
    if drops < summary["quota_drops"] or drops < 1:
        raise ValueError("component logs do not retain the reported quota drops")
    for (name, nonce), events in lifecycle.items():
        names = [event for event, _ in events]
        if names.count("member_work_completed") > 1 or names.count("member_work_returned") > 1:
            raise ValueError("duplicate member work completion")
        if "member_work_completed" in names:
            if ("member_work_queued" not in names
                    or names.index("member_work_queued") > names.index("member_work_completed")):
                raise ValueError("member work completed without a preceding queued admission")
            if "member_work_returned" in names and names.index("member_work_returned") < names.index("member_work_completed"):
                raise ValueError("member work was published before its durable completion")
        elif "member_work_returned" in names:
            raise ValueError("member work was published without durable completion")
    starts = operation_starts(directory)
    for payload in summary["refused_payloads"]:
        if any(start_payload == payload for _, start_payload, _ in starts):
            raise ValueError("refused flood payload started an executor operation")
    return {"quota_drops_in_components": drops, "member_work_lifecycles": len(lifecycle),
            "operation_starts": len(starts), "component_sha256": sources,
            "scope": "same-host diagnostics; member_work ordering is the retained durability-before-publication evidence, not a protocol proof"}


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
                  f"[M16Q-QUV] case=sole_correct member_position={i} process_index={i} terminal_replays=1 replay_elapsed_ms=1 elapsed_ms=5000 max_valid_reply_elapsed_ms=3999 qualified_envelope_ms=4500 result=executed"]
    lines += [
        "[M16Q-QUV] case=recovered_results exact_nonportable_results=4 result=recorded",
        "[M16Q-QUV] case=authenticated_saturation operations=4 elapsed_ms=5000 max_valid_reply_elapsed_ms=Some(4000) qualified_envelope_ms=4500 result=executed",
        "[M16Q-QUV] case=concurrent_valid_conflict accepts=1 conflict_rejections=1 durable_records=1 rejected_resources_unchanged=true elapsed_ms=5000 result=safe",
        "[M16Q-QUV] case=unrelated_after_conflict elapsed_ms=5000 result=executed",
        "[M16Q-QUV] case=expired_result expiry_height=64 observed_height=65 elapsed_ms=15 receipt_unchanged=true result=recorded",
        f"[M16Q-STATUS-CLAIM-EXPECT] member_position=0 account={CLAIMED_ACCOUNT} claimant_position=1 claimant_process=1 claimant_account={CLAIMANT_ACCOUNT} claimant_peer={CLAIMANT_PEER}",
        f"[M16Q-QUV] case=byzantine_status_claim claimed_account={CLAIMED_ACCOUNT} claimant_process=1 claimant_peer={CLAIMANT_PEER} members_valid=4 override_warnings=3 claim_refusals=2 elapsed_ms=5200 max_valid_reply_elapsed_ms=700 qualified_envelope_ms=4500 result=executed",
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;",
    ]
    fork_lines = []
    for index, case in enumerate(FORK_CASES):
        mode, order = case.split("-")
        refusals = 1 if order == "ab" else 2
        same_executor = "true" if mode == "owned" else "false"
        after_a = "claim_index" if same_executor == "true" else "expected_head"
        rules = after_a if order == "ab" else "expected_head," + after_a
        fork_lines.append(
            f"[M16Q-PREDECESSOR-FORK] case={case} mode={mode} order={order} refused_before_push=true "
            f"refusals={refusals} same_executor={same_executor} refusal_rules={rules} accepts=1 durable_records=1 predecessor_a={'4d' * 32} predecessor_b={'4e' * 32} "
            f"accepted_payload={f'{index * 2 + 1:064x}'} refused_payload={f'{index * 2 + 2:064x}'} result=safe")
    replay_line = (f"[M16Q-CONCURRENT-REPLAY] unrelated_elapsed_ms=5000 replay_count=40 replay_span_ms=5100 "
                   f"delta_rt_ms=5000 slack_ms=10000 replay_payload={'aa' * 32} unrelated_payload={'bb' * 32} lookup_only=true")
    lines = lines[:-1] + fork_lines + [replay_line, lines[-1]]
    valid = "\n".join(lines)
    validate(valid)
    validate(valid.replace("accepts=1 conflict_rejections=1 durable_records=1", "accepts=0 conflict_rejections=2 durable_records=0"))
    invalid = ["\n".join(lines[:i] + lines[i + 1:]) for i in range(len(lines))]
    invalid += [valid + "\n" + lines[0], valid + "\n" + lines[4],
                "\n".join([lines[4]] + lines[:4] + lines[5:]),
                valid + "\n" + fork_lines[0], valid + "\n" + replay_line]
    for before, after in [
        # R1 004: measured register evidence contradicting the outcome counts.
        ("accepts=1 conflict_rejections=1 durable_records=1", "accepts=1 conflict_rejections=1 durable_records=2"),
        ("accepts=1 conflict_rejections=1 durable_records=1", "accepts=0 conflict_rejections=2 durable_records=1"),
        ("rejected_resources_unchanged=true", "rejected_resources_unchanged=false"),
        # R1 001: predecessor fork rows.
        ("refused_before_push=true", "refused_before_push=false"),
        ("case=owned-ba mode=owned order=ba refused_before_push=true refusals=2", "case=owned-ba mode=owned order=ba refused_before_push=true refusals=1"),
        ("case=unowned-ab mode=unowned order=ab refused_before_push=true refusals=1 same_executor=false refusal_rules=expected_head accepts=1", "case=unowned-ab mode=unowned order=ab refused_before_push=true refusals=1 accepts=0"),
        ("case=unowned-ab mode=unowned order=ab refused_before_push=true refusals=1 same_executor=false refusal_rules=expected_head accepts=1 durable_records=1", "case=unowned-ab mode=unowned order=ab refused_before_push=true refusals=1 same_executor=false refusal_rules=expected_head accepts=1 durable_records=2"),
        ("case=owned-ab mode=owned", "case=owned-ab mode=unowned"),
        (f"predecessor_b={'4e' * 32}", f"predecessor_b={'4d' * 32}"),
        ("same_executor=true refusal_rules=expected_head,claim_index", "same_executor=true refusal_rules=claim_index"),
        ("same_executor=false refusal_rules=expected_head accepts", "same_executor=false refusal_rules=claim_index accepts"),
        ("same_executor=true refusal_rules=claim_index accepts", "same_executor=maybe refusal_rules=claim_index accepts"),
        ("same_executor=true refusal_rules=claim_index accepts", "same_executor=true refusal_rules=expected_head accepts"),
        (f"refused_payload={2:064x}", f"refused_payload={1:064x}"),
        ("result=safe\n[M16Q-PREDECESSOR-FORK] case=owned-ba", "result=unsafe\n[M16Q-PREDECESSOR-FORK] case=owned-ba"),
        # R1 010: concurrent terminal replay.
        ("unrelated_elapsed_ms=5000 replay_count=40", "unrelated_elapsed_ms=15001 replay_count=40"),
        ("unrelated_elapsed_ms=5000 replay_count=40", "unrelated_elapsed_ms=5001 replay_count=40"),
        ("replay_count=40", "replay_count=1"),
        ("lookup_only=true", "lookup_only=false"),
        ("slack_ms=10000", "slack_ms=3000"),
        ("delta_rt_ms=5000 slack_ms=10000", "delta_rt_ms=6000 slack_ms=10000"),
        (f"unrelated_payload={'bb' * 32}", f"unrelated_payload={'aa' * 32}"),
        # R1 007: Byzantine status claim.
        ("members_valid=4", "members_valid=3"),
        ("max_valid_reply_elapsed_ms=700 qualified_envelope_ms=4500 result=executed", "max_valid_reply_elapsed_ms=700 qualified_envelope_ms=4500 result=aborted"),
        (f"case=byzantine_status_claim claimed_account={CLAIMED_ACCOUNT}", f"case=byzantine_status_claim claimed_account={CLAIMANT_ACCOUNT}"),
        (f"member_position=0 account={CLAIMED_ACCOUNT}", f"member_position=1 account={CLAIMED_ACCOUNT}"),
        (f"claimant_account={CLAIMANT_ACCOUNT}", f"claimant_account={CLAIMED_ACCOUNT}"),
        ("claimant_position=1 claimant_process=1", "claimant_position=0 claimant_process=1"),
        ("claimant_position=1 claimant_process=1", "claimant_position=1 claimant_process=2"),
        ("claimant_position=1 claimant_process=1", "claimant_position=1 claimant_process=0"),
        (f"claimant_process=1 claimant_peer={CLAIMANT_PEER} members_valid", f"claimant_process=0 claimant_peer={CLAIMANT_PEER} members_valid"),
        (f"claimant_process=1 claimant_peer={CLAIMANT_PEER} members_valid", f"claimant_process=1 claimant_peer={CLAIMANT_PEER[:-1]}0 members_valid"),
        (f"claimant_process=1 claimant_peer={CLAIMANT_PEER} members_valid", "claimant_process=1 claimant_peer=peer members_valid"),
        ("override_warnings=3", "override_warnings=0"),
        ("claim_refusals=2", "claim_refusals=0"),
        ("claimed_account=" + CLAIMED_ACCOUNT[:-2] + CLAIMED_ACCOUNT[-2:], "claimed_account=" + CLAIMED_ACCOUNT[:-2]),
    ]:
        assert before in valid, before
        invalid.append(valid.replace(before, after))
    invalid.append(valid + "\n" + lines[-2])
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
        ("3999", "4501"), ("Some(4000)", "Some(4501)"),
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
            "overlap": overlap_self_test(), "no_push": no_push_self_test(valid),
            "status_claim": status_claim_self_test(valid), "status_squat": status_squat_self_test(),
            "flood": flood_self_test()}


CLAIMED_ACCOUNT = "c0" * 32
CLAIMANT_ACCOUNT = "b1" * 32
CLAIMANT_PEER = "12D3KooWByzantineSquatterPeer1111111111111111111111111"


STATUS_RESPONSE_MESSAGE = "Responding to status request."


def validate_status_squat(text: str) -> dict:
    """R1 007 first-contact trace (ruling 2026-09-06): process B launched with
    the status override claims C's account in its very first status response.
    B is Byzantine by construction (it never presents its own account, so no
    peer can bind it) and its own reply is not owed; every CORRECT member's
    reply is. The measured operation on C's executor executes with EXACTLY
    the three correct replies (C's own included, B's absent); a fourth reply
    would mean a squatter got bound. B is never authenticated under any
    account anywhere."""
    expect = prefixed_rows(text, "[M16Q-STATUS-SQUAT-EXPECT]")
    rows = prefixed_rows(text, "[M16Q-STATUS-SQUAT]")
    observed = prefixed_rows(text, "[M16Q-STATUS-SQUAT-OBSERVED]")
    if len(expect) != 1 or len(rows) != 1 or len(observed) != 1:
        raise ValueError("expected exactly one status-squat expectation, observed and result row")
    expect, row, observed = expect[0], rows[0], observed[0]
    if expect.get("first_contact") != "true" or row.get("first_contact") != "true":
        raise ValueError("status squat is not the first-contact trace")
    if (row.get("result") != "executed" or decimal(row, "members_configured") != 4
            or decimal(row, "members_valid") != 3 or row.get("claimant_excluded") != "true"
            or row.get("claimed_replied") != "true"):
        raise ValueError("first-contact squat did not execute with exactly the three correct replies")
    claimed = hash_field(row, "claimed_account")
    claimant_account = hash_field(expect, "claimant_account")
    if hash_field(expect, "claimed_account") != claimed or claimant_account == claimed:
        raise ValueError("claimed account differs from the fixture expectation or equals the claimant")
    valid_members = observed.get("valid_members", "").split(",")
    if (decimal(observed, "members_configured") != 4 or decimal(observed, "members_valid") != 3
            or len(valid_members) != 3 or len(set(valid_members)) != 3
            or any(not re.fullmatch(r"[0-9a-f]{64}", member) for member in valid_members)):
        raise ValueError("observed reply set is not exactly three distinct configured members")
    if claimed not in valid_members or observed.get("claimed_replied") != "true":
        raise ValueError("the claimed (correct) member's own reply is missing")
    if claimant_account in valid_members or observed.get("claimant_replied") != "false":
        raise ValueError("the claimant replied: a squatter was bound to a carrier")
    for field in ("configuration", "network", "measured_domain"):
        hash_field(expect, field)
    if decimal(row, "claimant_process") != 1 or decimal(expect, "claimant_process") != 1 or decimal(expect, "claimed_process") != 0:
        raise ValueError("first-contact squat must be launched on process 1 against process 0")
    claimant_peer, claimed_peer = expect.get("claimant_peer", ""), expect.get("claimed_peer", "")
    if (not re.fullmatch(PEER_ID_PATTERN, claimant_peer) or not re.fullmatch(PEER_ID_PATTERN, claimed_peer)
            or claimant_peer == claimed_peer or row.get("claimant_peer") != claimant_peer):
        raise ValueError("claimant/claimed peer ids are missing, equal or inconsistent")
    if decimal(row, "override_warnings") < 1 or decimal(row, "refusing_processes") != 3:
        raise ValueError("claim was not observed as advertised and refused on every other process")
    if decimal(row, "claimant_authenticated_any") != 0:
        raise ValueError("claimant was authenticated under some account")
    decimal(row, "warmup_attempts")
    decimal(row, "elapsed_ms")
    decimal(row, "max_valid_reply_elapsed_ms")
    if decimal(row, "qualified_envelope_ms") != QUALIFIED_ENVELOPE_MS:
        raise ValueError("unexpected qualified reply envelope in status-squat row")
    if len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", text, re.MULTILINE)) != 1:
        raise ValueError("expected one completed, non-ignored process test")
    return {"claimed_account": claimed, "claimant_account": claimant_account,
            "claimant_peer": claimant_peer, "claimed_peer": claimed_peer,
            "members_configured": 4, "members_valid": 3, "valid_members": sorted(valid_members),
            "claimant_excluded": True, "override_warnings": decimal(row, "override_warnings"),
            "warmup_attempts": decimal(row, "warmup_attempts"),
            "warmup_rows": prefixed_rows(text, "[M16Q-STATUS-SQUAT-WARMUP]")}


def validate_status_squat_components(text: str, directory: Path) -> dict:
    """Component logs (full run, launch window included): each log names its
    own peer (libp2p_swarm local_peer_id). The claimant's log holds the
    override WARN before its first status response and one per response; every
    other log refused or dropped the claimant's claim; no log authenticated the
    claimant under the claimed account; both genuine third processes
    authenticated the claimed carrier under the claimed account, and the
    claimed process itself refused the claim as an alias of its local endpoint."""
    summary = validate_status_squat(text)
    claimant_peer, claimed_peer, claimed = summary["claimant_peer"], summary["claimed_peer"], summary["claimed_account"]
    sources = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
               for path in sorted(directory.glob("*-orch.log"))}
    local_peer, overrides, responses, first_override, first_response = {}, {}, {}, {}, {}
    refused, authenticated_claimed, alias_refusals = set(), set(), set()
    for name, record in component_records(directory):
        fields = record["fields"]
        if record.get("target") == "libp2p_swarm" and isinstance(fields.get("local_peer_id"), str):
            if local_peer.get(name, fields["local_peer_id"]) != fields["local_peer_id"]:
                raise ValueError("component log names two local peer ids")
            local_peer[name] = fields["local_peer_id"]
        if record.get("target") == "sync" and fields.get("message") == STATUS_RESPONSE_MESSAGE:
            responses[name] = responses.get(name, 0) + 1
            first_response.setdefault(name, record.get("timestamp", ""))
        if record.get("target") != "network":
            continue
        event = fields.get("event")
        if event == "testing_status_account_override_invalid":
            raise ValueError("a process reported a malformed status override")
        if event == "testing_status_account_override":
            if record.get("level") != "WARN" or fields.get("claimed_account") != claimed or fields.get("local_peer") != claimant_peer:
                raise ValueError("status override is not a WARN naming the claimed account from the claimant")
            overrides[name] = overrides.get(name, 0) + 1
            first_override.setdefault(name, record.get("timestamp", ""))
        if event in {"pq_peer_enrollment_refused", "pq_handoff_peer_enrollment_refused", "pq_provisional_enrollment_lost"} \
                and fields.get("peer") == claimant_peer:
            refused.add(name)
            if "aliases the local endpoint" in str(fields.get("error", "")):
                alias_refusals.add(name)
        if event == "pq_carrier_authenticated":
            if fields.get("peer") == claimant_peer:
                raise ValueError("claimant was authenticated under some account")
            if fields.get("peer") == claimed_peer and fields.get("account") == claimed:
                authenticated_claimed.add(name)
    if len(sources) != 4 or set(local_peer) != set(sources):
        raise ValueError("expected four component logs each naming its local peer id")
    by_peer = {peer: name for name, peer in local_peer.items()}
    if len(by_peer) != 4 or claimant_peer not in by_peer or claimed_peer not in by_peer:
        raise ValueError("claimant/claimed peers are not among the four component logs")
    claimant_log, claimed_log = by_peer[claimant_peer], by_peer[claimed_peer]
    if set(overrides) != {claimant_log}:
        raise ValueError("status override must appear in exactly the claimant's log")
    if overrides[claimant_log] < summary["override_warnings"] or responses.get(claimant_log, 0) < 1:
        raise ValueError("claimant log lacks override warnings or status responses")
    if overrides[claimant_log] < responses[claimant_log] or first_override[claimant_log] > first_response[claimant_log]:
        raise ValueError("claimant sent a status response that was not preceded by its override warning")
    others = set(sources) - {claimant_log}
    if not others <= refused:
        raise ValueError("a genuine process never refused or dropped the claimant's claim")
    if claimed_log not in alias_refusals:
        raise ValueError("the claimed process did not refuse the claim as an alias of its local endpoint")
    genuine_third = others - {claimed_log}
    if not genuine_third <= authenticated_claimed:
        raise ValueError("a genuine third process never authenticated the claimed carrier under its account")
    return {"claimant_log": claimant_log, "claimed_log": claimed_log,
            "override_warnings_in_components": overrides[claimant_log],
            "status_responses_from_claimant": responses[claimant_log],
            "refusing_logs": sorted(refused), "claimed_carrier_authenticated_in": sorted(authenticated_claimed),
            "component_sha256": sources,
            "scope": "same-host diagnostics; first-contact claim refused everywhere, claimed carrier proven by handshake, receipt shows routing survived it"}


SQUAT_CLAIMED_PEER = "12D3KooWGenuineCarrierPeerC1111111111111111111111111"
SQUAT_OTHER_PEERS = ["12D3KooWGenuineThirdPeerA1111111111111111111111111111",
                     "12D3KooWGenuineThirdPeerB1111111111111111111111111111"]
SQUAT_THIRD_A, SQUAT_THIRD_B = "a3" * 32, "b3" * 32
SQUAT_CORRECT_SET = ",".join(sorted([CLAIMED_ACCOUNT, SQUAT_THIRD_A, SQUAT_THIRD_B]))


def status_squat_self_test() -> dict:
    lines = [
        f"[M16Q-STATUS-SQUAT-EXPECT] first_contact=true configuration={'01' * 32} network={'02' * 32} claimed_account={CLAIMED_ACCOUNT} "
        f"claimant_account={CLAIMANT_ACCOUNT} claimed_process=0 claimant_process=1 claimed_peer={SQUAT_CLAIMED_PEER} "
        f"claimant_peer={CLAIMANT_PEER} measured_domain={'03' * 32} manifests=3 build_elapsed_ms=90000",
        f"[M16Q-STATUS-SQUAT-WARMUP] attempt=1 slot=1 outcome=executed_expected_coverage members_valid=3 valid_members={SQUAT_CORRECT_SET} elapsed_ms=9000",
        f"[M16Q-STATUS-SQUAT-OBSERVED] members_configured=4 members_valid=3 valid_members={SQUAT_CORRECT_SET} claimed_replied=true claimant_replied=false elapsed_ms=6000",
        f"[M16Q-STATUS-SQUAT] first_contact=true claimed_account={CLAIMED_ACCOUNT} claimant_process=1 claimant_peer={CLAIMANT_PEER} "
        "members_configured=4 members_valid=3 claimant_excluded=true claimed_replied=true override_warnings=2 refusing_processes=3 refusal_reasons=x "
        "claimant_authenticated_any=0 warmup_attempts=1 elapsed_ms=6000 max_valid_reply_elapsed_ms=900 qualified_envelope_ms=4500 result=executed",
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;",
    ]
    valid = "\n".join(lines)
    assert validate_status_squat(valid)["override_warnings"] == 2
    invalid = ["\n".join(lines[:i] + lines[i + 1:]) for i in (0, 2, 3, 4)]
    invalid.append(valid + "\n" + lines[3])
    invalid.append(valid + "\n" + lines[2])
    squatter_bound = f"members_configured=4 members_valid=4 valid_members={SQUAT_CORRECT_SET},{CLAIMANT_ACCOUNT} claimed_replied=true claimant_replied=true"
    claimed_missing = f"members_configured=4 members_valid=3 valid_members={SQUAT_THIRD_A},{SQUAT_THIRD_B},{CLAIMANT_ACCOUNT} claimed_replied=false claimant_replied=true"
    for before, after in [
        ("[M16Q-STATUS-SQUAT] first_contact=true", "[M16Q-STATUS-SQUAT] first_contact=false"),
        # A fourth reply with the claimant present: a squatter got bound.
        (f"members_configured=4 members_valid=3 valid_members={SQUAT_CORRECT_SET} claimed_replied=true claimant_replied=false", squatter_bound),
        ("members_configured=4 members_valid=3 claimant_excluded=true claimed_replied=true override", "members_configured=4 members_valid=4 claimant_excluded=false claimed_replied=true override"),
        ("members_configured=4 members_valid=3 claimant_excluded=true claimed_replied=true override", "members_configured=4 members_valid=4 claimant_excluded=true claimed_replied=true override"),
        # The claimed (correct) member's own reply missing.
        (f"members_configured=4 members_valid=3 valid_members={SQUAT_CORRECT_SET} claimed_replied=true claimant_replied=false", claimed_missing),
        ("claimant_excluded=true claimed_replied=true override", "claimant_excluded=true claimed_replied=false override"),
        (f"valid_members={SQUAT_CORRECT_SET} claimed_replied=true claimant_replied=false", f"valid_members={SQUAT_THIRD_A},{SQUAT_THIRD_B} claimed_replied=true claimant_replied=false"),
        (f"valid_members={SQUAT_CORRECT_SET} claimed_replied=true claimant_replied=false", f"valid_members={SQUAT_CORRECT_SET} claimed_replied=true claimant_replied=true"),
        (f"valid_members={SQUAT_CORRECT_SET} claimed_replied=true claimant_replied=false", f"valid_members={CLAIMED_ACCOUNT},{SQUAT_THIRD_A},{SQUAT_THIRD_A} claimed_replied=true claimant_replied=false"),
        ("members_configured=4 members_valid=3 claimant_excluded", "members_configured=3 members_valid=3 claimant_excluded"),
        ("result=executed", "result=aborted"),
        (f"[M16Q-STATUS-SQUAT] first_contact=true claimed_account={CLAIMED_ACCOUNT}", f"[M16Q-STATUS-SQUAT] first_contact=true claimed_account={CLAIMANT_ACCOUNT}"),
        (f"claimant_account={CLAIMANT_ACCOUNT}", f"claimant_account={CLAIMED_ACCOUNT}"),
        ("claimed_process=0 claimant_process=1", "claimed_process=0 claimant_process=2"),
        ("claimed_process=0 claimant_process=1", "claimed_process=1 claimant_process=1"),
        (f"claimant_process=1 claimant_peer={CLAIMANT_PEER} members_configured", f"claimant_process=2 claimant_peer={CLAIMANT_PEER} members_configured"),
        (f"claimant_process=1 claimant_peer={CLAIMANT_PEER} members_configured", f"claimant_process=1 claimant_peer={SQUAT_CLAIMED_PEER} members_configured"),
        (f"claimed_peer={SQUAT_CLAIMED_PEER}", f"claimed_peer={CLAIMANT_PEER}"),
        ("override_warnings=2", "override_warnings=0"),
        ("refusing_processes=3", "refusing_processes=2"),
        ("claimant_authenticated_any=0", "claimant_authenticated_any=1"),
        ("qualified_envelope_ms=4500", "qualified_envelope_ms=4000"),
        ("0 ignored;", "1 ignored;"),
    ]:
        assert before in valid, before
        invalid.append(valid.replace(before, after))
    for index, sample in enumerate(invalid):
        try:
            validate_status_squat(sample)
        except ValueError:
            continue
        raise AssertionError(f"invalid status-squat sample {index} was accepted")

    def rec(target, second, level="INFO", **fields):
        return json.dumps({"timestamp": f"2026-09-06T00:00:{second:02d}Z", "level": level, "target": target, "fields": fields})

    def local(peer):
        return rec("libp2p_swarm", 0, local_peer_id=peer)

    def override(second):
        return rec("network", second, "WARN", event="testing_status_account_override", claimed_account=CLAIMED_ACCOUNT,
                   local_peer=CLAIMANT_PEER, local_account=CLAIMANT_ACCOUNT)

    def response(second):
        return rec("sync", second, message=STATUS_RESPONSE_MESSAGE, _peer=SQUAT_CLAIMED_PEER, height=1)

    def refusal(error="PQ provisional enrollment capacity exceeded", peer=CLAIMANT_PEER):
        return rec("network", 3, "WARN", event="pq_peer_enrollment_refused", peer=peer, error=error)

    def lost(peer=CLAIMANT_PEER):
        return rec("network", 3, "WARN", event="pq_provisional_enrollment_lost", peer=peer)

    def auth(peer, account):
        return rec("network", 4, event="pq_carrier_authenticated", peer=peer, account=account)

    claimed_log = [local(SQUAT_CLAIMED_PEER), refusal("PQ peer enrollment aliases the local endpoint"),
                   auth(SQUAT_OTHER_PEERS[0], "aa" * 32)]
    claimant_log = [local(CLAIMANT_PEER), override(1), response(1), override(2), response(2), auth(SQUAT_CLAIMED_PEER, CLAIMED_ACCOUNT)]
    third_a = [local(SQUAT_OTHER_PEERS[0]), lost(), auth(SQUAT_CLAIMED_PEER, CLAIMED_ACCOUNT)]
    third_b = [local(SQUAT_OTHER_PEERS[1]), refusal(), auth(SQUAT_CLAIMED_PEER, CLAIMED_ACCOUNT), auth(SQUAT_OTHER_PEERS[0], "aa" * 32)]
    base = [claimed_log, claimant_log, third_a, third_b]
    cases = [
        [claimed_log, [local(CLAIMANT_PEER), response(1)], third_a, third_b],
        [claimed_log, [local(CLAIMANT_PEER), response(1), override(2), response(2)], third_a, third_b],
        [claimed_log, [local(CLAIMANT_PEER), override(1), response(1), response(2)], third_a, third_b],
        [claimed_log + [override(5)], claimant_log, third_a, third_b],
        [claimed_log, [line.replace(CLAIMED_ACCOUNT, CLAIMANT_ACCOUNT) for line in claimant_log], third_a, third_b],
        [claimed_log, claimant_log + [rec("network", 6, "WARN", event="testing_status_account_override_invalid", error="bad")], third_a, third_b],
        [[local(SQUAT_CLAIMED_PEER), auth(SQUAT_OTHER_PEERS[0], "aa" * 32)], claimant_log, third_a, third_b],
        [[local(SQUAT_CLAIMED_PEER), refusal(), auth(SQUAT_OTHER_PEERS[0], "aa" * 32)], claimant_log, third_a, third_b],
        [claimed_log, claimant_log, [local(SQUAT_OTHER_PEERS[0]), auth(SQUAT_CLAIMED_PEER, CLAIMED_ACCOUNT)], third_b],
        [claimed_log, claimant_log, [local(SQUAT_OTHER_PEERS[0]), lost()], third_b],
        [claimed_log, claimant_log, third_a + [auth(CLAIMANT_PEER, CLAIMED_ACCOUNT)], third_b],
        [claimed_log, claimant_log, third_a, third_b + [auth(CLAIMANT_PEER, CLAIMED_ACCOUNT)]],
        # Bound under its OWN account is equally impossible for a process that never presents it.
        [claimed_log + [auth(CLAIMANT_PEER, CLAIMANT_ACCOUNT)], claimant_log, third_a, third_b],
        [[refusal("PQ peer enrollment aliases the local endpoint")], claimant_log, third_a, third_b],
        [claimed_log, claimant_log, [local(SQUAT_OTHER_PEERS[1]), lost(), auth(SQUAT_CLAIMED_PEER, CLAIMED_ACCOUNT)], third_b],
        base[:3],
    ]
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        write_component_logs(directory, base)
        result = validate_status_squat_components(valid, directory)
        assert result["claimant_log"] == "validator-1-orch.log" and result["claimed_log"] == "validator-0-orch.log", result
        for index, logs in enumerate(cases):
            write_component_logs(directory, logs)
            try:
                validate_status_squat_components(valid, directory)
            except ValueError:
                continue
            raise AssertionError(f"invalid status-squat component sample {index} was accepted")
    return {"positive_cases": 2, "negative_cases": len(invalid) + len(cases)}


def status_claim_self_test(valid_log: str) -> dict:
    """validate_status_claim_components over synthetic component logs."""

    def network(event, level="WARN", **fields):
        return json.dumps({"timestamp": "2026-09-06T00:00:01Z", "level": level, "target": "network",
                           "fields": {"event": event, **fields}})

    override = network("testing_status_account_override", claimed_account=CLAIMED_ACCOUNT,
                       local_peer=CLAIMANT_PEER, local_account=CLAIMANT_ACCOUNT)
    refusal = network("pq_peer_enrollment_refused", peer=CLAIMANT_PEER,
                      error="PQ peer enrollment aliases the local endpoint")
    other_refusal = network("pq_peer_enrollment_refused", peer="12D3KooWSomeOtherPeer", error="x")
    base = [[refusal, start_record("aa" * 32)], [override, override, override],
            [refusal, other_refusal], [other_refusal]]
    cases = [
        [base[0], [start_record("bb" * 32)], base[2], base[3]],
        [base[0] + [override], *base[1:]],
        [base[0], [override, override], base[2], base[3]],
        [base[0], [override.replace(CLAIMED_ACCOUNT, CLAIMANT_ACCOUNT)] * 3, base[2], base[3]],
        [base[0], [override.replace(CLAIMANT_PEER, "12D3KooWSomeOtherPeer")] * 3, base[2], base[3]],
        [base[0], base[1] + [network("testing_status_account_override_invalid", error="bad")], base[2], base[3]],
        [[start_record("aa" * 32)], base[1], [other_refusal], base[3]],
        [base[0], base[1], base[2], base[3] + [override.replace('"WARN"', '"INFO"')]],
        [[start_record("aa" * 32)], base[1] + [refusal], [other_refusal], base[3]],
        base[:3],
    ]
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        write_component_logs(directory, base)
        result = validate_status_claim_components(valid_log, directory)
        assert result["claimant_log"] == "validator-1-orch.log", result
        assert result["refusal_logs"] == ["validator-0-orch.log", "validator-2-orch.log"], result
        for index, logs in enumerate(cases):
            write_component_logs(directory, logs)
            try:
                validate_status_claim_components(valid_log, directory)
            except ValueError:
                continue
            raise AssertionError(f"invalid status-claim sample {index} was accepted")
    return {"positive_cases": 1, "negative_cases": len(cases)}


def write_component_logs(directory: Path, logs):
    for path in directory.glob("*.log"):
        path.unlink()
    for index, lines in enumerate(logs):
        (directory / f"validator-{index}-orch.log").write_text("\n".join(lines) + "\n")


def start_record(payload, preparation=False, second=0):
    return json.dumps({"timestamp": f"2026-09-06T00:00:{second:02d}Z", "level": "DEBUG", "target": "quv",
                       "fields": {"event": "operation_started", "nonce": "cd" * 32,
                                  "payload": payload, "independent_preparation": preparation}})


def no_push_self_test(valid_log: str) -> dict:
    """validate_no_push_evidence over synthetic component logs."""
    accepted = [f"{index * 2 + 1:064x}" for index in range(4)]
    refused = [f"{index * 2 + 2:064x}" for index in range(4)]
    base = [[start_record(accepted[0]), start_record("aa" * 32), start_record("bb" * 32)],
            [start_record(accepted[1]), start_record(accepted[0], True)],
            [start_record(accepted[2]), start_record("aa" * 32, True)],
            [start_record(accepted[3]), start_record("bb" * 32, True)]]
    cases = [
        [base[0] + [start_record(refused[0])], *base[1:]],
        [base[0] + [start_record(refused[1], True)], *base[1:]],
        [base[0] + [start_record(accepted[0])], *base[1:]],
        [base[0] + [start_record("aa" * 32)], *base[1:]],
        [base[0] + [start_record("bb" * 32)], *base[1:]],
        [base[0][1:], *base[1:]],
        [[start_record("aa" * 32), start_record("bb" * 32)], *base[1:]],
        [base[0] + [start_record("aa" * 32).replace('"independent_preparation": false', '"independent_preparation": "false"')], *base[1:]],
        base[:3],
    ]
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        write_component_logs(directory, base)
        assert validate_no_push_evidence(valid_log, directory)["operation_starts"] == 9
        for index, logs in enumerate(cases):
            write_component_logs(directory, logs)
            try:
                validate_no_push_evidence(valid_log, directory)
            except ValueError:
                continue
            raise AssertionError(f"invalid no-push sample {index} was accepted")
    return {"positive_cases": 1, "negative_cases": len(cases)}


def flood_self_test() -> dict:
    flooder, correct = "11" * 32, "22" * 32
    domains = ["31" * 32, "32" * 32, "33" * 32, "34" * 32]
    refused = ["41" * 32, "42" * 32]
    lines = [
        f"[M16Q-FLOOD-EXPECT] configuration={'01' * 32} network={'02' * 32} flooder={flooder} correct_executor={correct} "
        f"flood_domain={domains[0]} unrelated_domain={domains[1]} horizon_domain={domains[2]} post_restart_domain={domains[3]} "
        "delta_rt_ms=5000 slack_ms=10000 authority_slots=6 quota_max_requests=2 quota_window_ms=60000 manifests=22",
        "[M16Q-FLOOD] case=saturate accepts=1 typed_conflicts=1 durable_records=1 max_valid_reply_elapsed_ms=300 qualified_envelope_ms=4500 elapsed_ms=11000 result=safe",
        f"[M16Q-FLOOD] case=flood elapsed_ms=12000 min_millis=10000 saturated_live_requests=2 typed_conflicts=2 wrong_slot_refusals=8 "
        f"wrong_predecessor_refusals=8 quota_drops=3 executor_operations=2 accepts=0 durable_records=0 requester={flooder} "
        f"domain={domains[0]} refused_payloads={refused[0]},{refused[1]} result=safe",
        "[M16Q-FLOOD] case=unrelated_during_flood elapsed_ms=5600 delta_rt_ms=5000 slack_ms=10000 max_valid_reply_elapsed_ms=400 qualified_envelope_ms=4500 result=executed",
        "[M16Q-FLOOD] case=horizon authority_slots=6 filled=6 slot_elapsed_ms=[5400,15500,15500,15500,15500,15500] beyond_horizon_refused=true historical_replays=6 result=safe",
        "[M16Q-FLOOD] case=high_water_restart durable_store_holds_both_candidates=true durable_store_holds_horizon_head=true recovery_elapsed_ms=9000 recovery_budget_ms=120000 beyond_horizon_refused=true historical_replays=6 sole_member_conflict_refusals=2 sole_member_refusal_kinds=live_conflict,durable_claim second_candidate_retention=durable_store_bytes_only result=recovered",
        "[M16Q-FLOOD] case=post_restart_unrelated elapsed_ms=5700 delta_rt_ms=5000 slack_ms=10000 max_valid_reply_elapsed_ms=500 qualified_envelope_ms=4500 executor_operations_since_restart=2 live_sole_member_refusals=1 result=executed",
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;",
    ]
    valid = "\n".join(lines)
    assert validate_flood(valid)["quota_drops"] == 3
    invalid = ["\n".join(lines[:i] + lines[i + 1:]) for i in range(len(lines))]
    invalid.append("\n".join([lines[0], lines[2], lines[1], *lines[3:]]))
    for before, after in [
        ("elapsed_ms=12000 min_millis=10000", "elapsed_ms=9999 min_millis=10000"),
        ("saturated_live_requests=2 typed_conflicts=2", "saturated_live_requests=2 typed_conflicts=1"),
        ("saturated_live_requests=2 typed_conflicts=2", "saturated_live_requests=1 typed_conflicts=1"),
        ("executor_operations=2", "executor_operations=3"),
        ("wrong_slot_refusals=8", "wrong_slot_refusals=0"),
        ("wrong_predecessor_refusals=8", "wrong_predecessor_refusals=0"),
        ("quota_drops=3", "quota_drops=0"),
        ("accepts=0 durable_records=0", "accepts=1 durable_records=0"),
        ("accepts=0 durable_records=0", "accepts=0 durable_records=1"),
        (f"requester={flooder}", f"requester={correct}"),
        (f"refused_payloads={refused[0]},{refused[1]}", f"refused_payloads={refused[0]},{refused[0]}"),
        ("case=unrelated_during_flood elapsed_ms=5600", "case=unrelated_during_flood elapsed_ms=15001"),
        ("case=post_restart_unrelated elapsed_ms=5700", "case=post_restart_unrelated elapsed_ms=15001"),
        ("max_valid_reply_elapsed_ms=400", "max_valid_reply_elapsed_ms=4501"),
        ("filled=6", "filled=5"),
        ("15500]", "15500,15500]"),
        ("beyond_horizon_refused=true historical_replays=6 result=safe", "beyond_horizon_refused=false historical_replays=6 result=safe"),
        ("historical_replays=6 sole_member", "historical_replays=5 sole_member"),
        ("durable_store_holds_both_candidates=true", "durable_store_holds_both_candidates=false"),
        ("durable_store_holds_horizon_head=true", "durable_store_holds_horizon_head=false"),
        ("recovery_elapsed_ms=9000 recovery_budget_ms=120000", "recovery_elapsed_ms=120001 recovery_budget_ms=120000"),
        ("sole_member_conflict_refusals=2", "sole_member_conflict_refusals=1"),
        ("sole_member_refusal_kinds=live_conflict,durable_claim", "sole_member_refusal_kinds=durable_claim,durable_claim"),
        ("result=recovered", "result=executed"),
        ("executor_operations_since_restart=2", "executor_operations_since_restart=3"),
        ("live_sole_member_refusals=1", "live_sole_member_refusals=2"),
        ("authority_slots=6 quota_max_requests=2", "authority_slots=7 quota_max_requests=2"),
        ("quota_max_requests=2 quota_window_ms=60000", "quota_max_requests=2 quota_window_ms=4000"),
        ("slack_ms=10000 authority_slots=6", "slack_ms=2500 authority_slots=6"),
        (f"correct_executor={correct}", f"correct_executor={flooder}"),
        (f"post_restart_domain={domains[3]}", f"post_restart_domain={domains[0]}"),
        ("0 ignored;", "1 ignored;"),
    ]:
        assert before in valid, before
        invalid.append(valid.replace(before, after))
    for index, sample in enumerate(invalid):
        try:
            validate_flood(sample)
        except ValueError:
            continue
        raise AssertionError(f"invalid flood sample {index} was accepted")

    def record(event, nonce, second, **extra):
        return json.dumps({"timestamp": f"2026-09-06T00:00:{second:02d}Z", "level": "DEBUG", "target": "quv",
                           "fields": {"event": event, "nonce": nonce, **extra}})

    def drop(domain=domains[0], requester=flooder):
        return json.dumps({"timestamp": "2026-09-06T00:00:01Z", "level": "WARN", "target": "quv",
                           "fields": {"message": QUOTA_DROP_MESSAGE, "domain": domain, "requester": requester}})

    nonce = "ee" * 32
    work = [record("member_work_queued", nonce, 1), record("member_work_completed", nonce, 2, succeeded=True),
            record("member_work_returned", nonce, 3, succeeded=True)]
    base = [work + [drop()], work + [drop()], work + [drop()], work + [start_record("55" * 32)]]
    component_cases = [
        [work + [drop()], work + [drop()], work, work],
        [work + [drop(domain=domains[1])], work + [drop()], work + [drop()], work],
        [work + [drop(requester=correct)], work + [drop()], work + [drop()], work],
        [[work[1], work[2], drop()], *base[1:]],
        [[work[0], work[2], work[1], drop()], *base[1:]],
        [[work[0], work[2], drop()], *base[1:]],
        [[work[0], work[1], work[1], drop()], *base[1:]],
        [base[0] + [start_record(refused[0])], *base[1:]],
        [base[0] + [start_record(refused[1], True)], *base[1:]],
        [base[0] + [record("push_admission_overflow", nonce, 4)], *base[1:]],
        [base[0] + [record("operation_service_expired", nonce, 4)], *base[1:]],
        [base[0] + ["HARNESS_DIAGNOSTIC_WRITE_FAILURE"], *base[1:]],
        base[:3],
    ]
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        write_component_logs(directory, base)
        assert validate_flood_components(valid, directory)["quota_drops_in_components"] == 3
        for index, logs in enumerate(component_cases):
            write_component_logs(directory, logs)
            try:
                validate_flood_components(valid, directory)
            except ValueError:
                continue
            raise AssertionError(f"invalid flood component sample {index} was accepted")
    return {"positive_cases": 2, "negative_cases": len(invalid) + len(component_cases)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--components", type=Path,
                        help="require receipt-bound four-way overlap and the status-claim override/refusal "
                             "records (or, with --flood, quota drops and member-work ordering) in retained "
                             "component logs")
    parser.add_argument("--flood", action="store_true",
                        help="check the Byzantine flood / high-water restart process log instead")
    parser.add_argument("--status-squat", action="store_true",
                        help="check the first-contact status identity squat process log instead")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), sort_keys=True))
    elif args.log is not None:
        raw = args.log.read_bytes()
        text = raw.decode("utf-8")
        if args.flood and args.status_squat:
            parser.error("--flood and --status-squat are exclusive")
        if args.status_squat:
            result = validate_status_squat(text)
            if args.components is not None:
                result["components"] = validate_status_squat_components(text, args.components)
        elif args.flood:
            result = validate_flood(text)
            if args.components is not None:
                result["components"] = validate_flood_components(text, args.components)
        else:
            result = validate(text)
            if args.components is not None:
                result["workload_overlap"] = validate_overlap(text, args.components)
                result["no_push_evidence"] = validate_no_push_evidence(text, args.components)
                result["status_claim_components"] = validate_status_claim_components(text, args.components)
        print(json.dumps({"log_sha256": hashlib.sha256(raw).hexdigest(), **result}, sort_keys=True))
    else:
        parser.error("provide a log or --self-test")
