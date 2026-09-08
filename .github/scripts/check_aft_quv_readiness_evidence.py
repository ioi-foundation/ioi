#!/usr/bin/env python3
"""Check retained consecutive-slot host evidence; diagnostics never authorize."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
from check_aft_quv_handoff_evidence import hashes


def decimal(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
        raise ValueError("require exact nonnegative decimal string")
    return int(value)


def validate(text, records):
    if len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", text, re.M)) != 1:
        raise ValueError("require one passing nonignored process test")
    expectations = [row for row in text.splitlines() if row.startswith("[M16Q-READINESS-EXPECT] ")]
    rows = [dict(re.findall(r"(\w+)=([^ ]+)", row)) for row in text.splitlines() if row.startswith("[M16Q-READINESS] ")]
    if len(expectations) != 1 or len(rows) != 4:
        raise ValueError("missing or duplicate expectation/outcome rows")
    recovery = [row for row in text.splitlines() if row.startswith("[M16Q-READINESS-RECOVERY] ")]
    if recovery != ["[M16Q-READINESS-RECOVERY] exact_terminal_parent_replay=true startup_budget_millis=20000"]:
        raise ValueError("missing exact recovered parent readiness probe")
    expected = dict(re.findall(r"(\w+)=([^ ]+)", expectations[0]))
    members = hashes(expected["members"])
    candidates = expected["candidates"].split(",")
    if len(members) != 4 or len(hashes(expected["candidates"])) != 3:
        raise ValueError("require four members and three distinct candidates")
    for field in ("configuration", "domain", "probe_domain", "executor", "probe_candidate"):
        if len(hashes(expected[field])) != 1:
            raise ValueError("invalid exact scope")
    if expected["executor"] not in members or expected["domain"] == expected["probe_domain"]:
        raise ValueError("invalid executor or unrelated domain")
    if (expected["decision_millis"], expected["readiness_millis"], expected["reply_envelope_millis"]) != ("5000", "40000", "4500"):
        raise ValueError("unexpected finite fixture profile")
    slots = {int(row["slot"]): row for row in rows if "slot" in row}
    probes = [row for row in rows if row.get("case") == "unrelated_during_wait"]
    if set(slots) != {1, 2, 3} or len(probes) != 1:
        raise ValueError("missing consecutive slots or unrelated operation")
    if slots[2].get("restarted") != "false" or slots[3].get("restarted") != "true" or probes[0].get("terminal_parent_replay") != "true":
        raise ValueError("missing restart/replay assertions")
    pressure_count = decimal(probes[0].get("pressure_receipts"))
    pressure_span = decimal(probes[0].get("pressure_span_millis"))
    if not 2 <= pressure_count <= 4096 or not 5000 <= pressure_span <= 30000:
        raise ValueError("missing bounded terminal pressure across the live decision")
    if any(row.get("result") != "executed" for row in rows):
        raise ValueError("refusal is not effect progress")
    lifecycle = {event: {} for event in ("operation_started", "operation_finished", "operation_admission_released", "operation_accepted_audit", "foreground_readiness_wait", "foreground_readiness_admitted")}
    for index, (file, record) in enumerate(records):
        fields = record.get("fields", {})
        event = fields.get("event")
        if event in ("push_admission_overflow", "push_admission_worker_stopped", "preparation_service_expired", "operation_service_expired"):
            raise ValueError("component scheduling/service failure")
        if event not in lifecycle:
            continue
        nonce = fields.get("nonce", "")
        if len(hashes(nonce)) != 1 or (file, nonce) in lifecycle[event]:
            raise ValueError("invalid or duplicated lifecycle nonce")
        lifecycle[event][file, nonce] = (index, fields)
        if event in ("operation_finished", "operation_admission_released") and (fields.get("service_budgeted") is not True or fields.get("service_budget_met") is not True):
            raise ValueError("unqualified active completion/release")
    starts, finishes, releases, audits, waits, admitted = (lifecycle[event] for event in lifecycle)
    if not set(finishes) <= set(releases):
        raise ValueError("completed operation lacks actual final release")
    target_keys = []
    for slot, row in [(i, slots[i]) for i in (1, 2, 3)] + [(0, probes[0])]:
        nonce = row.get("nonce", "")
        if len(hashes(nonce)) != 1:
            raise ValueError("missing live effect nonce")
        keys = [key for key, (_, start) in starts.items() if key[1] == nonce and start.get("local_account_hex") == expected["executor"]]
        if len(keys) != 1 or keys[0] in target_keys:
            raise ValueError("missing/duplicated relying operation")
        key = keys[0]; target_keys.append(key)
        start_i, start = starts[key]; finish_i, finish = finishes[key]; _, audit = audits[key]
        if key not in releases or start.get("independent_preparation") is not False or finish.get("accepted") is not True or finish.get("error") != "None":
            raise ValueError("effect lacks successful own foreground completion")
        if audit.get("configuration_root") != expected["configuration"] or audit.get("domain_id") != expected["domain" if slot else "probe_domain"] or audit.get("candidate_hash") != (candidates[slot-1] if slot else expected["probe_candidate"]):
            raise ValueError("accepted audit changed the expected scope/candidate")
        if hashes(audit["configured_members"]) != members or hashes(audit["valid_members"]) != members or audit.get("portable_final_receipt") is not False:
            raise ValueError("wrong participation or portable authority claim")
        latency = audit.get("max_valid_reply_elapsed_millis")
        if start.get("decision_millis") != 5000 or audit.get("decision_interval_millis") != 5000 or type(latency) is not int or not 0 <= latency <= 4500:
            raise ValueError("wrong decision/reply envelope")
        if slot in (2, 3):
            wait_i, wait = waits[key]; admitted_i, observed = admitted[key]
            if not wait_i < admitted_i < start_i < finish_i or wait.get("slot") != slot or observed.get("slot") != slot or wait.get("domain") != expected["domain"] or observed.get("domain") != expected["domain"]:
                raise ValueError("readiness observation is not the matching pre-admission wait")
            required, elapsed = decimal(observed.get("required_remaining_nanos")), decimal(observed.get("elapsed_nanos"))
            if observed.get("deadline_elapsed") is not True or not 15_000_000_000 <= required <= 40_000_000_000 or elapsed < required:
                raise ValueError("absent, vacuous or early readiness wait")
    parent, child, restarted, probe = target_keys
    boots = [i for i, (file, record) in enumerate(records) if file == restarted[0] and record.get("target") == "rpc" and str(record.get("fields", {}).get("message", "")).startswith("Public gRPC API listening on ")]
    if len(boots) != 2 or not finishes[child][0] < boots[1] < waits[restarted][0]:
        raise ValueError("missing restarted executor listener between slot two completion and slot three wait")
    if parent[0] != child[0] or child[0] != restarted[0] or probe[0] != child[0] or not waits[child][0] < starts[probe][0] < finishes[probe][0] < admitted[child][0]:
        raise ValueError("unrelated effect did not complete on the same executor during the child wait")
    return dict(executed_slots=3, unrelated_during_wait=True, restarted_slot=3, correct_members=4,
                portable_final_receipt=False, scope="Finite host observations; not aggregate timing, full refinement or independent authorization")


def self_test():
    h = lambda n: format(n, "064x")
    members = ",".join(h(n) for n in (1,2,3,4))
    text = "test result: ok. 1 passed; 0 failed; 0 ignored;\n" + f"[M16Q-READINESS-EXPECT] configuration={h(10)} domain={h(11)} probe_domain={h(12)} executor={h(1)} members={members} candidates={h(21)},{h(22)},{h(23)} probe_candidate={h(24)} decision_millis=5000 readiness_millis=40000 reply_envelope_millis=4500\n"
    records = [("executor", {"target": "rpc", "fields": {"message": "Public gRPC API listening on 127.0.0.1:1"}})]
    def event(event, nonce, **fields):
        records.append(("executor", {"fields": dict(event=event, nonce=h(nonce), **fields)}))
    def operation(slot, nonce):
        event("operation_started", nonce, local_account_hex=h(1), independent_preparation=False, decision_millis=5000)
        event("operation_accepted_audit", nonce, configuration_root=h(10), domain_id=h(11 if slot else 12), candidate_hash=h(20+slot if slot else 24), configured_members=members, valid_members=members, portable_final_receipt=False, decision_interval_millis=5000, max_valid_reply_elapsed_millis=100)
        event("operation_finished", nonce, accepted=True, error="None", service_budgeted=True, service_budget_met=True)
        event("operation_admission_released", nonce, service_budgeted=True, service_budget_met=True)
    operation(1,31)
    event("foreground_readiness_wait",32,slot=2,domain=h(11))
    operation(0,34)
    event("foreground_readiness_admitted",32,slot=2,domain=h(11),required_remaining_nanos="30000000000",elapsed_nanos="30000000000",deadline_elapsed=True)
    operation(2,32)
    records.append(("executor", {"target": "rpc", "fields": {"message": "Public gRPC API listening on 127.0.0.1:1"}}))
    event("foreground_readiness_wait",33,slot=3,domain=h(11))
    event("foreground_readiness_admitted",33,slot=3,domain=h(11),required_remaining_nanos="30000000000",elapsed_nanos="30000000000",deadline_elapsed=True)
    operation(3,33)
    for slot in (1,2,3):
        text += f"[M16Q-READINESS] slot={slot} nonce={h(30+slot)} result=executed restarted={'true' if slot==3 else 'false'}\n"
    text += f"[M16Q-READINESS] case=unrelated_during_wait nonce={h(34)} result=executed terminal_parent_replay=true pressure_receipts=100 pressure_span_millis=6000\n"
    text += "[M16Q-READINESS-RECOVERY] exact_terminal_parent_replay=true startup_budget_millis=20000\n"
    validate(text,records)
    negatives=[]
    for event_name in ("operation_started","operation_finished","operation_admission_released","operation_accepted_audit","foreground_readiness_wait","foreground_readiness_admitted"):
        negatives.append((text,[row for row in records if row[1]["fields"].get("event")!=event_name]))
    for field,value in (("required_remaining_nanos","0"),("elapsed_nanos","1"),("elapsed_nanos",30000000000),("deadline_elapsed",False),("slot",1),("domain",h(99))):
        altered=copy.deepcopy(records)
        next(row[1]["fields"] for row in altered if row[1]["fields"].get("event")=="foreground_readiness_admitted")[field]=value
        negatives.append((text,altered))
    for event_name,field,value in (("operation_finished","accepted",False),("operation_finished","service_budget_met",False),("operation_admission_released","service_budgeted",False),("operation_accepted_audit","valid_members",h(1)),("operation_accepted_audit","candidate_hash",h(99)),("operation_accepted_audit","portable_final_receipt",True)):
        altered=copy.deepcopy(records); next(row[1]["fields"] for row in altered if row[1]["fields"].get("event")==event_name)[field]=value; negatives.append((text,altered))
    negatives.extend([(text.replace('1 passed; 0 failed','0 passed; 1 failed'),records),(text.replace('result=executed','result=refused'),records),(text,records+[records[1]]),(text,records+[("other",{"fields":dict(event="operation_service_expired")})])])
    negatives.append((text.replace("exact_terminal_parent_replay=true", "exact_terminal_parent_replay=false"), records))
    for old, new in [("pressure_receipts=100", "pressure_receipts=1"),
                     ("pressure_receipts=100", "pressure_receipts=4097"),
                     ("pressure_receipts=100", ""),
                     ("pressure_span_millis=6000", "pressure_span_millis=4999"),
                     ("pressure_span_millis=6000", "pressure_span_millis=30001"),
                     ("pressure_span_millis=6000", "pressure_span_millis=NaN")]:
        negatives.append((text.replace(old, new), records))
    negatives.append((text, [row for row in records if row[1].get("target") != "rpc"]))
    for bad_text,bad_records in negatives:
        try: validate(bad_text,bad_records)
        except (ValueError,KeyError): pass
        else: raise AssertionError("accepted invalid readiness evidence")
    return dict(positive_cases=1,negative_cases=len(negatives))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', nargs='?', type=Path)
    parser.add_argument('--components', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), sort_keys=True))
    else:
        if args.log is None or args.components is None:
            parser.error('provide a log and --components')
        records, sources = [], {}
        files = sorted(args.components.glob('*-orch.log'))
        if not files:
            raise ValueError('no component logs')
        for file in files:
            raw = file.read_bytes()
            if not raw or b'HARNESS_DIAGNOSTIC_WRITE_FAILURE' in raw:
                raise ValueError('component retention failed')
            sources[file.name] = hashlib.sha256(raw).hexdigest()
            for line in raw.decode().splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    if line.lstrip().startswith('{'):
                        raise ValueError('malformed component JSON')
                    continue
                if not isinstance(record, dict):
                    raise ValueError('invalid component record')
                records.append((file.name, record))
        result = validate(args.log.read_text(), records)
        print(json.dumps({'log_sha256': hashlib.sha256(args.log.read_bytes()).hexdigest(), 'components_sha256': sources, **result}, sort_keys=True))
