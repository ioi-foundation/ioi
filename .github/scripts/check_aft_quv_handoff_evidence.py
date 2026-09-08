#!/usr/bin/env python3
"""Check host-retained handoff participation; these diagnostics are not authority."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re


def hashes(value):
    parts = value.split(',')
    if not parts or len(parts) != len(set(parts)) or any(not re.fullmatch(r'[0-9a-f]{64}', p) for p in parts):
        raise ValueError('missing, duplicate or malformed member/hash values')
    return set(parts)


def validate(text, records):
    if len(re.findall(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', text, re.M)) != 1:
        raise ValueError('require exactly one passing nonignored test')
    rows = [r for r in text.splitlines() if r.startswith('[M16Q-HANDOFF] ')]
    if len(rows) != 1:
        raise ValueError('require one independent fixture expectation row')
    expected = dict(re.findall(r'(\w+)=([^ ]+)', rows[0]))
    old = hashes(expected['expected_old_members'])
    successors = hashes(expected['expected_successors'])
    if len(hashes(expected['old_root'])) != 1 or len(hashes(expected['domain'])) != 1:
        raise ValueError('invalid rooted scope')
    decision, envelope = int(expected['decision_millis']), int(expected['qualified_reply_millis'])
    if not 0 < envelope <= decision:
        raise ValueError('invalid timing envelope')
    starts, finishes, releases, audits = {}, {}, {}, []
    finished_at, startups, last_nonce_event = {}, {}, {}
    for file, record in records:
        fields = record.get('fields', {})
        event, nonce = fields.get('event'), fields.get('nonce')
        stamp = record.get('timestamp')
        if not isinstance(stamp, str):
            stamp = ''
        if event == 'startup':
            startups.setdefault(file, []).append(stamp)
        if nonce is not None and event is not None:
            last_nonce_event[(file, nonce)] = max(last_nonce_event.get((file, nonce), ''), stamp)
        if event == 'operation_finished':
            finished_at[(file, nonce)] = stamp
        if event in ('push_admission_overflow', 'push_admission_worker_stopped', 'preparation_service_expired', 'operation_service_expired'):
            raise ValueError('QUV scheduling/service failure invalidates handoff timing qualification')
        if event in ('operation_finished', 'operation_admission_released') and (fields.get('service_budgeted') is not True or fields.get('service_budget_met') is not True):
            raise ValueError('operation completion lacks a successful rooted active-service check')
        if event in ('operation_started', 'operation_finished', 'operation_admission_released'):
            target = starts if event == 'operation_started' else finishes if event == 'operation_finished' else releases
            key = (file, nonce)
            if key in target:
                raise ValueError('duplicate operation lifecycle event')
            target[key] = fields
        if event == 'operation_accepted_audit' and fields.get('domain_id') == expected['domain']:
            if fields.get('configuration_root') != expected['old_root']:
                raise ValueError('handoff audit changed rooted configuration')
            audits.append((file, fields))
    # The admission is process-local memory released when the admitted
    # authorization is consumed. A process that the fixture terminates in the
    # deliberate crash window between operation completion and that consumption
    # (the interrupted successor exits right after its handoff state is durable)
    # cannot log the release; its termination is proven only by a later
    # `startup` record in the same component log with no further event for the
    # nonce. Any other missing release is a runtime defect.
    terminated = set()
    for key in set(finishes) - set(releases):
        file, _ = key
        completed = finished_at.get(key, '')
        restarted = any(stamp > completed for stamp in startups.get(file, ()))
        if not restarted or last_nonce_event.get(key, '') > completed:
            raise ValueError("completed operation lacks final admission release")
        terminated.add(key)
    if len(audits) != len(successors):
        raise ValueError('require one accepted live handoff per expected successor')
    observed, nonces, candidates, elapsed = set(), set(), set(), []
    for file, audit in audits:
        nonce = audit['nonce']
        if len(hashes(nonce)) != 1 or nonce in nonces:
            raise ValueError('duplicate/malformed live nonce')
        nonces.add(nonce)
        start, finish = starts[(file, nonce)], finishes[(file, nonce)]
        if (file, nonce) not in releases and (file, nonce) not in terminated:
            raise ValueError('missing final admission release')
        account = start['local_account_hex']
        if account not in successors or account in observed:
            raise ValueError('missing, duplicate or unexpected relying successor')
        observed.add(account)
        if finish.get('accepted') is not True or finish.get('error') != 'None':
            raise ValueError('audit has no successful completed operation')
        if hashes(audit['configured_members']) != old or hashes(audit['valid_members']) != old:
            raise ValueError('expected correct-member participation is incomplete')
        if audit.get('portable_final_receipt') is not False:
            raise ValueError('handoff diagnostics must remain nonportable')
        if start.get('decision_millis') != decision or audit.get('decision_interval_millis') != decision:
            raise ValueError('decision interval differs from fixture policy')
        latency = audit['max_valid_reply_elapsed_millis']
        if type(latency) is not int or not 0 <= latency <= envelope:
            raise ValueError('reply observation exceeds qualified envelope')
        elapsed.append(latency)
        if len(hashes(audit['candidate_hash'])) != 1:
            raise ValueError('invalid candidate hash')
        candidates.add(audit['candidate_hash'])
    if observed != successors or len(candidates) != 1:
        raise ValueError('successor coverage or accepted candidate mismatch')
    return {'successors': len(successors), 'expected_correct_members': len(old),
            'max_valid_reply_elapsed_millis': max(elapsed), 'portable_final_receipt': False,
            'scope': 'host diagnostics; no independent authorization or full timing proof'}


def self_test():
    member = lambda n: f'{n:064x}'
    old = ','.join(member(i) for i in range(1, 5))
    successors = ','.join(member(i) for i in range(5, 9))
    text = f'[M16Q-HANDOFF] old_root={member(10)} domain={member(11)} expected_old_members={old} expected_successors={successors} decision_millis=30000 qualified_reply_millis=24000\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    records = []
    for i in range(5, 9):
        file, nonce = str(i), member(100 + i)
        for fields in [
            dict(event='operation_started', nonce=nonce, local_account_hex=member(i), decision_millis=30000),
            dict(event='operation_accepted_audit', nonce=nonce, configuration_root=member(10), domain_id=member(11), candidate_hash=member(12), configured_members=old, valid_members=old, max_valid_reply_elapsed_millis=1000, decision_interval_millis=30000, portable_final_receipt=False),
            dict(event='operation_finished', nonce=nonce, accepted=True, error='None', service_budgeted=True, service_budget_met=True),
            dict(event='operation_admission_released', nonce=nonce, service_budgeted=True, service_budget_met=True),
        ]:
            records.append((file, {'fields': fields}))
    validate(text, records)
    negatives = [(text.replace('[M16Q-HANDOFF]', '[missing]'), records),
                 (text.replace('1 passed', '0 passed'), records), (text, records[:-3]),
                 (text, records + [records[0]])]
    for event in ('push_admission_overflow', 'push_admission_worker_stopped', 'preparation_service_expired', 'operation_service_expired'):
        negatives.append((text, records + [('unrelated-orch.log', {'fields': {'event': event, 'nonce': member(999)}})]))
    for field, value in [('valid_members', ','.join(member(i) for i in range(1, 4))),
                         ('valid_members', old + ',' + member(1)), ('configured_members', member(1)),
                         ('configuration_root', member(99)), ('domain_id', member(99)),
                         ('candidate_hash', member(99)), ('portable_final_receipt', True),
                         ('max_valid_reply_elapsed_millis', 24001), ('max_valid_reply_elapsed_millis', True),
                         ('decision_interval_millis', 29999), ('nonce', member(999))]:
        changed = copy.deepcopy(records); changed[1][1]['fields'][field] = value
        negatives.append((text, changed))
    for index, field, value in [(0, 'local_account_hex', member(6)), (2, 'accepted', False), (2, 'error', 'failure')]:
        changed = copy.deepcopy(records); changed[index][1]['fields'][field] = value
        negatives.append((text, changed))
    for field in ['service_budgeted', 'service_budget_met']:
        for replacement in [False, None]:
            changed = copy.deepcopy(records)
            if replacement is None:
                del changed[2][1]['fields'][field]
            else:
                changed[2][1]['fields'][field] = replacement
            negatives.append((text, changed))
    negatives.append((text, [row for row in records if row[1]['fields']['event'] != 'operation_admission_released']))
    # A process terminated in the crash window between completion and release
    # is excused only by a later startup record with no further nonce event.
    stamped = copy.deepcopy(records)
    for index, (_, row) in enumerate(stamped):
        row['timestamp'] = f'2026-01-01T00:00:{index:02d}Z'
    stamped_finish = next(i for i, row in enumerate(stamped) if row[1]['fields']['event'] == 'operation_finished')
    stamped_release = next(i for i, row in enumerate(stamped) if row[1]['fields']['event'] == 'operation_admission_released')
    terminated_file = stamped[stamped_finish][0]
    without_release = [row for i, row in enumerate(stamped) if i != stamped_release]
    validate(text, without_release + [(terminated_file, {'timestamp': '2026-01-01T00:01:00Z', 'fields': {'event': 'startup'}})])
    negatives.append((text, without_release))
    negatives.append((text, without_release + [(terminated_file, {'timestamp': '2025-12-31T00:00:00Z', 'fields': {'event': 'startup'}})]))
    negatives.append((text, without_release + [('other-orch.log', {'timestamp': '2026-01-01T00:01:00Z', 'fields': {'event': 'startup'}})]))
    negatives.append((text, without_release
                      + [(terminated_file, {'timestamp': '2026-01-01T00:01:00Z', 'fields': {'event': 'startup'}}),
                         (terminated_file, {'timestamp': '2026-01-01T00:02:00Z', 'fields': {'event': 'reply_recorded', 'nonce': stamped[stamped_finish][1]['fields']['nonce']}})]))
    for field in ['service_budgeted', 'service_budget_met']:
        changed = copy.deepcopy(records); changed[3][1]['fields'][field] = False
        negatives.append((text, changed))
    negatives.append((text, records + [('unrelated', {'fields': dict(event='operation_finished', nonce=member(999), accepted=False, service_budgeted=True, service_budget_met=True)})]))
    for bad_text, bad_records in negatives:
        try:
            validate(bad_text, bad_records)
        except (ValueError, KeyError):
            continue
        raise AssertionError('invalid handoff evidence accepted')
    return {'positive_cases': 2, 'negative_cases': len(negatives)}


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
