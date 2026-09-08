#!/usr/bin/env python3
"""Check worker service diagnostics; not independent authorization or a timing proof."""
import argparse
import copy
import hashlib
import json
import re
from pathlib import Path


def validate(records):
    tables = {name: {} for name in ['operation_started', 'preparation_attempt_reserved',
        'operation_accepted_audit', 'operation_finished', 'preparation_finished']}
    for index, (file, fields) in enumerate(records):
        event = fields.get('event')
        if event == 'preparation_service_expired':
            raise ValueError('active service overrun was reported; no timing admission')
        if event not in tables:
            continue
        nonce = fields.get('nonce')
        if not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{64}', nonce):
            raise ValueError('missing/malformed operation nonce')
        key = file, nonce
        if key in tables[event]:
            raise ValueError('duplicate lifecycle diagnostic')
        tables[event][key] = index, fields
    starts = tables['operation_started']
    if any(type(fields.get('independent_preparation')) is not bool for _, fields in starts.values()):
        raise ValueError('missing explicit operation purpose')
    expected = {fields['local_account_hex'] for _, fields in starts.values()
        if fields['independent_preparation'] is False}
    if len(expected) != 4:
        raise ValueError('require four independently exercised foreground endpoints')
    completed, started, observed = 0, 0, set()
    for key, (start_index, start) in starts.items():
        if not start['independent_preparation']:
            continue
        started += 1
        reserved_index, reserved = tables['preparation_attempt_reserved'][key]
        if not reserved_index < start_index or type(reserved['attempt']) is not int or not 1 <= reserved['attempt'] <= 65535:
            raise ValueError('missing ordered positive attempt reservation')
        finish_pair = tables['operation_finished'].get(key)
        if finish_pair is None or finish_pair[1].get('accepted') is not True:
            continue
        finish_index, finish = finish_pair
        if finish.get('service_budgeted') is not True or finish.get('service_budget_met') is not True:
            raise ValueError('accepted worker lacks successful active service check')
        audit_index, audit = tables['operation_accepted_audit'][key]
        worker_index, worker = tables['preparation_finished'][key]
        if not start_index < audit_index < finish_index < worker_index:
            raise ValueError('worker completion lacks ordered own live acceptance')
        if finish.get('error') != 'None' or worker.get('accepted') is not True:
            raise ValueError('worker completion differs from operation outcome')
        if audit.get('portable_final_receipt') is not False:
            raise ValueError('portable diagnostic claim')
        for field in ['configured_members', 'valid_members']:
            members = audit[field].split(',')
            if len(members) != 4 or set(members) != expected:
                raise ValueError('worker lacks complete expected member participation')
        if audit['decision_interval_millis'] != start['decision_millis'] or not 0 <= audit['max_valid_reply_elapsed_millis'] <= start['decision_millis']:
            raise ValueError('reply outside rooted interval')
        observed.add(start['local_account_hex'])
        completed += 1
    if observed != expected:
        raise ValueError('missing accepted preparation at an expected worker endpoint')
    return {'worker_starts': started, 'accepted_worker_completions': completed,
        'workers_with_accepted_completion': len(observed),
        'scope': 'host diagnostics matched to own live acceptance and active-service checks; not aggregate readiness, storage/refinement or clean timing proof'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('components', type=Path)
    args = parser.parse_args()
    records, sources = [], {}
    for file in sorted(args.components.glob('*-orch.log')):
        raw = file.read_bytes()
        if not raw or b'HARNESS_DIAGNOSTIC_WRITE_FAILURE' in raw:
            raise ValueError('incomplete component retention')
        sources[file.name] = hashlib.sha256(raw).hexdigest()
        for line in raw.decode().splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                if line.lstrip().startswith('{'):
                    raise ValueError('malformed retained JSON')
                continue
            records.append((file.name, value.get('fields', {})))
    result = validate(records)
    # Evidence-check mutations only; these do not substitute for runtime mutation.
    controls = []
    controls.append([(file, fields) for file, fields in records if fields.get('event') != 'preparation_attempt_reserved'])
    changed = copy.deepcopy(records)
    for _, fields in changed:
        if fields.get('event') == 'operation_accepted_audit':
            fields['portable_final_receipt'] = True
    controls.append(changed)
    changed = copy.deepcopy(records)
    for _, fields in changed:
        if fields.get('event') == 'operation_accepted_audit':
            fields['valid_members'] = fields['valid_members'].split(',')[0]
    controls.append(changed)
    changed = copy.deepcopy(records)
    for _, fields in changed:
        if fields.get('event') == 'operation_finished' and fields.get('service_budgeted') is True:
            fields['service_budget_met'] = False
    controls.append(changed)
    controls.append(records + [('synthetic', {'event': 'preparation_service_expired'})])
    for changed in controls:
        try:
            validate(changed)
        except (ValueError, KeyError):
            continue
        raise AssertionError('weakened diagnostic evidence accepted')
    print(json.dumps({**result, 'components_sha256': sources,
        'evidence_negative_controls': len(controls)}, sort_keys=True))


if __name__ == '__main__':
    main()
