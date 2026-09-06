#!/usr/bin/env python3
"""Summarize final-release observations; never establish authority or worst-case bounds."""
import argparse
import copy
import hashlib
import json
import re
from pathlib import Path


def summarize(records):
    starts, finished, releases = {}, set(), {}
    for file, fields in records:
        event = fields.get('event')
        if event not in ('operation_started', 'operation_finished', 'operation_admission_released'):
            continue
        nonce = fields.get('nonce')
        if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{64}', nonce):
            raise ValueError('invalid lifecycle nonce')
        key = file, nonce
        if event == 'operation_started':
            if key in starts or type(fields.get('independent_preparation')) is not bool:
                raise ValueError('duplicate start or missing role')
            starts[key] = fields['independent_preparation']
        elif event == 'operation_finished':
            if key in finished:
                raise ValueError('duplicate completion')
            finished.add(key)
        else:
            if key in releases:
                raise ValueError('duplicate final release')
            if fields.get('service_budgeted') is not True or fields.get('service_budget_met') is not True:
                raise ValueError('unbudgeted or late final release')
            elapsed = fields.get('elapsed_micros')
            if not isinstance(elapsed, str) or not re.fullmatch('[0-9]+', elapsed):
                raise ValueError('missing exact elapsed-microsecond string')
            releases[key] = int(elapsed)
    if not finished or not finished <= releases.keys():
        raise ValueError('missing completed operation or matching final release')
    rows = [dict(file=file, nonce=nonce, elapsed_micros=elapsed)
            for (file, nonce), elapsed in sorted(releases.items())]
    maxima = {}
    for name, role in [('foreground_max_micros', False), ('preparation_max_micros', True)]:
        values = [elapsed for key, elapsed in releases.items() if starts.get(key) is role]
        maxima[name] = max(values) if values else None
    return dict(completed_operations=len(finished), release_records=len(releases),
                max_observed_active_release_micros=max(releases.values()), **maxima,
                scope='Runtime monotonic samples after final semaphore release; finite host observations, not a worst-case service/queue/readiness guarantee',
                release_records_detail=rows)


def self_test():
    nonce = '01' * 32
    valid = [('node', dict(event='operation_started', nonce=nonce, independent_preparation=False)),
             ('node', dict(event='operation_finished', nonce=nonce)),
             ('node', dict(event='operation_admission_released', nonce=nonce,
                           service_budgeted=True, service_budget_met=True, elapsed_micros='7'))]
    result = summarize(valid)
    assert result['foreground_max_micros'] == 7 and result['preparation_max_micros'] is None
    negatives = [valid[:-1], valid + [valid[-1]], valid[::2]]
    for field, value in [('service_budgeted', False), ('service_budget_met', False),
                         ('elapsed_micros', True), ('elapsed_micros', '-1'), ('nonce', 'bad')]:
        rows = copy.deepcopy(valid); rows[-1][1][field] = value; negatives.append(rows)
    for rows in negatives:
        try:
            summarize(rows)
        except ValueError:
            continue
        raise AssertionError('invalid release observations accepted')
    return dict(positive_cases=1, negative_cases=len(negatives))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('components', type=Path, nargs='?')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test())); return
    if args.components is None:
        parser.error('components required')
    records, sources = [], {}
    for file in sorted(args.components.glob('*-orch.log')):
        raw = file.read_bytes()
        if not raw or b'HARNESS_DIAGNOSTIC_WRITE_FAILURE' in raw:
            raise ValueError('incomplete component capture')
        sources[file.name] = hashlib.sha256(raw).hexdigest()
        for line in raw.decode().splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                if line.lstrip().startswith('{'):
                    raise ValueError('malformed component JSON')
                continue
            if isinstance(record, dict) and isinstance(record.get('fields'), dict):
                records.append((file.name, record['fields']))
    print(json.dumps(dict(**summarize(records), component_sha256=sources), indent=2))


if __name__ == '__main__':
    main()
