#!/usr/bin/env python3
"""Report retained reply-stage host timestamps; never admit timing or authority."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path

STAGES = [
    'member_work_completed', 'member_work_returned', 'reply_command_waiting',
    'reply_command_sending', 'reply_command_sent', 'reply_network_admitted',
    'reply_event_forwarded', 'reply_handler_entered', 'reply_routed',
]


def nonce_of(fields):
    if 'nonce' in fields:
        value = fields['nonce']
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError('malformed hexadecimal nonce')
        decoded = bytes.fromhex(value)
        if len(decoded) != 32 or decoded.hex() != value:
            raise ValueError('noncanonical hexadecimal nonce')
        return decoded.hex()
    if 'nonce_bytes' in fields:
        value = fields['nonce_bytes']
        raw = json.loads(value) if isinstance(value, str) else value
        if not isinstance(raw, list) or len(raw) != 32 or any(
                type(v) is not int or not 0 <= v <= 255 for v in raw):
            raise ValueError('malformed byte nonce')
        return bytes(raw).hex()
    return None


def millis(later, earlier):
    return round((datetime.fromisoformat(later.replace('Z', '+00:00')) -
                  datetime.fromisoformat(earlier.replace('Z', '+00:00'))).total_seconds() * 1000, 3)


def analyze(directory):
    records, sources = [], {}
    for file in sorted(directory.glob('*-orch.log')):
        raw = file.read_bytes()
        sources[file.name] = hashlib.sha256(raw).hexdigest()
        if not raw or b'HARNESS_DIAGNOSTIC_WRITE_FAILURE' in raw:
            raise ValueError('empty or failed diagnostic retention')
        for line in raw.decode('utf-8').splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                if line.lstrip().startswith('{'):
                    raise ValueError('malformed structured diagnostic')
                continue
            if not isinstance(row, dict) or not isinstance(row.get('fields'), dict):
                continue
            fields = row['fields']
            if fields.get('event') not in STAGES + ['operation_started']:
                continue
            nonce = nonce_of(fields)
            if nonce is None:
                raise ValueError('missing lifecycle nonce')
            records.append(dict(file=file.name, timestamp=row['timestamp'], fields=fields, nonce=nonce))
    if not sources:
        raise ValueError('no component logs')
    starts = [row for row in records if row['fields']['event'] == 'operation_started'
              and row['fields'].get('independent_preparation') is False]
    reports = []
    for start in starts:
        same = [row for row in records if row['nonce'] == start['nonce']]
        member_files = sorted({row['file'] for row in same
                               if row['fields']['event'] == 'member_work_completed'})
        for member_file in member_files:
            completed = [row for row in same if row['file'] == member_file
                         and row['fields']['event'] == 'member_work_completed']
            if len(completed) != 1:
                raise ValueError('duplicate durable completion')
            member = completed[0]['fields']['member']
            selected = []
            for stage in STAGES:
                matches = [row for row in same if row['fields']['event'] == stage and
                           (row['file'] == member_file if stage in STAGES[:5] else
                            row['file'] == start['file'] and
                            row['fields'].get('authenticated_member',
                                              row['fields'].get('authenticated_account')) == member)]
                if len(matches) > 1:
                    raise ValueError('duplicate reply boundary')
                selected.append(matches[0] if matches else None)
            timestamps = {stage: row['timestamp'] if row else None
                          for stage, row in zip(STAGES, selected)}
            gaps = {f'{left}->{right}': millis(timestamps[right], timestamps[left])
                    if timestamps[left] and timestamps[right] else None
                    for left, right in zip(STAGES, STAGES[1:])}
            routed = timestamps['reply_routed']
            reports.append(dict(nonce=start['nonce'], executor_file=start['file'],
                member_file=member_file, member=member,
                local_member=member_file == start['file'],
                operation_start=start['timestamp'],
                decision_millis=start['fields']['decision_millis'],
                routed_after_start_ms=millis(routed, start['timestamp']) if routed else None,
                stages=timestamps, adjacent_gaps_ms=gaps))
    return dict(scope='Host timestamp observations only; missing stages remain null. Local self-delivery does not traverse remote reply stages. No process pass, timing admission, monotonic bound or root-cause claim.',
                component_sha256=sources, foreground_operations=len(starts), replies=reports)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('components', type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.components), indent=2))
