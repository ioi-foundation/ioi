#!/usr/bin/env python3
"""Require issued directory sync ordering; this is not a power-loss proof."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def check(lines):
    first = next((i for i, line in enumerate(lines)
                  if 'openat(' in line and 'index.outbox.tmp"' in line), None)
    if first is None:
        return False
    match = re.search(r'"([^"]+/index.outbox.tmp)"', lines[first])
    if match is None:
        return False
    parent = Path(match.group(1)).parent
    expected = [str(parent), *(str(p) for p in parent.parents)]
    observed = [match.group(1) for line in lines[:first]
                if (match := re.search(r'fsync\(\d+<([^>]+)>\)\s+= 0', line))]
    position = -1
    for directory in expected:
        try:
            position = observed.index(directory, position + 1)
        except ValueError:
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = ['cargo', 'test', '--locked', '-p', 'ioi-networking', '--lib',
             '--no-run', '--message-format=json']
    result = subprocess.run(build, cwd=root, capture_output=True, text=True)
    (output / 'build.jsonl').write_text(result.stdout)
    (output / 'build.stderr').write_text(result.stderr)
    result.check_returncode()
    executables = []
    for line in result.stdout.splitlines():
        record = json.loads(line)
        if (record.get('reason') == 'compiler-artifact'
                and record.get('target', {}).get('name') == 'ioi_networking'
                and record.get('executable')):
            executables.append(record['executable'])
    if len(set(executables)) != 1:
        raise RuntimeError('expected one networking test executable')
    trace = output / 'ancestry.trace'
    command = ['strace', '-f', '-y', '-e',
               'trace=fsync,mkdir,mkdirat,rename,openat,close', '-o', str(trace),
               executables[0], '--exact',
               'libp2p::pq_channel::tests::indexed_outbox_recovers_commit_boundaries_without_resurrecting_retirements']
    (output / 'commands.json').write_text(json.dumps([build, command], indent=2) + '\n')
    with (output / 'test.log').open('w') as log:
        subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    if '1 passed; 0 failed' not in (output / 'test.log').read_text():
        raise RuntimeError('the required storage regression did not pass')
    lines = trace.read_text().splitlines()
    removed = [line for line in lines if not re.search(r'fsync\(\d+</>\)', line)]
    result = {'ancestry_before_first_staging_write': check(lines),
              'removed_root_sync_rejected': not check(removed),
              'scope': 'issued syscalls only; filesystem durability remains an assumption'}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    if not all(result[key] for key in ['ancestry_before_first_staging_write', 'removed_root_sync_rejected']):
        raise RuntimeError('outbox ancestry synchronization check failed')
    print('outbox ancestry ordering and removed-sync control passed')


if __name__ == '__main__':
    main()
