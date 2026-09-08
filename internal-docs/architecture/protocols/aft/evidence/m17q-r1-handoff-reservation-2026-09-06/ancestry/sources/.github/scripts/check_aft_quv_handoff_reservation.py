#!/usr/bin/env python3
"""Issued handoff reservation/commit syscalls; not a platform timing proof."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def sync(line, path):
    return bool(re.search(r'fsync\(\d+<' + re.escape(str(path)) + r'>\)\s+= 0$', line))


def check(lines):
    committed = []
    for move, line in enumerate(lines):
        match = re.search(r'rename\("([^"]+/state.scale.tmp)", "([^"]+/state.scale)"\)\s+= 0$', line)
        if not match:
            continue
        source, target = match.groups()
        allocations = [i for i in range(move) if 'fallocate(' in lines[i] and f'<{source}>' in lines[i] and 'FALLOC_FL_KEEP_SIZE' in lines[i] and lines[i].endswith('= 0')]
        if not allocations:  # Initial uninstalled state, before preparation.
            continue
        committed.append(move)
        allocation = allocations[-1]
        writes = [i for i in range(allocation+1, move) if 'write(' in lines[i] and f'<{source}>' in lines[i]]
        if not writes or not any(sync(line, source) for line in lines[allocation+1:writes[0]]):
            return False
        for line in lines[allocation+1:move]:
            if f'<{source}>' in line or f'"{source}"' in line:
                if any(token in line for token in ['fallocate(', 'ftruncate(', 'O_TRUNC', 'O_CREAT']):
                    return False
        parent = Path(target).parent
        for directory in [parent, *parent.parents]:
            if not any(sync(line, directory) for line in lines[allocation+1:writes[0]]):
                return False
        prior = next((line for line in reversed(lines[:move]) if 'fsync(' in line), '')
        after = next((line for line in lines[move+1:] if 'fsync(' in line), '')
        if not sync(prior, source) or not sync(after, parent):
            return False
        anchor = str(parent.parent/'custody'/'state.anchor')
        for directory in [Path(anchor).parent, *Path(anchor).parent.parents]:
            if not any(sync(line, directory) for line in lines[allocation+1:writes[0]]):
                return False
        swaps = [i for i, line in enumerate(lines) if 'renameat2(' in line and f'"{anchor}"' in line and 'RENAME_EXCHANGE' in line and line.endswith('= 0')]
        before = [i for i in swaps if i < move]
        following = [i for i in swaps if i > move]
        if len(before) != 1 or len(following) != 1:
            return False
        swap = following[0]
        if not sync(next((line for line in reversed(lines[:swap]) if 'fsync(' in line), ''), anchor+'.tmp'):
            return False
        if not sync(next((line for line in lines[swap+1:] if 'fsync(' in line), ''), Path(anchor).parent):
            return False
        for line in lines[before[0]+1:swap]:
            if any(f'<{p}>' in line or f'"{p}"' in line for p in [anchor, anchor+'.tmp']):
                if any(token in line for token in ['fallocate(', 'ftruncate(', 'O_TRUNC', 'O_CREAT']):
                    return False
    return len(committed) == 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[2]
    build = ['cargo', 'test', '--locked', '-p', 'ioi-consensus', '--features', 'aft', '--lib', '--no-run', '--message-format=json']
    result = subprocess.run(build, cwd=root, capture_output=True, text=True)
    (output/'build.jsonl').write_text(result.stdout)
    (output/'build.stderr').write_text(result.stderr)
    result.check_returncode()
    executables = {record['executable'] for line in result.stdout.splitlines()
                   if (record := json.loads(line)).get('reason') == 'compiler-artifact'
                   and record.get('target', {}).get('name') == 'ioi_consensus' and record.get('executable')}
    if len(executables) != 1:
        raise RuntimeError('expected one consensus test executable')
    trace = output/'handoff.trace'
    command = ['strace', '-f', '-y', '-s', '256', '-e', 'trace=fsync,fallocate,ftruncate,rename,renameat2,openat,write,close', '-o', str(trace), executables.pop(), '--exact', 'aft::query_unanimity::tests::handoff_reserved_capacity_precedes_live_consumption_and_reuses_inode']
    (output/'commands.json').write_text(json.dumps([build, command], indent=2)+'\n')
    with (output/'test.log').open('w') as log:
        subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    if '1 passed; 0 failed' not in (output/'test.log').read_text():
        raise RuntimeError('handoff reservation regression did not run')
    lines = trace.read_text().splitlines()
    no_state_sync = [line for line in lines if not ('fsync(' in line and '/state.scale.tmp>' in line)]
    no_anchor_sync = [line for line in lines if not ('fsync(' in line and '/state.anchor.tmp>' in line)]
    missing_custody_ancestry = [line for line in lines if not ('fsync(' in line and re.search(r'<(/tmp/\.tmp[^/>]+)>', line))]
    checks = {'missing_custody_ancestry_rejected': not check(missing_custody_ancestry), 'reserved_state_then_anchor': check(lines), 'missing_state_sync_rejected': not check(no_state_sync), 'missing_anchor_sync_rejected': not check(no_anchor_sync)}
    (output/'result.json').write_text(json.dumps(checks, indent=2)+'\n')
    if not all(checks.values()):
        raise RuntimeError('handoff syscall order or negative control failed')
    print('handoff preallocation, state/anchor sync order and negative controls passed')


if __name__ == '__main__':
    main()
