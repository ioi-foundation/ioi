#!/usr/bin/env python3
"""Verify issued allocation/sync/rename order; not a power-loss or latency proof."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def check(lines):
    moves = []
    for i, line in enumerate(lines):
        match = re.search(r'rename\("([^"]+\.reserve/[0-9]{20}\.rsv)", "([^"]+/[0-9]{20}\.quv)"\)\s+= 0$', line)
        if match:
            moves.append((i, match.group(1), match.group(2)))
    if len(moves) != 7:
        return False
    sources = {source for _, source, _ in moves}
    writes = [i for i, line in enumerate(lines) if 'write(' in line and any(f'<{p}>' in line for p in sources)]
    if not writes:
        return False
    first = writes[0]
    reservation_syncs = []
    for source in sources:
        alloc = [i for i, line in enumerate(lines[:first]) if 'fallocate(' in line
                 and f'<{source}>' in line and 'FALLOC_FL_KEEP_SIZE' in line
                 and re.search(r', 0, 8192\)\s+= 0$', line)]
        if len(alloc) != 1:
            return False
        syncs = [i for i in range(alloc[0]+1, first) if re.search(r'fsync\(\d+<' + re.escape(source) + r'>\)\s+= 0$', lines[i])]
        if not syncs:
            return False
        reservation_syncs.append(syncs[-1])
    pool = Path(moves[0][1]).parent
    expected = [str(pool), *(str(parent) for parent in pool.parents)]
    observed = [m.group(1) for line in lines[max(reservation_syncs)+1:first]
                if (m := re.search(r'fsync\(\d+<([^>]+)>\)\s+= 0$', line))]
    position = -1
    for directory in expected:
        try:
            position = observed.index(directory, position + 1)
        except ValueError:
            return False
    for line in lines[first:]:
        if any(f'<{p}>' in line or f'"{p}"' in line for p in sources):
            if any(token in line for token in ['fallocate(', 'ftruncate(', 'O_TRUNC', 'O_CREAT']):
                return False
    for i, source, target in moves:
        prior = next((line for line in reversed(lines[:i]) if 'fsync(' in line), '')
        following = [line for line in lines[i+1:] if 'fsync(' in line][:2]
        expected = [str(Path(target).parent), str(Path(source).parent)]
        if not re.search(r'fsync\(\d+<' + re.escape(source) + r'>\)\s+= 0$', prior):
            return False
        if len(following) != 2 or any(not re.search(r'fsync\(\d+<' + re.escape(path) + r'>\)\s+= 0$', line)
                                     for path, line in zip(expected, following)):
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = ['cargo', 'test', '--locked', '-p', 'ioi-consensus', '--features', 'aft', '--lib', '--no-run', '--message-format=json']
    result = subprocess.run(build, cwd=root, capture_output=True, text=True)
    (output/'build.jsonl').write_text(result.stdout)
    (output/'build.stderr').write_text(result.stderr)
    result.check_returncode()
    executables = set()
    for line in result.stdout.splitlines():
        record = json.loads(line)
        if record.get('reason') == 'compiler-artifact' and record.get('target', {}).get('name') == 'ioi_consensus' and record.get('executable'):
            executables.add(record['executable'])
    if len(executables) != 1:
        raise RuntimeError('expected one consensus test executable')
    trace = output/'reservation.trace'
    command = ['strace', '-f', '-y', '-s', '256', '-e', 'trace=fsync,fallocate,ftruncate,rename,openat,write,close',
               '-o', str(trace), executables.pop(), '--exact',
               'aft::query_unanimity::journal::tests::reserved_records_preserve_allocation_and_inode_through_complete_lifetime']
    (output/'commands.json').write_text(json.dumps([build, command], indent=2)+'\n')
    with (output/'test.log').open('w') as log:
        subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    if '1 passed; 0 failed' not in (output/'test.log').read_text():
        raise RuntimeError('required reserved-record regression did not pass')
    lines = trace.read_text().splitlines()
    allocation = next((i for i, line in enumerate(lines) if 'fallocate(' in line and '.rsv>' in line), None)
    if allocation is None:
        raise RuntimeError('missing record preallocation')
    source = re.search(r'<([^>]+\.rsv)>', lines[allocation]).group(1)
    first_write = next(i for i, line in enumerate(lines) if 'write(' in line and '.rsv>' in line)
    removed_sync = [line for i, line in enumerate(lines) if not
                    (i < first_write and 'fsync(' in line and f'<{source}>' in line)]
    # Put the mutation inside the observed live interval, after its first write.
    truncated = lines[:first_write+1]+[f'0 ftruncate(99<{source}>, 0) = 0']+lines[first_write+1:]
    result = {'all_future_records_reserved_before_live_write': check(lines),
              'missing_reservation_sync_rejected': not check(removed_sync),
              'live_truncation_rejected': not check(truncated),
              'scope': 'issued syscalls and reported blocks; filesystem semantics and timing remain assumptions'}
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    if not all(result[k] for k in ['all_future_records_reserved_before_live_write', 'missing_reservation_sync_rejected', 'live_truncation_rejected']):
        raise RuntimeError('reserved-record syscall check failed')
    print('record preallocation, inode transfer, synchronization and removed-rule checks passed')


if __name__ == '__main__':
    main()
