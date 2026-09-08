#!/usr/bin/env python3
"""Check production index syscalls; allocation/device semantics remain assumptions."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def check(lines):
    exchanges = [i for i, line in enumerate(lines) if 'renameat2(' in line]
    # Index startup, arena-format conversion, sixteen live commits, recovery.
    if len(exchanges) != 19:
        return False
    match = re.search(r'"([^"]+/reserved.outbox)"', lines[exchanges[0]])
    if match is None:
        return False
    active = match.group(1)
    spare = active + '.inactive'
    parent = str(Path(active).parent)
    for i in exchanges:
        line = lines[i]
        if not (f'"{active}"' in line and f'"{spare}"' in line
                and 'RENAME_EXCHANGE' in line and re.search(r'= 0$', line)):
            return False
    for i in exchanges[2:-1]:
        before = next((line for line in reversed(lines[:i]) if 'fsync(' in line), '')
        after = next((line for line in lines[i+1:] if 'fsync(' in line), '')
        if not (re.search(r'fsync\(\d+<' + re.escape(spare) + r'>\)\s+= 0$', before)
                and re.search(r'fsync\(\d+<' + re.escape(parent) + r'>\)\s+= 0$', after)):
            return False
    for line in lines[exchanges[1]+1:exchanges[-2]+1]:
        touches = any(f'<{path}>' in line or f'"{path}"' in line for path in (active, spare))
        if touches and any(term in line for term in ['fallocate(', 'ftruncate(', 'O_TRUNC', 'O_CREAT', 'rename(']):
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = ['cargo', 'test', '--locked', '-p', 'ioi-networking', '--lib', '--no-run', '--message-format=json']
    result = subprocess.run(build, cwd=root, capture_output=True, text=True)
    (output/'build.jsonl').write_text(result.stdout)
    (output/'build.stderr').write_text(result.stderr)
    result.check_returncode()
    executables = set()
    for line in result.stdout.splitlines():
        record = json.loads(line)
        if (record.get('reason') == 'compiler-artifact'
                and record.get('target', {}).get('name') == 'ioi_networking'
                and record.get('executable')):
            executables.add(record['executable'])
    if len(executables) != 1:
        raise RuntimeError('expected one networking test executable')
    trace = output/'reservation.trace'
    command = ['strace', '-f', '-y', '-e', 'trace=fsync,fallocate,ftruncate,rename,renameat2,openat,close',
               '-o', str(trace), executables.pop(), '--exact',
               'libp2p::pq_channel::tests::reserved_outbox_index_reuses_allocated_inodes_across_commits']
    (output/'commands.json').write_text(json.dumps([build, command], indent=2)+'\n')
    with (output/'test.log').open('w') as log:
        subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    if '1 passed; 0 failed' not in (output/'test.log').read_text():
        raise RuntimeError('required reservation regression did not run and pass')
    lines = trace.read_text().splitlines()
    exchanges = [i for i, line in enumerate(lines) if 'renameat2(' in line]
    if len(exchanges) < 3:
        raise RuntimeError('missing production exchanges')
    first_live = exchanges[2]
    sync = next(i for i in reversed(range(first_live)) if 'fsync(' in lines[i])
    removed_sync = lines[:sync]+lines[sync+1:]
    active = re.search(r'"([^"]+/reserved.outbox)"', lines[first_live]).group(1)
    truncated = lines[:first_live]+[f'0 ftruncate(99<{active}.inactive>, 0) = 0']+lines[first_live:]
    result = {'allocated_inode_reuse_and_sync_order': check(lines),
              'removed_sync_rejected': not check(removed_sync),
              'live_truncate_rejected': not check(truncated),
              'scope': 'issued syscalls and reported allocated blocks; not physical power-loss or timing proof'}
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    if not all(result[key] for key in ['allocated_inode_reuse_and_sync_order', 'removed_sync_rejected', 'live_truncate_rejected']):
        raise RuntimeError('reserved index production syscall check failed')
    print('reserved index syscall ordering and removed-rule controls passed')


if __name__ == '__main__':
    main()
