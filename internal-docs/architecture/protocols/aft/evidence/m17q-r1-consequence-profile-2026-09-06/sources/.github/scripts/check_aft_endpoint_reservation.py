#!/usr/bin/env python3
"""Check issued endpoint preallocation/durability syscalls, not power-loss semantics."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def check(lines):
    try:
        begin = next(i for i, line in enumerate(lines) if 'AFT_ENDPOINT_LIVE_BEGIN' in line)
        end = next(i for i, line in enumerate(lines) if 'AFT_ENDPOINT_LIVE_END' in line)
        if begin >= end:
            return False
        moves = [(i, m.group(1), m.group(2)) for i, line in enumerate(lines)
                 if begin < i < end and (m := re.search(r'rename\("([^"]+\.prepared)", "([^"]+\.json)"\)\s+= 0$', line))]
        if len(moves) != 1:
            return False
        move, source, target = moves[0]
        allocations = [i for i, line in enumerate(lines[:begin]) if 'fallocate(' in line
                       and f'<{source}>' in line and 'FALLOC_FL_KEEP_SIZE' in line
                       and re.search(r', 0, 81920\)\s+= 0$', line)]
        if len(allocations) != 1:
            return False
        def sync(line, path):
            return bool(re.search(r'fsync\(\d+<' + re.escape(path) + r'>\)\s+= 0$', line))
        synced = next(i for i in range(allocations[0] + 1, begin) if sync(lines[i], source))
        directory = Path(target).parent
        cursor = synced
        for parent in [directory, *directory.parents]:
            cursor = next(i for i in range(cursor + 1, begin) if sync(lines[i], str(parent)))
        if any(any(token in line for token in ['fallocate(', 'ftruncate(', 'O_CREAT', 'O_TRUNC'])
               for line in lines[begin + 1:end]):
            return False
        writes = [i for i in range(begin + 1, move) if 'write(' in lines[i] and f'<{source}>' in lines[i]]
        if not writes or not any(sync(lines[i], source) for i in range(writes[-1] + 1, move)):
            return False
        return any(sync(lines[i], str(directory)) for i in range(move + 1, end))
    except (StopIteration, IndexError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = ['cargo', 'test', '--locked', '-p', 'agentgres', '--lib', '--no-run', '--message-format=json']
    built = subprocess.run(build, cwd=root, text=True, capture_output=True)
    (output/'build.jsonl').write_text(built.stdout)
    (output/'build.log').write_text(built.stderr)
    built.check_returncode()
    executables = {r['executable'] for line in built.stdout.splitlines()
                   if (r := json.loads(line)).get('reason') == 'compiler-artifact'
                   and r.get('target', {}).get('name') == 'agentgres' and r.get('executable')}
    if len(executables) != 1:
        raise RuntimeError('expected one Agentgres test executable')
    trace = output/'reservation.trace'
    command = ['strace', '-f', '-y', '-s', '256', '-e', 'trace=fsync,fallocate,ftruncate,rename,openat,write,close',
               '-o', str(trace), executables.pop(), '--exact',
               'consequence::tests::online_pq_endpoint_consumes_reserved_inode_and_retains_active_authority', '--nocapture']
    (output/'commands.json').write_text(json.dumps([build, command], indent=2)+'\n')
    with (output/'test.log').open('w') as log:
        subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    if '1 passed; 0 failed' not in (output/'test.log').read_text():
        raise RuntimeError('required endpoint test did not pass')
    lines = trace.read_text().splitlines()
    begin = next(i for i, line in enumerate(lines) if 'AFT_ENDPOINT_LIVE_BEGIN' in line)
    result = {'issued_order': check(lines),
              'missing_allocation_rejected': not check([line for line in lines if 'fallocate(' not in line]),
              'missing_preparation_sync_rejected': not check([line for i, line in enumerate(lines) if not (i < begin and 'fsync(' in line)]),
              'missing_commit_sync_rejected': not check([line for i, line in enumerate(lines) if not (i > begin and 'fsync(' in line)]),
              'live_allocation_rejected': not check(lines[:begin+1]+['0 fallocate(99, 0, 0, 81920) = 0']+lines[begin+1:])}
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    if not all(result.values()):
        raise RuntimeError('endpoint reservation syscall checks failed')
    print('endpoint allocation, full ancestry, live write/sync/rename/sync, and removed-rule controls passed')


if __name__ == '__main__':
    main()
