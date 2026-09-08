#!/usr/bin/env python3
"""Check issued receipt reservation/exchange order; not a filesystem or timing proof."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def check(lines):
    try:
        begin = next(i for i, line in enumerate(lines) if 'AFT_RECEIPT_LIVE_BEGIN' in line)
        end = next(i for i, line in enumerate(lines) if 'AFT_RECEIPT_LIVE_END' in line)
        swaps = [(i, m.group(1), m.group(2)) for i, line in enumerate(lines)
                 if (m := re.search(r'renameat2\(AT_FDCWD(?:<[^>]+>)?, "([^"]+/effects/[^"]+\.json)", AT_FDCWD(?:<[^>]+>)?, "([^"]+\.prepared)", RENAME_EXCHANGE\)\s+= 0$', line))]
        early = [s for s in swaps if s[0] < begin]
        live = [s for s in swaps if begin < s[0] < end]
        if len(early) != 1 or len(live) != 4:
            return False
        first_swap, active, spare = early[0]
        def sync(line, path):
            return bool(re.search(r'fsync\(\d+<' + re.escape(path) + r'>\)\s+= 0$', line))
        allocations = [(i, int(m.group(1))) for i, line in enumerate(lines[:begin])
                       if f'<{spare}>' in line and 'FALLOC_FL_KEEP_SIZE' in line
                       and (m := re.search(r', 0, ([0-9]+)\)\s+= 0$', line))]
        if len(allocations) != 2 or allocations[0][1] != allocations[1][1]:
            return False
        capacity = allocations[0][1]
        if capacity <= 64 * 1024 * 1024 or not allocations[0][0] < first_swap < allocations[1][0]:
            return False
        last_sync = 0
        for (allocation, _), stop in zip(allocations, [first_swap, begin]):
            writes = [(i, int(m.group(1))) for i in range(allocation + 1, stop)
                      if 'write(' in lines[i] and f'<{spare}>' in lines[i]
                      and (m := re.search(r'\)\s+= ([0-9]+)$', lines[i]))]
            if sum(count for _, count in writes) < capacity:
                return False
            last_sync = next(i for i in range(writes[-1][0] + 1, stop) if sync(lines[i], spare))
        # Former active cannot be reset until the replacement name is durable.
        if not any(sync(lines[i], str(Path(active).parent)) for i in range(first_swap + 1, allocations[1][0])):
            return False
        cursor = last_sync
        directory = Path(active).parent
        for parent in [directory, *directory.parents]:
            cursor = next(i for i in range(cursor + 1, begin) if sync(lines[i], str(parent)))
        if any(any(token in line for token in ['fallocate(', 'ftruncate(', 'O_CREAT', 'O_TRUNC']) for line in lines[begin + 1:end]):
            return False
        previous = begin
        for move, target, source in live:
            if (target, source) != (active, spare):
                return False
            writes = [i for i in range(previous + 1, move) if 'write(' in lines[i] and f'<{spare}>' in lines[i]]
            if not writes or not any(sync(lines[i], spare) for i in range(writes[-1] + 1, move)):
                return False
            previous = next(i for i in range(move + 1, end) if sync(lines[i], str(directory)))
        return True
    except (StopIteration, IndexError):
        return False



def check_reuse(lines):
    """Ready-pair reuse preserves data and completes file/ancestry durability."""
    begins = [i for i, line in enumerate(lines) if 'AFT_RECEIPT_REUSE_BEGIN' in line]
    ends = [i for i, line in enumerate(lines) if 'AFT_RECEIPT_REUSE_END' in line]
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        return False
    span = lines[begins[0] + 1:ends[0]]
    forbidden = ['write(', 'writev(', 'pwrite64(', 'pwritev(', 'fallocate(',
                 'ftruncate(', 'truncate(', 'rename(', 'renameat(', 'renameat2(',
                 'unlink(', 'unlinkat(', 'link(', 'linkat(', 'symlink(', 'symlinkat(',
                 'O_CREAT', 'O_TRUNC']
    if any(any(token in line for token in forbidden) for line in span):
        return False
    synced = [m.group(1) for line in span
              if (m := re.search(r'fsync\(\d+<([^>]+)>\)\s+= 0$', line))]
    if not synced or not synced[0].endswith('/receipt.json'):
        return False
    active = Path(synced[0]); spare = active.with_name('.' + active.name + '.prepared')
    expected = [str(active), str(spare), str(active.parent),
                *(str(parent) for parent in active.parent.parents)]
    return synced == expected * 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    build = ['cargo', 'test', '--locked', '-p', 'agentgres', '--lib', '--no-run', '--message-format=json']
    built = subprocess.run(build, cwd=root, text=True, capture_output=True)
    (output/'build.jsonl').write_text(built.stdout); (output/'build.log').write_text(built.stderr)
    built.check_returncode()
    executables = {r['executable'] for line in built.stdout.splitlines()
                   if (r := json.loads(line)).get('reason') == 'compiler-artifact'
                   and r.get('target', {}).get('name') == 'agentgres' and r.get('executable')}
    if len(executables) != 1: raise RuntimeError('expected one Agentgres test executable')
    executable = executables.pop()
    trace = output/'reservation.trace'
    command = ['strace', '-f', '-y', '-s', '128', '-e', 'trace=fsync,fallocate,ftruncate,rename,renameat2,openat,write,close',
               '-o', str(trace), executable, '--exact',
               'consequence::tests::online_receipt_bound_covers_named_resource_execution_and_complete_budget', '--nocapture']
    (output/'commands.json').write_text(json.dumps([build, command], indent=2)+'\n')
    with (output/'test.log').open('w') as log:
        subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    if '1 passed; 0 failed' not in (output/'test.log').read_text(): raise RuntimeError('required receipt test did not pass')
    lines = trace.read_text().splitlines()
    begin = next(i for i, line in enumerate(lines) if 'AFT_RECEIPT_LIVE_BEGIN' in line)
    result = {'issued_order': check(lines),
              'missing_allocation_rejected': not check([line for line in lines if 'fallocate(' not in line]),
              'missing_initialization_rejected': not check([line for i, line in enumerate(lines) if not (i < begin and 'write(' in line and '.prepared>' in line)]),
              'missing_live_sync_rejected': not check([line for i, line in enumerate(lines) if not (i > begin and 'fsync(' in line)]),
              'live_truncation_rejected': not check(lines[:begin+1]+['0 ftruncate(99, 0) = 0']+lines[begin+1:])}
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    reuse_trace = output/'reuse.trace'
    reuse_command = ['strace', '-f', '-y', '-s', '128', '-e',
                     'trace=fsync,fallocate,ftruncate,truncate,rename,renameat,renameat2,openat,write,writev,pwrite64,pwritev,close,unlink,unlinkat,link,linkat,symlink,symlinkat',
                     '-o', str(reuse_trace), executable, '--exact',
                     'consequence::tests::receipt_preparation_reuses_valid_pair_and_repairs_only_incomplete_spare', '--nocapture']
    (output/'reuse-command.json').write_text(json.dumps(reuse_command, indent=2)+'\n')
    with (output/'reuse-test.log').open('w') as log:
        subprocess.run(reuse_command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    if '1 passed; 0 failed' not in (output/'reuse-test.log').read_text():
        raise RuntimeError('required reuse test did not pass')
    reuse_lines = reuse_trace.read_text().splitlines()
    reuse_begin = next(i for i, line in enumerate(reuse_lines) if 'AFT_RECEIPT_REUSE_BEGIN' in line)
    result.update({
        'reuse_preserves_data_and_syncs_custody': check_reuse(reuse_lines),
        'reuse_truncation_rejected': not check_reuse(reuse_lines[:reuse_begin+1]+['0 ftruncate(99, 0) = 0']+reuse_lines[reuse_begin+1:]),
        'reuse_missing_sync_rejected': not check_reuse([line for line in reuse_lines if 'fsync(' not in line]),
        'reuse_missing_marker_rejected': not check_reuse([line for line in reuse_lines if 'AFT_RECEIPT_REUSE_BEGIN' not in line]),
    })
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    if not all(result.values()): raise RuntimeError('receipt reservation syscall checks failed')
    print('receipt initialization, ancestry, live exchange/sync and removed-rule controls passed')


if __name__ == '__main__': main()
