#!/usr/bin/env python3
"""Check observed journal ancestry fsync ordering in a focused Linux trace."""
import argparse
import json
from pathlib import Path
import re


def check(trace: str, result: str) -> dict:
    if not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored", result):
        raise ValueError("the exact bootstrap regression did not pass once")
    lines = trace.splitlines()
    anchor = None
    for index, line in enumerate(lines):
        match = re.search(r'^\s*(\d+)\s+rename\("([^"]+\.anchor)\.tmp", "([^"]+\.anchor)"\)\s+= 0$', line)
        if match and match[2] == match[3]:
            anchor = (index, match[1], Path(match[3]))
            break
    if anchor is None:
        raise ValueError("no successful initial anchor rename was observed")
    boundary, pid, path = anchor
    if not path.is_absolute():
        raise ValueError("trace must expose absolute anchor paths")
    required = [str(parent) for parent in path.parents]
    observed = {}
    for index, line in enumerate(lines[:boundary]):
        match = re.search(r'^\s*(\d+)\s+fsync\(\d+<([^>]+)>\)\s+= 0$', line)
        if match and match[1] == pid and match[2] in required:
            observed[match[2]] = index
    missing = set(required) - observed.keys()
    if missing:
        raise ValueError("ancestry was not synced before the first anchor rename: " + ", ".join(sorted(missing)))
    return {"anchor": str(path), "pid": pid, "anchor_rename_line": boundary + 1,
            "ancestry_sync_lines": {path: index + 1 for path, index in observed.items()},
            "scope": "observed syscall order; power-loss durability still assumes filesystem fsync/rename semantics"}


def self_test() -> dict:
    result = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured"
    trace = '\n'.join(['7 fsync(3</tmp/quv-fixture>) = 0', '7 fsync(3</tmp>) = 0',
                       '7 fsync(3</>) = 0',
                       '7 rename("/tmp/quv-fixture/custody.anchor.tmp", "/tmp/quv-fixture/custody.anchor") = 0'])
    check(trace, result)
    negatives = [(trace.replace('7 fsync(3</>) = 0\n', ''), result),
                 ('\n'.join(trace.splitlines()[1:] + trace.splitlines()[:1]), result),
                 (trace.replace('7 fsync(3</>)', '8 fsync(3</>)'), result),
                 (trace.replace('fsync(3</>) = 0', 'fsync(3</>) = -1 EIO'), result),
                 (trace, result.replace('1 passed', '0 passed'))]
    for candidate, output in negatives:
        try:
            check(candidate, output)
        except ValueError:
            continue
        raise AssertionError("invalid sync evidence was accepted")
    return {"positive": 1, "negative": len(negatives)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--trace', type=Path)
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), indent=2))
    elif args.trace and args.result:
        try:
            print(json.dumps(check(args.trace.read_text(), args.result.read_text()), indent=2))
        except ValueError as error:
            parser.exit(1, str(error) + '\n')
    else:
        parser.error('--trace and --result are required')
