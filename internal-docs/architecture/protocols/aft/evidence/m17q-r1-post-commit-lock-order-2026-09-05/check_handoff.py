#!/usr/bin/env python3
"""Check a terminal retained handoff campaign; never launch or repeat it."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('campaign', choices=['disjoint-process', 'overlap-process'])
args = parser.parse_args()
base = Path(__file__).resolve().parent
campaign = base / args.campaign
result = json.loads((campaign / 'result.json').read_text())
commands = {
    'handoff-check': ['python3', '.github/scripts/check_aft_quv_handoff_evidence.py',
                      str(campaign / 'process.log'), '--components', str(campaign / 'components')],
    'release-observations': ['python3', str(base / 'analyze_admission_releases.py'),
                             str(campaign / 'components')],
}
checks = {}
for name, command in commands.items():
    run = subprocess.run(command, capture_output=True, text=True)
    (campaign / (name + '.json')).write_text(run.stdout)
    metadata = dict(command=command, exit_code=run.returncode, stderr=run.stderr,
                    checker_sha256=hashlib.sha256(Path(command[1]).read_bytes()).hexdigest())
    (campaign / (name + '-command.json')).write_text(json.dumps(metadata, indent=2) + '\n')
    checks[name] = run.returncode
passed = result['exit_code'] == 0 and not result['changed_sources'] and all(v == 0 for v in checks.values())
disposition = dict(disposition='PASS_SCOPED_CAMPAIGN' if passed else 'REPAIR_OR_INVESTIGATION_REQUIRED',
                   process_exit_code=result['exit_code'], changed_sources=result['changed_sources'],
                   checker_exit_codes=checks,
                   scope='Selected handoff/release assertions; not full restart/refinement, worst-case timing, clean R2 or whole R1 closure.')
(campaign / 'disposition.json').write_text(json.dumps(disposition, indent=2) + '\n')
print(json.dumps(disposition))
sys.exit(0 if passed else 1)
