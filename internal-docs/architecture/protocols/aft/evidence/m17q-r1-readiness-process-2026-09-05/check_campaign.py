#!/usr/bin/env python3
"""Inspect a retained terminal readiness campaign. Never launch a process test."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('campaign', choices=['consecutive-process', 'consecutive-process-rpc-observed', 'consecutive-process-recovery-probed'])
args = parser.parse_args()
base = Path(__file__).resolve().parent
campaign = base / args.campaign
result = json.loads((campaign / 'result.json').read_text())
checker_name = '.github/scripts/check_aft_quv_readiness_evidence.py'
checker = campaign / 'sources' / checker_name
assert hashlib.sha256(checker.read_bytes()).hexdigest() == result['sources'][checker_name]
commands = {
    'recorded-readiness-check': ['python3', str(checker), str(campaign / 'process.log'), '--components', str(campaign / 'components')],
    'release-observations': ['python3', str(base.parent / 'm17q-r1-final-admission-release-2026-09-05/analyze_admission_releases.py'), str(campaign / 'components')],
}
checks = {}
for name, command in commands.items():
    run = subprocess.run(command, capture_output=True, text=True)
    (campaign / (name + '.json')).write_text(run.stdout)
    (campaign / (name + '-command.json')).write_text(json.dumps(dict(command=command, exit_code=run.returncode, stderr=run.stderr, checker_sha256=hashlib.sha256(Path(command[1]).read_bytes()).hexdigest()), indent=2) + '\n')
    checks[name] = run.returncode
passed = result['exit_code'] == 0 and not result['changed_sources'] and all(code == 0 for code in checks.values())
summary = dict(disposition='PASS_SCOPED_CAMPAIGN' if passed else 'REPAIR_OR_INVESTIGATION_REQUIRED', process_exit_code=result['exit_code'], changed_sources=result['changed_sources'], checker_exit_codes=checks, scope='Selected consecutive-slot/restart and unrelated-effect assertions; not aggregate timing/resources, full transition refinement, clean R2 or whole R1 closure')
(campaign / 'checked-disposition.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary))
raise SystemExit(0 if passed else 1)
