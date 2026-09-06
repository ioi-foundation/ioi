#!/usr/bin/env python3
"""Check retained terminal campaign evidence; never start or repeat the campaign."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

root = Path.cwd()
base = Path(__file__).resolve().parent
process = base / 'foreground-process'
result = json.loads((process / 'result.json').read_text())
commands = {
    'strict-check': ['python3', '.github/scripts/check_aft_m16q_process_evidence.py',
                     str(process / 'process.log'), '--components', str(process / 'components')],
    'worker-service-check': ['python3', 'internal-docs/architecture/protocols/aft/evidence/m17q-r1-active-service-2026-09-05/check_worker_service_observations.py',
                             str(process / 'components')],
    'reply-boundaries': ['python3', 'internal-docs/architecture/protocols/aft/evidence/m17q-r1-reply-boundary-diagnostics-2026-09-05/analyze_reply_boundaries.py',
                         str(process / 'components')],
}
checks = {}
for name, command in commands.items():
    run = subprocess.run(command, capture_output=True, text=True)
    (process / (name + '.json')).write_text(run.stdout)
    metadata = {'command': command, 'exit_code': run.returncode, 'stderr': run.stderr,
                'checker_sha256': hashlib.sha256((root / command[1]).read_bytes()).hexdigest()}
    (process / (name + '-command.json')).write_text(json.dumps(metadata, indent=2) + '\n')
    checks[name] = run.returncode
passed = result['exit_code'] == 0 and not result['changed_sources'] and all(v == 0 for v in checks.values())
disposition = {'disposition': 'PASS_SCOPED_CAMPAIGN' if passed else 'REPAIR_OR_INVESTIGATION_REQUIRED',
               'process_exit_code': result['exit_code'], 'changed_sources': result['changed_sources'],
               'checker_exit_codes': checks,
               'scope': 'Selected foreground process assertions and host observations; not full R2, a worst-case bound or whole R1 closure.'}
(process / 'disposition.json').write_text(json.dumps(disposition, indent=2) + '\n')
print(json.dumps(disposition))
sys.exit(0 if passed else 1)
