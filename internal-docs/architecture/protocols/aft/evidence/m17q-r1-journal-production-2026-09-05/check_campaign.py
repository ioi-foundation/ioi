#!/usr/bin/env python3
"""Check one retained terminal campaign; never launch a process test."""
from pathlib import Path
import hashlib,json,subprocess
base=Path(__file__).resolve().parent
campaign=base/'consecutive-process'
result=json.loads((campaign/'result.json').read_text())
started=json.loads((base/'started.json').read_text())
checker_name='.github/scripts/check_aft_quv_readiness_evidence.py'
checker=base/'sources'/checker_name
assert hashlib.sha256(checker.read_bytes()).hexdigest()==started['sources'][checker_name]
analyzer=base.parent/'m17q-r1-final-admission-release-2026-09-05/analyze_admission_releases.py'
retained=base/'admission-release-analyzer.py'
if not retained.exists():retained.write_bytes(analyzer.read_bytes())
commands={'readiness-evidence':['python3',str(checker),str(campaign/'run.log'),'--components',str(campaign/'components')],
          'admission-releases':['python3',str(retained),str(campaign/'components')]}
checks={}
for name,command in commands.items():
 run=subprocess.run(command,capture_output=True,text=True)
 (campaign/(name+'.json')).write_text(run.stdout)
 (campaign/(name+'-command.json')).write_text(json.dumps({'command':command,'exit_code':run.returncode,'stderr':run.stderr,'checker_sha256':hashlib.sha256(Path(command[1]).read_bytes()).hexdigest()},indent=2)+'\n')
 checks[name]=run.returncode
passed=result['exit_code']==0 and not result['source_changes'] and all(code==0 for code in checks.values())
summary={'disposition':'PASS_SCOPED_CAMPAIGN' if passed else 'REPAIR_OR_INVESTIGATION_REQUIRED',
         'process_exit_code':result['exit_code'],'changed_sources':result['source_changes'],'checker_exit_codes':checks,
         'scope':'production schema-7 three-slot/restart and unrelated-effect assertions; not full rooted resource/fairness profile, sustained flood, complete refinement, clean R2 or whole R1 closure'}
(campaign/'checked-disposition.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
raise SystemExit(0 if passed else 1)
