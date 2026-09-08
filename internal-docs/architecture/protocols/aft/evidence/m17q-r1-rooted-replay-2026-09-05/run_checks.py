#!/usr/bin/env python3
"""Scoped defensive regression evidence; this is not the complete M16Q runner."""
from pathlib import Path
import datetime, hashlib, json, subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def put(name,value): (base/name).write_text(json.dumps(value,indent=2)+'\n')
prior=base.parent/'m17q-r1-journal-production-2026-09-05'
files=set(json.loads((prior/'started.json').read_text())['sources'])
files.update(str(p.relative_to(root)) for p in (root/'crates/consensus/src/aft/query_unanimity').rglob('*.rs'))
files.update(['.github/scripts/run_aft_m16q_qualification.sh','.github/scripts/run_aft_formal_checks.sh'])
hashes={name:digest(root/name) for name in sorted(files)}
for name in hashes:
 target=base/'sources'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((root/name).read_bytes())
put('started.json',{'started':now(),'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'sources':hashes,'scope':'selected dirty-worktree sources, not immutable R2','member_schema':8,'handoff_schema':3})
checks=[('quv-core',['cargo','test','--locked','-p','ioi-consensus','--features','aft','--lib','aft::query_unanimity','--no-fail-fast']),('quv-runtime',['cargo','test','--locked','-p','ioi-validator','--features','consensus-aft','--lib','standard::orchestration::quv::']),('cli-check',['cargo','check','--locked','-p','ioi-cli','--test','aft_e2e','--features','consensus-aft,vm-wasm,state-iavl']),('format',['cargo','fmt','--all','--','--check']),('runner-syntax',['bash','-n','.github/scripts/run_aft_m16q_qualification.sh'])]
results=[]
for name,command in checks:
 start=now();print('START',name,start,flush=True)
 with (base/(name+'.log')).open('w') as log: code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
 results.append({'name':name,'command':command,'started':start,'completed':now(),'exit_code':code})
 put('results.json',results);print('DONE',name,code,flush=True)
changed=[name for name,value in hashes.items() if digest(root/name)!=value]
put('completed.json',{'completed':now(),'source_changes':changed,'passing':not changed and all(r['exit_code']==0 for r in results),'scope':'scoped core/runtime/build/format checks only; full R2 and review outstanding'})
raise SystemExit(0 if not changed and all(r['exit_code']==0 for r in results) else 1)
