#!/usr/bin/env python3
"""Scoped member data-reservation verification, not full R2 qualification."""
from pathlib import Path
import datetime, hashlib, json, subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def put(name,obj): (base/name).write_text(json.dumps(obj,indent=2)+'\n')
files=['Cargo.toml','Cargo.lock','crates/consensus/Cargo.toml','crates/consensus/src/aft/query_unanimity.rs',
       'crates/types/src/app/query_unanimity.rs','.github/scripts/run_aft_formal_checks.sh',
       '.github/scripts/run_aft_m16q_qualification.sh','.github/scripts/check_aft_quv_record_reservation.py']
for directory,suffixes in [('crates/consensus/src/aft/query_unanimity',{'.rs'}),
                          ('internal-docs/architecture/protocols/aft/formal/resource_profile',{'.tla','.cfg'})]:
    files.extend(str(p.relative_to(root)) for p in (root/directory).rglob('*')
                 if p.name != 'anchor_reservation.rs' and p.suffix in suffixes and '_TTrace_' not in p.name and '.tlacache' not in p.parts)
hashes={name:digest(root/name) for name in sorted(set(files))}
for name in hashes:
    target=base/'sources'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((root/name).read_bytes())
put('started.json',{'started':now(),'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
                    'sources':hashes,'scope':'selected dirty-worktree source; narrative docs excluded'})
checks=[('core',['cargo','test','--locked','-p','ioi-consensus','--features','aft','--lib','aft::query_unanimity']),
        ('runtime',['cargo','test','--locked','-p','ioi-validator','--features','consensus-aft','--lib','standard::orchestration::quv::']),
        ('cli',['cargo','check','--locked','-p','ioi-cli','--test','aft_e2e','--features','consensus-aft,vm-wasm,state-iavl']),
        ('format',['cargo','fmt','--all','--','--check']),
        ('syntax',['bash','-n','.github/scripts/run_aft_m16q_qualification.sh']),
        ('formal',['bash','.github/scripts/run_aft_formal_checks.sh','--quv-record-reservation-only']),
        ('lifetime',['bash','.github/scripts/run_aft_formal_checks.sh','--quv-lifetime-budget-only']),
        ('trace',['python3','.github/scripts/check_aft_quv_record_reservation.py','--output',str(base/'trace')]),
]
results=[]
for name,command in checks:
    started=now();print('START',name,started,flush=True)
    with (base/(name+'.log')).open('w') as log:
        code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
    results.append({'name':name,'command':command,'started':started,'completed':now(),'exit_code':code})
    put('results.json',results);print('DONE',name,code,flush=True)
changed=[name for name,h in hashes.items() if digest(root/name)!=h]
passing=not changed and all(r['exit_code']==0 for r in results)
put('completed.json',{'completed':now(),'source_changes':changed,'passing':passing,'scope':'scoped only; full R2/refinement/review outstanding'})
raise SystemExit(0 if passing else 1)
