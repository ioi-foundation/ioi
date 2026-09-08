#!/usr/bin/env python3
"""Scoped final-source checks; not the full immutable M16Q runner."""
from pathlib import Path
import datetime, hashlib, json, subprocess
base = Path(__file__).resolve().parent
root = next(p for p in base.parents if (p/'Cargo.toml').exists())
files = ['Cargo.toml', 'crates/networking/Cargo.toml', '.github/scripts/check_aft_pq_outbox_reservation.py', '.github/scripts/check_aft_pq_outbox_ancestry.py', 'Cargo.lock', 'crates/types/src/app/query_unanimity.rs',
         'crates/crypto/src/transport/pq_authenticated_channel.rs',
         'crates/consensus/src/aft/query_unanimity.rs',
         'crates/networking/src/libp2p/pq_channel.rs',
         '.github/scripts/run_aft_m16q_qualification.sh', '.github/scripts/run_aft_formal_checks.sh']
for directory, suffixes in [('crates/networking/src/libp2p/pq_channel', {'.rs'}),
                            ('crates/consensus/src/aft/query_unanimity', {'.rs'}),
                            ('internal-docs/architecture/protocols/aft/formal/outbox', {'.tla','.cfg'})]:
    files.extend(str(p.relative_to(root)) for p in (root/directory).rglob('*') if p.suffix in suffixes)
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def put(name, obj): (base/name).write_text(json.dumps(obj, indent=2)+'\n')
hashes = {name:digest(root/name) for name in sorted(set(files))}
for name in hashes:
    target=base/'sources'/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes((root/name).read_bytes())
put('started.json', {'started':now(), 'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(), 'sources':hashes,'scope':'selected dirty-worktree sources; narrative docs excluded'})
checks = [('network',['cargo','test','--locked','-p','ioi-networking','--lib','pq_channel']),
          ('runtime',['cargo','test','--locked','-p','ioi-validator','--features','consensus-aft','--lib','standard::orchestration::quv::']),
          ('cli',['cargo','check','--locked','-p','ioi-cli','--test','aft_e2e','--features','consensus-aft,vm-wasm,state-iavl']),
          ('format',['cargo','fmt','--all','--','--check']),
          ('syntax',['bash','-n','.github/scripts/run_aft_m16q_qualification.sh']),
          ('formal',['bash','.github/scripts/run_aft_formal_checks.sh','--pq-reserved-index-only']),
          ('arena_formal',['bash','.github/scripts/run_aft_formal_checks.sh','--quv-payload-arena-only']),
          ('index_formal',['bash','.github/scripts/run_aft_formal_checks.sh','--pq-outbox-index-only']),
          ('ancestry',['python3','.github/scripts/check_aft_pq_outbox_ancestry.py','--output',str(base/'ancestry')]),
          ('reservation',['python3','.github/scripts/check_aft_pq_outbox_reservation.py','--output',str(base/'reservation')])]
results=[]
for name,command in checks:
    started=now(); print('START', name, started, flush=True)
    with (base/(name+'.log')).open('w') as log:
        code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
    results.append({'name':name,'command':command,'started':started,'completed':now(),'exit_code':code})
    put('results.json',results); print('DONE', name, code, flush=True)
changed=[name for name,h in hashes.items() if digest(root/name)!=h]
passing=not changed and all(r['exit_code']==0 for r in results)
put('completed.json',{'completed':now(),'source_changes':changed,'passing':passing,'scope':'scoped only; full R2 and review outstanding'})
raise SystemExit(0 if passing else 1)
