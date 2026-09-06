#!/usr/bin/env python3
"""Scoped receipt reuse checks; not full M16Q qualification."""
from pathlib import Path
import datetime, hashlib, json, subprocess, re
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def put(name,obj): (base/name).write_text(json.dumps(obj,indent=2)+'\n')
files=['crates/services/src/aft_effect_registry.rs','crates/execution/src/app/state_machine.rs','crates/execution/src/app/mod.rs','crates/api/src/state/overlay.rs','crates/execution/src/mv_memory.rs','crates/execution/src/mv_memory/tests.rs','crates/cli/tests/aft_e2e_parts/quv_readiness.rs','.github/scripts/check_aft_quv_readiness_evidence.py','Cargo.toml','Cargo.lock','crates/agentgres/Cargo.toml','crates/agentgres/src/consequence.rs','crates/agentgres/src/consequence/tests.rs','crates/types/src/app/consequence.rs','crates/crypto/src/sign/dilithium/mod.rs','.github/scripts/run_aft_formal_checks.sh','.github/scripts/run_aft_m16q_qualification.sh','crates/validator/src/standard/orchestration/mod.rs','crates/validator/src/standard/orchestration/grpc_public.rs','crates/validator/src/standard/orchestration/quv.rs']
files += ['.github/scripts/check_aft_m16q_process_evidence.py','crates/validator/src/standard/orchestration/quv/admission.rs','crates/cli/tests/aft_e2e.rs','crates/validator/src/standard/orchestration/runtime_finality.rs','crates/agentgres/src/recognized_effect.rs','crates/consensus/src/aft/query_unanimity.rs','crates/agentgres/src/consequence/resource_reservation.rs','crates/agentgres/src/consequence/receipt_reservation.rs', '.github/scripts/check_aft_endpoint_reservation.py', '.github/scripts/check_aft_receipt_reservation.py']
files.extend(str(p.relative_to(root)) for folder in ['consequence','resource_profile','outbox','concurrency'] for p in (root/'internal-docs/architecture/protocols/aft/formal'/folder).glob('*') if p.suffix in {'.tla','.cfg'} and '_TTrace_' not in p.name)
hashes={name:digest(root/name) for name in sorted(set(files))}
for name in hashes:
 target=base/'sources'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((root/name).read_bytes())
put('started.json',{'started':now(),'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'sources':hashes,'scope':'selected dirty-worktree source; not immutable qualification'})
put('toolchain.json',{'captured':now(),'rustc':subprocess.check_output(['rustc','-Vv'],cwd=root,text=True),'cargo':subprocess.check_output(['cargo','--version'],cwd=root,text=True)})
checks=[('consequence',['cargo','test','--locked','-p','agentgres','--lib','consequence::tests::']),
 ('runtime-finality',['cargo','test','--locked','-p','ioi-validator','--features','consensus-aft','--lib','standard::orchestration::runtime_finality::tests::']),
 ('runtime',['cargo','test','--locked','-p','ioi-validator','--features','consensus-aft','--lib','standard::orchestration::quv::']),
 ('executor',['cargo','test','--locked','-p','ioi-validator','--features','consensus-aft','--lib','standard::orchestration::grpc_public::quv_refusal_status_tests::']),
 ('cli',['cargo','check','--locked','-p','ioi-cli','--test','aft_e2e','--features','consensus-aft,vm-wasm,state-iavl']),
 ('format',['cargo','fmt','--all','--','--check']),
 ('syntax',['bash','-n','.github/scripts/run_aft_m16q_qualification.sh']),
 ('formal',['bash','.github/scripts/run_aft_formal_checks.sh','--quv-receipt-reuse-only'])]

results=[]
for name,command in checks:
 start=now();print('START',name,start,flush=True)
 with (base/(name+'.log')).open('w') as log:code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
 if command[:2]==['cargo','test'] and not re.search(r'test result: ok\. [1-9][0-9]* passed;', (base/(name+'.log')).read_text()):
  code=1
 results.append({'name':name,'command':command,'started':start,'completed':now(),'exit_code':code});put('results.json',results);print('DONE',name,code,flush=True)
changed=[name for name,h in hashes.items() if digest(root/name)!=h]
passing=not changed and all(r['exit_code']==0 for r in results)
put('completed.json',{'completed':now(),'source_changes':changed,'passing':passing,'scope':'scoped prepared receipt reuse validation; prior process evidence predates this production change; aggregate admission/profile/full transition refinement/R2/review outstanding'})
raise SystemExit(0 if passing else 1)
