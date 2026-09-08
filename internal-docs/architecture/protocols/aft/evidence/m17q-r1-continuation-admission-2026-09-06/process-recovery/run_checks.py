#!/usr/bin/env python3
"""Scoped process recovery harness checks; not full M16Q qualification."""
from pathlib import Path
import datetime, hashlib, json, subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def put(name,obj): (base/name).write_text(json.dumps(obj,indent=2)+'\n')
files=['Cargo.toml','Cargo.lock','crates/agentgres/Cargo.toml','crates/agentgres/src/consequence.rs','crates/agentgres/src/consequence/tests.rs','crates/types/src/app/consequence.rs','crates/crypto/src/sign/dilithium/mod.rs','.github/scripts/run_aft_formal_checks.sh','.github/scripts/run_aft_m16q_qualification.sh','crates/validator/src/standard/orchestration/mod.rs','crates/validator/src/standard/orchestration/grpc_public.rs','crates/validator/src/standard/orchestration/quv.rs']
files += ['crates/cli/tests/aft_e2e_parts/quv_readiness.rs','crates/cli/src/testing/build.rs','crates/cli/src/testing/validator.rs','crates/cli/src/testing/rpc.rs','crates/cli/src/testing/cluster.rs','crates/cli/tests/aft_e2e.rs','crates/validator/src/standard/orchestration/quv/admission.rs','crates/validator/src/standard/orchestration/runtime_finality.rs','crates/agentgres/src/recognized_effect.rs','crates/consensus/src/aft/query_unanimity.rs','crates/agentgres/src/consequence/resource_reservation.rs','crates/agentgres/src/consequence/receipt_reservation.rs', '.github/scripts/check_aft_endpoint_reservation.py', '.github/scripts/check_aft_receipt_reservation.py']
files.extend(str(p.relative_to(root)) for folder in ['consequence','resource_profile','outbox','concurrency'] for p in (root/'internal-docs/architecture/protocols/aft/formal'/folder).glob('*') if p.suffix in {'.tla','.cfg'} and '_TTrace_' not in p.name)
hashes={name:digest(root/name) for name in sorted(set(files))}
for name in hashes:
 target=base/'sources'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((root/name).read_bytes())
put('started.json',{'started':now(),'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'sources':hashes,'scope':'selected dirty-worktree source; not immutable qualification'})
checks=[('probe',['cargo','test','--locked','-p','ioi-cli','--test','aft_e2e','--features','consensus-aft,vm-wasm,state-iavl','recovery_probe_retries_only_startup_and_requires_exact_result','--','--exact']),('format',['cargo','fmt','--all','--','--check']),('syntax',['bash','-n','.github/scripts/run_aft_m16q_qualification.sh'])]

results=[]
for name,command in checks:
 start=now();print('START',name,start,flush=True)
 with (base/(name+'.log')).open('w') as log:code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
 results.append({'name':name,'command':command,'started':start,'completed':now(),'exit_code':code});put('results.json',results);print('DONE',name,code,flush=True)
changed=[name for name,h in hashes.items() if digest(root/name)!=h]
passing=not changed and all(r['exit_code']==0 for r in results)
put('completed.json',{'completed':now(),'source_changes':changed,'passing':passing,'scope':'scoped continuation admission ownership; aggregate admission/profile/full transition refinement/R2/review outstanding'})
raise SystemExit(0 if passing else 1)
