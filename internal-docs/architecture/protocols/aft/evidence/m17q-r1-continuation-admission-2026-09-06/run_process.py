#!/usr/bin/env python3
from pathlib import Path
import subprocess,json,os,hashlib,datetime
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
command=['cargo','test','--locked','-p','ioi-cli','--test','aft_e2e','--features','consensus-aft,vm-wasm,state-iavl','test_aft_quv_m16q_each_single_correct_member_and_conflict_isolation','--','--exact','--nocapture']
hashes=json.loads((base/'started.json').read_text())['sources']
assert all(hashlib.sha256((root/p).read_bytes()).hexdigest()==h for p,h in hashes.items())
env=os.environ.copy();env['IOI_TEST_ORCH_RUST_LOG']='quv=debug,network=debug'
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
(base/'process-started.json').write_text(json.dumps({'started':started,'command':command,'environment_overrides':{'IOI_TEST_ORCH_RUST_LOG':env['IOI_TEST_ORCH_RUST_LOG']},'scope':'scoped dirty-worktree process campaign; not immutable R2'},indent=2)+'\n')
with (base/'process.log').open('w') as log:
 code=subprocess.run(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
changed=[p for p,h in hashes.items() if hashlib.sha256((root/p).read_bytes()).hexdigest()!=h]
(base/'process-completed.json').write_text(json.dumps({'exit_code':code,'changed_sources':changed,'completed':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
raise SystemExit(code or bool(changed))
