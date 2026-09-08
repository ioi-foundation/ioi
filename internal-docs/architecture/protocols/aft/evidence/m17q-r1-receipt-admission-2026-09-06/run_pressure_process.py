#!/usr/bin/env python3
"""Source-bound scoped pressure/restart campaign, not immutable R2."""
from pathlib import Path
import subprocess, json, os, hashlib, datetime, tarfile
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
out=base/'pressure-process'; out.mkdir(exist_ok=False)
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def put(name, data): (out/name).write_text(json.dumps(data,indent=2)+'\n')
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
selected=json.loads((base/'started.json').read_text())['sources']
assert all(digest(root/p)==h for p,h in selected.items())
assert json.loads((base/'completed.json').read_text())['passing']
patterns=['*.rs','*.toml','*.proto','*.py','*.sh','*.c','*.h','*.cpp','*.wasm']
cmd=['rg','--files','--hidden','crates','.github','.cargo']
for pattern in patterns: cmd+=['-g',pattern]
files=set(subprocess.check_output(cmd,cwd=root,text=True).splitlines())|set(selected)|{'Cargo.toml','Cargo.lock'}
for name in ['rust-toolchain','rust-toolchain.toml','rustfmt.toml']:
 if (root/name).is_file(): files.add(name)
hashes={p:digest(root/p) for p in sorted(files)}
with tarfile.open(out/'source-snapshot.tar.gz','w:gz') as archive:
 for p in hashes: archive.add(root/p,arcname=p,recursive=False)
command=['cargo','test','--locked','-p','ioi-cli','--test','aft_e2e','--features','consensus-aft,vm-wasm,state-iavl','test_aft_quv_consecutive_slots_wait_and_reopen_without_blocking_unrelated_effects','--','--exact','--nocapture']
components=out/'components';components.mkdir()
env=os.environ.copy();overrides={'IOI_TEST_ORCH_RUST_LOG':'info,quv=debug,network=debug','IOI_AFT_BENCH_TRACE_DIR':str(components)};env.update(overrides)
put('started.json',{'started':now(),'command':command,'environment_overrides':overrides,'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'toolchain':subprocess.check_output(['rustc','-Vv'],cwd=root,text=True),'sources':hashes,'scope':'captured working-tree sources; not clean immutable qualification'})
with (out/'process.log').open('w') as log: code=subprocess.run(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
checker=['python3','.github/scripts/check_aft_quv_readiness_evidence.py',str(out/'process.log'),'--components',str(components)]
with (out/'checker.log').open('w') as log: checked=subprocess.run(checker,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
changed=[p for p,h in hashes.items() if not (root/p).is_file() or digest(root/p)!=h]
put('completed.json',{'completed':now(),'exit_code':code,'checker_command':checker,'checker_exit_code':checked,'changed_sources':changed,'passing':code==0 and checked==0 and not changed})
raise SystemExit(code or checked or bool(changed))
