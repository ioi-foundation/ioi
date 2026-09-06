#!/usr/bin/env python3
from pathlib import Path
import datetime, hashlib, json, os, shutil, subprocess

root = Path.cwd()
base = root / 'internal-docs/architecture/protocols/aft/evidence/m17q-r1-journal-production-2026-09-05'
prior = root / 'internal-docs/architecture/protocols/aft/evidence/m17q-r1-readiness-process-2026-09-05/consecutive-process-recovery-probed/started.json'
source_names = set(json.loads(prior.read_text())['sources'])
source_names.update(str(p.relative_to(root)) for p in (root / 'crates/consensus/src/aft/query_unanimity').rglob('*.rs'))
source_names.update(['.github/scripts/check_aft_quv_journal_sync.py', 'Cargo.toml', 'crates/consensus/Cargo.toml', 'crates/validator/Cargo.toml', 'crates/cli/Cargo.toml'])
source_names.update(str(p.relative_to(root)) for p in (root / 'crates/types/src').glob('config*.rs'))
sources = {}
for name in sorted(source_names):
    p = root / name
    sources[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    dest = base / 'sources' / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(p, dest)
started = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'git_head': subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip(),
           'toolchain': subprocess.check_output(['rustc','--version','--verbose'], text=True),
           'sources': sources, 'source_scope': 'retained source subset of dirty worktree; not immutable R2',
           'member_schema': 7, 'handoff_schema': 3}
(base/'started.json').write_text(json.dumps(started, indent=2)+'\n')
commands = [
    ('restored-quv-tests', ['cargo','test','--locked','-p','ioi-consensus','--features','aft','--lib','aft::query_unanimity','--no-fail-fast']),
    ('runtime-tests', ['cargo','test','--locked','-p','ioi-validator','--features','consensus-aft','--lib','standard::orchestration::quv::']),
    ('cli-check', ['cargo','check','--locked','-p','ioi-cli','--test','aft_e2e','--features','consensus-aft,vm-wasm,state-iavl']),
    ('durability-benchmark', ['cargo','test','--locked','-p','ioi-consensus','--features','aft','--lib','aft::query_unanimity::tests::m16q_profiles_mldsa_signing_and_durable_write_before_reply','--','--exact','--ignored','--nocapture']),
    ('ancestry-trace', ['strace','-f','-yy','-e','trace=fsync,rename,openat,mkdir','-o',str(base/'restored-ancestry.strace'),'cargo','test','--locked','-p','ioi-consensus','--features','aft','--lib','aft::query_unanimity::journal::tests::bootstrap_interruption_recovers_only_the_provisioned_initial_record','--','--exact','--nocapture']),
    ('ancestry-check', ['python3','.github/scripts/check_aft_quv_journal_sync.py','--trace',str(base/'restored-ancestry.strace'),'--result',str(base/'ancestry-trace.log')]),
]
results = []
for name, command in commands:
    begin = datetime.datetime.now(datetime.timezone.utc)
    with (base/(name+'.log')).open('wb') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    results.append({'name':name,'command':command,'exit_code':result.returncode,'started_utc':begin.isoformat(),
                    'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'log':name+'.log'})
    (base/'check-results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(name,result.returncode,flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)

campaign = base/'consecutive-process'
campaign.mkdir(exist_ok=True)
components = campaign/'components'
components.mkdir(exist_ok=True)
command = ['cargo','test','--locked','-p','ioi-cli','--test','aft_e2e','--features','consensus-aft,vm-wasm,state-iavl',
           'test_aft_quv_consecutive_slots_wait_and_reopen_without_blocking_unrelated_effects','--','--exact','--nocapture']
overrides = {'IOI_TEST_ORCH_RUST_LOG':'info,quv=debug,network=debug','IOI_AFT_BENCH_TRACE_DIR':str(components)}
header = dict(started, started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), command=command,
              environment_overrides=overrides, scope='Same finite three-slot scenario with production schema-7 incremental journal; no timing relaxation or authority from replay/probe bytes')
(campaign/'started.json').write_text(json.dumps(header,indent=2)+'\n')
print('consecutive-process started',flush=True)
with (campaign/'run.log').open('wb') as output:
    result = subprocess.run(command, env=dict(os.environ,**overrides), stdout=output, stderr=subprocess.STDOUT)
changed = [name for name,digest in sources.items() if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest]
completion = {'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'exit_code':result.returncode,
              'source_changes':changed,'process_scope':'finite three-slot campaign; not full M16Q R2'}
(campaign/'result.json').write_text(json.dumps(completion,indent=2)+'\n')
print('consecutive-process',result.returncode,'source_changes',changed,flush=True)
raise SystemExit(result.returncode or bool(changed))
