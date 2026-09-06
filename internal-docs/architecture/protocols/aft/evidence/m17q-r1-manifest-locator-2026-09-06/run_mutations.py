#!/usr/bin/env python3
"""Defensive selected-identity, duplicate, and recovery omission controls."""
from pathlib import Path
import hashlib,json,subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
p=root/'crates/validator/src/standard/orchestration/runtime_finality.rs'
original=p.read_bytes();source=original.decode()
mutations=[('identity','if manifest.effect_id != effect_id {','if false {'),
 ('duplicate','entry.insert(None);','entry.insert(Some(runtime_id));'),
 ('recovery','coordinator.committed_manifest_index = coordinator.rebuild_manifest_index()?;','// Recovery index intentionally omitted by defensive control.')]
archive=base/'mutation-sources';archive.mkdir(exist_ok=True)
(archive/'runtime_finality.baseline.rs').write_bytes(original)
command=['cargo','test','--locked','-p','ioi-validator','--features','consensus-aft','--lib','standard::orchestration::runtime_finality::tests::manifest_locator_rederives_one_block_and_preserves_duplicate_and_restart_refusal','--','--exact']
results=[]
try:
 for name,needle,replacement in mutations:
  assert source.count(needle)==1,(name,source.count(needle))
  mutant=source.replace(needle,replacement,1).encode();(archive/(name+'.rs')).write_bytes(mutant);p.write_bytes(mutant)
  with (base/('removed-'+name+'.log')).open('w') as log:code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
  output=(base/('removed-'+name+'.log')).read_text()
  result={'name':name,'command':command,'exit_code':code,'expected_failure':code==101 and ('assertion failed' in output or 'unwrap_err()' in output),'mutant_sha256':hashlib.sha256(mutant).hexdigest()}
  results.append(result);print(name,code,flush=True)
  assert result['expected_failure'],result
finally:p.write_bytes(original)
(base/'mutations.json').write_text(json.dumps({'results':results,'baseline_sha256':hashlib.sha256(original).hexdigest(),'restored':p.read_bytes()==original},indent=2)+'\n')
