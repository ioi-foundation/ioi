#!/usr/bin/env python3
"""Local defensive lifetime control; restores source in finally."""
from pathlib import Path
import hashlib,json,subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
p=root/'crates/validator/src/standard/orchestration/quv/admission.rs'
original=p.read_bytes();source=original.decode()
mutations=[('early-release','let result = work(value);\n        drop(admission);','drop(admission);\n        let result = work(value);')]
archive=base/'mutation-sources';archive.mkdir(exist_ok=True)
(archive/'admission.baseline.rs').write_bytes(original)
command=['cargo','test','--locked','-p','ioi-validator','--features','consensus-aft','--lib','standard::orchestration::quv::admission::tests::delivered_continuation_holds_admission_through_effect_and_cancelled_worker','--','--exact']
results=[]
try:
 for name,needle,replacement in mutations:
  assert source.count(needle)==1,(name,source.count(needle))
  mutant=source.replace(needle,replacement,1).encode();(archive/(name+'.rs')).write_bytes(mutant);p.write_bytes(mutant)
  with (base/('removed-'+name+'.log')).open('w') as log:code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
  output=(base/('removed-'+name+'.log')).read_text()
  result={'name':name,'command':command,'exit_code':code,'expected_failure':code==101 and 'test result: FAILED. 0 passed; 1 failed;' in output,'mutant_sha256':hashlib.sha256(mutant).hexdigest()}
  results.append(result);print(name,code,flush=True)
  assert result['expected_failure'],result
finally:
 p.write_bytes(original)
 (base/'mutations.json').write_text(json.dumps({'results':results,'baseline_sha256':hashlib.sha256(original).hexdigest(),'restored':p.read_bytes()==original},indent=2)+'\n')
