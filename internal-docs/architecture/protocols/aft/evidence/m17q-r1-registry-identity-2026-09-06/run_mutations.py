#!/usr/bin/env python3
"""Local defensive omission controls for preparation; restores source in finally."""
from pathlib import Path
import hashlib,json,subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
p=root/'crates/services/src/aft_effect_registry.rs'
original=p.read_bytes();source=original.decode()
needle = """        if state
            .get(&identity)
            .map_err(TransactionError::State)?
            .is_some()
        {
            return Err(TransactionError::Invalid(
                "AFT effect identity was already admitted".into(),
            ));
        }"""
mutations=[('identity',needle,''),('schema','        require_registry_schema(state)?;','')]
archive=base/'mutation-sources';archive.mkdir(exist_ok=True)
(archive/'registry.baseline.rs').write_bytes(original)
command_base=['cargo','test','--locked','-p','ioi-services','--lib']
results=[]
try:
 for name,needle,replacement in mutations:
  test='identity_substitution_refuses_without_invalidating_prior_admission' if name=='identity' else 'unindexed_or_unknown_registry_schema_refuses_without_reinitializing'
  command=command_base+['aft_effect_registry::tests::'+test,'--','--exact']
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
