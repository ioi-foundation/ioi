#!/usr/bin/env python3
"""Local defensive omission controls for preparation; restores source in finally."""
from pathlib import Path
import hashlib,json,subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
p=root/'crates/agentgres/src/consequence.rs'
original=p.read_bytes();source=original.decode()
presence = """    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ConsequenceError::Io(error)),
    }"""
mutations=[('presence',presence,'    Ok(path.exists())'),
 ('staging','let mut file = resource_reservation::private_open(&temporary, true)?;', 'let mut file = OpenOptions::new().create(true).read(true).write(true).open(&temporary)?;'),
 ('lock','let lock = resource_reservation::private_open(&root.join("consequence.lock"), true)?;', 'let lock = OpenOptions::new().create(true).read(true).write(true).open(root.join("consequence.lock"))?;')]
archive=base/'mutation-sources';archive.mkdir(exist_ok=True)
(archive/'consequence.baseline.rs').write_bytes(original)
command_base=['cargo','test','--locked','-p','agentgres','--lib']
results=[]
try:
 for name,needle,replacement in mutations:
  test='consequence_lock_refuses_aliases_and_retains_exclusive_ownership' if name=='lock' else 'receipt_admission_preserves_invalid_active_and_staging_aliases'
  command=command_base+['consequence::tests::'+test,'--','--exact']
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
