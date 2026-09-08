#!/usr/bin/env python3
"""Local defensive omission controls for preparation; restores source in finally."""
from pathlib import Path
import hashlib,json,subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
p=root/'crates/consensus/src/aft/query_unanimity.rs'
original=p.read_bytes();source=original.decode()
needle = """    if bytes.len() > CANDIDATE_MAX_ENCODED_BYTES {
        return Err(QuvError::CandidateCapacityExceeded);
    }
    codec::from_bytes_canonical(bytes).map_err(QuvError::Codec)"""
mutations=[('decode-length',needle,'    codec::from_bytes_canonical(bytes).map_err(QuvError::Codec)')]
archive=base/'mutation-sources';archive.mkdir(exist_ok=True)
(archive/'candidate.baseline.rs').write_bytes(original)
command_base=['cargo','test','--locked','-p','ioi-consensus','--features','aft','--lib']
results=[]
try:
 for name,needle,replacement in mutations:
  test='candidate_byte_cap_precedes_validation_and_store_mutation'
  command=command_base+['aft::query_unanimity::tests::'+test,'--','--exact']
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
