#!/usr/bin/env python3
"""Defensive omission test for the rooted consequence storage fields."""
from pathlib import Path
import hashlib,json,subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
p=root/'crates/consensus/src/aft/query_unanimity.rs'
original=p.read_bytes();needle=b'        ioi_types::app::QuvConsequenceStorageProfileV0::ROOTED_FIELDS,\n'
assert original.count(needle)==1
mutant=original.replace(needle,b'',1)
archive=base/'mutation-sources';archive.mkdir(exist_ok=True)
(archive/'query_unanimity.baseline.rs').write_bytes(original)
(archive/'query_unanimity.omitted-storage-fields.rs').write_bytes(mutant)
command=['cargo','test','--locked','-p','ioi-consensus','--features','aft','--lib','aft::query_unanimity::tests::policy_root_binds_authority_and_complete_timing_bounds','--','--exact']
try:
 p.write_bytes(mutant)
 with (base/'omitted-storage-fields.log').open('w') as log:code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
finally:p.write_bytes(original)
log=(base/'omitted-storage-fields.log').read_text();vector=json.loads((base/'policy_vector.json').read_text())
result={'command':command,'exit_code':code,'expected_failure':code==101 and vector['without_storage_fields'] in log and vector['policy_root'] in log,'restored':p.read_bytes()==original,'baseline_sha256':hashlib.sha256(original).hexdigest(),'mutant_sha256':hashlib.sha256(mutant).hexdigest()}
(base/'mutation.json').write_text(json.dumps(result,indent=2)+'\n')
assert result['expected_failure'] and result['restored'],result
