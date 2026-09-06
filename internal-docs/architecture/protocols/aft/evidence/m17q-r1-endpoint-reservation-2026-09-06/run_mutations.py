#!/usr/bin/env python3
"""Local defensive guard-removal regressions; restore exact baseline in finally."""
import hashlib, json, subprocess
from pathlib import Path
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
p=root/'crates/agentgres/src/consequence/resource_reservation.rs'
original=p.read_bytes()
text=original.decode()
needle='if file.metadata()?.len() != 0 || file.allocated_size()? != PQ_REGISTER_RECORD_MAX_BYTES as u64'
assert text.count(needle)==1
mutant=text.replace(needle,'if false',1).encode()
archive=base/'mutation-sources';archive.mkdir(exist_ok=True)
(archive/'resource_reservation.baseline.rs').write_bytes(original)
(archive/'resource_reservation.removed-capacity.rs').write_bytes(mutant)
command=['cargo','test','--locked','-p','agentgres','--lib','consequence::tests::endpoint_reservation_refuses_lost_capacity_and_recovers_only_uncommitted_staging','--','--exact']
try:
 p.write_bytes(mutant)
 with (base/'removed-capacity.log').open('w') as log:code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
finally:
 p.write_bytes(original)
log=(base/'removed-capacity.log').read_text()
result={'command':command,'exit_code':code,'expected_failure':code==101 and 'ResourceCapacityNotPrepared' in log and 'assertion failed' in log,'restored':p.read_bytes()==original,'baseline_sha256':hashlib.sha256(original).hexdigest(),'mutant_sha256':hashlib.sha256(mutant).hexdigest()}
(base/'mutation.json').write_text(json.dumps(result,indent=2)+'\n')
assert result['expected_failure'] and result['restored'],result
