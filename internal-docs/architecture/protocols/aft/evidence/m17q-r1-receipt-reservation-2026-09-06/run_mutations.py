#!/usr/bin/env python3
"""Local defensive live-allocation fallback mutant, always restoring baseline."""
from pathlib import Path
import hashlib,json,subprocess
base=Path(__file__).resolve().parent
root=next(p for p in base.parents if (p/'Cargo.toml').exists())
p=root/'crates/agentgres/src/consequence/receipt_reservation.rs'
original=p.read_bytes();source=original.decode()
needle='pub(super) fn commit('
a=source.index(needle);b=source.index('    #[cfg(not(target_os',a)
mutant=(source[:b]+'    return atomic_write(path, bytes);\n'+source[b:]).encode()
archive=base/'mutation-sources';archive.mkdir(exist_ok=True)
(archive/'receipt_reservation.baseline.rs').write_bytes(original)
(archive/'receipt_reservation.live-fallback.rs').write_bytes(mutant)
command=['cargo','test','--locked','-p','agentgres','--lib','consequence::tests::online_receipt_lost_reservation_refuses_before_claim_and_requires_reopen','--','--exact']
try:
 p.write_bytes(mutant)
 with (base/'removed-reservation.log').open('w') as log:code=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT).returncode
finally:p.write_bytes(original)
log=(base/'removed-reservation.log').read_text()
result={'command':command,'exit_code':code,'expected_failure':code==101 and 'assertion failed' in log and 'ResourceCapacityNotPrepared' in log,'restored':p.read_bytes()==original,'baseline_sha256':hashlib.sha256(original).hexdigest(),'mutant_sha256':hashlib.sha256(mutant).hexdigest()}
(base/'mutation.json').write_text(json.dumps(result,indent=2)+'\n')
assert result['expected_failure'] and result['restored'],result
