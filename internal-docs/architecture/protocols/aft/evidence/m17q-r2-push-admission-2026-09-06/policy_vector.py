#!/usr/bin/env python3
"""Independent SCALE byte construction for one policy-root v8 fixture.

Derived from m17q-r1-receipt-admission-2026-09-06/policy_vector.py (v7).
v8 inserts the rooted per-identity push admission quota
(QuvPushAdmissionPolicyV0 { max_requests_per_identity: u32, window_millis: u64 })
immediately after `authority_slots` in the canonical hash tuple and changes the
domain tag. Fixture: domain [3;32], Owned, owner [9;32], delta_rt 1000,
continuation 50, Fixed{initial_slot 1, predecessor [77;32]},
Independent{2, 1020, 1000000}, operation_service 1050, authority_slots 256,
push_admission {64, 1000}.
"""
from pathlib import Path
import hashlib,json,struct
u32=lambda n:struct.pack('<I',n)
u64=lambda n:struct.pack('<Q',n)
tag=b'ioi/aft/quv-policy/v8-push-admission'
assert len(tag)<64
prefix=bytes([len(tag)<<2])+tag+bytes([3])*32+b'\0\1'+bytes([9])*32
prefix+=u64(1000)+u64(50)+b'\0'+u64(1)+bytes([77])*32
prefix+=b'\0'+struct.pack('<H',2)+u64(1020)+u64(1000000)+u64(1050)+u32(256)
without_push_admission_prefix=prefix
push_admission=[64,1000]
prefix+=u32(push_admission[0])+u64(push_admission[1])
suffix=b''.join(map(u64,[2,4096,8192,512*1024*1024,1024,16*1024*1024,2,16384,32768]))
fields=[1,16*1024*1024,4,16384,81920,4,512,32768,32,4096,2,2,1,2,4096]  # v8 appends CLAIM_INDEX_FILES, CLAIM_INDEX_FILE_BYTES
suffix+=b''.join(map(u64,fields))
admission_fields=[1,1,1,1,1]  # v8 appends WAITING_PER_PRINCIPAL
suffix+=b''.join(map(u64,admission_fields))
encoded=prefix+suffix
# Control: the same bytes with the quota omitted from its tuple position.
without_push_admission=without_push_admission_prefix+suffix
result={'policy_root':hashlib.sha256(encoded).hexdigest(),'push_admission':push_admission,'without_push_admission':hashlib.sha256(without_push_admission).hexdigest(),'fields':fields,'admission_fields':admission_fields,'encoded_hex':encoded.hex()}
assert result['policy_root']!=result['without_push_admission']
Path(__file__).with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n')
print(result['policy_root'])
