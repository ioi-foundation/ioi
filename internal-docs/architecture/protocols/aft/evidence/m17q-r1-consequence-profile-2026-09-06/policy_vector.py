#!/usr/bin/env python3
"""Independent SCALE byte construction for one policy-root v6 fixture."""
from pathlib import Path
import hashlib,json,struct
u64=lambda n:struct.pack('<Q',n)
tag=b'ioi/aft/quv-policy/v6-consequence-storage'
assert len(tag)<64
prefix=bytes([len(tag)<<2])+tag+bytes([3])*32+b'\0\1'+bytes([9])*32
prefix+=u64(1000)+u64(50)+b'\0'+u64(1)+bytes([77])*32
prefix+=b'\0'+struct.pack('<H',2)+u64(1020)+u64(1000000)+u64(1050)+struct.pack('<I',256)
prefix+=b''.join(map(u64,[2,4096,8192,512*1024*1024,1024,16*1024*1024,2,16384,32768]))
fields=[1,16*1024*1024,4,16384,81920,4,512,32768,32,4096,2,2]
encoded=prefix+b''.join(map(u64,fields))
result={'policy_root':hashlib.sha256(encoded).hexdigest(),'without_storage_fields':hashlib.sha256(prefix).hexdigest(),'fields':fields,'encoded_hex':encoded.hex()}
assert result['policy_root']!=result['without_storage_fields']
Path(__file__).with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n')
print(result['policy_root'])
