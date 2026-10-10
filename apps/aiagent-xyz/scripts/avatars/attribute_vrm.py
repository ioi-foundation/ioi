"""Credit a derived VRM as derived: set VRMC_vrm.meta identity from assets/avatars/vrm-attribution.json.

Refuses to write unless every license and permission field is unchanged and the binary chunk is
byte-identical. bake_motion.py applies the same file when it writes a VRM, so a re-bake keeps it.
Usage: python3 scripts/avatars/attribute_vrm.py public/models/avatars/<file>.vrm [...]
"""
import json, struct, sys
from pathlib import Path

ATTRIBUTION = json.loads((Path(__file__).resolve().parents[2] / 'assets/avatars/vrm-attribution.json').read_text())

def attribute(document):
    meta = ((document.get('extensions') or {}).get('VRMC_vrm') or {}).get('meta')
    if meta is None: raise SystemExit('refusing: no VRMC_vrm.meta (not a VRM 1.0 file)')
    base, target = ATTRIBUTION['base_identity'], ATTRIBUTION['set']
    if not (all(meta.get(k) == v for k, v in base.items()) or all(meta.get(k) == v for k, v in target.items() if k in base)):
        raise SystemExit(f"refusing: meta identity is neither the pixiv base nor already attributed: {meta.get('name')!r}")
    before = {k: meta.get(k) for k in ATTRIBUTION['preserve']}
    meta.update(target)
    if {k: meta.get(k) for k in ATTRIBUTION['preserve']} != before: raise SystemExit('refusing: a license or permission field changed')
    return document

def main(paths):
    for path in map(Path, paths):
        data = path.read_bytes()
        magic, version, total = struct.unpack('<4sII', data[:12]); json_len, json_type = struct.unpack('<II', data[12:20])
        if magic != b'glTF' or version != 2 or json_type != 0x4E4F534A or total != len(data): raise SystemExit(f'{path}: not a GLB 2.0 container')
        binary_chunk = data[20 + json_len:]
        document = attribute(json.loads(data[20:20 + json_len]))
        js = json.dumps(document, separators=(',', ':')).encode(); js += b' ' * ((-len(js)) % 4)
        out = struct.pack('<4sII', b'glTF', 2, 12 + 8 + len(js) + len(binary_chunk)) + struct.pack('<II', len(js), 0x4E4F534A) + js + binary_chunk
        if out[20 + len(js):] != binary_chunk: raise SystemExit(f'{path}: binary chunk changed')
        path.write_bytes(out)
        print(f'{path}: attributed; {len(data)} -> {len(out)} bytes; binary chunk unchanged')

if __name__ == '__main__':
    main(sys.argv[1:])
