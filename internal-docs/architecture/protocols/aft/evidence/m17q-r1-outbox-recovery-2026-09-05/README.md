# Streaming outbox recovery

Recovery decodes the v2 header and entries through a 64 KiB reader, avoiding a
second full-file byte vector. Scope is checked before entry allocation. Entry
count is checked against available fixed identity bytes and never drives a
preallocated vector. Each entry's decoder sees at most 64 identity bytes plus
the existing record plaintext allowance. Trailing bytes, truncation and changed
file length refuse recovery. Full entry commitment/count validation still runs
before the recovered outbox is exposed. No old file is rewritten on refusal.

Twenty-three channel tests passed. The strengthened allocation probe then
passed separately: the valid exact-fit vector decodes, the malformed declared
length fails with zero allocation requests, and removing the preallocation
budget exposes a 100-byte allocation before the later read failure. Malformed
file tests retain truncation/trailing bytes unchanged and reopen the restored
valid v2 file. Raw commands/results and selected source snapshots are retained;
this is not immutable R2 qualification.

Refinement obligation: the header fields, Compact entry count and ordered entry
decoding match the old v2 layout; every sendable entry fits the 64+plaintext
budget, and complete consumption preserves DecodeAll's trailing-byte refusal.
The per-entry budget is an existing transport constraint, not a new admitted
traffic quota. The full production refinement bridge remains open.

Decoded retained entries still need aggregate memory; many valid entries can
still consume substantial resources. Physical capacity, aggregate reservations,
recovery duration, incremental disk persistence and fair service remain open.
No whole R1 finding, complete R2, fresh review or M18Q admission is established.
