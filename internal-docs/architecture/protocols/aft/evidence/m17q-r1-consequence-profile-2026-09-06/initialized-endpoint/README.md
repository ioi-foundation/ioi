# Fully initialized endpoint follow-up

84 core (one scoped benchmark ignored), 30 consequence, 8 types, 21 runtime,
2 executor, CLI, fmt/syntax and selected formal/syscall checks pass. Final source
hashes remain unchanged after the root-field omission mutant is restored. The
independent policy vector now has 13 fields, including ENDPOINT_INITIALIZED=1.

Endpoint staging is now fully space-initialized and synced before QUV; live
commit requires exact allocated capacity and untouched space padding. Canonical
signed JSON overwrites the prefix without truncation; lookup admits only raw
canonical JSON or exact full-size space-padded storage. The syscall gate requires
initialization and rejects its removal. Receipt AFTCR001 behavior is unchanged.

The parent campaign describes the prior 12-field, unwritten-endpoint revision.
Both are historical scoped evidence, not immutable qualification. Aggregate
admission/RAM/metadata/service, retention and full refinement remain open.
All 13 whole findings are OPEN. No R2/review/M18Q admission.

Reproduce with run_checks.py; run_mutations.py applies one local defensive
root-field omission and restores its exact baseline. No concurrent source writers.
