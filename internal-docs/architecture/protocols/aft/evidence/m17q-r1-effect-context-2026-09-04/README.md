# R1 effect-context separation — 2026-09-04

Status: local validation passed; **findings 001 and 013 remain OPEN**.

The effect manifest previously supplied its external-resource predecessor
state hash as the QUV predecessor. The typed QUV slot instead defines that
field as a prior accepted candidate or independently rooted initial head.
Those are distinct protocol meanings and must not be interchangeable.

`EffectManifestV1` now explicitly commits
`online_authorization_predecessor` and `online_authorization_authority_mode`.
QUV requires both, with a nonzero predecessor; portable mode forbids both.
For portable manifests they remain absent from serialization, preserving the
prior portable shape. Existing QUV manifests without these fields are rejected,
not silently interpreted as new authority.

The live consumed binding and non-authorizing audit carry QUV predecessor and
authority mode. Both production entry points compare them to the admitted
manifest, and the final consequence boundary compares the consumed binding
again. Process fixtures build the candidate from the admitted QUV fields;
external-resource `predecessor_root` remains unchanged in meaning. Public
fixture initial QUV heads are test data, not evidence of production expected-
head provisioning or advancement.

## Validation and exact scope

`source-manifest.json` records the dirty-tree base and source/lockfile hashes.
The type suite passed seven tests, including missing/zero context refusal,
distinct QUV/resource predecessors, commitment changes for predecessor/mode,
and omission of online-only fields from portable serialization.

The consequence test requires typed refusal, zero resource calls/mutations,
and unchanged Authorized phase for either the external-resource predecessor
substituted into the QUV binding or the wrong QUV authority mode, followed by
successful execution for the exact live binding.

The complete Agentgres library suite passed 104 tests. QUV core passed 21
tests with its performance benchmark ignored, the workload manifest registry
passed two tests, and representative portable receipt verification passed one.
`initial-check-results.json` records the type/Agentgres results;
`check-results.json` records subsequent checks and phase-log hashes.
Feature-enabled compilation of the AFT process fixture also passed.
`hygiene-results.json` records passing source formatting, runner syntax,
claim-discipline, theorem-assumption, and whitespace checks.
A compilation check
is not a process execution campaign; a representative portable receipt check
is not the complete M16Q portability/profile suite.

## Remaining obligations

Separating and committing fields does not derive the expected predecessor
from durable domain head/next-slot state, prove multi-slot advancement, or
complete member admission. It does not by itself close forged/stale/substituted
receipt coverage, process retries, transition refinement, or timing qualification.
All those obligations remain open. Clean full R2 qualification and fresh
independent review must cover the exact final immutable candidate before M18Q
can admit a claim. These schema changes invalidate affected earlier QUV evidence
until rerun. `portable_final_receipt=false` remains fixed.
