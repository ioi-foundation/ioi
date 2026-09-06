# R1 authenticated recovery hardening — 2026-09-04

Status: local repair evidence; **QUV-M17Q-002 remains OPEN**.

The member and handoff store formats now use schema 3. State and anchor
records use the existing `dcrypt-algorithms 4.0.1` HMAC-SHA-256 provider,
canonical domain-separated inputs, and the provider's fixed-width tag
verification. The custody key is supplied as the MAC key rather than encoded
into the data to hash. Schema 1/2 records fail closed; this change does not
migrate old ordinary bytes into new authority. Existing deployments require
an explicitly reviewed provisioning/migration decision before adopting it.

`command.json`, `result.json`, and `quv-core.log` bind the local development
run to base commit, dirty status, exact source hash, command, toolchain,
timestamps, outcome, and log hash. It passed **18 tests**, with the performance
benchmark explicitly ignored. Earlier local evidence describes earlier source
hashes and does not qualify this change.

## Coverage and limits

- A fixed HMAC result is checked against Python stdlib `hmac`/`hashlib` output.
  The public fixture and exact provider/lockfile hashes are retained in
  `provider-and-fixture.json`. This checks integration, not provider correctness
  in general or a cryptographic proof.
- Member state and a populated installed-handoff record are each tested with
  one flipped bit at every encoded byte, including nested fields and tags.
  Both the current-anchor and authenticated one-generation-pending recovery
  branches reject every changed record with typed corruption/codec errors,
  without modifying either file.
- Authentic records recover their exact member snapshot or successor activation
  and advance only to the expected authenticated anchor.
- Both anchor formats receive the same per-byte corruption check, requiring
  typed invalid-anchor/codec errors and no file mutation, followed by successful
  reopening of the restored authentic record.
- Existing rollback, unauthenticated pending-state, handoff, deadline, and
  candidate-context unit regressions pass.

The per-byte test flips one bit per byte; it is not exhaustive over all possible
corruptions or schedules. These are local restart/reopen tests, not process
kill/fsync campaigns. Separated non-rollback anchor custody, key secrecy, MAC
unforgeability, durable filesystem semantics, and conflict retention remain
explicit assumptions. Whole-store encoding/MAC cost remains proportional to
retained state; finding 006's bounded incremental-storage and timing work is
not closed by this repair. Production process recovery, formal refinement,
clean full R2 qualification, and fresh exact-candidate independent review
remain required. No QUV release or portable-finality claim is admitted.
