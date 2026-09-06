# QUV member/handoff persistence-error quarantine — local checks

Member and handoff stores now become unusable after persistence begins until
both state and anchor are durable and the memory snapshot has advanced. Any
reported persistence error leaves that live instance quarantined. Member
requests return StoreRequiresReopen before validation/signing; handoff install
retries refuse and activation predicates return false. Reopen performs the
existing authenticated state/anchor recovery before restoring service.

The flag is process-local, so disk schemas and MAC encodings are unchanged.
Capacity and input validation failures before persistence starts do not poison
the store. A signing error after a completed durable transition may still be
retried normally. Refusal is not transaction inclusion or effect liveness.

Tests exercise real state-staging and anchor-staging failures, removal of the
immediate fault, byte-preserved failed retries, zero signatures before recovery,
and successful reopen. When state was published before the anchor error, the
reopened member retains that candidate rather than overwriting it from stale
memory. Handoff tests require authenticated recovery before activation. The
initial command used a nonexistent consensus-aft crate feature and failed before
compilation; that failure is retained. The correct aft-feature QUV suite passed
22 tests with the separate qualification benchmark ignored. Final source and
validator checks are retained separately.

This repairs a storage prerequisite, not R1 accepted-head/next-slot enforcement.
The native candidate validator still checks only a nonzero predecessor; its
comment now states the missing durable history rule explicitly. Full process
failure schedules, filesystem refinement, non-rollback custody and M16Q R2
qualification remain open. No complete R1 finding is closed by these checks.
