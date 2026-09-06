# Reservation budget induction — local proof passed

TLAPS discharged all ten obligations for Spec implies always Inv, for any
MaxAttempts in Nat. Inv includes the type bounds, calls + legacy <= reserved,
and an unspent reservation whenever lookup readiness is true. The copied model
is byte-identical to the current ReconciliationBudget model; its hash is bound
in check.json. Reserve is atomic and non-rollback, Crash preserves durable
reservations, and Lookup requires process-local readiness that is consumed once.
These remain assumptions at the filesystem/runtime boundary. The proof does not
establish effect liveness, fairness, or full production transition refinement.

A separate finite abstract countermodel resets reservations on Crash. TLC reports
the expected ReservedBeforeLookup violation after Reserve, Lookup, Crash; raw
model, config, trace and checker result are retained. This is a mathematical
countermodel of weakened durability, not a production fault campaign.

The proof and abstract countermodel were integrated into the canonical formal
corpus and mandatory formal/M16Q runners after the process campaign completed.
The integrated consequence formal phase passed, including all ten TLAPS
obligations, positive finite models, and the expected named invariant violation.
The countermodel runner now retains the complete witness output. The process
source snapshot was checked before this later runner integration. Independent review, complete
refinement and clean full M16Q R2 qualification remain open.
