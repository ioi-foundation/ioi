---------------- MODULE QuvPayloadArenaCapacityProof ----------------
EXTENDS Integers, TLAPS
\* Numerical capacity kernel for arbitrary per-recipient occupancy counts.
\* The set/slot mapping is separately exercised by QuvPayloadArena and Rust.
THEOREM CapacityForBothReplacements ==
  \A retained, staged, need \in Int :
    retained \in 0..2 /\ need \in 0..2 /\ staged \in 0..need
    => 4 - retained - staged >= need - staged
BY SMT
THEOREM UnfinishedStageHasSlot ==
  \A retained, staged, need \in Int :
    retained \in 0..2 /\ need \in 0..2 /\ staged \in 0..need /\ staged < need
    => 4 - retained - staged > 0
BY SMT
THEOREM FrameFitsAllocatedSlot == 72 + 64 + 16384 <= 20480
BY SMT
=============================================================================
