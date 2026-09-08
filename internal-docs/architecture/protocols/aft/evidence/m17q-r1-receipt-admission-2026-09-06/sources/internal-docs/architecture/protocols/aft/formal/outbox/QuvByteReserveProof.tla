--------------------- MODULE QuvByteReserveProof ---------------------
EXTENDS QuvByteReserve, TLAPS
ASSUME Profile == /\ NormalBudget \in Nat /\ FrameBudget \in Nat
                  /\ FrameBudget > 0 /\ SharedBudget = FALSE
THEOREM ProfileBounds == Spec => []TypeOK
<1>1. Init => TypeOK
  BY Profile, SMT DEF Profile, Init, TypeOK
<1>2. TypeOK /\ [Next]_vars => TypeOK'
  BY Profile, SMT DEF Profile, TypeOK, Next, NormalTraffic, Push, Reply, CompletePush, CompleteReply, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec

\* This is logical byte capacity, not physical allocation or timed service.
THEOREM NormalCannotSpendQuvReserve == Spec => []EmptyLaneHasCapacity
<1>1. TypeOK => EmptyLaneHasCapacity
  BY Profile, SMT DEF Profile, TypeOK, EmptyLaneHasCapacity, Capacity
<1> QED BY ProfileBounds, <1>1, PTL
=============================================================================
