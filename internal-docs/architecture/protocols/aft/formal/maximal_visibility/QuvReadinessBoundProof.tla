---------------------- MODULE QuvReadinessBoundProof ----------------------
EXTENDS QuvReadinessBound, TLAPS
ASSUME ScheduleBounds == Premises
Inv == TypeOK /\ ReadyForNext /\ EveryIntroducedChildAdmissible

\* All slot counts and natural-valued bounds; still a conditional schedule
\* lemma. QueueBound is an assumption, not derived from FIFO or active caps.
THEOREM BoundedPreparationPreservesReadiness == Spec => []Inv
<1>1. Init => Inv
  BY SMT, ScheduleBounds DEF Init, Inv, TypeOK, ReadyForNext,
    EveryIntroducedChildAdmissible, Premises
<1>2. Inv /\ [Next]_vars => Inv'
  BY SMT, ScheduleBounds DEF Inv, Next, Advance, vars, TypeOK, ReadyForNext,
    EveryIntroducedChildAdmissible, Premises
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
