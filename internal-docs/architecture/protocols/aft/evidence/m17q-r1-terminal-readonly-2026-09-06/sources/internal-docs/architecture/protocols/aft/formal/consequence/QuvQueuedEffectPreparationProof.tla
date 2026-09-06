------------- MODULE QuvQueuedEffectPreparationProof -------------
EXTENDS QuvQueuedEffectPreparation, TLAPS
ASSUME Profile == /\ WriteDuringInspect = FALSE /\ HoldStoreWhileWaiting = FALSE
                  /\ SkipRevalidation = FALSE
Inv == TypeOK /\ QueueReleasesStore /\ PreparedAfterAdmission /\ PreparationRevalidated
       /\ WorkOwnsAdmission /\ PreparationCheck /\ GrantOwnsAdmission /\ CallWasAuthorized /\ PhaseHistory
THEOREM QueuedPreparationSafety == Spec => []Inv
<1>1. Init => Inv
  BY SMT DEF Init, Inv, TypeOK, QueueReleasesStore, PreparedAfterAdmission,
    PreparationRevalidated, WorkOwnsAdmission, PreparationCheck, GrantOwnsAdmission, CallWasAuthorized, PhaseHistory
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, QueueReleasesStore, PreparedAfterAdmission,
    PreparationRevalidated, WorkOwnsAdmission, PreparationCheck, GrantOwnsAdmission, CallWasAuthorized, PhaseHistory,
    Next, Inspect, Acquire, ChangeContext, Recheck, Prepare, OwnLive, Call, Abort, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
=================================================================
