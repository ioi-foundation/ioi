------------- MODULE QuvContinuationAdmissionProof -------------
EXTENDS QuvContinuationAdmission, TLAPS
ASSUME Profile == /\ ReleaseOnDelivery = FALSE /\ ReleaseOnCancel = FALSE
Inv == TypeOK /\ Ownership /\ Released
THEOREM ContinuationOwnership == Spec => []Inv
<1>1. Init => Inv
  BY SMT DEF Init, Inv, TypeOK, Ownership, Released
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, Ownership, Released, Next,
    Deliver, Start, CancelDelivery, CancelObservation, Finish, AdmitNext, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
=================================================================
