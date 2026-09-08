----------------- MODULE QuvAnchoredReservationProof -----------------
EXTENDS QuvAnchoredReservation, TLAPS
ASSUME Profile == /\ Limit \in Nat /\ EarlyExchange = FALSE /\ EarlyReply = FALSE
Inv == TypeOK /\ AnchorBacked /\ ReplyBacked /\ Shape
\* Conditional composition of durable record, atomic anchor exchange and
\* fsync primitives. RecoverValidateSync requires full authenticated semantic
\* replay. Device guarantees and full protocol refinement remain separate.
THEOREM OrderedCustody == Spec => []Inv
<1>1. Init => Inv
  BY Profile, SMT DEF Profile, Init, Inv, TypeOK, AnchorBacked, ReplyBacked, Shape
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, AnchorBacked, ReplyBacked, Shape,
    Next, PrepareRecord, SyncRecord, WriteAnchor, SyncAnchor, Exchange,
    SyncDirectory, Reply, Crash, RecoverValidateSync, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
