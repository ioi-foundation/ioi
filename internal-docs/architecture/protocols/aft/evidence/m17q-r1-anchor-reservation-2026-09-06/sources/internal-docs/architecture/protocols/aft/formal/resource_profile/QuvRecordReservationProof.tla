------------------ MODULE QuvRecordReservationProof ------------------
EXTENDS QuvRecordReservation, TLAPS
ASSUME Profile == /\ TruncateLive = FALSE /\ ForgetAcknowledged = FALSE
Inv == Partition /\ CapacityRetained /\ AcknowledgedRetained
\* Conditional storage primitive: startup fully reserves Slots, publication
\* retains the record inode, and anchor/reply follows durable publication.
\* Restart authenticates retained bytes before resetting uncommitted files;
\* transient startup reallocation occurs before admission, outside this model.
THEOREM ReservationSafety == Spec => []Inv
<1>1. Init => Inv
  BY SMT DEF Init, Inv, Partition, CapacityRetained, AcknowledgedRetained
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, Partition, CapacityRetained,
    AcknowledgedRetained, Next, Write, Publish, AnchorAndReply,
    AuthenticatedRestart, Forget, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
