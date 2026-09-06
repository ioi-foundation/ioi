-------------------- MODULE PqReservedIndexProof --------------------
EXTENDS PqReservedIndex, TLAPS
ASSUME Profile == /\ EarlyExchange = FALSE /\ TruncateInactive = FALSE
Inv == TypeOK /\ ActiveRecoverable /\ CapacityRetained /\ SyncedInactive /\ StableDirectory
\* Conditional primitive refinement: valid means a complete fsynced image;
\* Exchange is atomic and never deletes an inode. This does not prove device
\* persistence, filesystem journal capacity, payload reservation, or latency.
THEOREM ReservedIndexSafety == Spec => []Inv
<1>1. Init => Inv
  BY SMT DEF Init, Inv, TypeOK, ActiveRecoverable, CapacityRetained,
    SyncedInactive, StableDirectory, Buffers
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, ActiveRecoverable,
    CapacityRetained, SyncedInactive, StableDirectory, Next, BeginWrite, SyncImage,
    Exchange, SyncDirectory, CrashRecover, vars, Buffers, Other
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
