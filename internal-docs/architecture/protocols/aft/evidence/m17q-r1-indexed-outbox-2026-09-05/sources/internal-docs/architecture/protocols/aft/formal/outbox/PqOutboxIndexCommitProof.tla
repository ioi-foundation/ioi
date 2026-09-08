------------------- MODULE PqOutboxIndexCommitProof -------------------
EXTENDS PqOutboxIndexCommit, TLAPS
ASSUME Profile == /\ EarlyDelete = FALSE /\ EarlyPublish = FALSE
Inv == RecoverableIndex /\ PreparedPayloads

\* Abstract durable ordering only: filesystem atomicity/durability and the
\* production-to-model mapping are separate obligations.
THEOREM Recoverability == Spec => []Inv
<1>1. Init => Inv
  BY SMT DEF Init, Inv, RecoverableIndex, PreparedPayloads
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, RecoverableIndex, PreparedPayloads,
    Next, Stage, WriteOnePayload, WritePayloads, Publish, Cleanup, CrashRecover, TrimOrphan, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
