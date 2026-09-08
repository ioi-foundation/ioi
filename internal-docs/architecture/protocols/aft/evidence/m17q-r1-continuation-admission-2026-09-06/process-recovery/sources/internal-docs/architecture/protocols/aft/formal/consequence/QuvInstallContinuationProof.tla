----------------- MODULE QuvInstallContinuationProof -----------------
EXTENDS QuvInstallContinuation, TLAPS
ASSUME Profile == /\ Deadline \in Nat /\ MaxTime \in Nat /\ RestartLimit \in Nat
                  /\ SkipFinalFence = FALSE /\ RehydrateGrant = FALSE
Inv == TypeOK /\ LiveAtClaim /\ ProcessLocal /\ InstalledDurably /\ DurablePhase
\* Conditional implementation-boundary kernel, not full protocol refinement.
THEOREM InstallationFence == Spec => []Inv
<1>1. Init => Inv
  BY Profile, SMT DEF Profile, Init, Inv, TypeOK, LiveAtClaim, ProcessLocal, InstalledDurably, DurablePhase
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, LiveAtClaim, ProcessLocal, InstalledDurably, DurablePhase,
    Next, Acquire, Tick, Claim, Sync, Publish, Crash, Recover, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
