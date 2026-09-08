-------------------- MODULE QuvManifestLocatorProof --------------------
EXTENDS QuvManifestLocator, TLAPS
ASSUME Profile == /\ Owner \in [Records -> Effects]
                  /\ Absent \notin Records /\ Ambiguous \notin Records
                  /\ Absent # Ambiguous
                  /\ DropDuplicate = FALSE /\ TrustAfterCrash = FALSE
Inv == TypeOK /\ IndexCorrect /\ ReadyComplete
\* Conditional derived-index fold: source records have already been verified;
\* reads cannot observe a half-committed cache update or incomplete recovery.
\* A locator grants no authority: selected disk/root/identity checks remain required.
THEOREM LocatorSafety == Spec => []Inv
<1>1. Init => Inv
  BY Profile, SMT DEF Profile, Init, Inv, TypeOK, IndexCorrect, CellCorrect,
    ReadyComplete, EmptyIndex
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, IndexCorrect, CellCorrect,
    ReadyComplete, Next, Admit, Crash, RecoverRecord, FinishRecovery,
    EmptyIndex, Bump, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
