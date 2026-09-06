---------------------- MODULE QuvManifestLocator ----------------------
EXTENDS FiniteSets
CONSTANTS Records, Effects, Owner, Absent, Ambiguous, DropDuplicate, TrustAfterCrash
VARIABLES committed, scanned, index, ready
vars == <<committed, scanned, index, ready>>
EmptyIndex == [e \in Effects |-> Absent]
Bump(i, r) == [i EXCEPT ![Owner[r]] =
    IF @ = Absent \/ DropDuplicate THEN r ELSE IF @ = r THEN r ELSE Ambiguous]
Init == /\ committed = {} /\ scanned = {} /\ index = EmptyIndex /\ ready = TRUE
Admit == /\ ready
         /\ \E r \in Records :
               /\ committed' = committed \cup {r}
               /\ scanned' = scanned \cup {r}
               /\ index' = Bump(index, r)
         /\ UNCHANGED ready
Crash == /\ scanned' = {} /\ index' = EmptyIndex
         /\ ready' = TrustAfterCrash /\ UNCHANGED committed
RecoverRecord == /\ ~ready
                 /\ \E r \in committed \ scanned :
                       /\ scanned' = scanned \cup {r}
                       /\ index' = Bump(index, r)
                 /\ UNCHANGED <<committed, ready>>
FinishRecovery == /\ ~ready /\ scanned = committed /\ ready' = TRUE
                  /\ UNCHANGED <<committed, scanned, index>>
Next == Admit \/ Crash \/ RecoverRecord \/ FinishRecovery
Spec == Init /\ [][Next]_vars
TypeOK == /\ committed \subseteq Records /\ scanned \subseteq committed
          /\ index \in [Effects -> Records \cup {Absent, Ambiguous}]
          /\ ready \in BOOLEAN
CellCorrect(s, i, e) ==
    /\ (i[e] = Absent) <=> (\A r \in s : Owner[r] # e)
    /\ i[e] \in Records =>
        /\ i[e] \in s /\ Owner[i[e]] = e
        /\ \A r \in s : Owner[r] = e => r = i[e]
    /\ (i[e] = Ambiguous) <=> (\E r, t \in s : r # t /\ Owner[r] = e /\ Owner[t] = e)
IndexCorrect == \A e \in Effects : CellCorrect(scanned, index, e)
ReadyComplete == ready => scanned = committed
FixtureOwner == [r \in Records |-> IF r = "r3" THEN "e2" ELSE "e1"]
=============================================================================
