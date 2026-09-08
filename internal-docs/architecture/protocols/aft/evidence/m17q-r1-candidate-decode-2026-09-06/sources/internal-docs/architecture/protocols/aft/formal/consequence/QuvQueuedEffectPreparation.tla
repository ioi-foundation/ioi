---------------- MODULE QuvQueuedEffectPreparation ----------------
EXTENDS Naturals
CONSTANTS WriteDuringInspect, HoldStoreWhileWaiting, SkipRevalidation, SkipFinalRevalidation
VARIABLES phase, storeLocked, lease, acquired, valid, prepared, preparedCorrect,
          grant, called, callCorrect
vars == <<phase, storeLocked, lease, acquired, valid, prepared, preparedCorrect,
          grant, called, callCorrect>>
Init == /\ phase = "Inspect" /\ storeLocked = TRUE /\ lease = FALSE
        /\ acquired = FALSE /\ valid = TRUE /\ prepared = FALSE
        /\ preparedCorrect = FALSE /\ grant = FALSE /\ called = FALSE /\ callCorrect = FALSE
Inspect == /\ phase = "Inspect" /\ phase' = "Waiting"
           /\ storeLocked' = HoldStoreWhileWaiting
           /\ prepared' = WriteDuringInspect /\ preparedCorrect' = valid
           /\ UNCHANGED <<lease, acquired, valid, grant, called, callCorrect>>
Acquire == /\ phase = "Waiting" /\ phase' = "Recheck"
           /\ lease' = TRUE /\ acquired' = TRUE /\ storeLocked' = TRUE
           /\ UNCHANGED <<valid, prepared, preparedCorrect, grant, called, callCorrect>>
ChangeContext == /\ phase \in {"Waiting", "Query", "Reopen"} /\ valid' = FALSE
                 /\ UNCHANGED <<phase, storeLocked, lease, acquired, prepared,
                                 preparedCorrect, grant, called, callCorrect>>
Recheck == /\ phase = "Recheck" /\ (valid \/ SkipRevalidation)
           /\ phase' = "Prepare" /\ preparedCorrect' = valid
           /\ UNCHANGED <<storeLocked, lease, acquired, valid, prepared, grant, called, callCorrect>>
Prepare == /\ phase = "Prepare" /\ phase' = "Query"
           /\ prepared' = TRUE /\ storeLocked' = FALSE
           /\ UNCHANGED <<lease, acquired, valid, preparedCorrect, grant, called, callCorrect>>
\* Conditional abstraction of this executor's exact-context successful live QUV.
OwnLive == /\ phase = "Query" /\ valid /\ phase' = "Reopen"
           /\ grant' = TRUE /\ storeLocked' = FALSE
           /\ UNCHANGED <<lease, acquired, valid, prepared, preparedCorrect, called, callCorrect>>
\* Receipt access can queue after QUV. Holding the receipt lock alone does
\* not freeze committed context while the executor waits for finality.
OpenReceipt == /\ phase = "Reopen" /\ ~storeLocked /\ storeLocked' = TRUE
               /\ UNCHANGED <<phase, lease, acquired, valid, prepared,
                               preparedCorrect, grant, called, callCorrect>>
LockFinality == /\ phase = "Reopen" /\ storeLocked /\ phase' = "Claim"
                /\ UNCHANGED <<storeLocked, lease, acquired, valid, prepared,
                                preparedCorrect, grant, called, callCorrect>>
\* Models the synchronous final revalidation/claim/call critical section only.
Call == /\ phase = "Claim" /\ (valid \/ SkipFinalRevalidation) /\ grant /\ phase' = "Done"
        /\ called' = TRUE /\ callCorrect' = (valid /\ grant /\ lease)
        /\ grant' = FALSE /\ lease' = FALSE /\ storeLocked' = FALSE
        /\ UNCHANGED <<acquired, valid, prepared, preparedCorrect>>
Abort == /\ phase \in {"Waiting", "Recheck", "Prepare", "Query", "Reopen", "Claim"}
         /\ phase' = "Done" /\ storeLocked' = FALSE /\ lease' = FALSE /\ grant' = FALSE
         /\ UNCHANGED <<acquired, valid, prepared, preparedCorrect, called, callCorrect>>
Next == Inspect \/ Acquire \/ ChangeContext \/ Recheck \/ Prepare \/ OwnLive \/ OpenReceipt \/ LockFinality \/ Call \/ Abort
Spec == Init /\ [][Next]_vars
TypeOK == /\ phase \in {"Inspect", "Waiting", "Recheck", "Prepare", "Query", "Reopen", "Claim", "Done"}
          /\ storeLocked \in BOOLEAN /\ lease \in BOOLEAN /\ acquired \in BOOLEAN
          /\ valid \in BOOLEAN /\ prepared \in BOOLEAN /\ preparedCorrect \in BOOLEAN
          /\ grant \in BOOLEAN /\ called \in BOOLEAN /\ callCorrect \in BOOLEAN
QueueReleasesStore == phase = "Waiting" => ~storeLocked
PreparedAfterAdmission == prepared => acquired
PreparationRevalidated == prepared => preparedCorrect
WorkOwnsAdmission == phase \in {"Recheck", "Prepare", "Query", "Reopen", "Claim"} => lease
PreparationCheck == phase = "Prepare" => preparedCorrect
GrantOwnsAdmission == grant => lease
CallWasAuthorized == called => callCorrect
PhaseHistory == /\ (prepared => phase \in {"Query", "Reopen", "Claim", "Done"})
                /\ (grant => phase \in {"Reopen", "Claim"})
                /\ (lease => acquired)
=================================================================
