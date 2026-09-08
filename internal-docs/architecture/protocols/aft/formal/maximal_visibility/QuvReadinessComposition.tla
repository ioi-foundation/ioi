---------------------- MODULE QuvReadinessComposition ----------------------
EXTENDS Naturals
CONSTANT WaitBound, PreparationWaitBound, FastService, SlowService, ActiveServiceBound, Slots
VARIABLE slot, fastDone, slowDone, introducedAt, refused
vars == <<slot, fastDone, slowDone, introducedAt, refused>>

\* Completion-schedule accounting for a PROPOSED own-head waiting rule.
\* Not an asynchronous transition refinement. Each service includes its own
\* live decision interval and local head commit; correct PUSHQUERY processing
\* is ideal and immediate whenever that member's predecessor is already ready.
\* One candidate per slot, two correct members, no faults/restarts/competition.
\* PreparationWaitBound=WaitBound delays both roles after their own commits.
\* PreparationWaitBound=0 exempts retained-candidate preparation; foreground
\* introduction still waits. This assumes immediate selection and no queue.
\* The first slot starts from a common ready bootstrap without a wait.
Init == /\ slot = 0 /\ fastDone = 0 /\ slowDone = 0
        /\ introducedAt = 0 /\ refused = FALSE
Max(a, b) == IF a >= b THEN a ELSE b
Advance ==
    /\ slot < Slots /\ ~refused
    /\ LET start == IF slot = 0 THEN 0 ELSE fastDone + WaitBound
           slowStart == Max(start, IF slot = 0 THEN 0 ELSE slowDone + PreparationWaitBound)
       IN /\ slot' = slot + 1
          /\ introducedAt' = start
          /\ refused' = (slowDone > start)
          \* Stop before inventing any accepted grant for an inadmissible query.
          /\ fastDone' = IF refused' THEN fastDone ELSE start + FastService
          /\ slowDone' = IF refused' THEN slowDone ELSE slowStart + SlowService
Next == Advance
Spec == Init /\ [][Next]_vars
Premises == /\ WaitBound > 0 /\ Slots > 0
            /\ PreparationWaitBound \in 0..WaitBound
            /\ 0 < FastService /\ FastService <= SlowService
            /\ SlowService < ActiveServiceBound
            /\ ActiveServiceBound <= WaitBound
TypeOK == /\ slot \in 0..Slots /\ fastDone \in Nat /\ slowDone \in Nat
          /\ introducedAt \in Nat /\ refused \in BOOLEAN
EveryIntroducedChildAdmissible == ~refused
NoCompletedSequence == slot < Slots
=============================================================================
