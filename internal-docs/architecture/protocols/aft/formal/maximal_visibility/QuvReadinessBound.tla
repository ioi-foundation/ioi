------------------------ MODULE QuvReadinessBound ------------------------
EXTENDS Naturals
CONSTANT WaitBound, QueueBound, ServiceBound
VARIABLE slot, fastDone, slowDone, introducedAt, refused
vars == <<slot, fastDone, slowDone, introducedAt, refused>>

\* Conditional schedule abstraction, not runtime transition refinement.
\* Every introduced singleton candidate reaches each correct preparation worker.
\* Its aggregate selection/queue delay is bounded by QueueBound; its OWN live
\* query and durable commit take at most ServiceBound. No preparation wait is
\* imposed after the worker's own prior head commit. Foreground waits WaitBound.
\* Crash/retry/fairness/storage costs must be included in those bounds before
\* applying this abstraction. The current runtime does not establish them.
Init == /\ slot = 0 /\ fastDone = 0 /\ slowDone = 0
        /\ introducedAt = 0 /\ refused = FALSE
Advance ==
    /\ ~refused
    /\ \E queue \in 0..QueueBound, fast \in 1..ServiceBound,
          slow \in 1..ServiceBound :
        LET start == fastDone + WaitBound
        IN /\ slot' = slot + 1 /\ introducedAt' = start
           /\ refused' = (slowDone > start)
           /\ fastDone' = start + fast
           /\ slowDone' = start + queue + slow
\* TLC exploration only; the inductive theorem does not use this constraint.
BoundedSlots == slot <= 3
Next == Advance
Spec == Init /\ [][Next]_vars
Premises == /\ WaitBound \in Nat /\ QueueBound \in Nat
            /\ ServiceBound \in Nat /\ ServiceBound > 0
            /\ WaitBound >= QueueBound + ServiceBound
TypeOK == /\ slot \in Nat /\ fastDone \in Nat /\ slowDone \in Nat
          /\ introducedAt \in Nat /\ refused \in BOOLEAN
ReadyForNext == slowDone <= fastDone + WaitBound
EveryIntroducedChildAdmissible == ~refused
=============================================================================
