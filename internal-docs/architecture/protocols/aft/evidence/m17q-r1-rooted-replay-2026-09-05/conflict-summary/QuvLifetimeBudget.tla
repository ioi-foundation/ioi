----------------------- MODULE QuvLifetimeBudget -----------------------
EXTENDS Integers, FiniteSets
CONSTANTS Horizon, Attempts, RecordBudget, ReuseEvent
VARIABLES seen, charged
vars == <<seen, charged>>

\* One coordinate for each retained member transition in a Fixed slot:
\* 1/2 = distinct candidate insertions; 3..A+2 = durable reservations;
\* A+3 = accepted-head transition. This is a resource abstraction, not a
\* filesystem, online authorization, or complete runtime-refinement model.
Universe == (1..Horizon) \X (1..(Attempts+3))
Init == /\ seen = {} /\ charged = 0
Record == \E event \in (IF ReuseEvent THEN Universe ELSE Universe \ seen),
             cost \in 1..RecordBudget :
            /\ seen' = seen \cup {event}
            /\ charged' = charged + cost
Next == Record
Spec == Init /\ [][Next]_vars
TypeOK == /\ seen \subseteq Universe /\ IsFiniteSet(seen)
          /\ charged \in Nat
ChargedRecordBytes == charged <= Cardinality(seen) * RecordBudget
LifetimeBytes == charged <= Horizon * (Attempts+3) * RecordBudget
=============================================================================
