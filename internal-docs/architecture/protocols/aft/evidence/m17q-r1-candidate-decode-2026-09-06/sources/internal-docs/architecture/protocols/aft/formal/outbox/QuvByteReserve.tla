------------------------ MODULE QuvByteReserve ------------------------
EXTENDS Integers
CONSTANTS NormalBudget, FrameBudget, SharedBudget
VARIABLES normal, push, reply
vars == <<normal, push, reply>>
Init == /\ normal = 0 /\ push = 0 /\ reply = 0
Capacity(cost) == IF SharedBudget THEN normal + push + reply + cost <= NormalBudget
                  ELSE push + reply + cost <= 2 * FrameBudget
NormalTraffic == /\ normal' \in 0..NormalBudget /\ UNCHANGED <<push, reply>>
Push == /\ push = 0 /\ \E cost \in 1..FrameBudget : /\ Capacity(cost) /\ push' = cost
        /\ UNCHANGED <<normal, reply>>
Reply == /\ reply = 0 /\ \E cost \in 1..FrameBudget : /\ Capacity(cost) /\ reply' = cost
         /\ UNCHANGED <<normal, push>>
CompletePush == /\ push' = 0 /\ UNCHANGED <<normal, reply>>
CompleteReply == /\ reply' = 0 /\ UNCHANGED <<normal, push>>
Next == NormalTraffic \/ Push \/ Reply \/ CompletePush \/ CompleteReply
Spec == Init /\ [][Next]_vars
TypeOK == /\ normal \in 0..NormalBudget /\ push \in 0..FrameBudget /\ reply \in 0..FrameBudget
EmptyLaneHasCapacity == (push = 0 \/ reply = 0) => Capacity(FrameBudget)
=============================================================================
