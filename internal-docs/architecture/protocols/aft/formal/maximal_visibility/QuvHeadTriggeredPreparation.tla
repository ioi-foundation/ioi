-------------------- MODULE QuvHeadTriggeredPreparation --------------------
EXTENDS QuvHeadInterleaving
CONSTANT Initiator, AutoPrepare

\* Only the initiator supplies new singleton candidates. Other correct members
\* may schedule their own live query after durable candidate reception. Receipt
\* is a scheduling trigger, never an accepted-head authorization. Every Advance
\* still requires that member's own grant from a complete correct observation.
TriggeredBegin(m, v) ==
    /\ grants[m] = None
    /\ Len(histories[m]) < MaxSlot
    /\ (m = Initiator \/
         (AutoPrepare /\ v \in seen[m][Len(histories[m]) + 1]))
    /\ Begin(m, v)
TriggeredNext ==
    (\E m \in Correct, v \in Candidates : TriggeredBegin(m,v))
    \/ (\E m,c \in Correct : Capture(m,c) \/ Observe(m,c))
    \/ (\E m \in Correct : Decide(m) \/ ConcurrentAdvance(m))
TriggeredFairness ==
    /\ \A m \in Correct, v \in Candidates : WF_allvars(TriggeredBegin(m,v))
    /\ \A m,c \in Correct : WF_allvars(Capture(m,c)) /\ WF_allvars(Observe(m,c))
    /\ \A m \in Correct : WF_allvars(Decide(m)) /\ WF_allvars(ConcurrentAdvance(m))
TriggeredSpec == ConcurrentInit /\ [][TriggeredNext]_allvars /\ TriggeredFairness
TriggeredPremises == /\ Initiator \in Correct
                     /\ Cardinality(Candidates) = 1
                     /\ AutoPrepare \in BOOLEAN
AllTriggeredHistoriesAdvance == <> (\A m \in Correct : Len(histories[m]) = MaxSlot)
=============================================================================
