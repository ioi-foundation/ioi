-------------------------- MODULE QuvHeadProgress --------------------------
EXTENDS QuvHeadInterleaving
CONSTANT PreserveGrant

\* Conditional finite progress check, not a rooted latency theorem. These
\* executions have singleton inputs, no crashes, and per-action weak fairness.
\* An accepted local grant must remain available until durable advancement;
\* starting another query must not repeatedly discard it.
BeginPrepared(m, v) == /\ (~PreserveGrant \/ grants[m] = None)
                       /\ Begin(m, v)
ProgressNext ==
    (\E m \in Correct, v \in Candidates : BeginPrepared(m, v))
    \/ (\E m,c \in Correct : Capture(m,c) \/ Observe(m,c))
    \/ (\E m \in Correct : Decide(m) \/ ConcurrentAdvance(m))
FairPreparation ==
    /\ \A m \in Correct, v \in Candidates : WF_allvars(BeginPrepared(m,v))
    /\ \A m,c \in Correct : WF_allvars(Capture(m,c)) /\ WF_allvars(Observe(m,c))
    /\ \A m \in Correct : WF_allvars(Decide(m)) /\ WF_allvars(ConcurrentAdvance(m))
ProgressSpec == ConcurrentInit /\ [][ProgressNext]_allvars /\ FairPreparation
ProgressPremises == /\ Cardinality(Candidates) = 1
                    /\ Correct # {}
                    /\ PreserveGrant \in BOOLEAN
AllHistoriesAdvance == <> (\A m \in Correct : Len(histories[m]) = MaxSlot)
=============================================================================
