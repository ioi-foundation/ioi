---------------------- MODULE QuvHeadPreparationTiming ----------------------
EXTENDS Naturals, FiniteSets
CONSTANT Correct, Initiator, PreparationBound, DecisionBound, WaitForPreparation
VARIABLE now, ownGrant, ready, started, startTime, replied, refused, finished
vars == <<now, ownGrant, ready, started, startTime, replied, refused, finished>>

\* The initiator has just completed its own accepted parent query. All correct
\* members therefore retain that parent candidate (the prior Q-A3 premise).
\* Others still require their OWN query and durable commit. This model ASSUMES
\* bounded preparation service; it does not implement or prove a fair scheduler.
Init == /\ now = 0
        /\ ownGrant = {Initiator}
        /\ ready = {Initiator}
        /\ started = FALSE /\ startTime = 0
        /\ replied = {} /\ refused = {} /\ finished = FALSE
OwnParentQuery(m) ==
    /\ m \in Correct \ ownGrant
    /\ now <= PreparationBound
    /\ ownGrant' = ownGrant \cup {m}
    /\ UNCHANGED <<now, ready, started, startTime, replied, refused, finished>>
CommitParent(m) ==
    /\ m \in ownGrant \ ready
    /\ now <= PreparationBound
    /\ ready' = ready \cup {m}
    /\ UNCHANGED <<now, ownGrant, started, startTime, replied, refused, finished>>
BeginChild ==
    /\ ~started
    /\ (~WaitForPreparation \/ now >= PreparationBound)
    /\ started' = TRUE /\ startTime' = now
    /\ UNCHANGED <<now, ownGrant, ready, replied, refused, finished>>
DeliverChild(m) ==
    /\ started /\ ~finished
    /\ m \in Correct \ (replied \cup refused)
    /\ now <= startTime + DecisionBound
    /\ replied' = IF m \in ready THEN replied \cup {m} ELSE replied
    /\ refused' = IF m \in ready THEN refused ELSE refused \cup {m}
    /\ UNCHANGED <<now, ownGrant, ready, started, startTime, finished>>
FinishChild ==
    /\ started /\ ~finished /\ now >= startTime + DecisionBound
    /\ finished' = TRUE
    /\ UNCHANGED <<now, ownGrant, ready, started, startTime, replied, refused>>
Tick ==
    /\ now < PreparationBound + DecisionBound + 1
    \* Bounded local service is an explicit premise: time may reach the bound
    \* only after all correct members independently commit the parent.
    /\ (now + 1 >= PreparationBound => ready = Correct)
    \* Every correct member receives the child inside its decision interval.
    /\ (started /\ now + 1 >= startTime + DecisionBound => replied \cup refused = Correct)
    /\ now' = now + 1
    /\ UNCHANGED <<ownGrant, ready, started, startTime, replied, refused, finished>>
Next == (\E m \in Correct : OwnParentQuery(m) \/ CommitParent(m) \/ DeliverChild(m))
        \/ BeginChild \/ FinishChild \/ Tick
Spec == Init /\ [][Next]_vars
Premises == /\ Initiator \in Correct /\ PreparationBound > 0 /\ DecisionBound > 0
            /\ WaitForPreparation \in BOOLEAN
TypeOK == /\ now \in 0..(PreparationBound + DecisionBound + 1)
          /\ ownGrant \subseteq Correct /\ ready \subseteq ownGrant
          /\ replied \subseteq Correct /\ refused \subseteq Correct
          /\ replied \cap refused = {}
          /\ started \in BOOLEAN /\ finished \in BOOLEAN
CompleteCorrectProcessing == finished => replied = Correct
NoCompletedChild == ~finished
=============================================================================
