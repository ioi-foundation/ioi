----------------------- MODULE QuvHeadInterleaving -----------------------
EXTENDS QuvHeadPreparation
CONSTANT Candidates, MaxSlot, AuthorityMode
VARIABLE operations, firstSeen
allvars == <<histories, seen, grants, operations, firstSeen>>
Idle == [slot |-> 0, value |-> "A", parent |-> Genesis,
         captured |-> [c \in Correct |-> {}],
         capturedFirst |-> [c \in Correct |-> "unseen"], received |-> {}]

\* Owned/unowned component model with durable first-seen order. A process owns one operation at a time.
\* Capture is atomic durable processing followed by snapshot construction;
\* Observe is separate and may interleave with any other operation. Only a
\* complete correct-member observation set can Decide. This is a safety
\* premise, not an implementation test for the rooted timing assumption.
ConcurrentInit == Init /\ operations = [m \in Correct |-> Idle]
                       /\ firstSeen = [c \in Correct |-> [s \in Slots |-> "unseen"]]
Begin(m, v) ==
    /\ operations[m].slot = 0
    /\ Len(histories[m]) < MaxSlot
    /\ v \in Candidates
    /\ operations' = [operations EXCEPT ![m] =
         [Idle EXCEPT !.slot = Len(histories[m]) + 1,
                      !.value = v,
                      !.parent = Expected(m, Len(histories[m]) + 1)]]
    /\ grants' = [grants EXCEPT ![m] = None]
    /\ UNCHANGED <<histories, seen, firstSeen>>
Capture(m, c) ==
    /\ operations[m].slot # 0
    /\ operations[m].captured[c] = {}
    /\ Admissible(c, operations[m].slot, operations[m].parent)
    /\ seen' = [seen EXCEPT ![c][operations[m].slot] = @ \cup {operations[m].value}]
    /\ firstSeen' = [firstSeen EXCEPT ![c][operations[m].slot] =
         IF @ = "unseen" THEN operations[m].value ELSE @]
    /\ operations' = [operations EXCEPT
         ![m].captured[c] = seen[c][operations[m].slot] \cup {operations[m].value},
         ![m].capturedFirst[c] = IF firstSeen[c][operations[m].slot] = "unseen"
                               THEN operations[m].value ELSE firstSeen[c][operations[m].slot]]
    /\ UNCHANGED <<histories, grants>>
Observe(m, c) ==
    /\ operations[m].slot # 0
    /\ operations[m].captured[c] # {}
    /\ c \notin operations[m].received
    /\ operations' = [operations EXCEPT ![m].received = @ \cup {c}]
    /\ UNCHANGED <<histories, seen, grants, firstSeen>>
Decide(m) ==
    /\ operations[m].slot # 0
    /\ operations[m].received = Correct
    /\ grants' = [grants EXCEPT ![m] =
         IF \A c \in Correct :
              IF AuthorityMode = "owned"
              THEN operations[m].captured[c] = {operations[m].value}
              ELSE operations[m].capturedFirst[c] = operations[m].value
         THEN [slot |-> operations[m].slot, value |-> operations[m].value,
               parent |-> operations[m].parent]
         ELSE None]
    /\ operations' = [operations EXCEPT ![m] = Idle]
    /\ UNCHANGED <<histories, seen, firstSeen>>
ConcurrentAdvance(m) == Advance(m) /\ UNCHANGED <<operations, firstSeen>>
ConcurrentCrash(m) == Crash(m) /\ operations' = [operations EXCEPT ![m] = Idle]
                                  /\ UNCHANGED firstSeen
ConcurrentNext ==
    (\E m \in Correct, v \in Candidates : Begin(m, v))
    \/ (\E m,c \in Correct : Capture(m,c) \/ Observe(m,c))
    \/ (\E m \in Correct : Decide(m) \/ ConcurrentAdvance(m) \/ ConcurrentCrash(m))
ConcurrentSpec == ConcurrentInit /\ [][ConcurrentNext]_allvars
ConcurrentTypeOK == TypeOK /\ operations \in [Correct ->
    [slot : 0..MaxSlot, value : Values, parent : Values \cup {Genesis},
     captured : [Correct -> SUBSET Values],
     capturedFirst : [Correct -> Values \cup {"unseen"}], received : SUBSET Correct]]
    /\ firstSeen \in [Correct -> [Slots -> Values \cup {"unseen"}]]
    /\ AuthorityMode \in {"owned", "unowned"}
CapturedDurably == \A m,c \in Correct : operations[m].slot # 0 =>
    operations[m].captured[c] \subseteq seen[c][operations[m].slot]
ObservedWasCaptured == \A m,c \in Correct :
    c \in operations[m].received => operations[m].captured[c] # {}
GrantRetained == \A m,c \in Correct : grants[m].slot # 0 =>
    grants[m].value \in seen[c][grants[m].slot]
AcceptedGrantCompatible == \A a,b \in Correct :
    grants[a].slot # 0 =>
      /\ (grants[a].slot = grants[b].slot => grants[a].value = grants[b].value)
      /\ (grants[a].slot <= Len(histories[b]) =>
            grants[a].value = histories[b][grants[a].slot])
FirstSeenRetained == \A c \in Correct, s \in Slots :
    IF seen[c][s] = {} THEN firstSeen[c][s] = "unseen"
    ELSE firstSeen[c][s] \in seen[c][s]
CapturedFirstStable == \A m,c \in Correct :
    operations[m].captured[c] # {} =>
      /\ operations[m].capturedFirst[c] = firstSeen[c][operations[m].slot]
      /\ operations[m].capturedFirst[c] \in operations[m].captured[c]
NoCompletedConfiguredHistory == ~ (\A m \in Correct : Len(histories[m]) = MaxSlot)
=============================================================================
