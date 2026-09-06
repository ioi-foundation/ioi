----------------------- MODULE QuvHeadPreparation -----------------------
EXTENDS Naturals, Sequences, FiniteSets
CONSTANT Correct
Values == {"A", "B"}
Slots == 1..2
Genesis == "rooted genesis"
None == [slot |-> 0, value |-> "A", parent |-> Genesis]
VARIABLES histories, seen, grants
vars == <<histories, seen, grants>>

\* Finite protocol-design model, NOT a production refinement. Genesis and
\* initial slot 1 are independently rooted. Correct is nonempty; Byzantine
\* peers are silent. Query abstracts a COMPLETED local live operation with
\* every correct member's atomic durable write-before-snapshot. It does not
\* assume that simultaneous requests can obtain a runtime lane or meet time.
Init == /\ histories = [m \in Correct |-> <<>>]
        /\ seen = [m \in Correct |-> [s \in Slots |-> {}]]
        /\ grants = [m \in Correct |-> None]
Expected(m, s) == IF s = 1 THEN Genesis ELSE histories[m][s - 1]
Admissible(m, s, predecessor) ==
    /\ s \in Slots
    /\ s <= Len(histories[m]) + 1
    /\ predecessor = Expected(m, s)

Query(m, s, v, predecessor) ==
    /\ m \in Correct
    /\ s \in Slots
    /\ v \in Values
    /\ \A c \in Correct : Admissible(c, s, predecessor)
    /\ seen' = [c \in Correct |-> [seen[c] EXCEPT ![s] = @ \cup {v}]]
    /\ grants' = [grants EXCEPT ![m] =
         IF \A c \in Correct : seen[c][s] \cup {v} = {v}
         THEN [slot |-> s, value |-> v, parent |-> predecessor]
         ELSE None]
    /\ UNCHANGED histories

Advance(m) ==
    /\ m \in Correct
    /\ grants[m] # None
    /\ grants[m].slot = Len(histories[m]) + 1
    /\ grants[m].parent = Expected(m, grants[m].slot)
    /\ histories' = [histories EXCEPT ![m] = Append(@, grants[m].value)]
    /\ grants' = [grants EXCEPT ![m] = None]
    /\ UNCHANGED seen

\* Durable histories and conflict knowledge survive; local grant does not.
Crash(m) == /\ m \in Correct
            /\ grants' = [grants EXCEPT ![m] = None]
            /\ UNCHANGED <<histories, seen>>
Next == (\E m \in Correct, s \in Slots, v \in Values,
            p \in Values \cup {Genesis} : Query(m, s, v, p))
        \/ (\E m \in Correct : Advance(m) \/ Crash(m))
Spec == Init /\ [][Next]_vars
TypeOK == /\ histories \in [Correct -> Seq(Values)]
          /\ \A m \in Correct : Len(histories[m]) <= 2
          /\ seen \in [Correct -> [Slots -> SUBSET Values]]
          /\ grants \in [Correct ->
               [slot : 0..2, value : Values, parent : Values \cup {Genesis}]]
PrefixCompatible == \A a,b \in Correct :
    \A s \in 1..Len(histories[a]) :
      s <= Len(histories[b]) => histories[a][s] = histories[b][s]
RetainedKnowledge == \A a,b \in Correct :
    \A s \in 1..Len(histories[a]) : histories[a][s] \in seen[b][s]
NoFutureInsertion == \A m \in Correct, s \in Slots :
    seen[m][s] # {} => s <= Len(histories[m]) + 1
HistoricalQueriesAdmissible == \A a \in Correct :
    \A s \in 1..Len(histories[a]) :
      \A b \in Correct : s <= Len(histories[b]) + 1 =>
        Admissible(b, s, Expected(a, s))
\* A reachability probe, NOT a liveness theorem: its required violation
\* demonstrates a schedule where every correct member advances two slots.
NoCompletedTwoSlotHistory == ~ (\A m \in Correct : Len(histories[m]) = 2)
=============================================================================
