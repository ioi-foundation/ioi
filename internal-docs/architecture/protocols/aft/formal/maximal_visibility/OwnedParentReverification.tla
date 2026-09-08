-------------------- MODULE OwnedParentReverification --------------------
EXTENDS Naturals, FiniteSets, Sequences

\* Scope: one correct witness, silent Byzantine peers, owned authority that
\* may introduce two independently valid values. Operations are sequential
\* atomic completed live queries, with durable write-before-snapshot. This
\* is a claim-boundary model, not the transport or expected-head protocol.
Values == {"A", "B"}
VARIABLES seen, results
vars == <<seen, results>>
Init == /\ seen = {}
        /\ results = <<>>
Introduce(v) == /\ v \in Values
                /\ seen' = seen \cup {v}
                /\ UNCHANGED results
Query(v) == /\ v \in Values
            /\ Len(results) < 2
            /\ seen' = seen \cup {v}
            /\ results' = Append(results,
                 [candidate |-> v,
                  accepted |-> (seen \cup {v} = {v})])
Next == (\E v \in Values : Introduce(v) \/ Query(v))
Spec == Init /\ [][Next]_vars
TypeOK == /\ seen \subseteq Values
          /\ results \in Seq([candidate : Values, accepted : BOOLEAN])
          /\ Len(results) <= 2
AcceptedValues == {results[i].candidate :
                    i \in {j \in 1..Len(results) : results[j].accepted}}
AcceptedNonConflict == Cardinality(AcceptedValues) <= 1
SingletonProgress == Cardinality(seen) = 1 =>
                       \A i \in 1..Len(results) : results[i].accepted
\* Deliberately stronger than Q-T4. The negative configuration must refute
\* it, without refuting either admitted invariant above.
PriorAcceptancePersists ==
    Len(results) = 2 =>
      ((results[1].accepted /\
        results[1].candidate = results[2].candidate) => results[2].accepted)
=============================================================================
