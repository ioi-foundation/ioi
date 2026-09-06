---------------------- MODULE QuvAdmissionOrder ----------------------
EXTENDS Naturals, Sequences, FiniteSets
CONSTANT Domains, FIFO
Worker == "worker"
Idle == "idle"
VARIABLE queue, active, served, bypasses
vars == <<queue, active, served, bypasses>>
Items == Domains \cup {Worker}
Present(q) == {q[i] : i \in 1..Len(q)}
Remove(q, i) == SubSeq(q, 1, i - 1) \o SubSeq(q, i + 1, Len(q))
\* One waiting foreground per enrolled domain; a domain can also be active.
\* Start exactly when the one preparation worker has enqueued. Any permitted
\* foreground subset/order may already be ahead of it, plus one active caller.
InitialForeground == {q \in UNION { [1..n -> Domains] : n \in 0..Cardinality(Domains) } :
                       Cardinality(Present(q)) = Len(q)}
Init == /\ queue \in {q \o <<Worker>> : q \in InitialForeground}
        /\ active \in Domains \cup {Idle}
        /\ served = FALSE /\ bypasses = 0
Arrive == /\ ~served
          /\ \E d \in Domains \ Present(queue) :
               /\ queue' = Append(queue, d)
               /\ UNCHANGED <<active, served, bypasses>>
Cancel == /\ ~served
          /\ \E i \in 1..Len(queue) :
               /\ queue[i] \in Domains
               /\ queue' = Remove(queue, i)
               /\ UNCHANGED <<active, served, bypasses>>
Release == /\ active # Idle /\ active' = Idle
           /\ UNCHANGED <<queue, served, bypasses>>
Start == /\ ~served /\ active = Idle /\ Len(queue) > 0
         /\ \E i \in (IF FIFO THEN {1} ELSE 1..Len(queue)) :
             /\ active' = queue[i] /\ queue' = Remove(queue, i)
             /\ served' = (queue[i] = Worker)
             /\ bypasses' = IF queue[i] = Worker THEN bypasses
                              ELSE IF bypasses < Cardinality(Domains) + 1
                                   THEN bypasses + 1 ELSE bypasses
Done == /\ served /\ active = Idle /\ UNCHANGED vars
Next == Arrive \/ Cancel \/ Release \/ Start \/ Done
Spec == Init /\ [][Next]_vars /\ WF_vars(Release) /\ WF_vars(Start)
TypeOK == /\ queue \in UNION {[1..n -> Items] : n \in 0..(Cardinality(Domains)+1)}
          /\ Cardinality(Present(queue)) = Len(queue)
          /\ active \in Items \cup {Idle}
          /\ served \in BOOLEAN
          /\ (Worker \in Present(queue)) = ~served
          /\ bypasses \in 0..(Cardinality(Domains)+1)
BoundedPredecessors == bypasses <= Cardinality(Domains)
WorkerEventuallyAdmitted == <>served
=============================================================================
