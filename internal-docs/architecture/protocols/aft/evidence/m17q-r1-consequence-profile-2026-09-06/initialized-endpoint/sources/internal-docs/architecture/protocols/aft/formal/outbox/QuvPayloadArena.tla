---------------------- MODULE QuvPayloadArena ----------------------
EXTENDS Integers, FiniteSets
CONSTANTS Slots, OverwriteRetained
VARIABLES retained, staged, need
vars == <<retained, staged, need>>
Buffers == 1..Slots
Init == /\ retained \in SUBSET Buffers /\ Cardinality(retained) <= 2
        /\ staged = {} /\ need \in 0..2
Stage == /\ Cardinality(staged) < need
         /\ \E slot \in (IF OverwriteRetained THEN Buffers \ staged
                         ELSE Buffers \ (retained \cup staged)) :
               staged' = staged \cup {slot}
         /\ UNCHANGED <<retained, need>>
Crash == /\ staged' = {} /\ UNCHANGED <<retained, need>>
Next == Stage \/ Crash
Spec == Init /\ [][Next]_vars
TypeOK == /\ retained \subseteq Buffers /\ staged \subseteq Buffers
          /\ need \in 0..2 /\ Cardinality(retained) <= 2
          /\ Cardinality(staged) <= need
OldIndexPreserved == retained \cap staged = {}
StagingHasCapacity == Cardinality(Buffers \ (retained \cup staged)) >= need - Cardinality(staged)
=============================================================================
