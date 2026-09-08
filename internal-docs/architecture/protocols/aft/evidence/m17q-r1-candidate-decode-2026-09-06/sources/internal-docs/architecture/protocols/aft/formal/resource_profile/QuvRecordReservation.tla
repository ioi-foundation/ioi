--------------------- MODULE QuvRecordReservation ---------------------
EXTENDS FiniteSets
CONSTANTS Slots, TruncateLive, ForgetAcknowledged
VARIABLES pool, retained, allocated, dirty, acknowledged
vars == <<pool, retained, allocated, dirty, acknowledged>>
Init == /\ pool = Slots /\ retained = {} /\ allocated = Slots
        /\ dirty = {} /\ acknowledged = {}
Write == /\ dirty = {}
         /\ \E slot \in pool :
               /\ dirty' = {slot}
               /\ allocated' = IF TruncateLive THEN allocated \ {slot} ELSE allocated
         /\ UNCHANGED <<pool, retained, acknowledged>>
Publish == /\ dirty # {} /\ pool' = pool \ dirty
           /\ retained' = retained \cup dirty /\ dirty' = {}
           /\ UNCHANGED <<allocated, acknowledged>>
AnchorAndReply == /\ acknowledged' = retained
                  /\ UNCHANGED <<pool, retained, allocated, dirty>>
AuthenticatedRestart == /\ dirty' = {}
                        /\ UNCHANGED <<pool, retained, allocated, acknowledged>>
Forget == /\ ForgetAcknowledged /\ acknowledged # {} /\ dirty = {}
          /\ pool' = pool \cup retained /\ retained' = {}
          /\ UNCHANGED <<allocated, dirty, acknowledged>>
Next == Write \/ Publish \/ AnchorAndReply \/ AuthenticatedRestart \/ Forget
Spec == Init /\ [][Next]_vars
Partition == /\ pool \cap retained = {} /\ pool \cup retained = Slots
             /\ dirty \subseteq pool
CapacityRetained == allocated = Slots
AcknowledgedRetained == acknowledged \subseteq retained
=============================================================================
