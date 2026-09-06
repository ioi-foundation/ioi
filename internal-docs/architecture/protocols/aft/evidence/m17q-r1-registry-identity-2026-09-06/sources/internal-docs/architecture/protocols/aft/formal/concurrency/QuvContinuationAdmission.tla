---------------- MODULE QuvContinuationAdmission ----------------
EXTENDS Naturals
CONSTANTS ReleaseOnDelivery, ReleaseOnCancel
VARIABLES phase, held, observed, nextActive
vars == <<phase, held, observed, nextActive>>
Init == /\ phase = "Pending" /\ held = TRUE
        /\ observed = TRUE /\ nextActive = FALSE
Deliver == /\ phase = "Pending" /\ phase' = "Delivered"
           /\ held' = ~ReleaseOnDelivery
           /\ UNCHANGED <<observed, nextActive>>
Start == /\ phase = "Delivered" /\ phase' = "Worker"
         /\ UNCHANGED <<held, observed, nextActive>>
CancelDelivery == /\ phase \in {"Pending", "Delivered"}
                  /\ phase' = "Done" /\ held' = FALSE
                  /\ observed' = FALSE /\ UNCHANGED nextActive
CancelObservation == /\ phase = "Worker" /\ observed
                     /\ observed' = FALSE
                     /\ held' = IF ReleaseOnCancel THEN FALSE ELSE held
                     /\ UNCHANGED <<phase, nextActive>>
Finish == /\ phase = "Worker" /\ phase' = "Done" /\ held' = FALSE
          /\ UNCHANGED <<observed, nextActive>>
AdmitNext == /\ ~held /\ nextActive' = TRUE
             /\ UNCHANGED <<phase, held, observed>>
Next == Deliver \/ Start \/ CancelDelivery \/ CancelObservation \/ Finish \/ AdmitNext
Spec == Init /\ [][Next]_vars
TypeOK == /\ phase \in {"Pending", "Delivered", "Worker", "Done"}
          /\ held \in BOOLEAN /\ observed \in BOOLEAN /\ nextActive \in BOOLEAN
Ownership == (phase # "Done") => held /\ ~nextActive
Released == (phase = "Done") => ~held
=================================================================
