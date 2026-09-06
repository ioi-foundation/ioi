----------------------- MODULE ReconciliationBudgetVolatile -----------------------
EXTENDS Naturals
CONSTANT MaxAttempts
VARIABLES legacy, reserved, calls, ready
vars == <<legacy, reserved, calls, ready>>

\* Negative component model: Crash forgets reservations after lookup.
\* This deliberately violates the non-rollback durability assumption.
\* calls is a ghost history counter, not recoverable production state.
Init == /\ legacy \in 0..MaxAttempts
        /\ reserved = legacy
        /\ calls = 0
        /\ ready = FALSE
Reserve == /\ ~ready
           /\ reserved < MaxAttempts
           /\ reserved' = reserved + 1
           /\ ready' = TRUE
           /\ UNCHANGED <<legacy, calls>>
Lookup == /\ ready
          /\ calls' = calls + 1
          /\ ready' = FALSE
          /\ UNCHANGED <<legacy, reserved>>
Crash == /\ ready' = FALSE
         /\ reserved' = legacy
         /\ UNCHANGED <<legacy, calls>>
Next == Reserve \/ Lookup \/ Crash
Spec == Init /\ [][Next]_vars
TypeOK == /\ legacy \in 0..MaxAttempts
          /\ reserved \in 0..MaxAttempts
          /\ calls \in 0..MaxAttempts
          /\ ready \in BOOLEAN
ReservedBeforeLookup == calls + legacy <= reserved
BudgetBound == reserved <= MaxAttempts
ReadyHasUnspentReservation == ready => calls + legacy < reserved
=============================================================================
