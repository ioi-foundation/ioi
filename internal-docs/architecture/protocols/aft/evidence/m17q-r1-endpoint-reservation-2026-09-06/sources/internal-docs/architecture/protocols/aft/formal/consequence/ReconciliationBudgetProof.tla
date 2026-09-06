-------------------- MODULE ReconciliationBudgetProof --------------------
EXTENDS ReconciliationBudget, TLAPS
ASSUME BudgetIsNatural == MaxAttempts \in Nat
Inv == TypeOK /\ ReservedBeforeLookup /\ BudgetBound /\ ReadyHasUnspentReservation

\* Assumes: atomic non-rollback Reserve; Crash preserves durable reservations;
\* Lookup requires process-local readiness, consumed at most once. No liveness
\* or filesystem refinement is asserted by this component theorem.
THEOREM ReservationBudgetSafety == Spec => []Inv
<1>1. Init => Inv
  BY SMT, BudgetIsNatural DEF Init, Inv, TypeOK, ReservedBeforeLookup,
    BudgetBound, ReadyHasUnspentReservation
<1>2. Inv /\ [Next]_vars => Inv'
  BY SMT, BudgetIsNatural DEF Inv, Next, Reserve, Lookup, Crash, vars, TypeOK,
    ReservedBeforeLookup, BudgetBound, ReadyHasUnspentReservation
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
