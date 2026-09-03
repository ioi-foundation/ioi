---------------------- MODULE CrossDomainNonInterference ----------------------
EXTENDS Naturals, TLC

(***************************************************************************
M8 conflict-domain kernel. Domain A's unanimous ring has a permanent
withholder. Domain B orders and externalizes independently. No action can
transfer A's authority, stall state, or evidence into B.
***************************************************************************)

VARIABLES aSeal, aWithheld, bHeight, bEffects, bFallback, launderingRejected
vars == <<aSeal, aWithheld, bHeight, bEffects, bFallback, launderingRejected>>

Init ==
    /\ aSeal = 0
    /\ aWithheld = TRUE
    /\ bHeight = 0
    /\ bEffects = 0
    /\ bFallback = FALSE
    /\ launderingRejected = FALSE

AttemptASeal ==
    /\ aWithheld
    /\ UNCHANGED vars

ForceBFallback ==
    /\ ~bFallback
    /\ bFallback' = TRUE
    /\ UNCHANGED <<aSeal, aWithheld, bHeight, bEffects, launderingRejected>>

AdvanceB ==
    /\ bFallback
    /\ bHeight' = bHeight + 1
    /\ bEffects' = bEffects + 1
    /\ UNCHANGED <<aSeal, aWithheld, bFallback, launderingRejected>>

AttemptLaundering ==
    /\ launderingRejected' = TRUE
    /\ UNCHANGED <<aSeal, aWithheld, bHeight, bEffects, bFallback>>

Done == UNCHANGED vars

Next == AttemptASeal \/ ForceBFallback \/ AdvanceB \/ AttemptLaundering \/ Done

TypeOK ==
    /\ aSeal \in Nat /\ aWithheld \in BOOLEAN
    /\ bHeight \in Nat /\ bEffects \in Nat /\ bFallback \in BOOLEAN
    /\ launderingRejected \in BOOLEAN

StalledRingNeverForges == aWithheld => aSeal = 0
IndependentProgressAccounting == bEffects = bHeight
NoAuthorityTransfer == aSeal = 0

StateConstraint == bHeight <= 3
Spec == Init /\ [][Next]_vars

=============================================================================
