------------------------ MODULE DistinctCollateralFloor ------------------------
EXTENDS Naturals, FiniteSets, TLC

(***************************************************************************
Bounded M6 kernel for an offline collateral-floor verifier. A collateral lot
can enter the counted set once, and only while its lock, challenge horizon,
exclusive configuration, encumbrance, and evidence-predicate checks pass.
Rejected duplicate or ineligible presentations cannot change the floor.
***************************************************************************)

CONSTANTS Lots, Eligible

VARIABLES selected, floor, rejected

vars == <<selected, floor, rejected>>

RECURSIVE SetSum(_)
SetSum(S) ==
    IF S = {} THEN 0
    ELSE LET lot == CHOOSE candidate \in S : TRUE
         IN lot + SetSum(S \ {lot})

Init ==
    /\ selected = {}
    /\ floor = 0
    /\ rejected = FALSE

Accept(lot) ==
    /\ lot \in Eligible
    /\ lot \notin selected
    /\ selected' = selected \cup {lot}
    /\ floor' = floor + lot
    /\ UNCHANGED rejected

RejectDuplicate(lot) ==
    /\ lot \in selected
    /\ rejected' = TRUE
    /\ UNCHANGED <<selected, floor>>

RejectIneligible(lot) ==
    /\ lot \in Lots \ Eligible
    /\ rejected' = TRUE
    /\ UNCHANGED <<selected, floor>>

Done == UNCHANGED vars

Next ==
    (\E lot \in Lots : Accept(lot))
    \/ (\E lot \in Lots : RejectDuplicate(lot))
    \/ (\E lot \in Lots : RejectIneligible(lot))
    \/ Done

TypeOK ==
    /\ selected \subseteq Lots
    /\ floor \in Nat
    /\ rejected \in BOOLEAN

OnlyEligibleCollateral == selected \subseteq Eligible

DistinctFloor == floor = SetSum(selected)

RejectionCannotMintCollateral == rejected => floor = SetSum(selected)

Spec == Init /\ [][Next]_vars

=============================================================================
