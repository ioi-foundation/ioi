-------------------- MODULE ConsequenceTraceLifetime --------------------
EXTENDS Naturals
CONSTANTS Limit, ReuseLookup
VARIABLES phase, trace, reserved, used, ready
vars == <<phase, trace, reserved, used, ready>>
Init == /\ phase = "Authorized" /\ trace = 1 /\ reserved = 0 /\ used = 0 /\ ready = FALSE
Claim == /\ phase = "Authorized" /\ phase' = "Claimed" /\ trace' = trace + 1
         /\ UNCHANGED <<reserved, used, ready>>
Start == /\ phase = "Claimed" /\ phase' = "InFlight" /\ trace' = trace + 1
         /\ UNCHANGED <<reserved, used, ready>>
Outcome == /\ phase = "InFlight" /\ phase' \in {"Executed", "Unknown"}
           /\ trace' = trace + 1 /\ UNCHANGED <<reserved, used, ready>>
Reserve == /\ phase \in {"Executed", "Unknown"} /\ ~ready /\ reserved < Limit
           /\ reserved' = reserved + 1 /\ ready' = TRUE /\ UNCHANGED <<phase, trace, used>>
Lookup == /\ ready /\ phase \in {"Executed", "Unknown"}
          /\ phase' \in {phase, "Reconciled"} /\ used' = used + 1
          /\ trace' = IF phase = "Executed" /\ phase' = "Executed" THEN trace ELSE trace + 1
          /\ ready' = ReuseLookup /\ UNCHANGED reserved
\* Crash loses local lookup readiness. Recovering InFlight uses Outcome's
\* Unknown branch; it cannot add a second such edge once phase is Unknown.
Crash == /\ ready' = FALSE /\ UNCHANGED <<phase, trace, reserved, used>>
Next == Claim \/ Start \/ Outcome \/ Reserve \/ Lookup \/ Crash
Spec == Init /\ [][Next]_vars
TypeOK == /\ phase \in {"Authorized", "Claimed", "InFlight", "Executed", "Unknown", "Reconciled"}
          /\ trace \in Nat /\ reserved \in 0..Limit /\ used \in Nat /\ ready \in BOOLEAN
Base == CASE phase = "Authorized" -> 1 [] phase = "Claimed" -> 2 [] phase = "InFlight" -> 3 [] OTHER -> 4
Charge == trace <= Base + used
Budget == used <= reserved /\ reserved <= Limit
ReadyCharged == ready => used < reserved
TraceBound == trace <= 4 + Limit
=============================================================================
