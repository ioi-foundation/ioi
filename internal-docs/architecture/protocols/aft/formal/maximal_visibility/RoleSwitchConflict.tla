---------------------------- MODULE RoleSwitchConflict ----------------------------
EXTENDS FiniteSets

CONSTANTS Members, Values, P0, P1, X, Y

ASSUME /\ Members = {P0, P1}
       /\ P0 # P1
       /\ X \in Values
       /\ Y \in Values
       /\ X # Y

Proof(member, value) == [signer |-> member, decision |-> value]

VARIABLE proofs

vars == <<proofs>>

Init == proofs = {}

SoleHonestP0Progress ==
    /\ Proof(P0, X) \notin proofs
    /\ proofs' = proofs \cup {Proof(P0, X)}

RoleSwitchedP1Replay ==
    /\ Proof(P0, X) \in proofs
    /\ Proof(P1, Y) \notin proofs
    /\ proofs' = proofs \cup {Proof(P1, Y)}

Next == SoleHonestP0Progress \/ RoleSwitchedP1Replay

ExternalNonConflict ==
    ~(Proof(P0, X) \in proofs /\ Proof(P1, Y) \in proofs)

Spec == Init /\ [][Next]_vars

=============================================================================
