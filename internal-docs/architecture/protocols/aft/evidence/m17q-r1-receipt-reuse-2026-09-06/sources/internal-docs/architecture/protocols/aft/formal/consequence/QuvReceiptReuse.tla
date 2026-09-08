----------------------- MODULE QuvReceiptReuse -----------------------
EXTENDS Naturals
CONSTANTS RewriteReady, TrustSpare
VARIABLES activeValid, spareReady, rewroteReady, usedSpareAuthority
vars == <<activeValid, spareReady, rewroteReady, usedSpareAuthority>>
Init == /\ activeValid \in BOOLEAN /\ spareReady \in BOOLEAN
        /\ rewroteReady = FALSE /\ usedSpareAuthority = FALSE
Prepare == /\ (activeValid \/ (TrustSpare /\ spareReady))
           /\ activeValid' = TRUE /\ spareReady' = TRUE
           /\ rewroteReady' = (rewroteReady \/ (activeValid /\ spareReady /\ RewriteReady))
           /\ usedSpareAuthority' = (usedSpareAuthority \/ ~activeValid)
Next == Prepare
Spec == Init /\ [][Next]_vars
TypeOK == /\ activeValid \in BOOLEAN /\ spareReady \in BOOLEAN
          /\ rewroteReady \in BOOLEAN /\ usedSpareAuthority \in BOOLEAN
ReusePreservesData == ~rewroteReady
ActiveOnlyAuthority == ~usedSpareAuthority
=============================================================================
