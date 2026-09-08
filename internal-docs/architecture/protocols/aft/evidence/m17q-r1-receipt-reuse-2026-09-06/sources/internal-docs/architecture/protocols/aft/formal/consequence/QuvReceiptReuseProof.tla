-------------------- MODULE QuvReceiptReuseProof --------------------
EXTENDS QuvReceiptReuse, TLAPS
ASSUME Profile == /\ RewriteReady = FALSE /\ TrustSpare = FALSE
Inv == TypeOK /\ ReusePreservesData /\ ActiveOnlyAuthority
\* Conditional on truthful capacity/initialization validation and exclusive
\* custody. Synchronization of valid files stutters in this logical model;
\* device latency and physical metadata allocation are not modeled.
THEOREM ReuseSafety == Spec => []Inv
<1>1. Init => Inv
  BY SMT DEF Init, Inv, TypeOK, ReusePreservesData, ActiveOnlyAuthority
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, ReusePreservesData,
    ActiveOnlyAuthority, Next, Prepare, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
