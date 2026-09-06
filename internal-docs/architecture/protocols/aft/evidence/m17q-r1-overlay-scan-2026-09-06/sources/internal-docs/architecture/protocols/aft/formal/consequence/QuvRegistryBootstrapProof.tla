------------------ MODULE QuvRegistryBootstrapProof ------------------
EXTENDS QuvRegistryBootstrap, TLAPS
ASSUME Profile == HideScanError = FALSE
Inv == TypeOK /\ ScanSound /\ BootstrapSound
\* Conditional on exclusive namespace custody and an accurate backing scan.
\* This proves error propagation, not backing-store crash consistency.
THEOREM BootstrapSafety == Spec => []Inv
<1>1. Init => Inv
  BY SMT DEF Init, Inv, TypeOK, ScanSound, BootstrapSound
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, ScanSound, BootstrapSound,
    Next, Scan, Bootstrap, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
