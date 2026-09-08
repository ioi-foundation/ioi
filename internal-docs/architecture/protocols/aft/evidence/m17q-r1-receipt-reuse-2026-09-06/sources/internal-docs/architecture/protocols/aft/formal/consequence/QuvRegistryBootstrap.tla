-------------------- MODULE QuvRegistryBootstrap --------------------
EXTENDS Naturals
CONSTANT HideScanError
VARIABLES emptyNamespace, scanError, phase, observedEmpty, initialized
vars == <<emptyNamespace, scanError, phase, observedEmpty, initialized>>
Init == /\ emptyNamespace \in BOOLEAN /\ scanError \in BOOLEAN
        /\ phase = "Unread" /\ observedEmpty = FALSE /\ initialized = FALSE
Scan == /\ phase = "Unread"
        /\ observedEmpty' = IF scanError THEN HideScanError ELSE emptyNamespace
        /\ phase' = "Scanned"
        /\ UNCHANGED <<emptyNamespace, scanError, initialized>>
Bootstrap == /\ phase = "Scanned" /\ observedEmpty
             /\ initialized' = TRUE /\ phase' = "Done"
             /\ UNCHANGED <<emptyNamespace, scanError, observedEmpty>>
Next == Scan \/ Bootstrap
Spec == Init /\ [][Next]_vars
TypeOK == /\ emptyNamespace \in BOOLEAN /\ scanError \in BOOLEAN
          /\ phase \in {"Unread", "Scanned", "Done"}
          /\ observedEmpty \in BOOLEAN /\ initialized \in BOOLEAN
ScanSound == observedEmpty => emptyNamespace /\ ~scanError
BootstrapSound == initialized => emptyNamespace /\ ~scanError
=============================================================================
