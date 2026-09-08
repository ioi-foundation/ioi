---------------------- MODULE PqReservedIndex ----------------------
EXTENDS Integers, FiniteSets
CONSTANTS EarlyExchange, TruncateInactive
VARIABLES active, persistedActive, valid, allocated, phase
vars == <<active, persistedActive, valid, allocated, phase>>
Buffers == {0, 1}
Other(i) == IF i = 0 THEN 1 ELSE 0
Init == /\ active = 0 /\ persistedActive = 0 /\ valid = Buffers /\ allocated = Buffers
        /\ phase = "Idle"
BeginWrite == /\ phase = "Idle"
              /\ valid' = valid \ {Other(active)}
              /\ allocated' = IF TruncateInactive
                              THEN allocated \ {Other(active)} ELSE allocated
              /\ phase' = "Writing" /\ UNCHANGED <<active, persistedActive>>
SyncImage == /\ phase = "Writing"
             /\ valid' = valid \cup {Other(active)}
             /\ phase' = "Synced" /\ UNCHANGED <<active, persistedActive, allocated>>
Exchange == /\ (phase = "Synced" \/ (EarlyExchange /\ phase = "Writing"))
            /\ active' = Other(active) /\ phase' = "Exchanged"
            /\ UNCHANGED <<persistedActive, valid, allocated>>
SyncDirectory == /\ phase = "Exchanged" /\ persistedActive' = active
                 /\ phase' = "Idle" /\ UNCHANGED <<active, valid, allocated>>
CrashRecover == /\ phase' = "Idle"
                /\ \E recovered \in {active, persistedActive} :
                      /\ active' = recovered /\ persistedActive' = recovered
                /\ UNCHANGED <<valid, allocated>>
Next == BeginWrite \/ SyncImage \/ Exchange \/ SyncDirectory \/ CrashRecover
Spec == Init /\ [][Next]_vars
TypeOK == /\ active \in Buffers /\ persistedActive \in Buffers /\ valid \subseteq Buffers
          /\ allocated \subseteq Buffers
          /\ phase \in {"Idle", "Writing", "Synced", "Exchanged"}
ActiveRecoverable == /\ active \in valid /\ persistedActive \in valid
StableDirectory == phase # "Exchanged" => active = persistedActive
CapacityRetained == allocated = Buffers
SyncedInactive == phase = "Synced" => Other(active) \in valid
=============================================================================
