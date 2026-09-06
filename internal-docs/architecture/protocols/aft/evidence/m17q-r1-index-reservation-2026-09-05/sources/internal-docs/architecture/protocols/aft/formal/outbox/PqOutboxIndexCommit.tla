---------------------- MODULE PqOutboxIndexCommit ----------------------
EXTENDS FiniteSets
CONSTANTS Entries, Initial, EarlyDelete, EarlyPublish
VARIABLES index, blobs, pending, phase
vars == <<index, blobs, pending, phase>>
Init == /\ index = Initial /\ blobs = Initial /\ pending = {}
        /\ phase = "Idle"
Stage == /\ phase = "Idle"
         /\ \E next \in SUBSET Entries : pending' = next
         /\ phase' = "Prepared" /\ UNCHANGED <<index, blobs>>
WritePayloads == /\ phase = "Prepared"
                 /\ blobs' = IF EarlyDelete THEN pending ELSE blobs \cup pending
                 /\ phase' = "Payloads" /\ UNCHANGED <<index, pending>>
WriteOnePayload == /\ phase = "Prepared"
                   /\ \E entry \in pending \ blobs : blobs' = blobs \cup {entry}
                   /\ UNCHANGED <<index, pending, phase>>
Publish == /\ (phase = "Payloads" \/ (EarlyPublish /\ phase = "Prepared"))
           /\ index' = pending /\ phase' = "Committed"
           /\ UNCHANGED <<blobs, pending>>
Cleanup == /\ phase = "Committed" /\ blobs' = index
           /\ phase' = "Idle" /\ pending' = {} /\ UNCHANGED index
CrashRecover == /\ phase' = "Idle" /\ pending' = {}
                /\ UNCHANGED <<index, blobs>>
TrimOrphan == /\ phase \in {"Idle", "Committed"}
              /\ \E entry \in blobs \ index : blobs' = blobs \ {entry}
              /\ UNCHANGED <<index, pending, phase>>
Next == Stage \/ WriteOnePayload \/ WritePayloads \/ Publish \/ Cleanup \/ CrashRecover \/ TrimOrphan
Spec == Init /\ [][Next]_vars
TypeOK == /\ index \subseteq Entries /\ blobs \subseteq Entries
          /\ pending \subseteq Entries
          /\ phase \in {"Idle", "Prepared", "Payloads", "Committed"}
RecoverableIndex == index \subseteq blobs
PreparedPayloads == phase = "Payloads" => pending \subseteq blobs
=============================================================================
