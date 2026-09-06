-------------------- MODULE QuvAnchoredReservation --------------------
EXTENDS Integers
CONSTANTS Limit, EarlyExchange, EarlyReply
VARIABLES record, durableRecord, activeAnchor, persistedAnchor, memory, replied, phase
vars == <<record, durableRecord, activeAnchor, persistedAnchor, memory, replied, phase>>
Init == /\ record = 0 /\ durableRecord = 0 /\ activeAnchor = 0
        /\ persistedAnchor = 0 /\ memory = 0 /\ replied = 0 /\ phase = "Idle"
PrepareRecord == /\ phase = "Idle" /\ record < Limit /\ record' = record + 1
                 /\ phase' = "RecordWriting"
                 /\ UNCHANGED <<durableRecord, activeAnchor, persistedAnchor, memory, replied>>
SyncRecord == /\ phase = "RecordWriting" /\ durableRecord' = record
              /\ phase' = "RecordDurable"
              /\ UNCHANGED <<record, activeAnchor, persistedAnchor, memory, replied>>
WriteAnchor == /\ phase = "RecordDurable" /\ phase' = "AnchorWriting"
               /\ UNCHANGED <<record, durableRecord, activeAnchor, persistedAnchor, memory, replied>>
SyncAnchor == /\ phase = "AnchorWriting" /\ phase' = "AnchorDurable"
              /\ UNCHANGED <<record, durableRecord, activeAnchor, persistedAnchor, memory, replied>>
Exchange == /\ (phase = "AnchorDurable" \/ (EarlyExchange /\ phase = "RecordWriting"))
            /\ activeAnchor' = record /\ phase' = "Exchanged"
            /\ UNCHANGED <<record, durableRecord, persistedAnchor, memory, replied>>
SyncDirectory == /\ phase = "Exchanged" /\ persistedAnchor' = activeAnchor
                 /\ phase' = "Committed"
                 /\ UNCHANGED <<record, durableRecord, activeAnchor, memory, replied>>
Reply == /\ (phase = "Committed" \/ (EarlyReply /\ phase = "RecordDurable"))
         /\ memory' = record /\ replied' = record /\ phase' = "Idle"
         /\ UNCHANGED <<record, durableRecord, activeAnchor, persistedAnchor>>
Crash == /\ activeAnchor' \in {activeAnchor, persistedAnchor}
         /\ record' = durableRecord /\ memory' = 0 /\ phase' = "Recovery"
         /\ UNCHANGED <<durableRecord, persistedAnchor, replied>>
\* This transition assumes authenticated complete semantic replay, then both
\* anchor-file and directory sync. It restores retained state, not a live grant.
RecoverValidateSync == /\ phase = "Recovery" /\ activeAnchor' = durableRecord
                       /\ persistedAnchor' = durableRecord /\ memory' = durableRecord
                       /\ record' = durableRecord /\ phase' = "Idle"
                       /\ UNCHANGED <<durableRecord, replied>>
Next == PrepareRecord \/ SyncRecord \/ WriteAnchor \/ SyncAnchor \/ Exchange \/ SyncDirectory \/ Reply \/ Crash \/ RecoverValidateSync
Spec == Init /\ [][Next]_vars
TypeOK == /\ record \in 0..Limit /\ durableRecord \in 0..Limit
          /\ activeAnchor \in 0..Limit /\ persistedAnchor \in 0..Limit
          /\ memory \in 0..Limit /\ replied \in 0..Limit
          /\ phase \in {"Idle", "RecordWriting", "RecordDurable", "AnchorWriting", "AnchorDurable", "Exchanged", "Committed", "Recovery"}
AnchorBacked == persistedAnchor <= activeAnchor /\ activeAnchor <= durableRecord
ReplyBacked == memory <= persistedAnchor /\ replied <= persistedAnchor
Shape == /\ durableRecord <= record
         /\ (phase = "Idle" => record = durableRecord /\ record = persistedAnchor /\ memory = record)
         /\ (phase \in {"RecordDurable", "AnchorWriting", "AnchorDurable", "Exchanged", "Committed"} => record = durableRecord)
         /\ (phase \in {"Exchanged", "Committed"} => activeAnchor = record)
         /\ (phase = "Committed" => persistedAnchor = record)
=============================================================================
