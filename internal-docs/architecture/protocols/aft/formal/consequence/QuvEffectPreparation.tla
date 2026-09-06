--------------------- MODULE QuvEffectPreparation ---------------------
EXTENDS Naturals
CONSTANTS SkipBinding, SkipPreflight, PreparedBearer, WriteTerminal
VARIABLES bindingOK, candidateOK, admissionOK, initiallyTerminal,
          phase, prepared, live, ownInteraction, claimWasLive, storagePrepared
vars == <<bindingOK, candidateOK, admissionOK, initiallyTerminal,
          phase, prepared, live, ownInteraction, claimWasLive, storagePrepared>>
inputs == <<bindingOK, candidateOK, admissionOK, initiallyTerminal>>
Init == /\ bindingOK \in BOOLEAN /\ candidateOK \in BOOLEAN /\ admissionOK \in BOOLEAN
        /\ initiallyTerminal \in BOOLEAN
        /\ phase = IF initiallyTerminal THEN "Terminal" ELSE "Absent"
        /\ storagePrepared = FALSE /\ prepared = FALSE /\ live = FALSE /\ ownInteraction = FALSE /\ claimWasLive = FALSE
Prepare == /\ phase \in {"Absent", "Prepared", "Terminal"}
           /\ admissionOK /\ (bindingOK \/ SkipBinding)
           /\ (initiallyTerminal \/ candidateOK \/ SkipPreflight)
           /\ prepared' = TRUE
           /\ storagePrepared' = (~initiallyTerminal \/ WriteTerminal)
           /\ phase' = IF initiallyTerminal THEN "Terminal" ELSE "Prepared"
           /\ live' = PreparedBearer
           /\ UNCHANGED <<inputs, ownInteraction, claimWasLive>>
\* This abstracts the executor's own successful exact-context live QUV. It
\* does not assume that local preflight or a stored audit implies success.
OwnLive == /\ phase = "Prepared" /\ live' = TRUE /\ ownInteraction' = TRUE
           /\ UNCHANGED <<inputs, phase, prepared, claimWasLive, storagePrepared>>
Claim == /\ phase = "Prepared" /\ live /\ phase' = "Claimed"
         /\ claimWasLive' = (live /\ ownInteraction)
         /\ live' = FALSE /\ UNCHANGED <<inputs, prepared, ownInteraction, storagePrepared>>
\* No external call is modeled here: a crash after the claim fence returns
\* executable durable state to preparation, requiring another own live grant.
Crash == /\ live' = FALSE /\ ownInteraction' = FALSE
         /\ phase' = IF phase = "Claimed" THEN "Prepared" ELSE phase
         /\ UNCHANGED <<inputs, prepared, claimWasLive, storagePrepared>>
Next == Prepare \/ OwnLive \/ Claim \/ Crash
Spec == Init /\ [][Next]_vars
TypeOK == /\ bindingOK \in BOOLEAN /\ candidateOK \in BOOLEAN /\ admissionOK \in BOOLEAN
          /\ initiallyTerminal \in BOOLEAN /\ phase \in {"Absent", "Prepared", "Claimed", "Terminal"}
          /\ prepared \in BOOLEAN /\ live \in BOOLEAN /\ ownInteraction \in BOOLEAN
          /\ claimWasLive \in BOOLEAN /\ storagePrepared \in BOOLEAN
PreparationChecked == prepared => admissionOK /\ bindingOK /\ (initiallyTerminal \/ candidateOK)
GrantIsOwn == live => ownInteraction
ClaimIsOwn == phase = "Claimed" => claimWasLive
TerminalIsNotExecutable == initiallyTerminal => phase = "Terminal"
TerminalReadOnly == initiallyTerminal => ~storagePrepared
=============================================================================
