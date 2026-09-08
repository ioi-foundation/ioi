--------------------- MODULE QuvEffectPreparation ---------------------
EXTENDS Naturals
CONSTANTS SkipBinding, SkipPreflight, PreparedBearer
VARIABLES bindingOK, candidateOK, admissionOK, initiallyTerminal,
          phase, prepared, live, ownInteraction, claimWasLive
vars == <<bindingOK, candidateOK, admissionOK, initiallyTerminal,
          phase, prepared, live, ownInteraction, claimWasLive>>
inputs == <<bindingOK, candidateOK, admissionOK, initiallyTerminal>>
Init == /\ bindingOK \in BOOLEAN /\ candidateOK \in BOOLEAN /\ admissionOK \in BOOLEAN
        /\ initiallyTerminal \in BOOLEAN
        /\ phase = IF initiallyTerminal THEN "Terminal" ELSE "Absent"
        /\ prepared = FALSE /\ live = FALSE /\ ownInteraction = FALSE /\ claimWasLive = FALSE
Prepare == /\ phase \in {"Absent", "Prepared", "Terminal"}
           /\ admissionOK /\ (bindingOK \/ SkipBinding)
           /\ (initiallyTerminal \/ candidateOK \/ SkipPreflight)
           /\ prepared' = TRUE
           /\ phase' = IF initiallyTerminal THEN "Terminal" ELSE "Prepared"
           /\ live' = PreparedBearer
           /\ UNCHANGED <<inputs, ownInteraction, claimWasLive>>
\* This abstracts the executor's own successful exact-context live QUV. It
\* does not assume that local preflight or a stored audit implies success.
OwnLive == /\ phase = "Prepared" /\ live' = TRUE /\ ownInteraction' = TRUE
           /\ UNCHANGED <<inputs, phase, prepared, claimWasLive>>
Claim == /\ phase = "Prepared" /\ live /\ phase' = "Claimed"
         /\ claimWasLive' = live /\ ownInteraction
         /\ live' = FALSE /\ UNCHANGED <<inputs, prepared, ownInteraction>>
Crash == /\ phase # "Claimed" /\ live' = FALSE /\ ownInteraction' = FALSE
         /\ UNCHANGED <<inputs, phase, prepared, claimWasLive>>
Next == Prepare \/ OwnLive \/ Claim \/ Crash
Spec == Init /\ [][Next]_vars
TypeOK == /\ bindingOK \in BOOLEAN /\ candidateOK \in BOOLEAN /\ admissionOK \in BOOLEAN
          /\ initiallyTerminal \in BOOLEAN /\ phase \in {"Absent", "Prepared", "Claimed", "Terminal"}
          /\ prepared \in BOOLEAN /\ live \in BOOLEAN /\ ownInteraction \in BOOLEAN
          /\ claimWasLive \in BOOLEAN
PreparationChecked == prepared => admissionOK /\ bindingOK /\ (initiallyTerminal \/ candidateOK)
GrantIsOwn == live => ownInteraction
ClaimIsOwn == phase = "Claimed" => claimWasLive
TerminalIsNotExecutable == initiallyTerminal => phase = "Terminal"
=============================================================================
