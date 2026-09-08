-------------------- MODULE QuvInstallContinuation --------------------
EXTENDS Integers
CONSTANTS Deadline, MaxTime, RestartLimit, SkipFinalFence, RehydrateGrant
VARIABLES now, phase, epoch, grantEpoch, grant, consumedAt, durable, installed
vars == <<now, phase, epoch, grantEpoch, grant, consumedAt, durable, installed>>
Init == /\ now = 0 /\ phase = "Idle" /\ epoch = 0 /\ grantEpoch = 0
        /\ grant = FALSE /\ consumedAt = -1 /\ durable = FALSE /\ installed = FALSE
\* Acquire abstracts this executor's successful fresh, exact-root live QUV.
Acquire == /\ phase = "Idle" /\ now <= Deadline
           /\ grant' = TRUE /\ grantEpoch' = epoch /\ phase' = "Preparing"
           /\ UNCHANGED <<now, epoch, consumedAt, durable, installed>>
Tick == /\ now < MaxTime /\ now' = now + 1
        /\ UNCHANGED <<phase, epoch, grantEpoch, grant, consumedAt, durable, installed>>
\* Claim is the beginning of the durable install after all preparation work.
Claim == /\ phase = "Preparing" /\ grant
         /\ (SkipFinalFence \/ now <= Deadline)
         /\ grant' = FALSE /\ consumedAt' = now /\ phase' = "Claimed"
         /\ UNCHANGED <<now, epoch, grantEpoch, durable, installed>>
Sync == /\ phase = "Claimed" /\ durable' = TRUE /\ phase' = "Synced"
        /\ UNCHANGED <<now, epoch, grantEpoch, grant, consumedAt, installed>>
Publish == /\ phase = "Synced" /\ installed' = TRUE /\ phase' = "Installed"
           /\ UNCHANGED <<now, epoch, grantEpoch, grant, consumedAt, durable>>
Crash == /\ epoch < RestartLimit /\ epoch' = epoch + 1
         /\ grant' = FALSE /\ installed' = FALSE /\ phase' = "Recovery"
         /\ UNCHANGED <<now, grantEpoch, consumedAt, durable>>
\* Recovery requires authenticated exact state/anchor validation. It recognizes
\* an already durable install, without recreating a live continuation.
Recover == /\ phase = "Recovery" /\ installed' = durable
           /\ phase' = IF durable THEN "Installed" ELSE "Idle"
           /\ grant' = RehydrateGrant
           /\ UNCHANGED <<now, epoch, grantEpoch, consumedAt, durable>>
Next == Acquire \/ Tick \/ Claim \/ Sync \/ Publish \/ Crash \/ Recover
Spec == Init /\ [][Next]_vars
TypeOK == /\ now \in 0..MaxTime /\ epoch \in 0..RestartLimit
          /\ grantEpoch \in 0..epoch /\ grant \in BOOLEAN
          /\ consumedAt \in -1..MaxTime /\ durable \in BOOLEAN /\ installed \in BOOLEAN
          /\ phase \in {"Idle", "Preparing", "Claimed", "Synced", "Installed", "Recovery"}
LiveAtClaim == consumedAt <= Deadline
ProcessLocal == grant => grantEpoch = epoch /\ phase = "Preparing"
InstalledDurably == installed => durable
DurablePhase == phase \in {"Synced", "Installed"} => durable
=============================================================================
