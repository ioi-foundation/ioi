---- MODULE NestedGuardianRecoveryRecurringLivenessCore ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANT Validators, Witnesses, Blocks, Slots, Epochs, QuorumSize, MaxReassignmentDepth,
         InitialEpoch, InitialWitness, TotalCycles,
         TargetSlotOf(_), TargetBlockOf(_), StableEpochOf(_),
         SmallCommitteeSlot, SmallRecoveryThreshold, LargeRecoveryThreshold,
         SmallRecoveryCommittee, LargeRecoveryCommittee

ASSUME InitialEpoch \in Epochs
ASSUME InitialWitness \in Witnesses
ASSUME QuorumSize \in 1..Cardinality(Validators)
ASSUME TotalCycles \in Nat
ASSUME TotalCycles >= 1
ASSUME \A c \in 1..TotalCycles :
  /\ TargetSlotOf(c) \in Slots
  /\ TargetBlockOf(c) \in Blocks
  /\ StableEpochOf(c) \in Epochs

VARIABLES votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
          witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase, churnStage,
          continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
          continuationPagePublished, continuationPageBoundary, continuationFetched,
          shareReceipts, shareConflicts, windowClosed, missingShareClaims,
          missingThresholdCertificates, recovered, recoveredSurfaces,
          recoveryConflicts, aborted

Core ==
  INSTANCE NestedGuardianRecurringLivenessCore
  WITH Validators <- Validators,
       Witnesses <- Witnesses,
       Blocks <- Blocks,
       Slots <- Slots,
       Epochs <- Epochs,
       QuorumSize <- QuorumSize,
       MaxReassignmentDepth <- MaxReassignmentDepth,
       InitialEpoch <- InitialEpoch,
       InitialWitness <- InitialWitness,
       TotalCycles <- TotalCycles,
       TargetSlotOf <- TargetSlotOf,
       TargetBlockOf <- TargetBlockOf,
       StableEpochOf <- StableEpochOf,
       votes <- votes,
       witnessCerts <- witnessCerts,
       finalized <- finalized,
       finalizerSets <- finalizerSets,
       registryEpoch <- registryEpoch,
       guardianReady <- guardianReady,
       witnessOnline <- witnessOnline,
       witnessCheckpoint <- witnessCheckpoint,
       assignedWitness <- assignedWitness,
       reassignmentDepth <- reassignmentDepth,
       currentCycle <- currentCycle,
       phase <- phase,
       churnStage <- churnStage,
       continuationBoundary <- continuationBoundary,
       continuationAnchorPublished <- continuationAnchorPublished,
       continuationAnchorBoundary <- continuationAnchorBoundary,
       continuationPagePublished <- continuationPagePublished,
       continuationPageBoundary <- continuationPageBoundary,
       continuationFetched <- continuationFetched

Recovery ==
  INSTANCE NestedGuardianRecovery
  WITH Witnesses <- Witnesses,
       Blocks <- Blocks,
       Slots <- Slots,
       SmallCommitteeSlot <- SmallCommitteeSlot,
       SmallRecoveryThreshold <- SmallRecoveryThreshold,
       LargeRecoveryThreshold <- LargeRecoveryThreshold,
       SmallRecoveryCommittee <- SmallRecoveryCommittee,
       LargeRecoveryCommittee <- LargeRecoveryCommittee,
       witnessOnline <- witnessOnline,
       shareReceipts <- shareReceipts,
       shareConflicts <- shareConflicts,
       windowClosed <- windowClosed,
       missingShareClaims <- missingShareClaims,
       missingThresholdCertificates <- missingThresholdCertificates,
       recovered <- recovered,
       recoveredSurfaces <- recoveredSurfaces,
       recoveryConflicts <- recoveryConflicts,
       aborted <- aborted

vars ==
  <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
    witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase,
    churnStage, continuationBoundary, continuationAnchorPublished,
    continuationAnchorBoundary, continuationPagePublished, continuationPageBoundary,
    continuationFetched, shareReceipts, shareConflicts, windowClosed, missingShareClaims,
    missingThresholdCertificates, recovered, recoveredSurfaces, recoveryConflicts, aborted>>

CoreExclusiveVars ==
  <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
    witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase, churnStage,
    continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
    continuationPagePublished, continuationPageBoundary, continuationFetched>>

RecoveryExclusiveVars ==
  <<shareReceipts, shareConflicts, windowClosed, missingShareClaims,
    missingThresholdCertificates, recovered, recoveredSurfaces, recoveryConflicts, aborted>>

CurrentTargetSlot == Core!CurrentTargetSlot
CurrentTargetBlock == Core!CurrentTargetBlock
CycleRange == 1..TotalCycles
PrefixAdvanceRange == IF TotalCycles = 1 THEN {} ELSE 1..(TotalCycles - 1)

TargetSlotResolved(c) ==
  \/ Recovery!RecoveredSurface(Core!TargetSlot(c), Core!TargetBlock(c)) \in recoveredSurfaces
  \/ Core!TargetSlot(c) \in aborted

CurrentTargetResolved == TargetSlotResolved(currentCycle)

SomeGuardianOutage ==
  /\ Core!SomeGuardianOutage
  /\ UNCHANGED RecoveryExclusiveVars

TriggerWitnessOutage ==
  /\ Core!TriggerWitnessOutage
  /\ UNCHANGED RecoveryExclusiveVars

SomeTargetReassignment ==
  /\ Core!SomeTargetReassignment
  /\ UNCHANGED RecoveryExclusiveVars

SomeEpochRotation ==
  /\ Core!SomeEpochRotation
  /\ UNCHANGED RecoveryExclusiveVars

TriggerCheckpointRollback ==
  /\ Core!TriggerCheckpointRollback
  /\ UNCHANGED RecoveryExclusiveVars

TriggerContinuationBoundaryChurn ==
  /\ Core!TriggerContinuationBoundaryChurn
  /\ UNCHANGED RecoveryExclusiveVars

Stabilize ==
  /\ Core!Stabilize
  /\ UNCHANGED RecoveryExclusiveVars

SomeTargetWitness ==
  /\ Core!SomeTargetWitness
  /\ UNCHANGED RecoveryExclusiveVars

SomeTargetVote ==
  /\ Core!SomeTargetVote
  /\ UNCHANGED RecoveryExclusiveVars

FinalizeTarget ==
  /\ Core!FinalizeTarget
  /\ UNCHANGED RecoveryExclusiveVars

StartNextCycle ==
  /\ Core!StartNextCycle
  /\ UNCHANGED RecoveryExclusiveVars

SomeRecoveryTargetShare ==
  \E w \in Witnesses :
    /\ Recovery!IssueShare(w, CurrentTargetSlot, CurrentTargetBlock)
    /\ Recovery!BoundedRecoveredPrefixSlice
    /\ UNCHANGED CoreExclusiveVars

CloseCurrentRecoveryWindow ==
  /\ Recovery!CloseWindow(CurrentTargetSlot)
  /\ Recovery!BoundedRecoveredPrefixSlice
  /\ UNCHANGED CoreExclusiveVars

RecoverCurrentTargetSlot ==
  /\ Recovery!RecoverSlot(CurrentTargetSlot, CurrentTargetBlock)
  /\ Recovery!BoundedRecoveredPrefixSlice
  /\ UNCHANGED CoreExclusiveVars

ExtractCurrentRecoveredSurface ==
  /\ Recovery!ExtractRecoveredSurface(CurrentTargetSlot, CurrentTargetBlock)
  /\ Recovery!BoundedRecoveredPrefixSlice
  /\ UNCHANGED CoreExclusiveVars

SomeCurrentMissingShare ==
  \E w \in Witnesses :
    /\ Recovery!IssueMissingShare(w, CurrentTargetSlot)
    /\ Recovery!BoundedRecoveredPrefixSlice
    /\ UNCHANGED CoreExclusiveVars

SomeCurrentMissingThreshold ==
  \E supporters \in SUBSET Recovery!Committee(CurrentTargetSlot) :
    /\ Recovery!CertifyMissingThreshold(CurrentTargetSlot, supporters)
    /\ Recovery!BoundedRecoveredPrefixSlice
    /\ UNCHANGED CoreExclusiveVars

DeclareCurrentMissingAbort ==
  /\ Recovery!DeclareMissingAbort(CurrentTargetSlot)
  /\ Recovery!BoundedRecoveredPrefixSlice
  /\ UNCHANGED CoreExclusiveVars

PublishRecoveryBoundContinuationAnchor ==
  /\ Core!PublishContinuationAnchor
  /\ CurrentTargetResolved
  /\ UNCHANGED RecoveryExclusiveVars

PublishRecoveryBoundContinuationPage ==
  /\ Core!PublishContinuationPage
  /\ CurrentTargetResolved
  /\ UNCHANGED RecoveryExclusiveVars

FetchRecoveryBoundContinuation ==
  /\ Core!FetchContinuation
  /\ CurrentTargetResolved
  /\ UNCHANGED RecoveryExclusiveVars

Next ==
  \/ SomeGuardianOutage
  \/ TriggerWitnessOutage
  \/ SomeTargetReassignment
  \/ SomeEpochRotation
  \/ TriggerCheckpointRollback
  \/ TriggerContinuationBoundaryChurn
  \/ Stabilize
  \/ SomeTargetWitness
  \/ SomeTargetVote
  \/ FinalizeTarget
  \/ SomeRecoveryTargetShare
  \/ CloseCurrentRecoveryWindow
  \/ RecoverCurrentTargetSlot
  \/ ExtractCurrentRecoveredSurface
  \/ SomeCurrentMissingShare
  \/ SomeCurrentMissingThreshold
  \/ DeclareCurrentMissingAbort
  \/ PublishRecoveryBoundContinuationAnchor
  \/ PublishRecoveryBoundContinuationPage
  \/ FetchRecoveryBoundContinuation
  \/ StartNextCycle

Init ==
  /\ Core!Init
  /\ Recovery!Init

TypeInvariant ==
  /\ Core!TypeInvariant
  /\ Recovery!TypeInvariant

RecoveryBoundContinuationSoundness ==
  \A c \in CycleRange :
    continuationFetched[c] => TargetSlotResolved(c)

RecoveryCycleTransferLandingSoundness ==
  \A c \in 2..TotalCycles :
    Core!CycleTransferLanding(c) => TargetSlotResolved(c - 1)

Invariant ==
  /\ TypeInvariant
  /\ Core!Safety
  /\ Core!FinalizationWitnessSoundness
  /\ Core!ContinuationSoundness
  /\ Core!CycleAdvanceRequiresPreviousFetch
  /\ Core!CycleTransferLandingSoundness
  /\ Recovery!Invariant
  /\ RecoveryBoundContinuationSoundness
  /\ RecoveryCycleTransferLandingSoundness

RecoveryRecurringCycleFetches ==
  \A c \in CycleRange :
    <>(continuationFetched[c] /\ TargetSlotResolved(c))

RecoveryEventuallyFinalCycleFetches ==
  <>(continuationFetched[TotalCycles] /\ TargetSlotResolved(TotalCycles))

RecoveryClosedPrefix(c) ==
  /\ c \in CycleRange
  /\ \A i \in 1..c :
       /\ continuationFetched[i]
       /\ TargetSlotResolved(i)

RecoveryRecurringClosedPrefixes ==
  \A c \in CycleRange :
    <>RecoveryClosedPrefix(c)

RecoveryCycleRecurrenceContract(c) ==
  /\ c \in 2..TotalCycles
  /\ []((Core!CycleTransferLanding(c) /\ TargetSlotResolved(c - 1))
        => <>(continuationFetched[c] /\ TargetSlotResolved(c)))
  /\ IF c < TotalCycles
        THEN []((currentCycle = c /\ continuationFetched[c] /\ TargetSlotResolved(c))
                => <>Core!CycleTransferLanding(c + 1))
        ELSE TRUE

RecoveryRecurringRecurrenceContracts ==
  \A c \in 2..TotalCycles :
    RecoveryCycleRecurrenceContract(c)

RecoveryPrefixAdvanceContract(c) ==
  /\ c \in PrefixAdvanceRange
  /\ []((currentCycle = c /\ RecoveryClosedPrefix(c))
        => <>RecoveryClosedPrefix(c + 1))

RecoveryRecurringPrefixAdvanceContracts ==
  \A c \in PrefixAdvanceRange :
    RecoveryPrefixAdvanceContract(c)

RecurringCycleTransfers == Core!RecurringCycleTransfers

RecoveryRecurringLivenessSpec ==
  /\ Init
  /\ [][Next]_vars
  /\ WF_vars(SomeGuardianOutage)
  /\ WF_vars(TriggerWitnessOutage)
  /\ WF_vars(SomeTargetReassignment)
  /\ WF_vars(SomeEpochRotation)
  /\ WF_vars(TriggerCheckpointRollback)
  /\ WF_vars(TriggerContinuationBoundaryChurn)
  /\ WF_vars(Stabilize)
  /\ WF_vars(SomeTargetWitness)
  /\ WF_vars(SomeTargetVote)
  /\ WF_vars(FinalizeTarget)
  /\ WF_vars(SomeRecoveryTargetShare)
  /\ WF_vars(CloseCurrentRecoveryWindow)
  /\ WF_vars(RecoverCurrentTargetSlot)
  /\ WF_vars(ExtractCurrentRecoveredSurface)
  /\ WF_vars(SomeCurrentMissingShare)
  /\ WF_vars(SomeCurrentMissingThreshold)
  /\ WF_vars(DeclareCurrentMissingAbort)
  /\ WF_vars(PublishRecoveryBoundContinuationAnchor)
  /\ WF_vars(PublishRecoveryBoundContinuationPage)
  /\ WF_vars(FetchRecoveryBoundContinuation)
  /\ WF_vars(StartNextCycle)

====
