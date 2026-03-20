---- MODULE NestedGuardianRecoveryRecurringLiveness ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANT Validators, Witnesses, Blocks, Slots, Epochs, QuorumSize, MaxReassignmentDepth,
         InitialEpoch, InitialWitness,
         TargetSlot1, TargetSlot2, TargetSlot3,
         TargetBlock1, TargetBlock2, TargetBlock3,
         StableEpoch1, StableEpoch2, StableEpoch3,
         SmallCommitteeSlot, SmallRecoveryThreshold, LargeRecoveryThreshold,
         SmallRecoveryCommittee, LargeRecoveryCommittee

ASSUME InitialEpoch \in Epochs
ASSUME InitialWitness \in Witnesses
ASSUME QuorumSize \in 1..Cardinality(Validators)
ASSUME TargetSlot1 \in Slots
ASSUME TargetSlot2 \in Slots
ASSUME TargetSlot3 \in Slots
ASSUME TargetBlock1 \in Blocks
ASSUME TargetBlock2 \in Blocks
ASSUME TargetBlock3 \in Blocks
ASSUME StableEpoch1 \in Epochs
ASSUME StableEpoch2 \in Epochs
ASSUME StableEpoch3 \in Epochs
ASSUME Cardinality({TargetSlot1, TargetSlot2, TargetSlot3}) = 3

VARIABLES votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
          witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase, churnStage,
          continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
          continuationPagePublished, continuationPageBoundary, continuationFetched,
          shareReceipts, shareConflicts, windowClosed, missingShareClaims,
          missingThresholdCertificates, recovered, recoveredSurfaces,
          recoveryConflicts, aborted

TotalCycles == 3

TargetSlotOf(c) ==
  IF c = 1 THEN TargetSlot1
  ELSE IF c = 2 THEN TargetSlot2
  ELSE TargetSlot3

TargetBlockOf(c) ==
  IF c = 1 THEN TargetBlock1
  ELSE IF c = 2 THEN TargetBlock2
  ELSE TargetBlock3

StableEpochOf(c) ==
  IF c = 1 THEN StableEpoch1
  ELSE IF c = 2 THEN StableEpoch2
  ELSE StableEpoch3

Core ==
  INSTANCE NestedGuardianRecoveryRecurringLivenessCore
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
       SmallCommitteeSlot <- SmallCommitteeSlot,
       SmallRecoveryThreshold <- SmallRecoveryThreshold,
       LargeRecoveryThreshold <- LargeRecoveryThreshold,
       SmallRecoveryCommittee <- SmallRecoveryCommittee,
       LargeRecoveryCommittee <- LargeRecoveryCommittee,
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
       continuationFetched <- continuationFetched,
       shareReceipts <- shareReceipts,
       shareConflicts <- shareConflicts,
       windowClosed <- windowClosed,
       missingShareClaims <- missingShareClaims,
       missingThresholdCertificates <- missingThresholdCertificates,
       recovered <- recovered,
       recoveredSurfaces <- recoveredSurfaces,
       recoveryConflicts <- recoveryConflicts,
       aborted <- aborted

Induction ==
  INSTANCE NestedGuardianRecoveryRecurringInductionCore
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
       SmallCommitteeSlot <- SmallCommitteeSlot,
       SmallRecoveryThreshold <- SmallRecoveryThreshold,
       LargeRecoveryThreshold <- LargeRecoveryThreshold,
       SmallRecoveryCommittee <- SmallRecoveryCommittee,
       LargeRecoveryCommittee <- LargeRecoveryCommittee,
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
       continuationFetched <- continuationFetched,
       shareReceipts <- shareReceipts,
       shareConflicts <- shareConflicts,
       windowClosed <- windowClosed,
       missingShareClaims <- missingShareClaims,
       missingThresholdCertificates <- missingThresholdCertificates,
       recovered <- recovered,
       recoveredSurfaces <- recoveredSurfaces,
       recoveryConflicts <- recoveryConflicts,
       aborted <- aborted

vars == Core!vars
TypeInvariant == Core!TypeInvariant
RecoveryBoundContinuationSoundness == Core!RecoveryBoundContinuationSoundness
RecoveryCycleTransferLandingSoundness == Core!RecoveryCycleTransferLandingSoundness
Invariant == Core!Invariant
RecoveryRecurringCycleFetches == Core!RecoveryRecurringCycleFetches
RecoveryEventuallyFinalCycleFetches == Core!RecoveryEventuallyFinalCycleFetches
RecoveryClosedPrefix(c) == Induction!RecoveryClosedPrefix(c)
RecoveryInductionBase == Induction!RecoveryInductionBase
RecoveryInductionStep(c) == Induction!RecoveryInductionStep(c)
RecoveryInductionPremisesUpTo(c) == Induction!RecoveryInductionPremisesUpTo(c)
RecoveryRecurringInductionPremises == Induction!RecoveryRecurringInductionPremises
RecoveryClosedPrefixInductionKernel(c) == Induction!RecoveryClosedPrefixInductionKernel(c)
RecoveryRecurringInductionKernel == Induction!RecoveryRecurringInductionKernel
ClassicalAgreementDecisionObject(c) ==
  [cycle |-> c,
   slot |-> TargetSlotOf(c),
   block |-> TargetBlockOf(c),
   epoch |-> StableEpochOf(c)]
ClassicalAgreementPrefixObject(c) ==
  [i \in 1..c |-> ClassicalAgreementDecisionObject(i)]
FiniteClassicalAgreementPrefixRealized(c) ==
  /\ c \in 1..TotalCycles
  /\ <>RecoveryClosedPrefix(c)
FiniteClassicalAgreementLiveness ==
  \A c \in 1..TotalCycles :
    FiniteClassicalAgreementPrefixRealized(c)
RecoveryRecurringClosedPrefixes == Core!RecoveryRecurringClosedPrefixes
RecoveryRecurringRecurrenceContracts == Core!RecoveryRecurringRecurrenceContracts
RecoveryRecurringPrefixAdvanceContracts == Core!RecoveryRecurringPrefixAdvanceContracts
RecurringCycleTransfers == Core!RecurringCycleTransfers
RecoveryRecurringLivenessSpec == Core!RecoveryRecurringLivenessSpec

====
