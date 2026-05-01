---- MODULE NestedGuardianRecoveryRecurringInductionCore ----
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

vars == Core!vars
CycleRange == Core!CycleRange
PrefixAdvanceRange == Core!PrefixAdvanceRange
RecoveryClosedPrefix(c) == Core!RecoveryClosedPrefix(c)

PriorCycleRange(c) ==
  IF c = 1 THEN {}
  ELSE 1..(c - 1)

RecoveryInductionBase ==
  <>RecoveryClosedPrefix(1)

RecoveryInductionStep(c) ==
  /\ c \in PrefixAdvanceRange
  /\ Core!RecoveryPrefixAdvanceContract(c)

RecoveryInductionPremisesUpTo(c) ==
  /\ c \in CycleRange
  /\ RecoveryInductionBase
  /\ \A i \in PriorCycleRange(c) :
       RecoveryInductionStep(i)

RecoveryRecurringInductionPremises ==
  /\ RecoveryInductionBase
  /\ \A i \in PrefixAdvanceRange :
       RecoveryInductionStep(i)

RecoveryClosedPrefixInductionKernel(c) ==
  /\ c \in CycleRange
  /\ (RecoveryInductionPremisesUpTo(c)
      => <>RecoveryClosedPrefix(c))

RecoveryRecurringInductionKernel ==
  \A c \in CycleRange :
    RecoveryClosedPrefixInductionKernel(c)

====
