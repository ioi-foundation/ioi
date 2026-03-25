---- MODULE NestedGuardianRecurringLivenessFourCycle ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANT Validators, Witnesses, Blocks, Slots, Epochs, QuorumSize, MaxReassignmentDepth,
         InitialEpoch, InitialWitness,
         TargetSlot1, TargetSlot2, TargetSlot3, TargetSlot4,
         TargetBlock1, TargetBlock2, TargetBlock3, TargetBlock4,
         StableEpoch1, StableEpoch2, StableEpoch3, StableEpoch4

ASSUME InitialEpoch \in Epochs
ASSUME InitialWitness \in Witnesses
ASSUME QuorumSize \in 1..Cardinality(Validators)
ASSUME TargetSlot1 \in Slots
ASSUME TargetSlot2 \in Slots
ASSUME TargetSlot3 \in Slots
ASSUME TargetSlot4 \in Slots
ASSUME TargetBlock1 \in Blocks
ASSUME TargetBlock2 \in Blocks
ASSUME TargetBlock3 \in Blocks
ASSUME TargetBlock4 \in Blocks
ASSUME StableEpoch1 \in Epochs
ASSUME StableEpoch2 \in Epochs
ASSUME StableEpoch3 \in Epochs
ASSUME StableEpoch4 \in Epochs

VARIABLES votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
          witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase, churnStage,
          continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
          continuationPagePublished, continuationPageBoundary, continuationFetched

TotalCycles == 4

TargetSlotOf(c) ==
  IF c = 1 THEN TargetSlot1
  ELSE IF c = 2 THEN TargetSlot2
  ELSE IF c = 3 THEN TargetSlot3
  ELSE TargetSlot4

TargetBlockOf(c) ==
  IF c = 1 THEN TargetBlock1
  ELSE IF c = 2 THEN TargetBlock2
  ELSE IF c = 3 THEN TargetBlock3
  ELSE TargetBlock4

StableEpochOf(c) ==
  IF c = 1 THEN StableEpoch1
  ELSE IF c = 2 THEN StableEpoch2
  ELSE IF c = 3 THEN StableEpoch3
  ELSE StableEpoch4

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

vars == Core!vars
TypeInvariant == Core!TypeInvariant
Safety == Core!Safety
FinalizationWitnessSoundness == Core!FinalizationWitnessSoundness
ContinuationSoundness == Core!ContinuationSoundness
CycleAdvanceRequiresPreviousFetch == Core!CycleAdvanceRequiresPreviousFetch
CycleTransferLanding(c) == Core!CycleTransferLanding(c)
CycleTransferLandingSoundness == Core!CycleTransferLandingSoundness
EventuallyFinalCycleFetches == Core!EventuallyFinalCycleFetches
RecurringCycleFetches == Core!RecurringCycleFetches
RecurringCycleTransfers == Core!RecurringCycleTransfers
RecurringLivenessSpec == Core!RecurringLivenessSpec

====
