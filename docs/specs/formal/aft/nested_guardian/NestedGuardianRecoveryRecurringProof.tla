---- MODULE NestedGuardianRecoveryRecurringProof ----
EXTENDS Naturals, FiniteSets, TLC, TLAPS

CONSTANT Validators, Witnesses, Blocks, Slots, Epochs, QuorumSize, MaxReassignmentDepth,
         InitialEpoch, InitialWitness, TotalCycles,
         TargetSlotOf(_), TargetBlockOf(_), StableEpochOf(_),
         SmallCommitteeSlot, SmallRecoveryThreshold, LargeRecoveryThreshold,
         SmallRecoveryCommittee, LargeRecoveryCommittee

ASSUME InitialEpochInEpochs == InitialEpoch \in Epochs
ASSUME InitialWitnessInWitnesses == InitialWitness \in Witnesses
ASSUME QuorumSizeInValidatorRange == QuorumSize \in 1..Cardinality(Validators)
ASSUME TotalCyclesIsNat == TotalCycles \in Nat
ASSUME TotalCyclesAtLeastOne == TotalCycles >= 1
ASSUME TargetCycleDomains ==
  \A c \in 1..TotalCycles :
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

RecoveryRecurringClosedPrefixes ==
  \A c \in Core!CycleRange :
    <>Core!RecoveryClosedPrefix(c)

RecoveryParametricRecurrenceArgument ==
  /\ Core!RecoveryRecurringInductionPremises
  /\ Core!RecoveryRecurringInductionKernel
  => RecoveryRecurringClosedPrefixes

THEOREM PriorCycleRangeImpliesTotalCyclesNotOne ==
  \A c \in Core!CycleRange :
    \A i \in Core!PriorCycleRange(c) :
      TotalCycles # 1
  BY SMT, TotalCyclesIsNat, TotalCyclesAtLeastOne
     DEF Core!CycleRange, Core!Core!CycleRange, Core!PriorCycleRange

THEOREM PriorCycleRangeImpliesPrefixAdvanceInterval ==
  \A c \in Core!CycleRange :
    \A i \in Core!PriorCycleRange(c) :
      i \in 1..(TotalCycles - 1)
  BY SMT, TotalCyclesIsNat, TotalCyclesAtLeastOne
     DEF Core!CycleRange, Core!Core!CycleRange, Core!PriorCycleRange

THEOREM RecoveryInductionPremisesRestrict ==
  \A c \in Core!CycleRange :
    Core!RecoveryRecurringInductionPremises
      => Core!RecoveryInductionPremisesUpTo(c)
PROOF
  <1>1. TAKE c \in Core!CycleRange
  <1>2. ASSUME Core!RecoveryRecurringInductionPremises
        PROVE Core!RecoveryInductionPremisesUpTo(c)
    <2>1. Core!RecoveryInductionBase
          BY <1>2 DEF Core!RecoveryRecurringInductionPremises
    <2>2. \A i \in Core!PriorCycleRange(c) :
             Core!RecoveryInductionStep(i)
      PROOF
        <3>1. TAKE i \in Core!PriorCycleRange(c)
        <3>2. i \in Core!PrefixAdvanceRange
          PROOF
            <4>1. TotalCycles # 1
                  BY PriorCycleRangeImpliesTotalCyclesNotOne, <1>1, <3>1
            <4>2. i \in 1..(TotalCycles - 1)
                  BY PriorCycleRangeImpliesPrefixAdvanceInterval, <1>1, <3>1
            <4>3. TotalCycles # 1
                  BY <4>1
            <4>6. QED
                  BY <4>3, <4>2
                     DEF Core!PrefixAdvanceRange, Core!Core!PrefixAdvanceRange
        <3>3. Core!RecoveryInductionStep(i)
              BY <1>2, <3>2 DEF Core!RecoveryRecurringInductionPremises
        <3>4. QED
              BY <3>3
      <2>3. QED
          BY <1>1, <2>1, <2>2
             DEF Core!RecoveryInductionPremisesUpTo
  <1>3. QED
        BY <1>2

THEOREM RecoveryInductionKernelRestrict ==
  \A c \in Core!CycleRange :
    Core!RecoveryRecurringInductionKernel
      => Core!RecoveryClosedPrefixInductionKernel(c)
  BY DEF Core!RecoveryRecurringInductionKernel,
         Core!RecoveryClosedPrefixInductionKernel,
         Core!CycleRange

THEOREM RecoveryRecurringClosedPrefixFromKernel ==
  \A c \in Core!CycleRange :
    /\ Core!RecoveryRecurringInductionPremises
    /\ Core!RecoveryRecurringInductionKernel
    => <>Core!RecoveryClosedPrefix(c)
PROOF
  <1>1. TAKE c \in Core!CycleRange
  <1>2. ASSUME Core!RecoveryRecurringInductionPremises,
               Core!RecoveryRecurringInductionKernel
        PROVE <>Core!RecoveryClosedPrefix(c)
    <2>1. Core!RecoveryInductionPremisesUpTo(c)
          BY RecoveryInductionPremisesRestrict, <1>1, <1>2
    <2>2. Core!RecoveryClosedPrefixInductionKernel(c)
          BY RecoveryInductionKernelRestrict, <1>1, <1>2
    <2>3. QED
          BY <2>1, <2>2
             DEF Core!RecoveryClosedPrefixInductionKernel
  <1>3. QED
        BY <1>2

THEOREM RecoveryParametricRecurrenceArgumentTheorem ==
  RecoveryParametricRecurrenceArgument
  BY RecoveryRecurringClosedPrefixFromKernel
     DEF RecoveryParametricRecurrenceArgument,
         RecoveryRecurringClosedPrefixes

====
