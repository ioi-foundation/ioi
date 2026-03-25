---- MODULE NestedGuardianRecoveryClassicalAgreementTotality ----
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

Reduction ==
  INSTANCE NestedGuardianRecoveryClassicalAgreementReduction
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

CycleRange == 1..TotalCycles

RecoveryRecurringClosedPrefixes == Reduction!Proof!RecoveryRecurringClosedPrefixes
RecoveryRecurringInductionPremises == Reduction!Proof!Core!RecoveryRecurringInductionPremises
RecoveryRecurringInductionKernel == Reduction!Proof!Core!RecoveryRecurringInductionKernel
RecoveryClosedPrefix(c) == Reduction!Proof!Core!RecoveryClosedPrefix(c)

ClassicalAgreementTotalHistoryObject ==
  [i \in CycleRange |-> Reduction!ClassicalAgreementDecisionObject(i)]

ClassicalAgreementTotalHistoryExtendsFinitePrefixes ==
  \A c \in CycleRange :
    [i \in 1..c |-> ClassicalAgreementTotalHistoryObject[i]]
      = Reduction!ClassicalAgreementPrefixObject(c)

TotalClassicalAgreementHistoryRealized ==
  /\ <>RecoveryClosedPrefix(TotalCycles)
  /\ ClassicalAgreementTotalHistoryExtendsFinitePrefixes

TotalClassicalAgreementReduction ==
  Reduction!FiniteClassicalAgreementLiveness
    => TotalClassicalAgreementHistoryRealized

TotalClassicalAgreementFromRecurringPrefixes ==
  RecoveryRecurringClosedPrefixes
    => TotalClassicalAgreementHistoryRealized

TotalClassicalAgreementFromRecurrenceKernel ==
  /\ RecoveryRecurringInductionPremises
  /\ RecoveryRecurringInductionKernel
  => TotalClassicalAgreementHistoryRealized

THEOREM TotalHistoryEntryMatchesDecisionObject ==
  \A c \in CycleRange :
    \A i \in 1..c :
      ClassicalAgreementTotalHistoryObject[i]
        = Reduction!ClassicalAgreementDecisionObject(i)
  BY SMT, TotalCyclesIsNat, TotalCyclesAtLeastOne
     DEF CycleRange, ClassicalAgreementTotalHistoryObject

THEOREM ClassicalAgreementTotalHistoryExtendsFinitePrefixesTheorem ==
  ClassicalAgreementTotalHistoryExtendsFinitePrefixes
PROOF
  <1>1. \A c \in CycleRange :
           [i \in 1..c |-> ClassicalAgreementTotalHistoryObject[i]]
             = Reduction!ClassicalAgreementPrefixObject(c)
    PROOF
      <2>1. TAKE c \in CycleRange
      <2>2. \A i \in 1..c :
               ClassicalAgreementTotalHistoryObject[i]
                 = Reduction!ClassicalAgreementDecisionObject(i)
            BY TotalHistoryEntryMatchesDecisionObject, <2>1
      <2>3. QED
            BY IsaWithSetExtensionality, <2>1, <2>2
               DEF Reduction!ClassicalAgreementPrefixObject
  <1>2. QED
        BY <1>1 DEF ClassicalAgreementTotalHistoryExtendsFinitePrefixes

THEOREM TotalCyclesInCycleRange ==
  TotalCycles \in CycleRange
  BY SMT, TotalCyclesIsNat, TotalCyclesAtLeastOne DEF CycleRange

THEOREM TotalFinitePrefixFromFiniteLiveness ==
  Reduction!FiniteClassicalAgreementLiveness
    => Reduction!FiniteClassicalAgreementPrefixRealized(TotalCycles)
PROOF
  <1>1. ASSUME Reduction!FiniteClassicalAgreementLiveness
        PROVE Reduction!FiniteClassicalAgreementPrefixRealized(TotalCycles)
    <2>1. TotalCycles \in Reduction!CycleRange
          BY TotalCyclesInCycleRange DEF CycleRange, Reduction!CycleRange
    <2>2. QED
          BY <1>1, <2>1 DEF Reduction!FiniteClassicalAgreementLiveness
  <1>2. QED
        BY <1>1

THEOREM TotalRecoveryClosedPrefixFromFiniteLiveness ==
  Reduction!FiniteClassicalAgreementLiveness
    => <>RecoveryClosedPrefix(TotalCycles)
  BY TotalFinitePrefixFromFiniteLiveness
     DEF Reduction!FiniteClassicalAgreementPrefixRealized,
         RecoveryClosedPrefix

THEOREM TotalClassicalAgreementReductionTheorem ==
  TotalClassicalAgreementReduction
  BY TotalRecoveryClosedPrefixFromFiniteLiveness,
     ClassicalAgreementTotalHistoryExtendsFinitePrefixesTheorem
     DEF TotalClassicalAgreementReduction,
         TotalClassicalAgreementHistoryRealized

THEOREM ReductionLivenessFromRecurringPrefixes ==
  RecoveryRecurringClosedPrefixes
    => Reduction!FiniteClassicalAgreementLiveness
PROOF
  <1>1. ASSUME RecoveryRecurringClosedPrefixes
        PROVE Reduction!FiniteClassicalAgreementLiveness
    <2>1. \A c \in Reduction!CycleRange :
             Reduction!FiniteClassicalAgreementPrefixRealized(c)
      PROOF
        <3>1. TAKE c \in Reduction!CycleRange
        <3>2. c \in Reduction!Proof!Core!CycleRange
              BY <3>1
                 DEF Reduction!CycleRange,
                     Reduction!Proof!Core!CycleRange,
                     Reduction!Proof!Core!Core!CycleRange
        <3>3. Reduction!Proof!RecoveryRecurringClosedPrefixes
              BY <1>1 DEF RecoveryRecurringClosedPrefixes
        <3>4. <>Reduction!Proof!Core!RecoveryClosedPrefix(c)
              BY <3>2, <3>3 DEF Reduction!Proof!RecoveryRecurringClosedPrefixes
        <3>5. QED
              BY <3>1, <3>4 DEF Reduction!FiniteClassicalAgreementPrefixRealized
    <2>2. QED
          BY <2>1 DEF Reduction!FiniteClassicalAgreementLiveness
  <1>2. QED
        BY <1>1

THEOREM TotalClassicalAgreementFromRecurringPrefixesTheorem ==
  TotalClassicalAgreementFromRecurringPrefixes
PROOF
  <1>1. ASSUME RecoveryRecurringClosedPrefixes
        PROVE TotalClassicalAgreementHistoryRealized
    <2>1. Reduction!FiniteClassicalAgreementLiveness
          BY ReductionLivenessFromRecurringPrefixes, <1>1
    <2>2. Reduction!FiniteClassicalAgreementLiveness
             => TotalClassicalAgreementHistoryRealized
          BY TotalClassicalAgreementReductionTheorem
             DEF TotalClassicalAgreementReduction
    <2>3. QED
          BY <2>1, <2>2
  <1>2. QED
        BY <1>1 DEF TotalClassicalAgreementFromRecurringPrefixes

THEOREM RecoveryRecurringClosedPrefixesFromRecurrenceKernel ==
  /\ RecoveryRecurringInductionPremises
  /\ RecoveryRecurringInductionKernel
  => RecoveryRecurringClosedPrefixes
PROOF
  <1>1. ASSUME RecoveryRecurringInductionPremises,
               RecoveryRecurringInductionKernel
        PROVE RecoveryRecurringClosedPrefixes
    <2>1. \A c \in Reduction!Proof!Core!CycleRange :
             <>Reduction!Proof!Core!RecoveryClosedPrefix(c)
      PROOF
        <3>1. TAKE c \in Reduction!Proof!Core!CycleRange
        <3>2. Reduction!Proof!Core!RecoveryInductionPremisesUpTo(c)
          PROOF
            <4>1. Reduction!Proof!Core!RecoveryInductionBase
                  BY <1>1
                     DEF RecoveryRecurringInductionPremises,
                         Reduction!Proof!Core!RecoveryRecurringInductionPremises
            <4>2. \A i \in Reduction!Proof!Core!PriorCycleRange(c) :
                     Reduction!Proof!Core!RecoveryInductionStep(i)
              PROOF
                <5>1. TAKE i \in Reduction!Proof!Core!PriorCycleRange(c)
                <5>2. TotalCycles # 1
                      BY SMT, TotalCyclesIsNat, TotalCyclesAtLeastOne, <3>1, <5>1
                         DEF Reduction!Proof!Core!CycleRange,
                             Reduction!Proof!Core!Core!CycleRange,
                             Reduction!Proof!Core!PriorCycleRange
                <5>3. i \in 1..(TotalCycles - 1)
                      BY SMT, TotalCyclesIsNat, TotalCyclesAtLeastOne, <3>1, <5>1
                         DEF Reduction!Proof!Core!CycleRange,
                             Reduction!Proof!Core!Core!CycleRange,
                             Reduction!Proof!Core!PriorCycleRange
                <5>4. i \in Reduction!Proof!Core!PrefixAdvanceRange
                      BY <5>2, <5>3
                         DEF Reduction!Proof!Core!PrefixAdvanceRange,
                             Reduction!Proof!Core!Core!PrefixAdvanceRange
                <5>5. QED
                      BY <1>1, <5>4
                         DEF RecoveryRecurringInductionPremises,
                             Reduction!Proof!Core!RecoveryRecurringInductionPremises
              <4>3. QED
                    BY <3>1, <4>1, <4>2
                       DEF Reduction!Proof!Core!RecoveryInductionPremisesUpTo
        <3>3. Reduction!Proof!Core!RecoveryClosedPrefixInductionKernel(c)
              BY <1>1, <3>1
                 DEF RecoveryRecurringInductionKernel,
                     Reduction!Proof!Core!RecoveryRecurringInductionKernel
            <3>4. QED
                  BY <3>2, <3>3
                     DEF Reduction!Proof!Core!RecoveryClosedPrefixInductionKernel
    <2>2. QED
          BY <2>1 DEF RecoveryRecurringClosedPrefixes,
                     Reduction!Proof!RecoveryRecurringClosedPrefixes
  <1>2. QED
        BY <1>1
           DEF RecoveryRecurringClosedPrefixes,
               RecoveryRecurringInductionPremises,
               RecoveryRecurringInductionKernel,
               Reduction!Proof!RecoveryRecurringClosedPrefixes

THEOREM TotalClassicalAgreementFromRecurrenceKernelTheorem ==
  TotalClassicalAgreementFromRecurrenceKernel
PROOF
  <1>1. ASSUME RecoveryRecurringInductionPremises,
               RecoveryRecurringInductionKernel
        PROVE TotalClassicalAgreementHistoryRealized
    <2>1. RecoveryRecurringClosedPrefixes
          BY RecoveryRecurringClosedPrefixesFromRecurrenceKernel, <1>1
    <2>2. TotalClassicalAgreementFromRecurringPrefixes
          BY TotalClassicalAgreementFromRecurringPrefixesTheorem
    <2>3. QED
          BY <2>1, <2>2 DEF TotalClassicalAgreementFromRecurringPrefixes
  <1>2. QED
        BY <1>1 DEF TotalClassicalAgreementFromRecurrenceKernel

====
