---- MODULE NestedGuardianRecoveryClassicalAgreementCollapse ----
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

Totality ==
  INSTANCE NestedGuardianRecoveryClassicalAgreementTotality
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

CycleRange == Totality!CycleRange

ClassicalAgreementDecision(c) ==
  [cycle |-> c,
   slot |-> TargetSlotOf(c),
   block |-> TargetBlockOf(c),
   epoch |-> StableEpochOf(c)]

ClassicalAgreementHistory(history) ==
  \A i \in CycleRange :
    history[i] = ClassicalAgreementDecision(i)

OrdinaryClassicalAgreementHistory(history) ==
  /\ ClassicalAgreementHistory(history)
  /\ <>Totality!RecoveryClosedPrefix(TotalCycles)

UnconditionalClassicalAgreementSentence ==
  OrdinaryClassicalAgreementHistory(
    Totality!ClassicalAgreementTotalHistoryObject
  )

THEOREM TotalHistoryMatchesCollapsedClassicalHistory ==
  ClassicalAgreementHistory(Totality!ClassicalAgreementTotalHistoryObject)
PROOF
  <1>1. \A i \in CycleRange :
           Totality!ClassicalAgreementTotalHistoryObject[i]
             = ClassicalAgreementDecision(i)
    PROOF
      <2>1. TAKE i \in CycleRange
      <2>2. QED
            BY <2>1
               DEF ClassicalAgreementDecision,
                   CycleRange,
                   Totality!ClassicalAgreementTotalHistoryObject,
                   Totality!Reduction!ClassicalAgreementDecisionObject
  <1>2. QED
        BY <1>1 DEF ClassicalAgreementHistory

THEOREM TotalityCyclePrefixEntriesStayInCycleRange ==
  \A c \in Totality!CycleRange :
    \A i \in 1..c :
      i \in Totality!CycleRange
  BY SMT, TotalCyclesIsNat, TotalCyclesAtLeastOne
     DEF Totality!CycleRange

THEOREM TotalityReductionCorePriorCycleRangeImpliesPrefixAdvanceRange ==
  \A c \in Totality!Reduction!Proof!Core!CycleRange :
    \A i \in Totality!Reduction!Proof!Core!PriorCycleRange(c) :
      i \in Totality!Reduction!Proof!Core!PrefixAdvanceRange
  BY SMT, TotalCyclesIsNat, TotalCyclesAtLeastOne
     DEF Totality!Reduction!Proof!Core!CycleRange,
         Totality!Reduction!Proof!Core!Core!CycleRange,
         Totality!Reduction!Proof!Core!PriorCycleRange,
         Totality!Reduction!Proof!Core!PrefixAdvanceRange,
         Totality!Reduction!Proof!Core!Core!PrefixAdvanceRange

THEOREM LocalReductionLivenessFromRecurringPrefixesTheorem ==
  Totality!RecoveryRecurringClosedPrefixes
    => Totality!Reduction!FiniteClassicalAgreementLiveness
PROOF
  <1>1. ASSUME Totality!RecoveryRecurringClosedPrefixes
        PROVE Totality!Reduction!FiniteClassicalAgreementLiveness
    <2>1. \A c \in Totality!Reduction!CycleRange :
             Totality!Reduction!FiniteClassicalAgreementPrefixRealized(c)
      PROOF
        <3>1. TAKE c \in Totality!Reduction!CycleRange
        <3>2. c \in Totality!Reduction!Proof!Core!CycleRange
              BY <3>1
                 DEF Totality!Reduction!CycleRange,
                     Totality!Reduction!Proof!Core!CycleRange,
                     Totality!Reduction!Proof!Core!Core!CycleRange
        <3>3. <>Totality!Reduction!Proof!Core!RecoveryClosedPrefix(c)
              BY <1>1, <3>2
                 DEF Totality!RecoveryRecurringClosedPrefixes,
                     Totality!Reduction!Proof!RecoveryRecurringClosedPrefixes
        <3>4. QED
              BY <3>1, <3>3
                 DEF Totality!Reduction!FiniteClassicalAgreementPrefixRealized
      <2>2. QED
            BY <2>1 DEF Totality!Reduction!FiniteClassicalAgreementLiveness
  <1>2. QED
        BY <1>1

THEOREM LocalTotalClassicalAgreementHistoryFromFiniteLivenessTheorem ==
  Totality!Reduction!FiniteClassicalAgreementLiveness
    => Totality!TotalClassicalAgreementHistoryRealized
PROOF
  <1>1. ASSUME Totality!Reduction!FiniteClassicalAgreementLiveness
        PROVE Totality!TotalClassicalAgreementHistoryRealized
    <2>1. TotalCycles \in Totality!Reduction!CycleRange
          BY SMT, TotalCyclesIsNat, TotalCyclesAtLeastOne
             DEF Totality!Reduction!CycleRange
    <2>2. Totality!Reduction!FiniteClassicalAgreementPrefixRealized(TotalCycles)
          BY <1>1, <2>1 DEF Totality!Reduction!FiniteClassicalAgreementLiveness
    <2>3. <>Totality!RecoveryClosedPrefix(TotalCycles)
          BY <2>2
             DEF Totality!Reduction!FiniteClassicalAgreementPrefixRealized,
                 Totality!RecoveryClosedPrefix
    <2>4. Totality!ClassicalAgreementTotalHistoryExtendsFinitePrefixes
      PROOF
        <3>1. \A c \in Totality!CycleRange :
                 [i \in 1..c |-> Totality!ClassicalAgreementTotalHistoryObject[i]]
                   = Totality!Reduction!ClassicalAgreementPrefixObject(c)
          PROOF
            <4>1. TAKE c \in Totality!CycleRange
            <4>2. \A i \in 1..c :
                     Totality!ClassicalAgreementTotalHistoryObject[i]
                       = Totality!Reduction!ClassicalAgreementDecisionObject(i)
              PROOF
                <5>1. TAKE i \in 1..c
                <5>2. c \in 1..TotalCycles
                      BY <4>1 DEF Totality!CycleRange
                <5>3. i \in Totality!CycleRange
                      BY TotalityCyclePrefixEntriesStayInCycleRange, <4>1, <5>1
                <5>4. QED
                      BY <5>3
                         DEF Totality!ClassicalAgreementTotalHistoryObject
              <4>3. QED
                    BY IsaWithSetExtensionality, <4>1, <4>2
                       DEF Totality!Reduction!ClassicalAgreementPrefixObject
        <3>2. QED
              BY <3>1 DEF Totality!ClassicalAgreementTotalHistoryExtendsFinitePrefixes
    <2>5. QED
          BY <2>3, <2>4 DEF Totality!TotalClassicalAgreementHistoryRealized
  <1>2. QED
        BY <1>1

THEOREM LocalRecurringPrefixesFromRecurrenceKernelTheorem ==
  /\ Totality!RecoveryRecurringInductionPremises
  /\ Totality!RecoveryRecurringInductionKernel
  => Totality!RecoveryRecurringClosedPrefixes
PROOF
  <1>1. ASSUME Totality!RecoveryRecurringInductionPremises,
               Totality!RecoveryRecurringInductionKernel
        PROVE Totality!RecoveryRecurringClosedPrefixes
    <2>1. \A c \in Totality!Reduction!Proof!Core!CycleRange :
             <>Totality!Reduction!Proof!Core!RecoveryClosedPrefix(c)
      PROOF
        <3>1. TAKE c \in Totality!Reduction!Proof!Core!CycleRange
        <3>2. /\ Totality!Reduction!Proof!Core!RecoveryRecurringInductionPremises
              /\ Totality!Reduction!Proof!Core!RecoveryRecurringInductionKernel
              BY <1>1
                 DEF Totality!RecoveryRecurringInductionPremises,
                     Totality!RecoveryRecurringInductionKernel
        <3>3. Totality!Reduction!Proof!Core!RecoveryInductionPremisesUpTo(c)
          PROOF
            <4>1. Totality!Reduction!Proof!Core!RecoveryInductionBase
                  BY <3>2
                     DEF Totality!Reduction!Proof!Core!RecoveryRecurringInductionPremises
            <4>2. \A i \in Totality!Reduction!Proof!Core!PriorCycleRange(c) :
                     Totality!Reduction!Proof!Core!RecoveryInductionStep(i)
              PROOF
                <5>1. TAKE i \in Totality!Reduction!Proof!Core!PriorCycleRange(c)
                <5>2. i \in Totality!Reduction!Proof!Core!PrefixAdvanceRange
                      BY TotalityReductionCorePriorCycleRangeImpliesPrefixAdvanceRange,
                         <3>1, <5>1
                <5>3. QED
                      BY <3>2, <5>2
                         DEF Totality!Reduction!Proof!Core!RecoveryRecurringInductionPremises
            <4>3. QED
                  BY <3>1, <4>1, <4>2
                     DEF Totality!Reduction!Proof!Core!RecoveryInductionPremisesUpTo
        <3>4. Totality!Reduction!Proof!Core!RecoveryClosedPrefixInductionKernel(c)
              BY <3>1, <3>2
                 DEF Totality!Reduction!Proof!Core!RecoveryRecurringInductionKernel
        <3>5. <>Totality!Reduction!Proof!Core!RecoveryClosedPrefix(c)
              BY <3>3, <3>4
                 DEF Totality!Reduction!Proof!Core!RecoveryClosedPrefixInductionKernel
        <3>6. (/\ Totality!Reduction!Proof!Core!RecoveryRecurringInductionPremises
                /\ Totality!Reduction!Proof!Core!RecoveryRecurringInductionKernel)
                => <>Totality!Reduction!Proof!Core!RecoveryClosedPrefix(c)
              BY <3>5
        <3>7. QED
              BY <3>5
    <2>2. QED
            BY <2>1
               DEF Totality!RecoveryRecurringClosedPrefixes,
                   Totality!Reduction!Proof!RecoveryRecurringClosedPrefixes
  <1>2. QED
        BY <1>1

THEOREM UnconditionalClassicalAgreementFromTotalHistoryTheorem ==
  Totality!TotalClassicalAgreementHistoryRealized
    => UnconditionalClassicalAgreementSentence
PROOF
  <1>1. ASSUME Totality!TotalClassicalAgreementHistoryRealized
        PROVE UnconditionalClassicalAgreementSentence
    <2>1. ClassicalAgreementHistory(Totality!ClassicalAgreementTotalHistoryObject)
          BY TotalHistoryMatchesCollapsedClassicalHistory
    <2>2. <>Totality!RecoveryClosedPrefix(TotalCycles)
          BY <1>1 DEF Totality!TotalClassicalAgreementHistoryRealized
    <2>3. QED
          BY <2>1, <2>2
             DEF UnconditionalClassicalAgreementSentence,
                 OrdinaryClassicalAgreementHistory
  <1>2. QED
        BY <1>1

THEOREM UnconditionalClassicalAgreementFromRecurringPrefixesTheorem ==
  Totality!RecoveryRecurringClosedPrefixes
    => UnconditionalClassicalAgreementSentence
PROOF
  <1>1. ASSUME Totality!RecoveryRecurringClosedPrefixes
        PROVE UnconditionalClassicalAgreementSentence
    <2>1. Totality!Reduction!FiniteClassicalAgreementLiveness
          BY LocalReductionLivenessFromRecurringPrefixesTheorem, <1>1
    <2>2. Totality!TotalClassicalAgreementHistoryRealized
          BY LocalTotalClassicalAgreementHistoryFromFiniteLivenessTheorem, <2>1
    <2>3. QED
          BY UnconditionalClassicalAgreementFromTotalHistoryTheorem, <2>2
  <1>2. QED
        BY <1>1

THEOREM UnconditionalClassicalAgreementFromRecurrenceKernelTheorem ==
  /\ Totality!RecoveryRecurringInductionPremises
  /\ Totality!RecoveryRecurringInductionKernel
  => UnconditionalClassicalAgreementSentence
PROOF
  <1>1. ASSUME Totality!RecoveryRecurringInductionPremises,
               Totality!RecoveryRecurringInductionKernel
        PROVE UnconditionalClassicalAgreementSentence
    <2>1. Totality!RecoveryRecurringClosedPrefixes
          BY LocalRecurringPrefixesFromRecurrenceKernelTheorem, <1>1
    <2>2. Totality!Reduction!FiniteClassicalAgreementLiveness
          BY LocalReductionLivenessFromRecurringPrefixesTheorem, <2>1
    <2>3. Totality!TotalClassicalAgreementHistoryRealized
          BY LocalTotalClassicalAgreementHistoryFromFiniteLivenessTheorem, <2>2
    <2>4. QED
          BY UnconditionalClassicalAgreementFromTotalHistoryTheorem, <2>3
  <1>3. QED
        BY <1>1

====
