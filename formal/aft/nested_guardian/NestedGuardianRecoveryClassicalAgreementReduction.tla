---- MODULE NestedGuardianRecoveryClassicalAgreementReduction ----
EXTENDS Naturals, FiniteSets, TLC, TLAPS

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

Proof ==
  INSTANCE NestedGuardianRecoveryRecurringProof
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

ClassicalAgreementDecisionObject(c) ==
  [cycle |-> c,
   slot |-> TargetSlotOf(c),
   block |-> TargetBlockOf(c),
   epoch |-> StableEpochOf(c)]

ClassicalAgreementPrefixObject(c) ==
  [i \in 1..c |-> ClassicalAgreementDecisionObject(i)]

FiniteClassicalAgreementPrefixRealized(c) ==
  /\ c \in CycleRange
  /\ <>Proof!Core!RecoveryClosedPrefix(c)

FiniteClassicalAgreementLiveness ==
  \A c \in CycleRange :
    FiniteClassicalAgreementPrefixRealized(c)

ClassicalAgreementFiniteReduction ==
  Proof!RecoveryRecurringClosedPrefixes
    => FiniteClassicalAgreementLiveness

THEOREM ProofCycleRangeMatchesCycleRange ==
  Proof!Core!CycleRange = CycleRange
  BY DEF Proof!Core!CycleRange, Proof!Core!Core!CycleRange, CycleRange

THEOREM FiniteClassicalAgreementPrefixFromRecurringPrefixes ==
  \A c \in CycleRange :
    Proof!RecoveryRecurringClosedPrefixes
      => FiniteClassicalAgreementPrefixRealized(c)
PROOF
  <1>1. TAKE c \in CycleRange
  <1>2. ASSUME Proof!RecoveryRecurringClosedPrefixes
        PROVE FiniteClassicalAgreementPrefixRealized(c)
    <2>1. c \in Proof!Core!CycleRange
          BY ProofCycleRangeMatchesCycleRange, <1>1
    <2>2. <>Proof!Core!RecoveryClosedPrefix(c)
          BY <1>2, <2>1 DEF Proof!RecoveryRecurringClosedPrefixes
    <2>3. QED
          BY <1>1, <2>2 DEF FiniteClassicalAgreementPrefixRealized
  <1>3. QED
        BY <1>2

THEOREM ClassicalAgreementFiniteReductionTheorem ==
  ClassicalAgreementFiniteReduction
  BY FiniteClassicalAgreementPrefixFromRecurringPrefixes
     DEF ClassicalAgreementFiniteReduction,
         FiniteClassicalAgreementLiveness

====
