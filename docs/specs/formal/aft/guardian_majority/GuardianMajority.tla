---- MODULE GuardianMajority ----
EXTENDS Naturals, FiniteSets, TLC, TLAPS

CONSTANT Validators, Blocks, Slots, Epochs, QuorumSize, InitialEpoch

ASSUME InitialEpochInEpochs == InitialEpoch \in Epochs

ASSUME QuorumIntersection ==
  \A S, T \in SUBSET Validators :
    /\ Cardinality(S) >= QuorumSize
    /\ Cardinality(T) >= QuorumSize
    => S \cap T # {}

VARIABLES votes, finalized, finalizerSets, registryEpoch, manifestEpoch, guardianReady, checkpointLevel

vars == <<votes, finalized, finalizerSets, registryEpoch, manifestEpoch, guardianReady, checkpointLevel>>

CheckpointLevels == 0..2

VoteEvent(v, s, b, e) == <<v, s, b, e>>
Finalization(s, b, e) == <<s, b, e>>

VoteDomain == {VoteEvent(v, s, b, e) : v \in Validators, s \in Slots, b \in Blocks, e \in Epochs}
FinalizationDomain == {Finalization(s, b, e) : s \in Slots, b \in Blocks, e \in Epochs}

Init ==
  /\ votes = {}
  /\ finalized = {}
  /\ finalizerSets = [f \in FinalizationDomain |-> {}]
  /\ registryEpoch = [v \in Validators |-> InitialEpoch]
  /\ manifestEpoch = [v \in Validators |-> InitialEpoch]
  /\ guardianReady = [v \in Validators |-> TRUE]
  /\ checkpointLevel = [v \in Validators |-> 1]

HasVote(v, s) ==
  \E b \in Blocks, e \in Epochs : VoteEvent(v, s, b, e) \in votes

CanVote(v, s, b, e) ==
  /\ v \in Validators
  /\ s \in Slots
  /\ b \in Blocks
  /\ e \in Epochs
  /\ guardianReady[v]
  /\ checkpointLevel[v] > 0
  /\ registryEpoch[v] = e
  /\ manifestEpoch[v] = e
  /\ ~HasVote(v, s)

Vote(v, s, b, e) ==
  /\ CanVote(v, s, b, e)
  /\ votes' = votes \cup {VoteEvent(v, s, b, e)}
  /\ UNCHANGED <<finalized, finalizerSets, registryEpoch, manifestEpoch, guardianReady, checkpointLevel>>

EligibleVoters(s, b, e) ==
  {v \in Validators :
      /\ VoteEvent(v, s, b, e) \in votes
      /\ guardianReady[v]
      /\ checkpointLevel[v] > 0
      /\ registryEpoch[v] = e
      /\ manifestEpoch[v] = e}

CanFinalize(s, b, e) ==
  /\ s \in Slots
  /\ b \in Blocks
  /\ e \in Epochs
  /\ Cardinality(EligibleVoters(s, b, e)) >= QuorumSize

Finalize(s, b, e) ==
  /\ CanFinalize(s, b, e)
  /\ finalized' = finalized \cup {Finalization(s, b, e)}
  /\ finalizerSets' = [finalizerSets EXCEPT ![Finalization(s, b, e)] = EligibleVoters(s, b, e)]
  /\ UNCHANGED <<votes, registryEpoch, manifestEpoch, guardianReady, checkpointLevel>>

AdoptEpoch(v, e) ==
  /\ v \in Validators
  /\ e \in Epochs
  /\ e >= registryEpoch[v]
  /\ registryEpoch' = [registryEpoch EXCEPT ![v] = e]
  /\ manifestEpoch' = [manifestEpoch EXCEPT ![v] = e]
  /\ UNCHANGED <<votes, finalized, finalizerSets, guardianReady, checkpointLevel>>

RegistryRollback(v, e) ==
  /\ v \in Validators
  /\ e \in Epochs
  /\ e < registryEpoch[v]
  /\ registryEpoch' = [registryEpoch EXCEPT ![v] = e]
  /\ UNCHANGED <<votes, finalized, finalizerSets, manifestEpoch, guardianReady, checkpointLevel>>

ManifestRollback(v, e) ==
  /\ v \in Validators
  /\ e \in Epochs
  /\ e < manifestEpoch[v]
  /\ manifestEpoch' = [manifestEpoch EXCEPT ![v] = e]
  /\ UNCHANGED <<votes, finalized, finalizerSets, registryEpoch, guardianReady, checkpointLevel>>

GuardianOutage(v) ==
  /\ v \in Validators
  /\ guardianReady[v]
  /\ guardianReady' = [guardianReady EXCEPT ![v] = FALSE]
  /\ UNCHANGED <<votes, finalized, finalizerSets, registryEpoch, manifestEpoch, checkpointLevel>>

GuardianRecovery(v) ==
  /\ v \in Validators
  /\ ~guardianReady[v]
  /\ guardianReady' = [guardianReady EXCEPT ![v] = TRUE]
  /\ UNCHANGED <<votes, finalized, finalizerSets, registryEpoch, manifestEpoch, checkpointLevel>>

AdvanceCheckpoint(v, level) ==
  /\ v \in Validators
  /\ level \in CheckpointLevels
  /\ level > checkpointLevel[v]
  /\ checkpointLevel' = [checkpointLevel EXCEPT ![v] = level]
  /\ UNCHANGED <<votes, finalized, finalizerSets, registryEpoch, manifestEpoch, guardianReady>>

CheckpointRollback(v, level) ==
  /\ v \in Validators
  /\ level \in CheckpointLevels
  /\ level < checkpointLevel[v]
  /\ checkpointLevel' = [checkpointLevel EXCEPT ![v] = level]
  /\ UNCHANGED <<votes, finalized, finalizerSets, registryEpoch, manifestEpoch, guardianReady>>

Next ==
  \/ \E v \in Validators, s \in Slots, b \in Blocks, e \in Epochs : Vote(v, s, b, e)
  \/ \E s \in Slots, b \in Blocks, e \in Epochs : Finalize(s, b, e)
  \/ \E v \in Validators, e \in Epochs : AdoptEpoch(v, e)
  \/ \E v \in Validators, e \in Epochs : RegistryRollback(v, e)
  \/ \E v \in Validators, e \in Epochs : ManifestRollback(v, e)
  \/ \E v \in Validators : GuardianOutage(v)
  \/ \E v \in Validators : GuardianRecovery(v)
  \/ \E v \in Validators, level \in CheckpointLevels : AdvanceCheckpoint(v, level)
  \/ \E v \in Validators, level \in CheckpointLevels : CheckpointRollback(v, level)

TypeInvariant ==
  /\ votes \subseteq VoteDomain
  /\ finalized \subseteq FinalizationDomain
  /\ finalizerSets \in [FinalizationDomain -> SUBSET Validators]
  /\ registryEpoch \in [Validators -> Epochs]
  /\ manifestEpoch \in [Validators -> Epochs]
  /\ guardianReady \in [Validators -> BOOLEAN]
  /\ checkpointLevel \in [Validators -> CheckpointLevels]

NoDualVotes ==
  \A v \in Validators, s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ VoteEvent(v, s, b1, e1) \in votes
    /\ VoteEvent(v, s, b2, e2) \in votes
    => /\ b1 = b2
       /\ e1 = e2

FinalizationWitnessSoundness ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    Finalization(s, b, e) \in finalized
    => /\ Cardinality(finalizerSets[Finalization(s, b, e)]) >= QuorumSize
       /\ \A v \in finalizerSets[Finalization(s, b, e)] :
            VoteEvent(v, s, b, e) \in votes

Invariant == TypeInvariant /\ NoDualVotes /\ FinalizationWitnessSoundness

Safety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ Finalization(s, b1, e1) \in finalized
    /\ Finalization(s, b2, e2) \in finalized
    => b1 = b2

Spec ==
  Init /\ [][Next]_vars

THEOREM OneInCheckpointLevels == 1 \in CheckpointLevels
  BY SMT DEF CheckpointLevels

THEOREM InitImpliesInvariant == Init => Invariant
PROOF
<1>1. Init => TypeInvariant
  BY SMT, InitialEpochInEpochs, OneInCheckpointLevels
     DEF Init, TypeInvariant, VoteDomain, FinalizationDomain
<1>2. Init => NoDualVotes
  BY DEF Init, NoDualVotes
<1>3. Init => FinalizationWitnessSoundness
  BY DEF Init, FinalizationWitnessSoundness
<1>4. QED
  BY <1>1, <1>2, <1>3 DEF Invariant

THEOREM StepPreservesTypeInvariant == Invariant /\ Next => TypeInvariant'
  BY SMTT(30) DEF Invariant, TypeInvariant, Next, Vote, Finalize, AdoptEpoch,
             RegistryRollback, ManifestRollback, GuardianOutage, GuardianRecovery,
             AdvanceCheckpoint, CheckpointRollback, CanVote, HasVote, CanFinalize,
             EligibleVoters, VoteEvent, Finalization, VoteDomain, FinalizationDomain

THEOREM StepPreservesNoDualVotes == Invariant /\ Next => NoDualVotes'
  BY SMT DEF Invariant, NoDualVotes, Next, Vote, Finalize, AdoptEpoch,
             RegistryRollback, ManifestRollback, GuardianOutage, GuardianRecovery,
             AdvanceCheckpoint, CheckpointRollback, CanVote, HasVote, VoteEvent

THEOREM StepPreservesFinalizationWitnessSoundness ==
  Invariant /\ Next => FinalizationWitnessSoundness'
  BY SMTT(30) DEF Invariant, FinalizationWitnessSoundness, Next, Vote, Finalize,
             AdoptEpoch, RegistryRollback, ManifestRollback, GuardianOutage,
             GuardianRecovery, AdvanceCheckpoint, CheckpointRollback,
             CanFinalize, EligibleVoters, VoteEvent, Finalization

THEOREM StutterPreservesInvariant == Invariant /\ UNCHANGED vars => Invariant'
  BY SMT DEF Invariant, vars

THEOREM NextPreservesInvariant == Invariant /\ [Next]_vars => Invariant'
PROOF
<1>1. Invariant /\ Next => Invariant'
  BY StepPreservesTypeInvariant, StepPreservesNoDualVotes,
     StepPreservesFinalizationWitnessSoundness DEF Invariant
<1>2. Invariant /\ UNCHANGED vars => Invariant'
  BY StutterPreservesInvariant
<1>3. QED
  BY <1>1, <1>2 DEF vars

THEOREM FinalizedWitnessesIntersect ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ Invariant
    /\ <<s, b1, e1>> \in finalized
    /\ <<s, b2, e2>> \in finalized
    => \E v \in Validators :
         /\ <<v, s, b1, e1>> \in votes
         /\ <<v, s, b2, e2>> \in votes
PROOF
<1>1. TAKE s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs
<1>2. ASSUME Invariant,
               <<s, b1, e1>> \in finalized,
               <<s, b2, e2>> \in finalized
        PROVE \E v \in Validators :
                /\ <<v, s, b1, e1>> \in votes
                /\ <<v, s, b2, e2>> \in votes
  <2>1. finalizerSets[<<s, b1, e1>>] \subseteq Validators
    BY SMT, <1>2 DEF Invariant, TypeInvariant, FinalizationDomain, Finalization
  <2>2. finalizerSets[<<s, b2, e2>>] \subseteq Validators
    BY SMT, <1>2 DEF Invariant, TypeInvariant, FinalizationDomain, Finalization
  <2>3. Cardinality(finalizerSets[<<s, b1, e1>>]) >= QuorumSize
    BY SMT, <1>2 DEF Invariant, FinalizationWitnessSoundness
  <2>4. Cardinality(finalizerSets[<<s, b2, e2>>]) >= QuorumSize
    BY SMT, <1>2 DEF Invariant, FinalizationWitnessSoundness
  <2>5. finalizerSets[<<s, b1, e1>>] \cap finalizerSets[<<s, b2, e2>>] # {}
    BY <2>1, <2>2, <2>3, <2>4, QuorumIntersection
  <2>6. PICK v \in finalizerSets[<<s, b1, e1>>] \cap finalizerSets[<<s, b2, e2>>] : TRUE
    BY <2>5
  <2>7. <<v, s, b1, e1>> \in votes
    BY SMT, <1>2, <2>6 DEF Invariant, FinalizationWitnessSoundness
  <2>8. <<v, s, b2, e2>> \in votes
    BY SMT, <1>2, <2>6 DEF Invariant, FinalizationWitnessSoundness
  <2>9. QED
    BY SMT, <2>6, <2>7, <2>8
<1>3. QED
  BY <1>2

THEOREM InvariantImpliesSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ Invariant
    /\ <<s, b1, e1>> \in finalized
    /\ <<s, b2, e2>> \in finalized
    => /\ b1 = b2
       /\ e1 = e2
PROOF
<1>1. TAKE s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs
<1>2. ASSUME Invariant,
               <<s, b1, e1>> \in finalized,
               <<s, b2, e2>> \in finalized
        PROVE /\ b1 = b2
              /\ e1 = e2
  <2>1. \E v \in Validators :
          /\ <<v, s, b1, e1>> \in votes
          /\ <<v, s, b2, e2>> \in votes
    BY SMT, FinalizedWitnessesIntersect, <1>2
  <2>2. PICK v \in Validators :
          /\ <<v, s, b1, e1>> \in votes
          /\ <<v, s, b2, e2>> \in votes
    BY <2>1
  <2>3. QED
    BY SMT, <1>2, <2>2 DEF Invariant, NoDualVotes
<1>3. QED
  BY <1>2

====
