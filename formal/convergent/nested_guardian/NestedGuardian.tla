---- MODULE NestedGuardian ----
EXTENDS Naturals, FiniteSets, TLC, TLAPS

CONSTANT Validators, Witnesses, Blocks, Slots, Epochs, QuorumSize, MaxReassignmentDepth,
         InitialEpoch, InitialWitness

ASSUME InitialEpochInEpochs == InitialEpoch \in Epochs
ASSUME InitialWitnessInWitnesses == InitialWitness \in Witnesses

ASSUME QuorumIntersection ==
  \A S, T \in SUBSET Validators :
    /\ Cardinality(S) >= QuorumSize
    /\ Cardinality(T) >= QuorumSize
    => S \cap T # {}

VARIABLES votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
          witnessCheckpoint, assignedWitness, reassignmentDepth

vars == <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
          witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth>>

CheckpointLevels == 0..2

VoteEvent(v, s, b, e) == <<v, s, b, e>>
WitnessEvent(w, s, b, e) == <<w, s, b, e>>
Finalization(s, b, e) == <<s, b, e>>

VoteDomain == {VoteEvent(v, s, b, e) : v \in Validators, s \in Slots, b \in Blocks, e \in Epochs}
WitnessDomain == {WitnessEvent(w, s, b, e) : w \in Witnesses, s \in Slots, b \in Blocks, e \in Epochs}
FinalizationDomain == {Finalization(s, b, e) : s \in Slots, b \in Blocks, e \in Epochs}

Init ==
  /\ votes = {}
  /\ witnessCerts = {}
  /\ finalized = {}
  /\ finalizerSets = [f \in FinalizationDomain |-> {}]
  /\ registryEpoch = [v \in Validators |-> InitialEpoch]
  /\ guardianReady = [v \in Validators |-> TRUE]
  /\ witnessOnline = [w \in Witnesses |-> TRUE]
  /\ witnessCheckpoint = [w \in Witnesses |-> 1]
  /\ assignedWitness = [s \in Slots |-> InitialWitness]
  /\ reassignmentDepth = [s \in Slots |-> 0]

HasVote(v, s) ==
  \E b \in Blocks, e \in Epochs : VoteEvent(v, s, b, e) \in votes

HasWitnessCert(w, s) ==
  \E b \in Blocks, e \in Epochs : WitnessEvent(w, s, b, e) \in witnessCerts

CanIssueWitness(w, s, b, e) ==
  /\ w \in Witnesses
  /\ s \in Slots
  /\ b \in Blocks
  /\ e \in Epochs
  /\ witnessOnline[w]
  /\ witnessCheckpoint[w] > 0
  /\ assignedWitness[s] = w
  /\ ~HasWitnessCert(w, s)

IssueWitness(w, s, b, e) ==
  /\ CanIssueWitness(w, s, b, e)
  /\ witnessCerts' = witnessCerts \cup {WitnessEvent(w, s, b, e)}
  /\ UNCHANGED <<votes, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth>>

CanReassign(s, w) ==
  /\ s \in Slots
  /\ w \in Witnesses
  /\ w # assignedWitness[s]
  /\ ~witnessOnline[assignedWitness[s]]
  /\ reassignmentDepth[s] < MaxReassignmentDepth

ReassignWitness(s, w) ==
  /\ CanReassign(s, w)
  /\ assignedWitness' = [assignedWitness EXCEPT ![s] = w]
  /\ reassignmentDepth' = [reassignmentDepth EXCEPT ![s] = @ + 1]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint>>

CanVote(v, s, b, e) ==
  /\ v \in Validators
  /\ s \in Slots
  /\ b \in Blocks
  /\ e \in Epochs
  /\ guardianReady[v]
  /\ registryEpoch[v] = e
  /\ ~HasVote(v, s)
  /\ WitnessEvent(assignedWitness[s], s, b, e) \in witnessCerts

Vote(v, s, b, e) ==
  /\ CanVote(v, s, b, e)
  /\ votes' = votes \cup {VoteEvent(v, s, b, e)}
  /\ UNCHANGED <<witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth>>

EligibleVoters(s, b, e) ==
  {v \in Validators :
      /\ VoteEvent(v, s, b, e) \in votes
      /\ guardianReady[v]
      /\ registryEpoch[v] = e
      /\ WitnessEvent(assignedWitness[s], s, b, e) \in witnessCerts}

CanFinalize(s, b, e) ==
  /\ s \in Slots
  /\ b \in Blocks
  /\ e \in Epochs
  /\ Cardinality(EligibleVoters(s, b, e)) >= QuorumSize

Finalize(s, b, e) ==
  /\ CanFinalize(s, b, e)
  /\ finalized' = finalized \cup {Finalization(s, b, e)}
  /\ finalizerSets' = [finalizerSets EXCEPT ![Finalization(s, b, e)] = EligibleVoters(s, b, e)]
  /\ UNCHANGED <<votes, witnessCerts, registryEpoch, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth>>

AdoptEpoch(v, e) ==
  /\ v \in Validators
  /\ e \in Epochs
  /\ e >= registryEpoch[v]
  /\ registryEpoch' = [registryEpoch EXCEPT ![v] = e]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth>>

RegistryRollback(v, e) ==
  /\ v \in Validators
  /\ e \in Epochs
  /\ e < registryEpoch[v]
  /\ registryEpoch' = [registryEpoch EXCEPT ![v] = e]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth>>

GuardianOutage(v) ==
  /\ v \in Validators
  /\ guardianReady[v]
  /\ guardianReady' = [guardianReady EXCEPT ![v] = FALSE]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth>>

WitnessOutage(w) ==
  /\ w \in Witnesses
  /\ witnessOnline[w]
  /\ witnessOnline' = [witnessOnline EXCEPT ![w] = FALSE]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessCheckpoint, assignedWitness, reassignmentDepth>>

WitnessRecovery(w) ==
  /\ w \in Witnesses
  /\ ~witnessOnline[w]
  /\ witnessOnline' = [witnessOnline EXCEPT ![w] = TRUE]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessCheckpoint, assignedWitness, reassignmentDepth>>

AdvanceWitnessCheckpoint(w, level) ==
  /\ w \in Witnesses
  /\ level \in CheckpointLevels
  /\ level > witnessCheckpoint[w]
  /\ witnessCheckpoint' = [witnessCheckpoint EXCEPT ![w] = level]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, assignedWitness, reassignmentDepth>>

WitnessCheckpointRollback(w, level) ==
  /\ w \in Witnesses
  /\ level \in CheckpointLevels
  /\ level < witnessCheckpoint[w]
  /\ witnessCheckpoint' = [witnessCheckpoint EXCEPT ![w] = level]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, assignedWitness, reassignmentDepth>>

Next ==
  \/ \E w \in Witnesses, s \in Slots, b \in Blocks, e \in Epochs : IssueWitness(w, s, b, e)
  \/ \E s \in Slots, w \in Witnesses : ReassignWitness(s, w)
  \/ \E v \in Validators, s \in Slots, b \in Blocks, e \in Epochs : Vote(v, s, b, e)
  \/ \E s \in Slots, b \in Blocks, e \in Epochs : Finalize(s, b, e)
  \/ \E v \in Validators, e \in Epochs : AdoptEpoch(v, e)
  \/ \E v \in Validators, e \in Epochs : RegistryRollback(v, e)
  \/ \E v \in Validators : GuardianOutage(v)
  \/ \E w \in Witnesses : WitnessOutage(w)
  \/ \E w \in Witnesses : WitnessRecovery(w)
  \/ \E w \in Witnesses, level \in CheckpointLevels : AdvanceWitnessCheckpoint(w, level)
  \/ \E w \in Witnesses, level \in CheckpointLevels : WitnessCheckpointRollback(w, level)

TypeInvariant ==
  /\ votes \subseteq VoteDomain
  /\ witnessCerts \subseteq WitnessDomain
  /\ finalized \subseteq FinalizationDomain
  /\ finalizerSets \in [FinalizationDomain -> SUBSET Validators]
  /\ registryEpoch \in [Validators -> Epochs]
  /\ guardianReady \in [Validators -> BOOLEAN]
  /\ witnessOnline \in [Witnesses -> BOOLEAN]
  /\ witnessCheckpoint \in [Witnesses -> CheckpointLevels]
  /\ assignedWitness \in [Slots -> Witnesses]
  /\ reassignmentDepth \in [Slots -> 0..MaxReassignmentDepth]

WitnessAssignmentSoundness ==
  \A s \in Slots :
    reassignmentDepth[s] <= MaxReassignmentDepth

NoDualVotes ==
  \A v \in Validators, s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ VoteEvent(v, s, b1, e1) \in votes
    /\ VoteEvent(v, s, b2, e2) \in votes
    => /\ b1 = b2
       /\ e1 = e2

WitnessCertificatesStayAssigned ==
  \A w \in Witnesses, s \in Slots, b \in Blocks, e \in Epochs :
    WitnessEvent(w, s, b, e) \in witnessCerts
    => assignedWitness[s] = w \/ reassignmentDepth[s] > 0

FinalizationWitnessSoundness ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    Finalization(s, b, e) \in finalized
    => /\ Cardinality(finalizerSets[Finalization(s, b, e)]) >= QuorumSize
       /\ \A v \in finalizerSets[Finalization(s, b, e)] :
            VoteEvent(v, s, b, e) \in votes

Invariant ==
  /\ TypeInvariant
  /\ WitnessAssignmentSoundness
  /\ NoDualVotes
  /\ WitnessCertificatesStayAssigned
  /\ FinalizationWitnessSoundness

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
  BY SMT, InitialEpochInEpochs, InitialWitnessInWitnesses, OneInCheckpointLevels
     DEF Init, TypeInvariant, VoteDomain, WitnessDomain, FinalizationDomain
<1>2. Init => WitnessAssignmentSoundness
  BY DEF Init, WitnessAssignmentSoundness
<1>3. Init => NoDualVotes
  BY DEF Init, NoDualVotes
<1>4. Init => WitnessCertificatesStayAssigned
  BY DEF Init, WitnessCertificatesStayAssigned
<1>5. Init => FinalizationWitnessSoundness
  BY DEF Init, FinalizationWitnessSoundness
<1>6. QED
  BY <1>1, <1>2, <1>3, <1>4, <1>5 DEF Invariant

THEOREM StepPreservesInvariant == Invariant /\ Next => Invariant'
  BY SMTT(30) DEF Invariant, TypeInvariant, WitnessAssignmentSoundness, NoDualVotes,
             WitnessCertificatesStayAssigned, FinalizationWitnessSoundness, Next,
             IssueWitness, ReassignWitness, Vote, Finalize, AdoptEpoch,
             RegistryRollback, GuardianOutage, WitnessOutage, WitnessRecovery,
             AdvanceWitnessCheckpoint, WitnessCheckpointRollback, CanIssueWitness,
             CanVote, HasVote, CanFinalize, EligibleVoters, VoteEvent,
             WitnessEvent, Finalization, VoteDomain, WitnessDomain, FinalizationDomain

THEOREM StutterPreservesInvariant == Invariant /\ UNCHANGED vars => Invariant'
  BY SMT DEF Invariant, vars

THEOREM NextPreservesInvariant == Invariant /\ [Next]_vars => Invariant'
  BY SMT, StepPreservesInvariant, StutterPreservesInvariant DEF vars

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

THEOREM InvariantImpliesSafety == Invariant => Safety
PROOF
<1>1. TAKE s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs
<1>2. ASSUME Invariant,
               <<s, b1, e1>> \in finalized,
               <<s, b2, e2>> \in finalized
        PROVE b1 = b2
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
  BY <1>2 DEF Safety

====
