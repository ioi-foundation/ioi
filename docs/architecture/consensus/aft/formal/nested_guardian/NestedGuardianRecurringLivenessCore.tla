---- MODULE NestedGuardianRecurringLivenessCore ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANT Validators, Witnesses, Blocks, Slots, Epochs, QuorumSize, MaxReassignmentDepth,
         InitialEpoch, InitialWitness, TotalCycles,
         TargetSlotOf(_), TargetBlockOf(_), StableEpochOf(_)

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
          continuationPagePublished, continuationPageBoundary, continuationFetched

vars == <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
          witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase,
          churnStage, continuationBoundary, continuationAnchorPublished,
          continuationAnchorBoundary, continuationPagePublished,
          continuationPageBoundary, continuationFetched>>

CheckpointLevels == 0..2
Phases == {"churn", "stable"}
ChurnStages == 0..7
CycleRange == 1..TotalCycles
ContinuationBoundaries == 0..TotalCycles

VoteEvent(v, s, b, e) == <<v, s, b, e>>
WitnessEvent(w, s, b, e) == <<w, s, b, e>>
Finalization(s, b, e) == <<s, b, e>>

VoteDomain == {VoteEvent(v, s, b, e) : v \in Validators, s \in Slots, b \in Blocks, e \in Epochs}
WitnessDomain == {WitnessEvent(w, s, b, e) : w \in Witnesses, s \in Slots, b \in Blocks, e \in Epochs}
FinalizationDomain == {Finalization(s, b, e) : s \in Slots, b \in Blocks, e \in Epochs}

TargetSlot(c) ==
  TargetSlotOf(c)
TargetBlock(c) ==
  TargetBlockOf(c)
StableEpoch(c) ==
  StableEpochOf(c)
PreviousStableEpoch(c) ==
  IF c = 1 THEN InitialEpoch
  ELSE StableEpoch(c - 1)

CurrentTargetSlot == TargetSlot(currentCycle)
CurrentTargetBlock == TargetBlock(currentCycle)
CurrentStableEpoch == StableEpoch(currentCycle)

CycleFinalized(c) ==
  Finalization(TargetSlot(c), TargetBlock(c), StableEpoch(c)) \in finalized

CycleTransferLanding(c) ==
  /\ c \in 2..TotalCycles
  /\ currentCycle = c
  /\ phase = "churn"
  /\ churnStage = 0
  /\ continuationBoundary = c - 1
  /\ continuationFetched[c - 1]
  /\ \A v \in Validators :
       /\ guardianReady[v]
       /\ registryEpoch[v] = PreviousStableEpoch(c)
  /\ \A w \in Witnesses :
       /\ witnessOnline[w]
       /\ witnessCheckpoint[w] = 1

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
  /\ currentCycle = 1
  /\ phase = "churn"
  /\ churnStage = 0
  /\ continuationBoundary = 0
  /\ continuationAnchorPublished = [c \in CycleRange |-> FALSE]
  /\ continuationAnchorBoundary = [c \in CycleRange |-> 0]
  /\ continuationPagePublished = [c \in CycleRange |-> FALSE]
  /\ continuationPageBoundary = [c \in CycleRange |-> 0]
  /\ continuationFetched = [c \in CycleRange |-> FALSE]

HasVote(v, s) ==
  \E b \in Blocks, e \in Epochs : VoteEvent(v, s, b, e) \in votes

HasWitnessCert(w, s) ==
  \E b \in Blocks, e \in Epochs : WitnessEvent(w, s, b, e) \in witnessCerts

CanReassign(s, w) ==
  /\ s \in Slots
  /\ w \in Witnesses
  /\ w # assignedWitness[s]
  /\ ~witnessOnline[assignedWitness[s]]
  /\ reassignmentDepth[s] < MaxReassignmentDepth

TriggerGuardianOutage(v) ==
  /\ phase = "churn"
  /\ churnStage = 0
  /\ v \in Validators
  /\ guardianReady[v]
  /\ guardianReady' = [guardianReady EXCEPT ![v] = FALSE]
  /\ churnStage' = 1
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase,
                continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

TriggerWitnessOutage ==
  /\ phase = "churn"
  /\ churnStage = 1
  /\ witnessOnline[assignedWitness[CurrentTargetSlot]]
  /\ witnessOnline' =
       [witnessOnline EXCEPT ![assignedWitness[CurrentTargetSlot]] = FALSE]
  /\ churnStage' = 2
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase,
                continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

TriggerReassignment(w) ==
  /\ phase = "churn"
  /\ churnStage = 2
  /\ CanReassign(CurrentTargetSlot, w)
  /\ assignedWitness' = [assignedWitness EXCEPT ![CurrentTargetSlot] = w]
  /\ reassignmentDepth' = [reassignmentDepth EXCEPT ![CurrentTargetSlot] = @ + 1]
  /\ churnStage' = 3
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, currentCycle, phase,
                continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

TriggerEpochRotation(v) ==
  /\ phase = "churn"
  /\ churnStage = 3
  /\ v \in Validators
  /\ registryEpoch[v] # CurrentStableEpoch
  /\ registryEpoch' = [registryEpoch EXCEPT ![v] = CurrentStableEpoch]
  /\ churnStage' = 4
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase,
                continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

TriggerCheckpointRollback ==
  /\ phase = "churn"
  /\ churnStage = 4
  /\ witnessCheckpoint[assignedWitness[CurrentTargetSlot]] > 0
  /\ witnessCheckpoint' =
       [witnessCheckpoint EXCEPT ![assignedWitness[CurrentTargetSlot]] = 0]
  /\ churnStage' = 5
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, assignedWitness, reassignmentDepth, currentCycle, phase,
                continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

TriggerContinuationBoundaryChurn ==
  /\ phase = "churn"
  /\ churnStage = 5
  /\ continuationBoundary < currentCycle
  /\ continuationBoundary' = currentCycle
  /\ churnStage' = 6
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth,
                currentCycle, phase, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

Stabilize ==
  /\ phase = "churn"
  /\ churnStage = 6
  /\ phase' = "stable"
  /\ churnStage' = 7
  /\ guardianReady' = [v \in Validators |-> TRUE]
  /\ witnessOnline' = [w \in Witnesses |-> TRUE]
  /\ witnessCheckpoint' = [w \in Witnesses |-> 1]
  /\ registryEpoch' = [v \in Validators |-> CurrentStableEpoch]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, assignedWitness, reassignmentDepth,
                currentCycle, continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

CanIssueTargetWitness(w) ==
  /\ phase = "stable"
  /\ w = assignedWitness[CurrentTargetSlot]
  /\ witnessOnline[w]
  /\ witnessCheckpoint[w] > 0
  /\ ~HasWitnessCert(w, CurrentTargetSlot)

IssueTargetWitness(w) ==
  /\ CanIssueTargetWitness(w)
  /\ witnessCerts' = witnessCerts \cup {WitnessEvent(w, CurrentTargetSlot, CurrentTargetBlock, CurrentStableEpoch)}
  /\ UNCHANGED <<votes, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase, churnStage,
                continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

CanCastTargetVote(v) ==
  /\ phase = "stable"
  /\ v \in Validators
  /\ guardianReady[v]
  /\ registryEpoch[v] = CurrentStableEpoch
  /\ ~HasVote(v, CurrentTargetSlot)
  /\ WitnessEvent(assignedWitness[CurrentTargetSlot], CurrentTargetSlot, CurrentTargetBlock, CurrentStableEpoch) \in witnessCerts

CastTargetVote(v) ==
  /\ CanCastTargetVote(v)
  /\ votes' = votes \cup {VoteEvent(v, CurrentTargetSlot, CurrentTargetBlock, CurrentStableEpoch)}
  /\ UNCHANGED <<witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase, churnStage,
                continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

TargetEligibleVoters ==
  {v \in Validators :
      /\ VoteEvent(v, CurrentTargetSlot, CurrentTargetBlock, CurrentStableEpoch) \in votes
      /\ guardianReady[v]
      /\ registryEpoch[v] = CurrentStableEpoch
      /\ WitnessEvent(assignedWitness[CurrentTargetSlot], CurrentTargetSlot, CurrentTargetBlock, CurrentStableEpoch) \in witnessCerts}

CanFinalizeTarget ==
  /\ phase = "stable"
  /\ Cardinality(TargetEligibleVoters) >= QuorumSize
  /\ ~CycleFinalized(currentCycle)

FinalizeTarget ==
  /\ CanFinalizeTarget
  /\ finalized' = finalized \cup {Finalization(CurrentTargetSlot, CurrentTargetBlock, CurrentStableEpoch)}
  /\ finalizerSets' =
       [finalizerSets EXCEPT ![Finalization(CurrentTargetSlot, CurrentTargetBlock, CurrentStableEpoch)] = TargetEligibleVoters]
  /\ UNCHANGED <<votes, witnessCerts, registryEpoch, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle, phase, churnStage,
                continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

CanPublishContinuationAnchor ==
  /\ phase = "stable"
  /\ CycleFinalized(currentCycle)
  /\ ~continuationAnchorPublished[currentCycle]

PublishContinuationAnchor ==
  /\ CanPublishContinuationAnchor
  /\ continuationAnchorPublished' = [continuationAnchorPublished EXCEPT ![currentCycle] = TRUE]
  /\ continuationAnchorBoundary' = [continuationAnchorBoundary EXCEPT ![currentCycle] = continuationBoundary]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle,
                phase, churnStage, continuationBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

CanPublishContinuationPage ==
  /\ phase = "stable"
  /\ continuationAnchorPublished[currentCycle]
  /\ ~continuationPagePublished[currentCycle]

PublishContinuationPage ==
  /\ CanPublishContinuationPage
  /\ continuationPagePublished' = [continuationPagePublished EXCEPT ![currentCycle] = TRUE]
  /\ continuationPageBoundary' = [continuationPageBoundary EXCEPT ![currentCycle] = continuationBoundary]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle,
                phase, churnStage, continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationFetched>>

CanFetchContinuation ==
  /\ phase = "stable"
  /\ continuationAnchorPublished[currentCycle]
  /\ continuationPagePublished[currentCycle]
  /\ continuationAnchorBoundary[currentCycle] = currentCycle
  /\ continuationPageBoundary[currentCycle] = currentCycle
  /\ ~continuationFetched[currentCycle]

FetchContinuation ==
  /\ CanFetchContinuation
  /\ continuationFetched' = [continuationFetched EXCEPT ![currentCycle] = TRUE]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, currentCycle,
                phase, churnStage, continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary>>

CanStartNextCycle ==
  /\ phase = "stable"
  /\ continuationFetched[currentCycle]
  /\ currentCycle < TotalCycles

StartNextCycle ==
  /\ CanStartNextCycle
  /\ currentCycle' = currentCycle + 1
  /\ phase' = "churn"
  /\ churnStage' = 0
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth,
                continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

SomeGuardianOutage == \E v \in Validators : TriggerGuardianOutage(v)
SomeTargetReassignment == \E w \in Witnesses : TriggerReassignment(w)
SomeEpochRotation == \E v \in Validators : TriggerEpochRotation(v)
SomeTargetWitness == \E w \in Witnesses : IssueTargetWitness(w)
SomeTargetVote == \E v \in Validators : CastTargetVote(v)

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
  \/ PublishContinuationAnchor
  \/ PublishContinuationPage
  \/ FetchContinuation
  \/ StartNextCycle

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
  /\ currentCycle \in CycleRange
  /\ phase \in Phases
  /\ churnStage \in ChurnStages
  /\ continuationBoundary \in ContinuationBoundaries
  /\ continuationAnchorPublished \in [CycleRange -> BOOLEAN]
  /\ continuationAnchorBoundary \in [CycleRange -> ContinuationBoundaries]
  /\ continuationPagePublished \in [CycleRange -> BOOLEAN]
  /\ continuationPageBoundary \in [CycleRange -> ContinuationBoundaries]
  /\ continuationFetched \in [CycleRange -> BOOLEAN]

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

ContinuationSoundness ==
  \A c \in CycleRange :
    continuationFetched[c]
      => /\ continuationAnchorPublished[c]
         /\ continuationPagePublished[c]
         /\ CycleFinalized(c)
         /\ continuationAnchorBoundary[c] = c
         /\ continuationPageBoundary[c] = c

CycleAdvanceRequiresPreviousFetch ==
  currentCycle > 1 => continuationFetched[currentCycle - 1]

CycleTransferLandingSoundness ==
  \A c \in 2..TotalCycles :
    CycleTransferLanding(c)
      => \A prior \in 1..(c - 1) : continuationFetched[prior]

Safety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ Finalization(s, b1, e1) \in finalized
    /\ Finalization(s, b2, e2) \in finalized
    => b1 = b2

EventuallyFinalCycleFetches ==
  <>continuationFetched[TotalCycles]

RecurringCycleFetches ==
  \A c \in CycleRange : <>continuationFetched[c]

RecurringCycleTransfers ==
  \A c \in 2..TotalCycles :
    []((currentCycle = c - 1 /\ continuationFetched[c - 1]) => <>CycleTransferLanding(c))

RecurringLivenessSpec ==
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
  /\ WF_vars(PublishContinuationAnchor)
  /\ WF_vars(PublishContinuationPage)
  /\ WF_vars(FetchContinuation)
  /\ WF_vars(StartNextCycle)

====
