---- MODULE NestedGuardianLiveness ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANT Validators, Witnesses, Blocks, Slots, Epochs, QuorumSize, MaxReassignmentDepth,
         InitialEpoch, InitialWitness, TargetSlot, TargetBlock, StableEpoch

ASSUME InitialEpoch \in Epochs
ASSUME InitialWitness \in Witnesses
ASSUME TargetSlot \in Slots
ASSUME TargetBlock \in Blocks
ASSUME StableEpoch \in Epochs
ASSUME QuorumSize \in 1..Cardinality(Validators)

VARIABLES votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
          witnessCheckpoint, assignedWitness, reassignmentDepth, phase, churnStage,
          continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
          continuationPagePublished, continuationPageBoundary, continuationFetched

vars == <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
          witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, phase, churnStage,
          continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
          continuationPagePublished, continuationPageBoundary, continuationFetched>>

CheckpointLevels == 0..2
Phases == {"churn", "stable"}
ChurnStages == 0..7
ContinuationBoundaries == 0..1

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
  /\ phase = "churn"
  /\ churnStage = 0
  /\ continuationBoundary = 0
  /\ continuationAnchorPublished = FALSE
  /\ continuationAnchorBoundary = 0
  /\ continuationPagePublished = FALSE
  /\ continuationPageBoundary = 0
  /\ continuationFetched = FALSE

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
                witnessCheckpoint, assignedWitness, reassignmentDepth, phase,
                continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

TriggerWitnessOutage ==
  /\ phase = "churn"
  /\ churnStage = 1
  /\ witnessOnline[assignedWitness[TargetSlot]]
  /\ witnessOnline' =
       [witnessOnline EXCEPT ![assignedWitness[TargetSlot]] = FALSE]
  /\ churnStage' = 2
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessCheckpoint, assignedWitness, reassignmentDepth, phase,
                continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

TriggerReassignment(w) ==
  /\ phase = "churn"
  /\ churnStage = 2
  /\ CanReassign(TargetSlot, w)
  /\ assignedWitness' = [assignedWitness EXCEPT ![TargetSlot] = w]
  /\ reassignmentDepth' = [reassignmentDepth EXCEPT ![TargetSlot] = @ + 1]
  /\ churnStage' = 3
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, phase,
                continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

TriggerEpochRotation(v) ==
  /\ phase = "churn"
  /\ churnStage = 3
  /\ v \in Validators
  /\ registryEpoch[v] # StableEpoch
  /\ registryEpoch' = [registryEpoch EXCEPT ![v] = StableEpoch]
  /\ churnStage' = 4
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth, phase,
                continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

TriggerCheckpointRollback ==
  /\ phase = "churn"
  /\ churnStage = 4
  /\ witnessCheckpoint[assignedWitness[TargetSlot]] > 0
  /\ witnessCheckpoint' =
       [witnessCheckpoint EXCEPT ![assignedWitness[TargetSlot]] = 0]
  /\ churnStage' = 5
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, assignedWitness, reassignmentDepth, phase,
                continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

TriggerContinuationBoundaryChurn ==
  /\ phase = "churn"
  /\ churnStage = 5
  /\ continuationBoundary = 0
  /\ continuationBoundary' = 1
  /\ churnStage' = 6
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, phase,
                continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

Stabilize ==
  /\ phase = "churn"
  /\ churnStage = 6
  /\ phase' = "stable"
  /\ churnStage' = 7
  /\ guardianReady' = [v \in Validators |-> TRUE]
  /\ witnessOnline' = [w \in Witnesses |-> TRUE]
  /\ witnessCheckpoint' = [w \in Witnesses |-> 1]
  /\ registryEpoch' = [v \in Validators |-> StableEpoch]
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, assignedWitness, reassignmentDepth,
                continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

CanIssueTargetWitness(w) ==
  /\ phase = "stable"
  /\ w = assignedWitness[TargetSlot]
  /\ witnessOnline[w]
  /\ witnessCheckpoint[w] > 0
  /\ ~HasWitnessCert(w, TargetSlot)

IssueTargetWitness(w) ==
  /\ CanIssueTargetWitness(w)
  /\ witnessCerts' = witnessCerts \cup {WitnessEvent(w, TargetSlot, TargetBlock, StableEpoch)}
  /\ UNCHANGED <<votes, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth, phase, churnStage,
                continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

CanCastTargetVote(v) ==
  /\ phase = "stable"
  /\ v \in Validators
  /\ guardianReady[v]
  /\ registryEpoch[v] = StableEpoch
  /\ ~HasVote(v, TargetSlot)
  /\ WitnessEvent(assignedWitness[TargetSlot], TargetSlot, TargetBlock, StableEpoch) \in witnessCerts

CastTargetVote(v) ==
  /\ CanCastTargetVote(v)
  /\ votes' = votes \cup {VoteEvent(v, TargetSlot, TargetBlock, StableEpoch)}
  /\ UNCHANGED <<witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth, phase, churnStage,
                continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

TargetEligibleVoters ==
  {v \in Validators :
      /\ VoteEvent(v, TargetSlot, TargetBlock, StableEpoch) \in votes
      /\ guardianReady[v]
      /\ registryEpoch[v] = StableEpoch
      /\ WitnessEvent(assignedWitness[TargetSlot], TargetSlot, TargetBlock, StableEpoch) \in witnessCerts}

CanFinalizeTarget ==
  /\ phase = "stable"
  /\ Cardinality(TargetEligibleVoters) >= QuorumSize
  /\ Finalization(TargetSlot, TargetBlock, StableEpoch) \notin finalized

FinalizeTarget ==
  /\ CanFinalizeTarget
  /\ finalized' = finalized \cup {Finalization(TargetSlot, TargetBlock, StableEpoch)}
  /\ finalizerSets' =
       [finalizerSets EXCEPT ![Finalization(TargetSlot, TargetBlock, StableEpoch)] = TargetEligibleVoters]
  /\ UNCHANGED <<votes, witnessCerts, registryEpoch, guardianReady, witnessOnline,
                witnessCheckpoint, assignedWitness, reassignmentDepth, phase, churnStage,
                continuationBoundary, continuationAnchorPublished, continuationAnchorBoundary,
                continuationPagePublished, continuationPageBoundary, continuationFetched>>

CanPublishContinuationAnchor ==
  /\ phase = "stable"
  /\ Finalization(TargetSlot, TargetBlock, StableEpoch) \in finalized
  /\ ~continuationAnchorPublished

PublishContinuationAnchor ==
  /\ CanPublishContinuationAnchor
  /\ continuationAnchorPublished' = TRUE
  /\ continuationAnchorBoundary' = continuationBoundary
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, phase,
                churnStage, continuationBoundary, continuationPagePublished,
                continuationPageBoundary, continuationFetched>>

CanPublishContinuationPage ==
  /\ phase = "stable"
  /\ continuationAnchorPublished
  /\ ~continuationPagePublished

PublishContinuationPage ==
  /\ CanPublishContinuationPage
  /\ continuationPagePublished' = TRUE
  /\ continuationPageBoundary' = continuationBoundary
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, phase,
                churnStage, continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationFetched>>

CanFetchContinuation ==
  /\ phase = "stable"
  /\ continuationAnchorPublished
  /\ continuationPagePublished
  /\ continuationAnchorBoundary = continuationBoundary
  /\ continuationPageBoundary = continuationBoundary
  /\ ~continuationFetched

FetchContinuation ==
  /\ CanFetchContinuation
  /\ continuationFetched' = TRUE
  /\ UNCHANGED <<votes, witnessCerts, finalized, finalizerSets, registryEpoch, guardianReady,
                witnessOnline, witnessCheckpoint, assignedWitness, reassignmentDepth, phase,
                churnStage, continuationBoundary, continuationAnchorPublished,
                continuationAnchorBoundary, continuationPagePublished,
                continuationPageBoundary>>

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
  /\ phase \in Phases
  /\ churnStage \in ChurnStages
  /\ continuationBoundary \in ContinuationBoundaries
  /\ continuationAnchorPublished \in BOOLEAN
  /\ continuationAnchorBoundary \in ContinuationBoundaries
  /\ continuationPagePublished \in BOOLEAN
  /\ continuationPageBoundary \in ContinuationBoundaries
  /\ continuationFetched \in BOOLEAN

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
  continuationFetched
    => /\ continuationAnchorPublished
       /\ continuationPagePublished
       /\ Finalization(TargetSlot, TargetBlock, StableEpoch) \in finalized
       /\ continuationAnchorBoundary = continuationBoundary
       /\ continuationPageBoundary = continuationBoundary

Safety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ Finalization(s, b1, e1) \in finalized
    /\ Finalization(s, b2, e2) \in finalized
    => b1 = b2

TargetFinalized ==
  Finalization(TargetSlot, TargetBlock, StableEpoch) \in finalized

EventualStabilization ==
  <>(phase = "stable")

PostStabilizationEventuallyFinalizes ==
  (phase = "stable") ~> TargetFinalized

PostStabilizationEventuallyFetchesContinuation ==
  (phase = "stable") ~> continuationFetched

LivenessSpec ==
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

====
