---- MODULE NestedGuardianRecoveryRecurringLiveness_TTrace_1774033721 ----
EXTENDS Sequences, TLCExt, NestedGuardianRecoveryRecurringLiveness_TEConstants, Toolbox, Naturals, TLC, NestedGuardianRecoveryRecurringLiveness

_expression ==
    LET NestedGuardianRecoveryRecurringLiveness_TEExpression == INSTANCE NestedGuardianRecoveryRecurringLiveness_TEExpression
    IN NestedGuardianRecoveryRecurringLiveness_TEExpression!expression
----

_trace ==
    LET NestedGuardianRecoveryRecurringLiveness_TETrace == INSTANCE NestedGuardianRecoveryRecurringLiveness_TETrace
    IN NestedGuardianRecoveryRecurringLiveness_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        continuationAnchorBoundary = (<<0, 0, 0>>)
        /\
        recoveredSurfaces = ()
        /\
        aborted = ()
        /\
        continuationPagePublished = (<<FALSE, FALSE, FALSE>>)
        /\
        continuationBoundary = (0)
        /\
        assignedWitness = (<<w1, w1, w1>>)
        /\
        churnStage = (1)
        /\
        registryEpoch = ((v1 :> 1 @@ v2 :> 1))
        /\
        phase = ("churn")
        /\
        continuationAnchorPublished = (<<FALSE, FALSE, FALSE>>)
        /\
        shareConflicts = ()
        /\
        recoveryConflicts = ()
        /\
        finalizerSets = ((<<1, b1, 1>> :> {} @@ <<1, b1, 2>> :> {} @@ <<1, b1, 3>> :> {} @@ <<1, b1, 4>> :> {} @@ <<1, b2, 1>> :> {} @@ <<1, b2, 2>> :> {} @@ <<1, b2, 3>> :> {} @@ <<1, b2, 4>> :> {} @@ <<1, b3, 1>> :> {} @@ <<1, b3, 2>> :> {} @@ <<1, b3, 3>> :> {} @@ <<1, b3, 4>> :> {} @@ <<2, b1, 1>> :> {} @@ <<2, b1, 2>> :> {} @@ <<2, b1, 3>> :> {} @@ <<2, b1, 4>> :> {} @@ <<2, b2, 1>> :> {} @@ <<2, b2, 2>> :> {} @@ <<2, b2, 3>> :> {} @@ <<2, b2, 4>> :> {} @@ <<2, b3, 1>> :> {} @@ <<2, b3, 2>> :> {} @@ <<2, b3, 3>> :> {} @@ <<2, b3, 4>> :> {} @@ <<3, b1, 1>> :> {} @@ <<3, b1, 2>> :> {} @@ <<3, b1, 3>> :> {} @@ <<3, b1, 4>> :> {} @@ <<3, b2, 1>> :> {} @@ <<3, b2, 2>> :> {} @@ <<3, b2, 3>> :> {} @@ <<3, b2, 4>> :> {} @@ <<3, b3, 1>> :> {} @@ <<3, b3, 2>> :> {} @@ <<3, b3, 3>> :> {} @@ <<3, b3, 4>> :> {}))
        /\
        continuationFetched = (<<FALSE, FALSE, FALSE>>)
        /\
        witnessCerts = ({})
        /\
        currentCycle = (1)
        /\
        missingShareClaims = ()
        /\
        reassignmentDepth = (<<0, 0, 0>>)
        /\
        guardianReady = ((v1 :> FALSE @@ v2 :> TRUE))
        /\
        finalized = ({})
        /\
        windowClosed = ()
        /\
        recovered = ()
        /\
        shareReceipts = ()
        /\
        missingThresholdCertificates = ()
        /\
        witnessCheckpoint = ((w1 :> 1 @@ w2 :> 1))
        /\
        votes = ({})
        /\
        witnessOnline = ((w1 :> TRUE @@ w2 :> TRUE))
        /\
        continuationPageBoundary = (<<0, 0, 0>>)
    )
----

_init ==
    /\ recovered = _TETrace[1].recovered
    /\ votes = _TETrace[1].votes
    /\ registryEpoch = _TETrace[1].registryEpoch
    /\ shareConflicts = _TETrace[1].shareConflicts
    /\ finalizerSets = _TETrace[1].finalizerSets
    /\ witnessCheckpoint = _TETrace[1].witnessCheckpoint
    /\ reassignmentDepth = _TETrace[1].reassignmentDepth
    /\ finalized = _TETrace[1].finalized
    /\ continuationAnchorBoundary = _TETrace[1].continuationAnchorBoundary
    /\ currentCycle = _TETrace[1].currentCycle
    /\ guardianReady = _TETrace[1].guardianReady
    /\ missingShareClaims = _TETrace[1].missingShareClaims
    /\ phase = _TETrace[1].phase
    /\ continuationPagePublished = _TETrace[1].continuationPagePublished
    /\ continuationFetched = _TETrace[1].continuationFetched
    /\ shareReceipts = _TETrace[1].shareReceipts
    /\ recoveredSurfaces = _TETrace[1].recoveredSurfaces
    /\ missingThresholdCertificates = _TETrace[1].missingThresholdCertificates
    /\ continuationPageBoundary = _TETrace[1].continuationPageBoundary
    /\ churnStage = _TETrace[1].churnStage
    /\ continuationAnchorPublished = _TETrace[1].continuationAnchorPublished
    /\ witnessCerts = _TETrace[1].witnessCerts
    /\ recoveryConflicts = _TETrace[1].recoveryConflicts
    /\ assignedWitness = _TETrace[1].assignedWitness
    /\ aborted = _TETrace[1].aborted
    /\ continuationBoundary = _TETrace[1].continuationBoundary
    /\ witnessOnline = _TETrace[1].witnessOnline
    /\ windowClosed = _TETrace[1].windowClosed
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ recovered  = _TETrace[i].recovered
        /\ recovered' = _TETrace[j].recovered
        /\ votes  = _TETrace[i].votes
        /\ votes' = _TETrace[j].votes
        /\ registryEpoch  = _TETrace[i].registryEpoch
        /\ registryEpoch' = _TETrace[j].registryEpoch
        /\ shareConflicts  = _TETrace[i].shareConflicts
        /\ shareConflicts' = _TETrace[j].shareConflicts
        /\ finalizerSets  = _TETrace[i].finalizerSets
        /\ finalizerSets' = _TETrace[j].finalizerSets
        /\ witnessCheckpoint  = _TETrace[i].witnessCheckpoint
        /\ witnessCheckpoint' = _TETrace[j].witnessCheckpoint
        /\ reassignmentDepth  = _TETrace[i].reassignmentDepth
        /\ reassignmentDepth' = _TETrace[j].reassignmentDepth
        /\ finalized  = _TETrace[i].finalized
        /\ finalized' = _TETrace[j].finalized
        /\ continuationAnchorBoundary  = _TETrace[i].continuationAnchorBoundary
        /\ continuationAnchorBoundary' = _TETrace[j].continuationAnchorBoundary
        /\ currentCycle  = _TETrace[i].currentCycle
        /\ currentCycle' = _TETrace[j].currentCycle
        /\ guardianReady  = _TETrace[i].guardianReady
        /\ guardianReady' = _TETrace[j].guardianReady
        /\ missingShareClaims  = _TETrace[i].missingShareClaims
        /\ missingShareClaims' = _TETrace[j].missingShareClaims
        /\ phase  = _TETrace[i].phase
        /\ phase' = _TETrace[j].phase
        /\ continuationPagePublished  = _TETrace[i].continuationPagePublished
        /\ continuationPagePublished' = _TETrace[j].continuationPagePublished
        /\ continuationFetched  = _TETrace[i].continuationFetched
        /\ continuationFetched' = _TETrace[j].continuationFetched
        /\ shareReceipts  = _TETrace[i].shareReceipts
        /\ shareReceipts' = _TETrace[j].shareReceipts
        /\ recoveredSurfaces  = _TETrace[i].recoveredSurfaces
        /\ recoveredSurfaces' = _TETrace[j].recoveredSurfaces
        /\ missingThresholdCertificates  = _TETrace[i].missingThresholdCertificates
        /\ missingThresholdCertificates' = _TETrace[j].missingThresholdCertificates
        /\ continuationPageBoundary  = _TETrace[i].continuationPageBoundary
        /\ continuationPageBoundary' = _TETrace[j].continuationPageBoundary
        /\ churnStage  = _TETrace[i].churnStage
        /\ churnStage' = _TETrace[j].churnStage
        /\ continuationAnchorPublished  = _TETrace[i].continuationAnchorPublished
        /\ continuationAnchorPublished' = _TETrace[j].continuationAnchorPublished
        /\ witnessCerts  = _TETrace[i].witnessCerts
        /\ witnessCerts' = _TETrace[j].witnessCerts
        /\ recoveryConflicts  = _TETrace[i].recoveryConflicts
        /\ recoveryConflicts' = _TETrace[j].recoveryConflicts
        /\ assignedWitness  = _TETrace[i].assignedWitness
        /\ assignedWitness' = _TETrace[j].assignedWitness
        /\ aborted  = _TETrace[i].aborted
        /\ aborted' = _TETrace[j].aborted
        /\ continuationBoundary  = _TETrace[i].continuationBoundary
        /\ continuationBoundary' = _TETrace[j].continuationBoundary
        /\ witnessOnline  = _TETrace[i].witnessOnline
        /\ witnessOnline' = _TETrace[j].witnessOnline
        /\ windowClosed  = _TETrace[i].windowClosed
        /\ windowClosed' = _TETrace[j].windowClosed

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("NestedGuardianRecoveryRecurringLiveness_TTrace_1774033721.json", _TETrace)

=============================================================================

 Note that you can extract this module `NestedGuardianRecoveryRecurringLiveness_TEExpression`
  to a dedicated file to reuse `expression` (the module in the
  dedicated `NestedGuardianRecoveryRecurringLiveness_TEExpression.tla` file takes precedence
  over the module `NestedGuardianRecoveryRecurringLiveness_TEExpression` below).

---- MODULE NestedGuardianRecoveryRecurringLiveness_TEExpression ----
EXTENDS Sequences, TLCExt, NestedGuardianRecoveryRecurringLiveness_TEConstants, Toolbox, Naturals, TLC, NestedGuardianRecoveryRecurringLiveness

expression ==
    [
        \* To hide variables of the `NestedGuardianRecoveryRecurringLiveness` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        recovered |-> recovered
        ,votes |-> votes
        ,registryEpoch |-> registryEpoch
        ,shareConflicts |-> shareConflicts
        ,finalizerSets |-> finalizerSets
        ,witnessCheckpoint |-> witnessCheckpoint
        ,reassignmentDepth |-> reassignmentDepth
        ,finalized |-> finalized
        ,continuationAnchorBoundary |-> continuationAnchorBoundary
        ,currentCycle |-> currentCycle
        ,guardianReady |-> guardianReady
        ,missingShareClaims |-> missingShareClaims
        ,phase |-> phase
        ,continuationPagePublished |-> continuationPagePublished
        ,continuationFetched |-> continuationFetched
        ,shareReceipts |-> shareReceipts
        ,recoveredSurfaces |-> recoveredSurfaces
        ,missingThresholdCertificates |-> missingThresholdCertificates
        ,continuationPageBoundary |-> continuationPageBoundary
        ,churnStage |-> churnStage
        ,continuationAnchorPublished |-> continuationAnchorPublished
        ,witnessCerts |-> witnessCerts
        ,recoveryConflicts |-> recoveryConflicts
        ,assignedWitness |-> assignedWitness
        ,aborted |-> aborted
        ,continuationBoundary |-> continuationBoundary
        ,witnessOnline |-> witnessOnline
        ,windowClosed |-> windowClosed

        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_recoveredUnchanged |-> recovered = recovered'

        \* Format the `recovered` variable as Json value.
        \* ,_recoveredJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(recovered)

        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_recoveredModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].recovered # _TETrace[s-1].recovered
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE NestedGuardianRecoveryRecurringLiveness_TETrace ----
\*EXTENDS IOUtils, NestedGuardianRecoveryRecurringLiveness_TEConstants, TLC, NestedGuardianRecoveryRecurringLiveness
\*
\*trace == IODeserialize("NestedGuardianRecoveryRecurringLiveness_TTrace_1774033721.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE NestedGuardianRecoveryRecurringLiveness_TETrace ----
EXTENDS NestedGuardianRecoveryRecurringLiveness_TEConstants, TLC, NestedGuardianRecoveryRecurringLiveness

trace ==
    <<
    ([continuationAnchorBoundary |-> <<0, 0, 0>>,recoveredSurfaces |-> {},aborted |-> {},continuationPagePublished |-> <<FALSE, FALSE, FALSE>>,continuationBoundary |-> 0,assignedWitness |-> <<w1, w1, w1>>,churnStage |-> 0,registryEpoch |-> (v1 :> 1 @@ v2 :> 1),phase |-> "churn",continuationAnchorPublished |-> <<FALSE, FALSE, FALSE>>,shareConflicts |-> {},recoveryConflicts |-> {},finalizerSets |-> (<<1, b1, 1>> :> {} @@ <<1, b1, 2>> :> {} @@ <<1, b1, 3>> :> {} @@ <<1, b1, 4>> :> {} @@ <<1, b2, 1>> :> {} @@ <<1, b2, 2>> :> {} @@ <<1, b2, 3>> :> {} @@ <<1, b2, 4>> :> {} @@ <<1, b3, 1>> :> {} @@ <<1, b3, 2>> :> {} @@ <<1, b3, 3>> :> {} @@ <<1, b3, 4>> :> {} @@ <<2, b1, 1>> :> {} @@ <<2, b1, 2>> :> {} @@ <<2, b1, 3>> :> {} @@ <<2, b1, 4>> :> {} @@ <<2, b2, 1>> :> {} @@ <<2, b2, 2>> :> {} @@ <<2, b2, 3>> :> {} @@ <<2, b2, 4>> :> {} @@ <<2, b3, 1>> :> {} @@ <<2, b3, 2>> :> {} @@ <<2, b3, 3>> :> {} @@ <<2, b3, 4>> :> {} @@ <<3, b1, 1>> :> {} @@ <<3, b1, 2>> :> {} @@ <<3, b1, 3>> :> {} @@ <<3, b1, 4>> :> {} @@ <<3, b2, 1>> :> {} @@ <<3, b2, 2>> :> {} @@ <<3, b2, 3>> :> {} @@ <<3, b2, 4>> :> {} @@ <<3, b3, 1>> :> {} @@ <<3, b3, 2>> :> {} @@ <<3, b3, 3>> :> {} @@ <<3, b3, 4>> :> {}),continuationFetched |-> <<FALSE, FALSE, FALSE>>,witnessCerts |-> {},currentCycle |-> 1,missingShareClaims |-> {},reassignmentDepth |-> <<0, 0, 0>>,guardianReady |-> (v1 :> TRUE @@ v2 :> TRUE),finalized |-> {},windowClosed |-> <<FALSE, FALSE, FALSE>>,recovered |-> {},shareReceipts |-> {},missingThresholdCertificates |-> {},witnessCheckpoint |-> (w1 :> 1 @@ w2 :> 1),votes |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE),continuationPageBoundary |-> <<0, 0, 0>>]),
    ([continuationAnchorBoundary |-> <<0, 0, 0>>,recoveredSurfaces |-> ,aborted |-> ,continuationPagePublished |-> <<FALSE, FALSE, FALSE>>,continuationBoundary |-> 0,assignedWitness |-> <<w1, w1, w1>>,churnStage |-> 1,registryEpoch |-> (v1 :> 1 @@ v2 :> 1),phase |-> "churn",continuationAnchorPublished |-> <<FALSE, FALSE, FALSE>>,shareConflicts |-> ,recoveryConflicts |-> ,finalizerSets |-> (<<1, b1, 1>> :> {} @@ <<1, b1, 2>> :> {} @@ <<1, b1, 3>> :> {} @@ <<1, b1, 4>> :> {} @@ <<1, b2, 1>> :> {} @@ <<1, b2, 2>> :> {} @@ <<1, b2, 3>> :> {} @@ <<1, b2, 4>> :> {} @@ <<1, b3, 1>> :> {} @@ <<1, b3, 2>> :> {} @@ <<1, b3, 3>> :> {} @@ <<1, b3, 4>> :> {} @@ <<2, b1, 1>> :> {} @@ <<2, b1, 2>> :> {} @@ <<2, b1, 3>> :> {} @@ <<2, b1, 4>> :> {} @@ <<2, b2, 1>> :> {} @@ <<2, b2, 2>> :> {} @@ <<2, b2, 3>> :> {} @@ <<2, b2, 4>> :> {} @@ <<2, b3, 1>> :> {} @@ <<2, b3, 2>> :> {} @@ <<2, b3, 3>> :> {} @@ <<2, b3, 4>> :> {} @@ <<3, b1, 1>> :> {} @@ <<3, b1, 2>> :> {} @@ <<3, b1, 3>> :> {} @@ <<3, b1, 4>> :> {} @@ <<3, b2, 1>> :> {} @@ <<3, b2, 2>> :> {} @@ <<3, b2, 3>> :> {} @@ <<3, b2, 4>> :> {} @@ <<3, b3, 1>> :> {} @@ <<3, b3, 2>> :> {} @@ <<3, b3, 3>> :> {} @@ <<3, b3, 4>> :> {}),continuationFetched |-> <<FALSE, FALSE, FALSE>>,witnessCerts |-> {},currentCycle |-> 1,missingShareClaims |-> ,reassignmentDepth |-> <<0, 0, 0>>,guardianReady |-> (v1 :> FALSE @@ v2 :> TRUE),finalized |-> {},windowClosed |-> ,recovered |-> ,shareReceipts |-> ,missingThresholdCertificates |-> ,witnessCheckpoint |-> (w1 :> 1 @@ w2 :> 1),votes |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE),continuationPageBoundary |-> <<0, 0, 0>>])
    >>
----


=============================================================================

---- MODULE NestedGuardianRecoveryRecurringLiveness_TEConstants ----
EXTENDS NestedGuardianRecoveryRecurringLiveness

CONSTANTS v1, v2, w1, w2, b1, b2, b3

=============================================================================

---- CONFIG NestedGuardianRecoveryRecurringLiveness_TTrace_1774033721 ----
CONSTANTS
    Validators = { v1 , v2 }
    Witnesses = { w1 , w2 }
    Blocks = { b1 , b2 , b3 }
    Slots = { 1 , 2 , 3 }
    Epochs = { 1 , 2 , 3 , 4 }
    QuorumSize = 2
    MaxReassignmentDepth = 1
    InitialEpoch = 1
    InitialWitness = w1
    TargetSlot1 = 1
    TargetSlot2 = 2
    TargetSlot3 = 3
    TargetBlock1 = b1
    TargetBlock2 = b2
    TargetBlock3 = b3
    StableEpoch1 = 2
    StableEpoch2 = 3
    StableEpoch3 = 4
    SmallCommitteeSlot = 1
    SmallRecoveryThreshold = 2
    LargeRecoveryThreshold = 2
    SmallRecoveryCommittee = { w1 , w2 }
    LargeRecoveryCommittee = { w1 , w2 }
    b2 = b2
    b3 = b3
    b1 = b1
    w2 = w2
    v1 = v1
    w1 = w1
    v2 = v2

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Fri Mar 20 15:08:41 EDT 2026