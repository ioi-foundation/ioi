---- MODULE NestedGuardianLiveness_TTrace_1774028346 ----
EXTENDS NestedGuardianLiveness, Sequences, TLCExt, Toolbox, Naturals, TLC, NestedGuardianLiveness_TEConstants

_expression ==
    LET NestedGuardianLiveness_TEExpression == INSTANCE NestedGuardianLiveness_TEExpression
    IN NestedGuardianLiveness_TEExpression!expression
----

_trace ==
    LET NestedGuardianLiveness_TETrace == INSTANCE NestedGuardianLiveness_TETrace
    IN NestedGuardianLiveness_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        phase = ("churn")
        /\
        continuationAnchorBoundary = ()
        /\
        continuationAnchorPublished = ()
        /\
        continuationFetched = ()
        /\
        finalizerSets = ((<<s1, b1, 1>> :> {} @@ <<s1, b1, 2>> :> {} @@ <<s1, b2, 1>> :> {} @@ <<s1, b2, 2>> :> {}))
        /\
        witnessCerts = ({})
        /\
        continuationPagePublished = ()
        /\
        reassignmentDepth = ((s1 :> 0))
        /\
        continuationBoundary = ()
        /\
        guardianReady = ((v1 :> FALSE @@ v2 :> TRUE))
        /\
        assignedWitness = ((s1 :> w1))
        /\
        finalized = ({})
        /\
        churnStage = (1)
        /\
        registryEpoch = ((v1 :> 1 @@ v2 :> 1))
        /\
        witnessCheckpoint = ((w1 :> 1 @@ w2 :> 1))
        /\
        votes = ({})
        /\
        witnessOnline = ((w1 :> TRUE @@ w2 :> TRUE))
        /\
        continuationPageBoundary = ()
    )
----

_init ==
    /\ phase = _TETrace[1].phase
    /\ continuationFetched = _TETrace[1].continuationFetched
    /\ continuationPagePublished = _TETrace[1].continuationPagePublished
    /\ guardianReady = _TETrace[1].guardianReady
    /\ assignedWitness = _TETrace[1].assignedWitness
    /\ witnessOnline = _TETrace[1].witnessOnline
    /\ continuationAnchorPublished = _TETrace[1].continuationAnchorPublished
    /\ witnessCheckpoint = _TETrace[1].witnessCheckpoint
    /\ continuationBoundary = _TETrace[1].continuationBoundary
    /\ finalizerSets = _TETrace[1].finalizerSets
    /\ continuationPageBoundary = _TETrace[1].continuationPageBoundary
    /\ churnStage = _TETrace[1].churnStage
    /\ witnessCerts = _TETrace[1].witnessCerts
    /\ votes = _TETrace[1].votes
    /\ continuationAnchorBoundary = _TETrace[1].continuationAnchorBoundary
    /\ registryEpoch = _TETrace[1].registryEpoch
    /\ finalized = _TETrace[1].finalized
    /\ reassignmentDepth = _TETrace[1].reassignmentDepth
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ phase  = _TETrace[i].phase
        /\ phase' = _TETrace[j].phase
        /\ continuationFetched  = _TETrace[i].continuationFetched
        /\ continuationFetched' = _TETrace[j].continuationFetched
        /\ continuationPagePublished  = _TETrace[i].continuationPagePublished
        /\ continuationPagePublished' = _TETrace[j].continuationPagePublished
        /\ guardianReady  = _TETrace[i].guardianReady
        /\ guardianReady' = _TETrace[j].guardianReady
        /\ assignedWitness  = _TETrace[i].assignedWitness
        /\ assignedWitness' = _TETrace[j].assignedWitness
        /\ witnessOnline  = _TETrace[i].witnessOnline
        /\ witnessOnline' = _TETrace[j].witnessOnline
        /\ continuationAnchorPublished  = _TETrace[i].continuationAnchorPublished
        /\ continuationAnchorPublished' = _TETrace[j].continuationAnchorPublished
        /\ witnessCheckpoint  = _TETrace[i].witnessCheckpoint
        /\ witnessCheckpoint' = _TETrace[j].witnessCheckpoint
        /\ continuationBoundary  = _TETrace[i].continuationBoundary
        /\ continuationBoundary' = _TETrace[j].continuationBoundary
        /\ finalizerSets  = _TETrace[i].finalizerSets
        /\ finalizerSets' = _TETrace[j].finalizerSets
        /\ continuationPageBoundary  = _TETrace[i].continuationPageBoundary
        /\ continuationPageBoundary' = _TETrace[j].continuationPageBoundary
        /\ churnStage  = _TETrace[i].churnStage
        /\ churnStage' = _TETrace[j].churnStage
        /\ witnessCerts  = _TETrace[i].witnessCerts
        /\ witnessCerts' = _TETrace[j].witnessCerts
        /\ votes  = _TETrace[i].votes
        /\ votes' = _TETrace[j].votes
        /\ continuationAnchorBoundary  = _TETrace[i].continuationAnchorBoundary
        /\ continuationAnchorBoundary' = _TETrace[j].continuationAnchorBoundary
        /\ registryEpoch  = _TETrace[i].registryEpoch
        /\ registryEpoch' = _TETrace[j].registryEpoch
        /\ finalized  = _TETrace[i].finalized
        /\ finalized' = _TETrace[j].finalized
        /\ reassignmentDepth  = _TETrace[i].reassignmentDepth
        /\ reassignmentDepth' = _TETrace[j].reassignmentDepth

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("NestedGuardianLiveness_TTrace_1774028346.json", _TETrace)

=============================================================================

 Note that you can extract this module `NestedGuardianLiveness_TEExpression`
  to a dedicated file to reuse `expression` (the module in the
  dedicated `NestedGuardianLiveness_TEExpression.tla` file takes precedence
  over the module `NestedGuardianLiveness_TEExpression` below).

---- MODULE NestedGuardianLiveness_TEExpression ----
EXTENDS NestedGuardianLiveness, Sequences, TLCExt, Toolbox, Naturals, TLC, NestedGuardianLiveness_TEConstants

expression ==
    [
        \* To hide variables of the `NestedGuardianLiveness` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        phase |-> phase
        ,continuationFetched |-> continuationFetched
        ,continuationPagePublished |-> continuationPagePublished
        ,guardianReady |-> guardianReady
        ,assignedWitness |-> assignedWitness
        ,witnessOnline |-> witnessOnline
        ,continuationAnchorPublished |-> continuationAnchorPublished
        ,witnessCheckpoint |-> witnessCheckpoint
        ,continuationBoundary |-> continuationBoundary
        ,finalizerSets |-> finalizerSets
        ,continuationPageBoundary |-> continuationPageBoundary
        ,churnStage |-> churnStage
        ,witnessCerts |-> witnessCerts
        ,votes |-> votes
        ,continuationAnchorBoundary |-> continuationAnchorBoundary
        ,registryEpoch |-> registryEpoch
        ,finalized |-> finalized
        ,reassignmentDepth |-> reassignmentDepth

        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_phaseUnchanged |-> phase = phase'

        \* Format the `phase` variable as Json value.
        \* ,_phaseJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(phase)

        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_phaseModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].phase # _TETrace[s-1].phase
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE NestedGuardianLiveness_TETrace ----
\*EXTENDS NestedGuardianLiveness, IOUtils, TLC, NestedGuardianLiveness_TEConstants
\*
\*trace == IODeserialize("NestedGuardianLiveness_TTrace_1774028346.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE NestedGuardianLiveness_TETrace ----
EXTENDS NestedGuardianLiveness, TLC, NestedGuardianLiveness_TEConstants

trace ==
    <<
    ([phase |-> "churn",continuationAnchorBoundary |-> 0,continuationAnchorPublished |-> FALSE,continuationFetched |-> FALSE,finalizerSets |-> (<<s1, b1, 1>> :> {} @@ <<s1, b1, 2>> :> {} @@ <<s1, b2, 1>> :> {} @@ <<s1, b2, 2>> :> {}),witnessCerts |-> {},continuationPagePublished |-> FALSE,reassignmentDepth |-> (s1 :> 0),continuationBoundary |-> 0,guardianReady |-> (v1 :> TRUE @@ v2 :> TRUE),assignedWitness |-> (s1 :> w1),finalized |-> {},churnStage |-> 0,registryEpoch |-> (v1 :> 1 @@ v2 :> 1),witnessCheckpoint |-> (w1 :> 1 @@ w2 :> 1),votes |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE),continuationPageBoundary |-> 0]),
    ([phase |-> "churn",continuationAnchorBoundary |-> ,continuationAnchorPublished |-> ,continuationFetched |-> ,finalizerSets |-> (<<s1, b1, 1>> :> {} @@ <<s1, b1, 2>> :> {} @@ <<s1, b2, 1>> :> {} @@ <<s1, b2, 2>> :> {}),witnessCerts |-> {},continuationPagePublished |-> ,reassignmentDepth |-> (s1 :> 0),continuationBoundary |-> ,guardianReady |-> (v1 :> FALSE @@ v2 :> TRUE),assignedWitness |-> (s1 :> w1),finalized |-> {},churnStage |-> 1,registryEpoch |-> (v1 :> 1 @@ v2 :> 1),witnessCheckpoint |-> (w1 :> 1 @@ w2 :> 1),votes |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE),continuationPageBoundary |-> ])
    >>
----


=============================================================================

---- MODULE NestedGuardianLiveness_TEConstants ----
EXTENDS NestedGuardianLiveness

CONSTANTS v1, v2, w1, w2, b1, b2, s1

=============================================================================

---- CONFIG NestedGuardianLiveness_TTrace_1774028346 ----
CONSTANTS
    Validators = { v1 , v2 }
    Witnesses = { w1 , w2 }
    Blocks = { b1 , b2 }
    Slots = { s1 }
    Epochs = { 1 , 2 }
    QuorumSize = 2
    MaxReassignmentDepth = 1
    InitialEpoch = 1
    InitialWitness = w1
    TargetSlot = s1
    TargetBlock = b1
    StableEpoch = 2
    w2 = w2
    v1 = v1
    b1 = b1
    w1 = w1
    b2 = b2
    v2 = v2
    s1 = s1

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
\* Generated on Fri Mar 20 13:39:07 EDT 2026