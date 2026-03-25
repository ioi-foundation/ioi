---- MODULE NestedGuardianRecovery_TTrace_1773909267 ----
EXTENDS NestedGuardianRecovery, Sequences, TLCExt, NestedGuardianRecovery_TEConstants, Toolbox, Naturals, TLC

_expression ==
    LET NestedGuardianRecovery_TEExpression == INSTANCE NestedGuardianRecovery_TEExpression
    IN NestedGuardianRecovery_TEExpression!expression
----

_trace ==
    LET NestedGuardianRecovery_TETrace == INSTANCE NestedGuardianRecovery_TETrace
    IN NestedGuardianRecovery_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        windowClosed = ((s1 :> FALSE))
        /\
        recovered = ({})
        /\
        shareReceipts = ({<<w1, s1, b1>>, <<w2, s1, b1>>, <<w3, s1, b1>>, <<w3, s1, b2>>, <<w4, s1, b2>>})
        /\
        shareConflicts = ({<<w3, s1, {b1, b2}>>})
        /\
        recoveryConflicts = ({<<s1, {b1, b2}>>})
        /\
        aborted = ({})
        /\
        missingThresholdCertificates = ({})
        /\
        missingShareClaims = ({})
        /\
        witnessOnline = ((w1 :> TRUE @@ w2 :> TRUE @@ w3 :> TRUE @@ w4 :> TRUE))
    )
----

_init ==
    /\ aborted = _TETrace[1].aborted
    /\ missingThresholdCertificates = _TETrace[1].missingThresholdCertificates
    /\ witnessOnline = _TETrace[1].witnessOnline
    /\ shareConflicts = _TETrace[1].shareConflicts
    /\ missingShareClaims = _TETrace[1].missingShareClaims
    /\ shareReceipts = _TETrace[1].shareReceipts
    /\ windowClosed = _TETrace[1].windowClosed
    /\ recoveryConflicts = _TETrace[1].recoveryConflicts
    /\ recovered = _TETrace[1].recovered
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ aborted  = _TETrace[i].aborted
        /\ aborted' = _TETrace[j].aborted
        /\ missingThresholdCertificates  = _TETrace[i].missingThresholdCertificates
        /\ missingThresholdCertificates' = _TETrace[j].missingThresholdCertificates
        /\ witnessOnline  = _TETrace[i].witnessOnline
        /\ witnessOnline' = _TETrace[j].witnessOnline
        /\ shareConflicts  = _TETrace[i].shareConflicts
        /\ shareConflicts' = _TETrace[j].shareConflicts
        /\ missingShareClaims  = _TETrace[i].missingShareClaims
        /\ missingShareClaims' = _TETrace[j].missingShareClaims
        /\ shareReceipts  = _TETrace[i].shareReceipts
        /\ shareReceipts' = _TETrace[j].shareReceipts
        /\ windowClosed  = _TETrace[i].windowClosed
        /\ windowClosed' = _TETrace[j].windowClosed
        /\ recoveryConflicts  = _TETrace[i].recoveryConflicts
        /\ recoveryConflicts' = _TETrace[j].recoveryConflicts
        /\ recovered  = _TETrace[i].recovered
        /\ recovered' = _TETrace[j].recovered

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("NestedGuardianRecovery_TTrace_1773909267.json", _TETrace)

=============================================================================

 Note that you can extract this module `NestedGuardianRecovery_TEExpression`
  to a dedicated file to reuse `expression` (the module in the
  dedicated `NestedGuardianRecovery_TEExpression.tla` file takes precedence
  over the module `NestedGuardianRecovery_TEExpression` below).

---- MODULE NestedGuardianRecovery_TEExpression ----
EXTENDS NestedGuardianRecovery, Sequences, TLCExt, NestedGuardianRecovery_TEConstants, Toolbox, Naturals, TLC

expression ==
    [
        \* To hide variables of the `NestedGuardianRecovery` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        aborted |-> aborted
        ,missingThresholdCertificates |-> missingThresholdCertificates
        ,witnessOnline |-> witnessOnline
        ,shareConflicts |-> shareConflicts
        ,missingShareClaims |-> missingShareClaims
        ,shareReceipts |-> shareReceipts
        ,windowClosed |-> windowClosed
        ,recoveryConflicts |-> recoveryConflicts
        ,recovered |-> recovered

        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_abortedUnchanged |-> aborted = aborted'

        \* Format the `aborted` variable as Json value.
        \* ,_abortedJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(aborted)

        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_abortedModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].aborted # _TETrace[s-1].aborted
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE NestedGuardianRecovery_TETrace ----
\*EXTENDS NestedGuardianRecovery, IOUtils, NestedGuardianRecovery_TEConstants, TLC
\*
\*trace == IODeserialize("NestedGuardianRecovery_TTrace_1773909267.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE NestedGuardianRecovery_TETrace ----
EXTENDS NestedGuardianRecovery, NestedGuardianRecovery_TEConstants, TLC

trace ==
    <<
    ([windowClosed |-> (s1 :> FALSE),recovered |-> {},shareReceipts |-> {},shareConflicts |-> {},recoveryConflicts |-> {},aborted |-> {},missingThresholdCertificates |-> {},missingShareClaims |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE @@ w3 :> TRUE @@ w4 :> TRUE)]),
    ([windowClosed |-> (s1 :> FALSE),recovered |-> {},shareReceipts |-> {<<w1, s1, b1>>},shareConflicts |-> {},recoveryConflicts |-> {},aborted |-> {},missingThresholdCertificates |-> {},missingShareClaims |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE @@ w3 :> TRUE @@ w4 :> TRUE)]),
    ([windowClosed |-> (s1 :> FALSE),recovered |-> {},shareReceipts |-> {<<w1, s1, b1>>, <<w2, s1, b1>>},shareConflicts |-> {},recoveryConflicts |-> {},aborted |-> {},missingThresholdCertificates |-> {},missingShareClaims |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE @@ w3 :> TRUE @@ w4 :> TRUE)]),
    ([windowClosed |-> (s1 :> FALSE),recovered |-> {},shareReceipts |-> {<<w1, s1, b1>>, <<w2, s1, b1>>, <<w3, s1, b2>>},shareConflicts |-> {},recoveryConflicts |-> {},aborted |-> {},missingThresholdCertificates |-> {},missingShareClaims |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE @@ w3 :> TRUE @@ w4 :> TRUE)]),
    ([windowClosed |-> (s1 :> FALSE),recovered |-> {},shareReceipts |-> {<<w1, s1, b1>>, <<w2, s1, b1>>, <<w3, s1, b2>>, <<w4, s1, b2>>},shareConflicts |-> {},recoveryConflicts |-> {},aborted |-> {},missingThresholdCertificates |-> {},missingShareClaims |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE @@ w3 :> TRUE @@ w4 :> TRUE)]),
    ([windowClosed |-> (s1 :> FALSE),recovered |-> {},shareReceipts |-> {<<w1, s1, b1>>, <<w2, s1, b1>>, <<w3, s1, b2>>, <<w4, s1, b2>>},shareConflicts |-> {},recoveryConflicts |-> {<<s1, {b1, b2}>>},aborted |-> {},missingThresholdCertificates |-> {},missingShareClaims |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE @@ w3 :> TRUE @@ w4 :> TRUE)]),
    ([windowClosed |-> (s1 :> FALSE),recovered |-> {},shareReceipts |-> {<<w1, s1, b1>>, <<w2, s1, b1>>, <<w3, s1, b1>>, <<w3, s1, b2>>, <<w4, s1, b2>>},shareConflicts |-> {<<w3, s1, {b1, b2}>>},recoveryConflicts |-> {<<s1, {b1, b2}>>},aborted |-> {},missingThresholdCertificates |-> {},missingShareClaims |-> {},witnessOnline |-> (w1 :> TRUE @@ w2 :> TRUE @@ w3 :> TRUE @@ w4 :> TRUE)])
    >>
----


=============================================================================

---- MODULE NestedGuardianRecovery_TEConstants ----
EXTENDS NestedGuardianRecovery

CONSTANTS w1, w2, w3, w4, b1, b2, s1

=============================================================================

---- CONFIG NestedGuardianRecovery_TTrace_1773909267 ----
CONSTANTS
    Witnesses = { w1 , w2 , w3 , w4 }
    Blocks = { b1 , b2 }
    Slots = { s1 }
    SmallCommitteeSlot = s1
    SmallRecoveryThreshold = 2
    LargeRecoveryThreshold = 2
    SmallRecoveryCommittee = { w1 , w2 , w3 , w4 }
    LargeRecoveryCommittee = { w1 , w2 , w3 , w4 }
    w4 = w4
    w1 = w1
    s1 = s1
    w2 = w2
    b1 = b1
    b2 = b2
    w3 = w3

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
\* Generated on Thu Mar 19 04:34:28 EDT 2026