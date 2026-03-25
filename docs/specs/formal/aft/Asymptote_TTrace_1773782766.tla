---- MODULE Asymptote_TTrace_1773782766 ----
EXTENDS Asymptote_TEConstants, Sequences, TLCExt, Toolbox, Naturals, TLC, Asymptote

_expression ==
    LET Asymptote_TEExpression == INSTANCE Asymptote_TEExpression
    IN Asymptote_TEExpression!expression
----

_trace ==
    LET Asymptote_TETrace == INSTANCE Asymptote_TETrace
    IN Asymptote_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        canonicalCloses = ({})
        /\
        sealedFinal = ({})
        /\
        baseCerts = ({<<s1, b1, e1, {v1, v2}>>})
        /\
        validatorVotes = ({<<v1, s1, b1, e1>>, <<v2, s1, b1, e1>>})
        /\
        challengeSurfaces = ({<<s1, b1, e1, c1>>})
        /\
        collapseState = ((s1 :> 3))
        /\
        canonicalAborts = ({})
        /\
        transcriptSurfaces = ({<<s1, b1, e1, t0>>})
    )
----

_init ==
    /\ canonicalAborts = _TETrace[1].canonicalAborts
    /\ validatorVotes = _TETrace[1].validatorVotes
    /\ baseCerts = _TETrace[1].baseCerts
    /\ collapseState = _TETrace[1].collapseState
    /\ sealedFinal = _TETrace[1].sealedFinal
    /\ canonicalCloses = _TETrace[1].canonicalCloses
    /\ challengeSurfaces = _TETrace[1].challengeSurfaces
    /\ transcriptSurfaces = _TETrace[1].transcriptSurfaces
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ canonicalAborts  = _TETrace[i].canonicalAborts
        /\ canonicalAborts' = _TETrace[j].canonicalAborts
        /\ validatorVotes  = _TETrace[i].validatorVotes
        /\ validatorVotes' = _TETrace[j].validatorVotes
        /\ baseCerts  = _TETrace[i].baseCerts
        /\ baseCerts' = _TETrace[j].baseCerts
        /\ collapseState  = _TETrace[i].collapseState
        /\ collapseState' = _TETrace[j].collapseState
        /\ sealedFinal  = _TETrace[i].sealedFinal
        /\ sealedFinal' = _TETrace[j].sealedFinal
        /\ canonicalCloses  = _TETrace[i].canonicalCloses
        /\ canonicalCloses' = _TETrace[j].canonicalCloses
        /\ challengeSurfaces  = _TETrace[i].challengeSurfaces
        /\ challengeSurfaces' = _TETrace[j].challengeSurfaces
        /\ transcriptSurfaces  = _TETrace[i].transcriptSurfaces
        /\ transcriptSurfaces' = _TETrace[j].transcriptSurfaces

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("Asymptote_TTrace_1773782766.json", _TETrace)

=============================================================================

 Note that you can extract this module `Asymptote_TEExpression`
  to a dedicated file to reuse `expression` (the module in the
  dedicated `Asymptote_TEExpression.tla` file takes precedence
  over the module `Asymptote_TEExpression` below).

---- MODULE Asymptote_TEExpression ----
EXTENDS Asymptote_TEConstants, Sequences, TLCExt, Toolbox, Naturals, TLC, Asymptote

expression ==
    [
        \* To hide variables of the `Asymptote` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        canonicalAborts |-> canonicalAborts
        ,validatorVotes |-> validatorVotes
        ,baseCerts |-> baseCerts
        ,collapseState |-> collapseState
        ,sealedFinal |-> sealedFinal
        ,canonicalCloses |-> canonicalCloses
        ,challengeSurfaces |-> challengeSurfaces
        ,transcriptSurfaces |-> transcriptSurfaces

        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_canonicalAbortsUnchanged |-> canonicalAborts = canonicalAborts'

        \* Format the `canonicalAborts` variable as Json value.
        \* ,_canonicalAbortsJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(canonicalAborts)

        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_canonicalAbortsModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].canonicalAborts # _TETrace[s-1].canonicalAborts
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE Asymptote_TETrace ----
\*EXTENDS Asymptote_TEConstants, IOUtils, TLC, Asymptote
\*
\*trace == IODeserialize("Asymptote_TTrace_1773782766.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE Asymptote_TETrace ----
EXTENDS Asymptote_TEConstants, TLC, Asymptote

trace ==
    <<
    ([canonicalCloses |-> {},sealedFinal |-> {},baseCerts |-> {},validatorVotes |-> {},challengeSurfaces |-> {},collapseState |-> (s1 :> 0),canonicalAborts |-> {},transcriptSurfaces |-> {}]),
    ([canonicalCloses |-> {},sealedFinal |-> {},baseCerts |-> {},validatorVotes |-> {<<v1, s1, b1, e1>>},challengeSurfaces |-> {},collapseState |-> (s1 :> 0),canonicalAborts |-> {},transcriptSurfaces |-> {}]),
    ([canonicalCloses |-> {},sealedFinal |-> {},baseCerts |-> {},validatorVotes |-> {<<v1, s1, b1, e1>>, <<v2, s1, b1, e1>>},challengeSurfaces |-> {},collapseState |-> (s1 :> 0),canonicalAborts |-> {},transcriptSurfaces |-> {}]),
    ([canonicalCloses |-> {},sealedFinal |-> {},baseCerts |-> {<<s1, b1, e1, {v1, v2}>>},validatorVotes |-> {<<v1, s1, b1, e1>>, <<v2, s1, b1, e1>>},challengeSurfaces |-> {},collapseState |-> (s1 :> 1),canonicalAborts |-> {},transcriptSurfaces |-> {}]),
    ([canonicalCloses |-> {},sealedFinal |-> {},baseCerts |-> {<<s1, b1, e1, {v1, v2}>>},validatorVotes |-> {<<v1, s1, b1, e1>>, <<v2, s1, b1, e1>>},challengeSurfaces |-> {},collapseState |-> (s1 :> 2),canonicalAborts |-> {},transcriptSurfaces |-> {<<s1, b1, e1, t0>>}]),
    ([canonicalCloses |-> {},sealedFinal |-> {},baseCerts |-> {<<s1, b1, e1, {v1, v2}>>},validatorVotes |-> {<<v1, s1, b1, e1>>, <<v2, s1, b1, e1>>},challengeSurfaces |-> {<<s1, b1, e1, c1>>},collapseState |-> (s1 :> 3),canonicalAborts |-> {},transcriptSurfaces |-> {<<s1, b1, e1, t0>>}])
    >>
----


=============================================================================

---- MODULE Asymptote_TEConstants ----
EXTENDS Asymptote

CONSTANTS v1, v2, v3, b1, b2, s1, e1, t0, t1, c0, c1

=============================================================================

---- CONFIG Asymptote_TTrace_1773782766 ----
CONSTANTS
    Validators = { v1 , v2 , v3 }
    Blocks = { b1 , b2 }
    Slots = { s1 }
    Epochs = { e1 }
    ValidatorQuorum = 2
    TranscriptRoots = { t0 , t1 }
    ChallengeRoots = { c0 , c1 }
    EmptyChallengeRoot = c0
    t0 = t0
    e1 = e1
    v3 = v3
    v2 = v2
    s1 = s1
    t1 = t1
    c1 = c1
    b1 = b1
    v1 = v1
    b2 = b2
    c0 = c0

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
\* Generated on Tue Mar 17 17:26:07 EDT 2026