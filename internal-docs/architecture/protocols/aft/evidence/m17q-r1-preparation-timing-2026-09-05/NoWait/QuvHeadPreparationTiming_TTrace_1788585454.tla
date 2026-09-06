---- MODULE QuvHeadPreparationTiming_TTrace_1788585454 ----
EXTENDS Sequences, QuvHeadPreparationTiming, TLCExt, Toolbox, Naturals, TLC, QuvHeadPreparationTiming_TEConstants

_expression ==
    LET QuvHeadPreparationTiming_TEExpression == INSTANCE QuvHeadPreparationTiming_TEExpression
    IN QuvHeadPreparationTiming_TEExpression!expression
----

_trace ==
    LET QuvHeadPreparationTiming_TETrace == INSTANCE QuvHeadPreparationTiming_TETrace
    IN QuvHeadPreparationTiming_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        refused = ({m2})
        /\
        replied = ({m1})
        /\
        ready = ({m1})
        /\
        now = (1)
        /\
        started = (TRUE)
        /\
        startTime = (0)
        /\
        finished = (TRUE)
        /\
        ownGrant = ({m1})
    )
----

_init ==
    /\ replied = _TETrace[1].replied
    /\ now = _TETrace[1].now
    /\ ownGrant = _TETrace[1].ownGrant
    /\ refused = _TETrace[1].refused
    /\ started = _TETrace[1].started
    /\ startTime = _TETrace[1].startTime
    /\ ready = _TETrace[1].ready
    /\ finished = _TETrace[1].finished
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ replied  = _TETrace[i].replied
        /\ replied' = _TETrace[j].replied
        /\ now  = _TETrace[i].now
        /\ now' = _TETrace[j].now
        /\ ownGrant  = _TETrace[i].ownGrant
        /\ ownGrant' = _TETrace[j].ownGrant
        /\ refused  = _TETrace[i].refused
        /\ refused' = _TETrace[j].refused
        /\ started  = _TETrace[i].started
        /\ started' = _TETrace[j].started
        /\ startTime  = _TETrace[i].startTime
        /\ startTime' = _TETrace[j].startTime
        /\ ready  = _TETrace[i].ready
        /\ ready' = _TETrace[j].ready
        /\ finished  = _TETrace[i].finished
        /\ finished' = _TETrace[j].finished

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("QuvHeadPreparationTiming_TTrace_1788585454.json", _TETrace)

=============================================================================

 Note that you can extract this module `QuvHeadPreparationTiming_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `QuvHeadPreparationTiming_TEExpression.tla` file takes precedence 
  over the module `QuvHeadPreparationTiming_TEExpression` below).

---- MODULE QuvHeadPreparationTiming_TEExpression ----
EXTENDS Sequences, QuvHeadPreparationTiming, TLCExt, Toolbox, Naturals, TLC, QuvHeadPreparationTiming_TEConstants

expression == 
    [
        \* To hide variables of the `QuvHeadPreparationTiming` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        replied |-> replied
        ,now |-> now
        ,ownGrant |-> ownGrant
        ,refused |-> refused
        ,started |-> started
        ,startTime |-> startTime
        ,ready |-> ready
        ,finished |-> finished
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_repliedUnchanged |-> replied = replied'
        
        \* Format the `replied` variable as Json value.
        \* ,_repliedJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(replied)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_repliedModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].replied # _TETrace[s-1].replied
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE QuvHeadPreparationTiming_TETrace ----
\*EXTENDS IOUtils, QuvHeadPreparationTiming, TLC, QuvHeadPreparationTiming_TEConstants
\*
\*trace == IODeserialize("QuvHeadPreparationTiming_TTrace_1788585454.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE QuvHeadPreparationTiming_TETrace ----
EXTENDS QuvHeadPreparationTiming, TLC, QuvHeadPreparationTiming_TEConstants

trace == 
    <<
    ([refused |-> {},replied |-> {},ready |-> {m1},now |-> 0,started |-> FALSE,startTime |-> 0,finished |-> FALSE,ownGrant |-> {m1}]),
    ([refused |-> {},replied |-> {},ready |-> {m1},now |-> 0,started |-> TRUE,startTime |-> 0,finished |-> FALSE,ownGrant |-> {m1}]),
    ([refused |-> {},replied |-> {m1},ready |-> {m1},now |-> 0,started |-> TRUE,startTime |-> 0,finished |-> FALSE,ownGrant |-> {m1}]),
    ([refused |-> {m2},replied |-> {m1},ready |-> {m1},now |-> 0,started |-> TRUE,startTime |-> 0,finished |-> FALSE,ownGrant |-> {m1}]),
    ([refused |-> {m2},replied |-> {m1},ready |-> {m1},now |-> 1,started |-> TRUE,startTime |-> 0,finished |-> FALSE,ownGrant |-> {m1}]),
    ([refused |-> {m2},replied |-> {m1},ready |-> {m1},now |-> 1,started |-> TRUE,startTime |-> 0,finished |-> TRUE,ownGrant |-> {m1}])
    >>
----


=============================================================================

---- MODULE QuvHeadPreparationTiming_TEConstants ----
EXTENDS QuvHeadPreparationTiming

CONSTANTS m1, m2

=============================================================================

---- CONFIG QuvHeadPreparationTiming_TTrace_1788585454 ----
CONSTANTS
    Correct = { m1 , m2 }
    Initiator = m1
    PreparationBound = 2
    DecisionBound = 1
    WaitForPreparation = FALSE
    m1 = m1
    m2 = m2

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
\* Generated on Sat Sep 05 01:17:34 EDT 2026