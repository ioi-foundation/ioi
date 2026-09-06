---- MODULE QuvHeadPreparation_TTrace_1788576505 ----
EXTENDS Sequences, TLCExt, QuvHeadPreparation_TEConstants, Toolbox, Naturals, TLC, QuvHeadPreparation

_expression ==
    LET QuvHeadPreparation_TEExpression == INSTANCE QuvHeadPreparation_TEExpression
    IN QuvHeadPreparation_TEExpression!expression
----

_trace ==
    LET QuvHeadPreparation_TETrace == INSTANCE QuvHeadPreparation_TETrace
    IN QuvHeadPreparation_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        grants = ((m1 :> [slot |-> 1, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> "no live grant"))
        /\
        histories = ((m1 :> <<>> @@ m2 :> <<>>))
        /\
        seen = ((m1 :> <<{"A"}, {}>> @@ m2 :> <<{"A"}, {}>>))
    )
----

_init ==
    /\ seen = _TETrace[1].seen
    /\ grants = _TETrace[1].grants
    /\ histories = _TETrace[1].histories
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ seen  = _TETrace[i].seen
        /\ seen' = _TETrace[j].seen
        /\ grants  = _TETrace[i].grants
        /\ grants' = _TETrace[j].grants
        /\ histories  = _TETrace[i].histories
        /\ histories' = _TETrace[j].histories

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("QuvHeadPreparation_TTrace_1788576505.json", _TETrace)

=============================================================================

 Note that you can extract this module `QuvHeadPreparation_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `QuvHeadPreparation_TEExpression.tla` file takes precedence 
  over the module `QuvHeadPreparation_TEExpression` below).

---- MODULE QuvHeadPreparation_TEExpression ----
EXTENDS Sequences, TLCExt, QuvHeadPreparation_TEConstants, Toolbox, Naturals, TLC, QuvHeadPreparation

expression == 
    [
        \* To hide variables of the `QuvHeadPreparation` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        seen |-> seen
        ,grants |-> grants
        ,histories |-> histories
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_seenUnchanged |-> seen = seen'
        
        \* Format the `seen` variable as Json value.
        \* ,_seenJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(seen)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_seenModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].seen # _TETrace[s-1].seen
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE QuvHeadPreparation_TETrace ----
\*EXTENDS IOUtils, QuvHeadPreparation_TEConstants, TLC, QuvHeadPreparation
\*
\*trace == IODeserialize("QuvHeadPreparation_TTrace_1788576505.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE QuvHeadPreparation_TETrace ----
EXTENDS QuvHeadPreparation_TEConstants, TLC, QuvHeadPreparation

trace == 
    <<
    ([grants |-> (m1 :> "no live grant" @@ m2 :> "no live grant"),histories |-> (m1 :> <<>> @@ m2 :> <<>>),seen |-> (m1 :> <<{}, {}>> @@ m2 :> <<{}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 1, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> "no live grant"),histories |-> (m1 :> <<>> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {}>> @@ m2 :> <<{"A"}, {}>>)])
    >>
----


=============================================================================

---- MODULE QuvHeadPreparation_TEConstants ----
EXTENDS QuvHeadPreparation

CONSTANTS m1, m2

=============================================================================

---- CONFIG QuvHeadPreparation_TTrace_1788576505 ----
CONSTANTS
    Correct = { m1 , m2 }
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
\* Generated on Fri Sep 04 22:48:25 EDT 2026