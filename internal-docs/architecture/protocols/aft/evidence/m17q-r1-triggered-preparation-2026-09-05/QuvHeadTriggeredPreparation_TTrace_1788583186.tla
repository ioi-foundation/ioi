---- MODULE QuvHeadTriggeredPreparation_TTrace_1788583186 ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, QuvHeadTriggeredPreparation, QuvHeadTriggeredPreparation_TEConstants

_expression ==
    LET QuvHeadTriggeredPreparation_TEExpression == INSTANCE QuvHeadTriggeredPreparation_TEExpression
    IN QuvHeadTriggeredPreparation_TEExpression!expression
----

_trace ==
    LET QuvHeadTriggeredPreparation_TETrace == INSTANCE QuvHeadTriggeredPreparation_TETrace
    IN QuvHeadTriggeredPreparation_TETrace!trace
----

_prop ==
    ~<>[](
        grants = ((m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]))
        /\
        operations = ((m1 :> [slot |-> 2, value |-> "A", parent |-> "A", captured |-> (m1 :> {"A"} @@ m2 :> {}), capturedFirst |-> (m1 :> "A" @@ m2 :> "unseen"), received |-> {m1}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]))
        /\
        firstSeen = ((m1 :> <<"A", "A">> @@ m2 :> <<"A", "unseen">>))
        /\
        histories = ((m1 :> <<"A">> @@ m2 :> <<>>))
        /\
        seen = ((m1 :> <<{"A"}, {"A"}>> @@ m2 :> <<{"A"}, {}>>))
    )
----

_init ==
    /\ grants = _TETrace[1].grants
    /\ operations = _TETrace[1].operations
    /\ histories = _TETrace[1].histories
    /\ firstSeen = _TETrace[1].firstSeen
    /\ seen = _TETrace[1].seen
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ grants  = _TETrace[i].grants
        /\ grants' = _TETrace[j].grants
        /\ operations  = _TETrace[i].operations
        /\ operations' = _TETrace[j].operations
        /\ histories  = _TETrace[i].histories
        /\ histories' = _TETrace[j].histories
        /\ firstSeen  = _TETrace[i].firstSeen
        /\ firstSeen' = _TETrace[j].firstSeen
        /\ seen  = _TETrace[i].seen
        /\ seen' = _TETrace[j].seen

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("QuvHeadTriggeredPreparation_TTrace_1788583186.json", _TETrace)

=============================================================================

 Note that you can extract this module `QuvHeadTriggeredPreparation_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `QuvHeadTriggeredPreparation_TEExpression.tla` file takes precedence 
  over the module `QuvHeadTriggeredPreparation_TEExpression` below).

---- MODULE QuvHeadTriggeredPreparation_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, QuvHeadTriggeredPreparation, QuvHeadTriggeredPreparation_TEConstants

expression == 
    [
        \* To hide variables of the `QuvHeadTriggeredPreparation` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        grants |-> grants
        ,operations |-> operations
        ,histories |-> histories
        ,firstSeen |-> firstSeen
        ,seen |-> seen
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_grantsUnchanged |-> grants = grants'
        
        \* Format the `grants` variable as Json value.
        \* ,_grantsJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(grants)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_grantsModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].grants # _TETrace[s-1].grants
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE QuvHeadTriggeredPreparation_TETrace ----
\*EXTENDS IOUtils, TLC, QuvHeadTriggeredPreparation, QuvHeadTriggeredPreparation_TEConstants
\*
\*trace == IODeserialize("QuvHeadTriggeredPreparation_TTrace_1788583186.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE QuvHeadTriggeredPreparation_TETrace ----
EXTENDS TLC, QuvHeadTriggeredPreparation, QuvHeadTriggeredPreparation_TEConstants

trace == 
    <<
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"unseen", "unseen">> @@ m2 :> <<"unseen", "unseen">>),histories |-> (m1 :> <<>> @@ m2 :> <<>>),seen |-> (m1 :> <<{}, {}>> @@ m2 :> <<{}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 1, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"unseen", "unseen">> @@ m2 :> <<"unseen", "unseen">>),histories |-> (m1 :> <<>> @@ m2 :> <<>>),seen |-> (m1 :> <<{}, {}>> @@ m2 :> <<{}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 1, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {"A"} @@ m2 :> {}), capturedFirst |-> (m1 :> "A" @@ m2 :> "unseen"), received |-> {}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"A", "unseen">> @@ m2 :> <<"unseen", "unseen">>),histories |-> (m1 :> <<>> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {}>> @@ m2 :> <<{}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 1, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {"A"} @@ m2 :> {"A"}), capturedFirst |-> (m1 :> "A" @@ m2 :> "A"), received |-> {}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"A", "unseen">> @@ m2 :> <<"A", "unseen">>),histories |-> (m1 :> <<>> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {}>> @@ m2 :> <<{"A"}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 1, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {"A"} @@ m2 :> {"A"}), capturedFirst |-> (m1 :> "A" @@ m2 :> "A"), received |-> {m1}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"A", "unseen">> @@ m2 :> <<"A", "unseen">>),histories |-> (m1 :> <<>> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {}>> @@ m2 :> <<{"A"}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 1, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {"A"} @@ m2 :> {"A"}), capturedFirst |-> (m1 :> "A" @@ m2 :> "A"), received |-> {m1, m2}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"A", "unseen">> @@ m2 :> <<"A", "unseen">>),histories |-> (m1 :> <<>> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {}>> @@ m2 :> <<{"A"}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 1, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"A", "unseen">> @@ m2 :> <<"A", "unseen">>),histories |-> (m1 :> <<>> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {}>> @@ m2 :> <<{"A"}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"A", "unseen">> @@ m2 :> <<"A", "unseen">>),histories |-> (m1 :> <<"A">> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {}>> @@ m2 :> <<{"A"}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 2, value |-> "A", parent |-> "A", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"A", "unseen">> @@ m2 :> <<"A", "unseen">>),histories |-> (m1 :> <<"A">> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {}>> @@ m2 :> <<{"A"}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 2, value |-> "A", parent |-> "A", captured |-> (m1 :> {"A"} @@ m2 :> {}), capturedFirst |-> (m1 :> "A" @@ m2 :> "unseen"), received |-> {}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"A", "A">> @@ m2 :> <<"A", "unseen">>),histories |-> (m1 :> <<"A">> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {"A"}>> @@ m2 :> <<{"A"}, {}>>)]),
    ([grants |-> (m1 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis"]),operations |-> (m1 :> [slot |-> 2, value |-> "A", parent |-> "A", captured |-> (m1 :> {"A"} @@ m2 :> {}), capturedFirst |-> (m1 :> "A" @@ m2 :> "unseen"), received |-> {m1}] @@ m2 :> [slot |-> 0, value |-> "A", parent |-> "rooted genesis", captured |-> (m1 :> {} @@ m2 :> {}), capturedFirst |-> (m1 :> "unseen" @@ m2 :> "unseen"), received |-> {}]),firstSeen |-> (m1 :> <<"A", "A">> @@ m2 :> <<"A", "unseen">>),histories |-> (m1 :> <<"A">> @@ m2 :> <<>>),seen |-> (m1 :> <<{"A"}, {"A"}>> @@ m2 :> <<{"A"}, {}>>)])
    >>
----


=============================================================================

---- MODULE QuvHeadTriggeredPreparation_TEConstants ----
EXTENDS QuvHeadTriggeredPreparation

CONSTANTS m1, m2

=============================================================================

---- CONFIG QuvHeadTriggeredPreparation_TTrace_1788583186 ----
CONSTANTS
    Correct = { m1 , m2 }
    Candidates = { "A" }
    MaxSlot = 2
    AuthorityMode = "owned"
    Initiator = m1
    AutoPrepare = FALSE
    m1 = m1
    m2 = m2

PROPERTY
    _prop

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
\* Generated on Sat Sep 05 00:39:47 EDT 2026