---- MODULE CanonicalOrderingOmissionTrace_TTrace_1773787920 ----
EXTENDS Sequences, CanonicalOrderingOmissionTrace, TLCExt, Toolbox, Naturals, TLC

_expression ==
    LET CanonicalOrderingOmissionTrace_TEExpression == INSTANCE CanonicalOrderingOmissionTrace_TEExpression
    IN CanonicalOrderingOmissionTrace_TEExpression!expression
----

_trace ==
    LET CanonicalOrderingOmissionTrace_TETrace == INSTANCE CanonicalOrderingOmissionTrace_TETrace
    IN CanonicalOrderingOmissionTrace_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        candidateCerts = ({<<1, {"tx1"}>>})
        /\
        closedCutoffs = ({1})
        /\
        recoveredSets = (<<{"tx1", "tx2"}>>)
        /\
        omissionProofs = ({<<1, {"tx1"}, "tx2">>})
        /\
        admittedCerts = ({})
        /\
        bulletin = (<<{"tx1", "tx2"}>>)
    )
----

_init ==
    /\ bulletin = _TETrace[1].bulletin
    /\ admittedCerts = _TETrace[1].admittedCerts
    /\ recoveredSets = _TETrace[1].recoveredSets
    /\ omissionProofs = _TETrace[1].omissionProofs
    /\ closedCutoffs = _TETrace[1].closedCutoffs
    /\ candidateCerts = _TETrace[1].candidateCerts
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ bulletin  = _TETrace[i].bulletin
        /\ bulletin' = _TETrace[j].bulletin
        /\ admittedCerts  = _TETrace[i].admittedCerts
        /\ admittedCerts' = _TETrace[j].admittedCerts
        /\ recoveredSets  = _TETrace[i].recoveredSets
        /\ recoveredSets' = _TETrace[j].recoveredSets
        /\ omissionProofs  = _TETrace[i].omissionProofs
        /\ omissionProofs' = _TETrace[j].omissionProofs
        /\ closedCutoffs  = _TETrace[i].closedCutoffs
        /\ closedCutoffs' = _TETrace[j].closedCutoffs
        /\ candidateCerts  = _TETrace[i].candidateCerts
        /\ candidateCerts' = _TETrace[j].candidateCerts

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("CanonicalOrderingOmissionTrace_TTrace_1773787920.json", _TETrace)

=============================================================================

 Note that you can extract this module `CanonicalOrderingOmissionTrace_TEExpression`
  to a dedicated file to reuse `expression` (the module in the
  dedicated `CanonicalOrderingOmissionTrace_TEExpression.tla` file takes precedence
  over the module `CanonicalOrderingOmissionTrace_TEExpression` below).

---- MODULE CanonicalOrderingOmissionTrace_TEExpression ----
EXTENDS Sequences, CanonicalOrderingOmissionTrace, TLCExt, Toolbox, Naturals, TLC

expression ==
    [
        \* To hide variables of the `CanonicalOrderingOmissionTrace` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        bulletin |-> bulletin
        ,admittedCerts |-> admittedCerts
        ,recoveredSets |-> recoveredSets
        ,omissionProofs |-> omissionProofs
        ,closedCutoffs |-> closedCutoffs
        ,candidateCerts |-> candidateCerts

        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_bulletinUnchanged |-> bulletin = bulletin'

        \* Format the `bulletin` variable as Json value.
        \* ,_bulletinJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(bulletin)

        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_bulletinModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].bulletin # _TETrace[s-1].bulletin
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE CanonicalOrderingOmissionTrace_TETrace ----
\*EXTENDS IOUtils, CanonicalOrderingOmissionTrace, TLC
\*
\*trace == IODeserialize("CanonicalOrderingOmissionTrace_TTrace_1773787920.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE CanonicalOrderingOmissionTrace_TETrace ----
EXTENDS CanonicalOrderingOmissionTrace, TLC

trace ==
    <<
    ([candidateCerts |-> {},closedCutoffs |-> {},recoveredSets |-> <<{}>>,omissionProofs |-> {},admittedCerts |-> {},bulletin |-> <<{}>>]),
    ([candidateCerts |-> {},closedCutoffs |-> {},recoveredSets |-> <<{}>>,omissionProofs |-> {},admittedCerts |-> {},bulletin |-> <<{"tx1"}>>]),
    ([candidateCerts |-> {},closedCutoffs |-> {},recoveredSets |-> <<{}>>,omissionProofs |-> {},admittedCerts |-> {},bulletin |-> <<{"tx1", "tx2"}>>]),
    ([candidateCerts |-> {},closedCutoffs |-> {1},recoveredSets |-> <<{"tx1", "tx2"}>>,omissionProofs |-> {},admittedCerts |-> {},bulletin |-> <<{"tx1", "tx2"}>>]),
    ([candidateCerts |-> {<<1, {"tx1"}>>},closedCutoffs |-> {1},recoveredSets |-> <<{"tx1", "tx2"}>>,omissionProofs |-> {},admittedCerts |-> {},bulletin |-> <<{"tx1", "tx2"}>>]),
    ([candidateCerts |-> {<<1, {"tx1"}>>},closedCutoffs |-> {1},recoveredSets |-> <<{"tx1", "tx2"}>>,omissionProofs |-> {<<1, {"tx1"}, "tx2">>},admittedCerts |-> {},bulletin |-> <<{"tx1", "tx2"}>>])
    >>
----


=============================================================================

---- CONFIG CanonicalOrderingOmissionTrace_TTrace_1773787920 ----
CONSTANTS
    Slots = { 1 }
    Transactions = { "tx1" , "tx2" }

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
\* Generated on Tue Mar 17 18:52:01 EDT 2026