---- MODULE ReconciliationBudgetVolatile_TTrace_1788574521 ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, ReconciliationBudgetVolatile

_expression ==
    LET ReconciliationBudgetVolatile_TEExpression == INSTANCE ReconciliationBudgetVolatile_TEExpression
    IN ReconciliationBudgetVolatile_TEExpression!expression
----

_trace ==
    LET ReconciliationBudgetVolatile_TETrace == INSTANCE ReconciliationBudgetVolatile_TETrace
    IN ReconciliationBudgetVolatile_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        legacy = (0)
        /\
        reserved = (0)
        /\
        calls = (1)
        /\
        ready = (FALSE)
    )
----

_init ==
    /\ legacy = _TETrace[1].legacy
    /\ reserved = _TETrace[1].reserved
    /\ calls = _TETrace[1].calls
    /\ ready = _TETrace[1].ready
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ legacy  = _TETrace[i].legacy
        /\ legacy' = _TETrace[j].legacy
        /\ reserved  = _TETrace[i].reserved
        /\ reserved' = _TETrace[j].reserved
        /\ calls  = _TETrace[i].calls
        /\ calls' = _TETrace[j].calls
        /\ ready  = _TETrace[i].ready
        /\ ready' = _TETrace[j].ready

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("ReconciliationBudgetVolatile_TTrace_1788574521.json", _TETrace)

=============================================================================

 Note that you can extract this module `ReconciliationBudgetVolatile_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `ReconciliationBudgetVolatile_TEExpression.tla` file takes precedence 
  over the module `ReconciliationBudgetVolatile_TEExpression` below).

---- MODULE ReconciliationBudgetVolatile_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, ReconciliationBudgetVolatile

expression == 
    [
        \* To hide variables of the `ReconciliationBudgetVolatile` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        legacy |-> legacy
        ,reserved |-> reserved
        ,calls |-> calls
        ,ready |-> ready
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_legacyUnchanged |-> legacy = legacy'
        
        \* Format the `legacy` variable as Json value.
        \* ,_legacyJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(legacy)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_legacyModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].legacy # _TETrace[s-1].legacy
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE ReconciliationBudgetVolatile_TETrace ----
\*EXTENDS IOUtils, TLC, ReconciliationBudgetVolatile
\*
\*trace == IODeserialize("ReconciliationBudgetVolatile_TTrace_1788574521.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE ReconciliationBudgetVolatile_TETrace ----
EXTENDS TLC, ReconciliationBudgetVolatile

trace == 
    <<
    ([legacy |-> 0,reserved |-> 0,calls |-> 0,ready |-> FALSE]),
    ([legacy |-> 0,reserved |-> 1,calls |-> 0,ready |-> TRUE]),
    ([legacy |-> 0,reserved |-> 1,calls |-> 1,ready |-> FALSE]),
    ([legacy |-> 0,reserved |-> 0,calls |-> 1,ready |-> FALSE])
    >>
----


=============================================================================

---- CONFIG ReconciliationBudgetVolatile_TTrace_1788574521 ----
CONSTANTS
    MaxAttempts = 3

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
\* Generated on Fri Sep 04 22:15:21 EDT 2026