---- MODULE QuvAdmissionOrder_TTrace_1788611672 ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, QuvAdmissionOrder_TEConstants, QuvAdmissionOrder

_expression ==
    LET QuvAdmissionOrder_TEExpression == INSTANCE QuvAdmissionOrder_TEExpression
    IN QuvAdmissionOrder_TEExpression!expression
----

_trace ==
    LET QuvAdmissionOrder_TETrace == INSTANCE QuvAdmissionOrder_TETrace
    IN QuvAdmissionOrder_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        bypasses = (2)
        /\
        served = (FALSE)
        /\
        active = (d1)
        /\
        queue = (<<"worker">>)
    )
----

_init ==
    /\ bypasses = _TETrace[1].bypasses
    /\ active = _TETrace[1].active
    /\ served = _TETrace[1].served
    /\ queue = _TETrace[1].queue
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ bypasses  = _TETrace[i].bypasses
        /\ bypasses' = _TETrace[j].bypasses
        /\ active  = _TETrace[i].active
        /\ active' = _TETrace[j].active
        /\ served  = _TETrace[i].served
        /\ served' = _TETrace[j].served
        /\ queue  = _TETrace[i].queue
        /\ queue' = _TETrace[j].queue

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("QuvAdmissionOrder_TTrace_1788611672.json", _TETrace)

=============================================================================

 Note that you can extract this module `QuvAdmissionOrder_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `QuvAdmissionOrder_TEExpression.tla` file takes precedence 
  over the module `QuvAdmissionOrder_TEExpression` below).

---- MODULE QuvAdmissionOrder_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, QuvAdmissionOrder_TEConstants, QuvAdmissionOrder

expression == 
    [
        \* To hide variables of the `QuvAdmissionOrder` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        bypasses |-> bypasses
        ,active |-> active
        ,served |-> served
        ,queue |-> queue
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_bypassesUnchanged |-> bypasses = bypasses'
        
        \* Format the `bypasses` variable as Json value.
        \* ,_bypassesJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(bypasses)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_bypassesModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].bypasses # _TETrace[s-1].bypasses
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE QuvAdmissionOrder_TETrace ----
\*EXTENDS IOUtils, TLC, QuvAdmissionOrder_TEConstants, QuvAdmissionOrder
\*
\*trace == IODeserialize("QuvAdmissionOrder_TTrace_1788611672.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE QuvAdmissionOrder_TETrace ----
EXTENDS TLC, QuvAdmissionOrder_TEConstants, QuvAdmissionOrder

trace == 
    <<
    ([bypasses |-> 0,served |-> FALSE,active |-> "idle",queue |-> <<d1, "worker">>]),
    ([bypasses |-> 1,served |-> FALSE,active |-> d1,queue |-> <<"worker">>]),
    ([bypasses |-> 1,served |-> FALSE,active |-> d1,queue |-> <<"worker", d1>>]),
    ([bypasses |-> 1,served |-> FALSE,active |-> "idle",queue |-> <<"worker", d1>>]),
    ([bypasses |-> 2,served |-> FALSE,active |-> d1,queue |-> <<"worker">>])
    >>
----


=============================================================================

---- MODULE QuvAdmissionOrder_TEConstants ----
EXTENDS QuvAdmissionOrder

CONSTANTS d1

=============================================================================

---- CONFIG QuvAdmissionOrder_TTrace_1788611672 ----
CONSTANTS
    Domains = { d1 }
    FIFO = FALSE
    d1 = d1

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
\* Generated on Sat Sep 05 08:34:32 EDT 2026