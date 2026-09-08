---- MODULE PostCommitLockOrder_TTrace_1788610114 ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, PostCommitLockOrder

_expression ==
    LET PostCommitLockOrder_TEExpression == INSTANCE PostCommitLockOrder_TEExpression
    IN PostCommitLockOrder_TEExpression!expression
----

_trace ==
    LET PostCommitLockOrder_TETrace == INSTANCE PostCommitLockOrder_TETrace
    IN PostCommitLockOrder_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        nodeOwner = ("F")
        /\
        s = (1)
        /\
        f = (2)
        /\
        contextOwner = ("S")
    )
----

_init ==
    /\ contextOwner = _TETrace[1].contextOwner
    /\ f = _TETrace[1].f
    /\ s = _TETrace[1].s
    /\ nodeOwner = _TETrace[1].nodeOwner
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ contextOwner  = _TETrace[i].contextOwner
        /\ contextOwner' = _TETrace[j].contextOwner
        /\ f  = _TETrace[i].f
        /\ f' = _TETrace[j].f
        /\ s  = _TETrace[i].s
        /\ s' = _TETrace[j].s
        /\ nodeOwner  = _TETrace[i].nodeOwner
        /\ nodeOwner' = _TETrace[j].nodeOwner

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("PostCommitLockOrder_TTrace_1788610114.json", _TETrace)

=============================================================================

 Note that you can extract this module `PostCommitLockOrder_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `PostCommitLockOrder_TEExpression.tla` file takes precedence 
  over the module `PostCommitLockOrder_TEExpression` below).

---- MODULE PostCommitLockOrder_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, PostCommitLockOrder

expression == 
    [
        \* To hide variables of the `PostCommitLockOrder` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        contextOwner |-> contextOwner
        ,f |-> f
        ,s |-> s
        ,nodeOwner |-> nodeOwner
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_contextOwnerUnchanged |-> contextOwner = contextOwner'
        
        \* Format the `contextOwner` variable as Json value.
        \* ,_contextOwnerJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(contextOwner)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_contextOwnerModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].contextOwner # _TETrace[s-1].contextOwner
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE PostCommitLockOrder_TETrace ----
\*EXTENDS IOUtils, TLC, PostCommitLockOrder
\*
\*trace == IODeserialize("PostCommitLockOrder_TTrace_1788610114.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE PostCommitLockOrder_TETrace ----
EXTENDS TLC, PostCommitLockOrder

trace == 
    <<
    ([nodeOwner |-> "none",s |-> 0,f |-> 0,contextOwner |-> "none"]),
    ([nodeOwner |-> "F",s |-> 0,f |-> 1,contextOwner |-> "none"]),
    ([nodeOwner |-> "F",s |-> 0,f |-> 2,contextOwner |-> "none"]),
    ([nodeOwner |-> "F",s |-> 1,f |-> 2,contextOwner |-> "S"])
    >>
----


=============================================================================

---- CONFIG PostCommitLockOrder_TTrace_1788610114 ----
CONSTANTS
    ReleaseBeforeContinuation = FALSE

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
\* Generated on Sat Sep 05 08:08:35 EDT 2026