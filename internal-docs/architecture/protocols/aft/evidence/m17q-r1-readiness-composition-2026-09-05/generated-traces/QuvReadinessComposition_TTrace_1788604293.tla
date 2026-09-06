---- MODULE QuvReadinessComposition_TTrace_1788604293 ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, QuvReadinessComposition

_expression ==
    LET QuvReadinessComposition_TEExpression == INSTANCE QuvReadinessComposition_TEExpression
    IN QuvReadinessComposition_TEExpression!expression
----

_trace ==
    LET QuvReadinessComposition_TETrace == INSTANCE QuvReadinessComposition_TETrace
    IN QuvReadinessComposition_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        refused = (TRUE)
        /\
        introducedAt = (16)
        /\
        fastDone = (13)
        /\
        slot = (5)
        /\
        slowDone = (17)
    )
----

_init ==
    /\ slot = _TETrace[1].slot
    /\ refused = _TETrace[1].refused
    /\ fastDone = _TETrace[1].fastDone
    /\ introducedAt = _TETrace[1].introducedAt
    /\ slowDone = _TETrace[1].slowDone
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ slot  = _TETrace[i].slot
        /\ slot' = _TETrace[j].slot
        /\ refused  = _TETrace[i].refused
        /\ refused' = _TETrace[j].refused
        /\ fastDone  = _TETrace[i].fastDone
        /\ fastDone' = _TETrace[j].fastDone
        /\ introducedAt  = _TETrace[i].introducedAt
        /\ introducedAt' = _TETrace[j].introducedAt
        /\ slowDone  = _TETrace[i].slowDone
        /\ slowDone' = _TETrace[j].slowDone

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("QuvReadinessComposition_TTrace_1788604293.json", _TETrace)

=============================================================================

 Note that you can extract this module `QuvReadinessComposition_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `QuvReadinessComposition_TEExpression.tla` file takes precedence 
  over the module `QuvReadinessComposition_TEExpression` below).

---- MODULE QuvReadinessComposition_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, QuvReadinessComposition

expression == 
    [
        \* To hide variables of the `QuvReadinessComposition` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        slot |-> slot
        ,refused |-> refused
        ,fastDone |-> fastDone
        ,introducedAt |-> introducedAt
        ,slowDone |-> slowDone
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_slotUnchanged |-> slot = slot'
        
        \* Format the `slot` variable as Json value.
        \* ,_slotJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(slot)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_slotModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].slot # _TETrace[s-1].slot
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE QuvReadinessComposition_TETrace ----
\*EXTENDS IOUtils, TLC, QuvReadinessComposition
\*
\*trace == IODeserialize("QuvReadinessComposition_TTrace_1788604293.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE QuvReadinessComposition_TETrace ----
EXTENDS TLC, QuvReadinessComposition

trace == 
    <<
    ([refused |-> FALSE,introducedAt |-> 0,fastDone |-> 0,slot |-> 0,slowDone |-> 0]),
    ([refused |-> FALSE,introducedAt |-> 0,fastDone |-> 1,slot |-> 1,slowDone |-> 2]),
    ([refused |-> FALSE,introducedAt |-> 4,fastDone |-> 5,slot |-> 2,slowDone |-> 7]),
    ([refused |-> FALSE,introducedAt |-> 8,fastDone |-> 9,slot |-> 3,slowDone |-> 12]),
    ([refused |-> FALSE,introducedAt |-> 12,fastDone |-> 13,slot |-> 4,slowDone |-> 17]),
    ([refused |-> TRUE,introducedAt |-> 16,fastDone |-> 13,slot |-> 5,slowDone |-> 17])
    >>
----


=============================================================================

---- CONFIG QuvReadinessComposition_TTrace_1788604293 ----
CONSTANTS
    WaitBound = 3
    FastService = 1
    SlowService = 2
    ActiveServiceBound = 3
    Slots = 5

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
\* Generated on Sat Sep 05 06:31:33 EDT 2026