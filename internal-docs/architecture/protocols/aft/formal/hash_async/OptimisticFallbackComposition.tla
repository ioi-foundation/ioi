-------------------- MODULE OptimisticFallbackComposition --------------------
EXTENDS Integers, TLC

\* Bounded transition kernel for one height. Quorum authentication and the
\* n=3f+1/q=2f+1 intersection arithmetic are discharged by the Rust exact-
\* geometry tests; this model checks the temporal seam those quorums drive:
\* safe state is captured at durable fallback start, optimistic authority is
\* then fenced, and randomness can select work but cannot change authority.

Values == {"A", "B"}
None == "None"

VARIABLES phase, optimisticCommitted, fallbackRoot, asyncDecided

vars == <<phase, optimisticCommitted, fallbackRoot, asyncDecided>>

Init ==
    /\ phase = "Optimistic"
    /\ optimisticCommitted = None
    /\ fallbackRoot = None
    /\ asyncDecided = None

OptimisticCommit(value) ==
    /\ value \in Values
    /\ phase = "Optimistic"
    /\ optimisticCommitted = None
    /\ optimisticCommitted' = value
    /\ UNCHANGED <<phase, fallbackRoot, asyncDecided>>

StartFallback(candidate) ==
    /\ candidate \in Values
    /\ phase = "Optimistic"
    /\ phase' = "Fallback"
    /\ fallbackRoot' =
         IF optimisticCommitted = None THEN candidate ELSE optimisticCommitted
    /\ UNCHANGED <<optimisticCommitted, asyncDecided>>

AsyncDecide ==
    /\ phase = "Fallback"
    /\ fallbackRoot \in Values
    /\ asyncDecided = None
    /\ asyncDecided' = fallbackRoot
    /\ UNCHANGED <<phase, optimisticCommitted, fallbackRoot>>

Next ==
    \/ \E value \in Values : OptimisticCommit(value)
    \/ \E candidate \in Values : StartFallback(candidate)
    \/ AsyncDecide
    \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in {"Optimistic", "Fallback"}
    /\ optimisticCommitted \in Values \cup {None}
    /\ fallbackRoot \in Values \cup {None}
    /\ asyncDecided \in Values \cup {None}

FallbackCapturesSafeState ==
    phase = "Fallback" =>
      /\ fallbackRoot \in Values
      /\ (optimisticCommitted # None => fallbackRoot = optimisticCommitted)

NoCrossPathConflict ==
    optimisticCommitted = None \/ asyncDecided = None
      \/ optimisticCommitted = asyncDecided

=============================================================================
