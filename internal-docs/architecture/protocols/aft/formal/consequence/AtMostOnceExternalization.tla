-------------------- MODULE AtMostOnceExternalization --------------------
EXTENDS Naturals, TLC

(*
Bounded M5 kernel for one accepted effect authorization and one atomic
idempotency register.  An invocation may mutate and then crash while local
state remains InFlight.  callIssued is durable model state: no action can
issue a second mutation call after it becomes TRUE.
*)

VARIABLES phase, callIssued, invocations, registerPresent, mutations, observations

vars == <<phase, callIssued, invocations, registerPresent, mutations, observations>>

Init ==
    /\ phase = "Authorized"
    /\ callIssued = FALSE
    /\ invocations = 0
    /\ registerPresent \in BOOLEAN
    /\ mutations = 0
    /\ observations = 0

Claim ==
    /\ phase = "Authorized"
    /\ phase' = "Claimed"
    /\ UNCHANGED <<callIssued, invocations, registerPresent, mutations, observations>>

EnterInFlight ==
    /\ phase = "Claimed"
    /\ phase' = "InFlight"
    /\ UNCHANGED <<callIssued, invocations, registerPresent, mutations, observations>>

InvokeFirst ==
    /\ phase = "InFlight"
    /\ ~callIssued
    /\ ~registerPresent
    /\ callIssued' = TRUE
    /\ invocations' = invocations + 1
    /\ registerPresent' = TRUE
    /\ mutations' = mutations + 1
    /\ phase' \in {"InFlight", "Executed", "Unknown"}
    /\ UNCHANGED observations

InvokeExisting ==
    /\ phase = "InFlight"
    /\ ~callIssued
    /\ registerPresent
    /\ callIssued' = TRUE
    /\ invocations' = invocations + 1
    /\ phase' \in {"InFlight", "Executed", "Unknown"}
    /\ UNCHANGED <<registerPresent, mutations, observations>>

(* A crash from durable InFlight never returns to an invocation-enabled phase. *)
RecoverInFlight ==
    /\ phase = "InFlight"
    /\ phase' = "Unknown"
    /\ UNCHANGED <<callIssued, invocations, registerPresent, mutations, observations>>

AmbiguousLookup ==
    /\ phase = "Unknown"
    /\ phase' = "Unknown"
    /\ observations' = observations + 1
    /\ UNCHANGED <<callIssued, invocations, registerPresent, mutations>>

Reconcile ==
    /\ phase \in {"Executed", "Unknown"}
    /\ phase' = "Reconciled"
    /\ UNCHANGED <<callIssued, invocations, registerPresent, mutations, observations>>

Done ==
    /\ phase = "Reconciled"
    /\ UNCHANGED vars

Next == Claim \/ EnterInFlight \/ InvokeFirst \/ InvokeExisting
        \/ RecoverInFlight \/ AmbiguousLookup \/ Reconcile \/ Done

TypeOK ==
    /\ phase \in {"Authorized", "Claimed", "InFlight", "Executed", "Unknown", "Reconciled"}
    /\ callIssued \in BOOLEAN
    /\ invocations \in Nat
    /\ registerPresent \in BOOLEAN
    /\ mutations \in Nat
    /\ observations \in Nat

AtMostOneMutation == mutations <= 1

ClaimDurableBeforeCall ==
    callIssued => phase \notin {"Authorized", "Claimed"}

MutationRequiresCall ==
    mutations > 0 => callIssued

MutationCreatesRegisterRecord ==
    mutations > 0 => registerPresent

NoBlindReplayAfterAmbiguity ==
    invocations <= 1

StateConstraint == observations <= 3

Spec == Init /\ [][Next]_vars

=============================================================================
