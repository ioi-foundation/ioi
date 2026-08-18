---- MODULE SuccessionSchedule ----
(***************************************************************************)
(* AFT-CB T5d resolution — SCHEDULED succession is safe; RESPONSIVE       *)
(* succession is impossible.                                              *)
(*                                                                         *)
(* Two independent fresh-context theory reviews (blind to the three       *)
(* refuted T5d formulations) converged: detection-triggered (responsive)  *)
(* succession cannot be both safe and live in the async model — a dead    *)
(* ring is indistinguishable from a partitioned one (CAP + FLP). The ONLY *)
(* escape is a CLOCK-FENCED LEASE pre-consented at formation: at least    *)
(* one honest member of the original ring emits no signature for any slot *)
(* past a fixed public clock deadline T. Because a seal is n-of-n, that   *)
(* one fenced honest member vetoes EVERY future original seal above the   *)
(* fence, so the standby can seal strictly above T with provable          *)
(* slot-range disjointness and never needs to learn the partitioned       *)
(* ring's hidden prefix.                                                  *)
(*                                                                         *)
(* This module mechanizes the SUFFICIENCY construction (the minimal one:  *)
(* safe in the pure async model given only the fence, no synchrony        *)
(* bound). The adversary schedules the clock and may create the original  *)
(* seal at any admissible moment; the fence is the only safety mechanism. *)
(* TLC checks Disjoint (inductive) and NoFork over the reachable states.  *)
(*                                                                         *)
(* THE MUTATION (the impossibility, mechanized): remove the `s <= Fence`  *)
(* fence from OrigSeal (i.e. let the original seal above the fence, as an  *)
(* unfenced honest member legally may in the pure model) and TLC          *)
(* reaches a state with conflicting seals for one slot — NoFork RED. That *)
(* is Theorem 1 (responsive succession impossible) reproduced in the      *)
(* model checker; the fence is exactly the load-bearing assumption.       *)
(*                                                                         *)
(* Reviews (internal workspace): reviews/t5d-clean-slate-{neutral,        *)
(* impossibility}.md.  Adjudication: specs/t5d_succession_resolution.md.  *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
  Slots,       \* the finite slot space explored (e.g. 1..4)
  Values,      \* candidate seal values (>= 2 so a conflict is expressible)
  NoVal,       \* sentinel: "no seal for this slot"; a model value outside Values
  Fence,       \* T: the public lease deadline; original seals only slots <= T
  MaxTick      \* clock exploration bound

ASSUME ConstantAssumptions ==
  /\ NoVal \notin Values
  /\ Fence \in Slots
  /\ \E a, b \in Values : a # b      \* a conflict must be expressible

VARIABLES
  clk,         \* the public VDF tick (monotone; the adversary advances it)
  origSealed,  \* [Slots -> Values \cup {NoVal}] : the original ring's seals
  stbySealed   \* [Slots -> Values \cup {NoVal}] : the standby ring's seals

vars == <<clk, origSealed, stbySealed>>

TypeOK ==
  /\ clk \in 0..MaxTick
  /\ origSealed \in [Slots -> Values \cup {NoVal}]
  /\ stbySealed \in [Slots -> Values \cup {NoVal}]

Init ==
  /\ clk = 0
  /\ origSealed = [s \in Slots |-> NoVal]
  /\ stbySealed = [s \in Slots |-> NoVal]

(***************************************************************************)
(* Tick: the adversary advances the public clock (bounded for TLC). The   *)
(* clock delivers no messages and compels nothing — it only measures      *)
(* elapsed time.                                                          *)
(***************************************************************************)
Tick ==
  /\ clk < MaxTick
  /\ clk' = clk + 1
  /\ UNCHANGED <<origSealed, stbySealed>>

(***************************************************************************)
(* OrigSeal: the original ring seals slot s with value v. THE FENCE is    *)
(* the conjunct `s <= Fence`: the modeled content of the clock-fenced     *)
(* lease. An unfenced honest original member could sign any slot at any   *)
(* time (honesty bounds VALUES, never TIMING); the lease strengthens it   *)
(* so no signature is emitted past the fence, and n-of-n makes that one   *)
(* member's refusal veto the whole seal. The adversary chooses WHEN this  *)
(* fires (any clk) and WHICH value — a partitioned-but-alive ring may     *)
(* seal late, which is exactly why only the slot fence, not a timeout,    *)
(* can be safe.                                                           *)
(***************************************************************************)
OrigSeal(s, v) ==
  /\ s \in Slots
  /\ v \in Values
  /\ origSealed[s] = NoVal
  /\ s <= Fence                          \* <-- THE FENCE (delete => NoFork RED)
  /\ origSealed' = [origSealed EXCEPT ![s] = v]
  /\ UNCHANGED <<clk, stbySealed>>

(***************************************************************************)
(* StbySeal: the standby ring seals slot s, strictly above the fence and  *)
(* only after the public clock has passed the fence. It NEVER consults    *)
(* the original ring's state — it does not need to, because the ranges    *)
(* are disjoint. The adversary chooses the value.                         *)
(***************************************************************************)
StbySeal(s, v) ==
  /\ s \in Slots
  /\ v \in Values
  /\ stbySealed[s] = NoVal
  /\ s > Fence
  /\ clk > Fence
  /\ stbySealed' = [stbySealed EXCEPT ![s] = v]
  /\ UNCHANGED <<clk, origSealed>>

Next ==
  \/ Tick
  \/ \E s \in Slots, v \in Values : OrigSeal(s, v)
  \/ \E s \in Slots, v \in Values : StbySeal(s, v)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The safety property: no slot bears conflicting seals from the two      *)
(* rings.                                                                 *)
(***************************************************************************)
NoFork ==
  \A s \in Slots :
    (stbySealed[s] # NoVal /\ origSealed[s] # NoVal) => stbySealed[s] = origSealed[s]

(***************************************************************************)
(* The inductive invariant that implies it — slot-range disjointness. The *)
(* original never seals above the fence (the lease); the standby never    *)
(* seals at or below it (its guard). So no slot ever bears two seals, a   *)
(* fortiori no conflicting pair — NoFork holds vacuously.                 *)
(***************************************************************************)
Disjoint ==
  /\ \A s \in Slots : (origSealed[s] # NoVal) => (s <= Fence)
  /\ \A s \in Slots : (stbySealed[s] # NoVal) => (s > Fence)

Inv ==
  /\ TypeOK
  /\ Disjoint
  /\ NoFork

====
