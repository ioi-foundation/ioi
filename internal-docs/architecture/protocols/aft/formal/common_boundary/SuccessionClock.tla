---- MODULE SuccessionClock ----
(***************************************************************************)
(* AFT-CB P2.7 — the §16 v3 succession kernel.  HONEST LABEL AFTER REVIEW *)
(* ROUND 5: this module discharges a STRICTLY NARROWED statement, not §16 *)
(* (R5-F3): the Byzantine standby member has no modeled behavior,         *)
(* obs_commit is computed as the honest union (never adversary-chosen),   *)
(* lastSealTick never advances, and the MHA-corner config cannot hold two *)
(* conflicting old seals.  The proof is internally valid and RETAINED as  *)
(* the record of what v3's refusal mechanism does prove; it is NOT a      *)
(* discharge of §16, whose v3 was refuted (see the spec banner and        *)
(* p2-7-respec-review.md).  A faithful re-mechanization is a v4           *)
(* precondition.                                                          *)
(*                                                                         *)
(* v3's design (spec §16, RESPECIFIED — pending its own review): the       *)
(* standby S_v adjudicates under its OWN per-configuration MHA.  A rival   *)
(* old-ring seal BINDS iff it is in the fallback seal's UBC-committed      *)
(* observation set; an honest standby member REFUSES to sign a fallback    *)
(* seal that omits an observed object or covers a slot where it observed   *)
(* a rival seal at all — preemption by refusal, before any certificate     *)
(* exists.  Unobserved rivals are VOID by the old ring's own               *)
(* formation-time signature.  No bulletin, no stamps, no delivery bound    *)
(* on any medium exists in this design.                                    *)
(*                                                                         *)
(* Time: ticks advance monotonically (A9 gives objectivity; the chain      *)
(* condition "≥ T_halt seal-free ticks" is read off the single-valued      *)
(* seal-seeded chain, modeled as lastSealTick).  The adversary schedules   *)
(* everything, including when submissions become observations (A10 — an    *)
(* object submitted to the standby reaches ≥1 honest member within        *)
(* G_deliv — is the FAIRNESS the old ring's protection rides; the safety  *)
(* theorem below never consumes it, which is the point: safety holds       *)
(* even when A10 fails, at the old ring's liveness cost).                  *)
(*                                                                         *)
(* Single contested slot; roots are the contested content.                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  OldRing,
  HonestOld,      \* honest subset of the old ring
  Standby,
  HonestStandby,  \* honest subset of the standby (A2(S_v) enters theorems)
  Roots,
  NoRoot,
  T_halt,         \* activation threshold (ticks since last seal)
  G,              \* release wait after activation
  MaxTick

ASSUME SuccessionConstants ==
  /\ HonestOld \subseteq OldRing
  /\ HonestStandby \subseteq Standby
  /\ T_halt \in Nat \ {0}
  /\ G \in Nat
  /\ MaxTick \in Nat

VARIABLES
  tick,           \* the objective clock (monotone; A9)
  lastSealTick,   \* tick of the last old-ring seal folded into the chain
  policySigned,   \* BOOLEAN: formation-time unanimous succession policy
  oldJournal,     \* [HonestOld -> Roots \cup {NoRoot}]: single-final-ack (A3)
  oldSeals,       \* assembled old-ring seals for the contested slot: roots
  submitted,      \* old seals submitted to the standby set: roots
  observedBy,     \* [HonestStandby -> SUBSET Roots]: rival seals observed
  activation,     \* 0 = none, else the activation tick T_a
  fallbackSeals,  \* [root : Roots, obs : SUBSET Roots]: obs = obs_commit
  released        \* roots whose fallback irreversible effect released

vars == <<tick, lastSealTick, policySigned, oldJournal, oldSeals, submitted,
          observedBy, activation, fallbackSeals, released>>

OldAckedBy(m, r) ==
  IF m \in HonestOld THEN oldJournal[m] = r ELSE TRUE

TypeOK ==
  /\ tick \in 0..MaxTick
  /\ lastSealTick \in 0..MaxTick
  /\ policySigned \in BOOLEAN
  /\ oldJournal \in [HonestOld -> Roots \cup {NoRoot}]
  /\ oldSeals \subseteq Roots
  /\ submitted \subseteq Roots
  /\ observedBy \in [HonestStandby -> SUBSET Roots]
  /\ activation \in 0..MaxTick
  /\ fallbackSeals \subseteq [root : Roots, obs : SUBSET Roots]
  /\ released \subseteq Roots

Init ==
  /\ tick = 0
  /\ lastSealTick = 0
  /\ policySigned = TRUE   \* formation-time unanimity (the drill flips it)
  /\ oldJournal = [m \in HonestOld |-> NoRoot]
  /\ oldSeals = {}
  /\ submitted = {}
  /\ observedBy = [h \in HonestStandby |-> {}]
  /\ activation = 0
  /\ fallbackSeals = {}
  /\ released = {}

Tick ==
  /\ tick < MaxTick
  /\ tick' = tick + 1
  /\ UNCHANGED <<lastSealTick, policySigned, oldJournal, oldSeals, submitted,
                 observedBy, activation, fallbackSeals, released>>

(* Old-ring final-ack (honest, journal-guarded) and structural Byzantine   *)
(* availability let old seals assemble; the standby race is what this      *)
(* module studies, so seal assembly is one action.                         *)
OldAck(m, r) ==
  /\ m \in HonestOld
  /\ r \in Roots
  /\ oldJournal[m] = NoRoot
  /\ oldJournal' = [oldJournal EXCEPT ![m] = r]
  /\ UNCHANGED <<tick, lastSealTick, policySigned, oldSeals, submitted,
                 observedBy, activation, fallbackSeals, released>>

AssembleOldSeal(r) ==
  /\ r \in Roots
  /\ \A m \in OldRing : OldAckedBy(m, r)
  /\ oldSeals' = oldSeals \cup {r}
  /\ UNCHANGED <<tick, lastSealTick, policySigned, oldJournal, submitted,
                 observedBy, activation, fallbackSeals, released>>

(* Submission of a rival old seal toward the standby set, and its          *)
(* adversary-scheduled arrival at an honest standby member's observation.  *)
(* A10 (reach within G_deliv) is deliberately NOT enforced here: safety    *)
(* must hold on every schedule, including ones where A10 fails.            *)
Submit(r) ==
  /\ r \in oldSeals
  /\ submitted' = submitted \cup {r}
  /\ UNCHANGED <<tick, lastSealTick, policySigned, oldJournal, oldSeals,
                 observedBy, activation, fallbackSeals, released>>

Observe(h, r) ==
  /\ h \in HonestStandby
  /\ r \in submitted
  /\ observedBy' = [observedBy EXCEPT ![h] = observedBy[h] \cup {r}]
  /\ UNCHANGED <<tick, lastSealTick, policySigned, oldJournal, oldSeals,
                 submitted, activation, fallbackSeals, released>>

(* Activation: valid only through the formation-time policy AND the        *)
(* objective chain condition — ≥ T_halt seal-free ticks (A9; the chain is  *)
(* single-valued because only seals fold into it).  No silence-derived     *)
(* input exists anywhere in this action.                                   *)
Activate ==
  /\ policySigned
  /\ activation = 0
  /\ tick - lastSealTick >= T_halt
  /\ activation' = tick
  /\ UNCHANGED <<tick, lastSealTick, policySigned, oldJournal, oldSeals,
                 submitted, observedBy, fallbackSeals, released>>

(* The observation-committed fallback seal.  The honest-refusal guard is   *)
(* the v3 mechanism: every honest standby member's observations must be    *)
(* inside obs_commit, and NO honest member may have observed ANY rival —   *)
(* otherwise no certificate can exist (A2(S_v) makes the honest share      *)
(* necessary).  obs_commit is exactly the union of honest observations at  *)
(* signing time.                                                           *)
AssembleFallback(r) ==
  /\ activation > 0
  /\ r \in Roots
  /\ \A h \in HonestStandby : \A rv \in observedBy[h] : rv = r
  /\ fallbackSeals' = fallbackSeals \cup
       {[root |-> r, obs |-> UNION {observedBy[h] : h \in HonestStandby}]}
  /\ UNCHANGED <<tick, lastSealTick, policySigned, oldJournal, oldSeals,
                 submitted, observedBy, activation, released>>

(* Release: the fallback irreversible effect for r, after the wait.        *)
Release(r) ==
  /\ activation > 0
  /\ tick >= activation + G
  /\ \E fs \in fallbackSeals : fs.root = r
  /\ released' = released \cup {r}
  /\ UNCHANGED <<tick, lastSealTick, policySigned, oldJournal, oldSeals,
                 submitted, observedBy, activation, fallbackSeals>>

Next ==
  \/ Tick
  \/ \E m \in OldRing, r \in Roots : OldAck(m, r)
  \/ \E r \in Roots : AssembleOldSeal(r) \/ Submit(r) \/ AssembleFallback(r)
                      \/ Release(r)
  \/ \E h \in Standby, r \in Roots : Observe(h, r)
  \/ Activate

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Bindingness (§16.5): a rival old seal binds against fallback root r iff *)
(* it is in some r-fallback-seal's committed observation set.  VoidByPolicy *)
(* is its complement — definitional, by the old ring's own formation        *)
(* signature.                                                              *)
(***************************************************************************)
Binding(rv, r) ==
  \E fs \in fallbackSeals : fs.root = r /\ rv \in fs.obs /\ rv # r

(* T5d-v3: no released fallback effect coexists with a BINDING rival.      *)
NoBindingRivalReleased ==
  \A r \in released, rv \in Roots : ~Binding(rv, r)

(* Activation is never silence-justified: it exists only with the          *)
(* formation policy and the chain condition met at its tick.               *)
ActivationJustified ==
  (activation > 0) => (policySigned /\ activation - lastSealTick >= T_halt)

Inv ==
  /\ TypeOK
  /\ \A fs \in fallbackSeals :
       \A rv \in fs.obs : rv = fs.root
  /\ ActivationJustified

====
