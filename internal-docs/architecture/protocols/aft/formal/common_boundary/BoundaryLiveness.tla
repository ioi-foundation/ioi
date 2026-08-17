---- MODULE BoundaryLiveness ----
(***************************************************************************)
(* AFT-CB P2.2 — SEAL CADENCE, not chain liveness (T4b), and the two-tier  *)
(* separation property.                                                    *)
(*                                                                         *)
(* Claim scope (standing rule 2, stated exactly): the cadence and          *)
(* separation results below are model-checked at n≤4 — never "proven".    *)
(* Live-tier liveness (T4a) is the engine's own obligation, tracked at     *)
(* R10 and deliberately NOT claimed here: LiveBlock below is a progress    *)
(* ABSTRACTION that reads no ring variable, so the separation property is  *)
(* visible by construction and checked by TLC.                             *)
(*                                                                         *)
(* A5 is modeled as FAIRNESS: weak fairness on responsive members' acks    *)
(* and on seal assembly is exactly the post-GST eventual-delivery          *)
(* abstraction (T4b's Assumes line carries A5; this module says where it   *)
(* lives).  A2/A3's safety content is BoundaryRing's business (P2.1) —    *)
(* this module checks progress, with honest-shaped members only.           *)
(*                                                                         *)
(* The action set includes the assurance-preserving handover (§9): an     *)
(* unresponsive member can be replaced by a responsive standby when        *)
(* HandoverEnabled — modeled as an available transition; its safety terms *)
(* (old-ring unanimity + new-ring acceptance) are P2.3's obligation, not   *)
(* re-proved here.  NO EJECTION ACTION EXISTS AT THIS LAYER: weighted      *)
(* ejection is live-tier-only (spec §5), and the strong ring changes only  *)
(* by handover here.                                                       *)
(*                                                                         *)
(* Mutation drill (leg-mandated): one member permanently silent with       *)
(* handover disabled ⇒ SealCadenceReached goes RED while                   *)
(* LiveTierProgressReached stays GREEN — both directions of the tier       *)
(* split, demonstrated by the same counterexample run.                     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Members,          \* the initial ring configuration
  Standbys,         \* standby pool for handover (disjoint from Members)
  Responsive,       \* the responsive subset of Members \cup Standbys
  MaxSeals,         \* cadence target the property demands be reached
  MaxBlocks,        \* live-tier progress target
  HandoverEnabled   \* BOOLEAN: is the §9 handover transition available?

ASSUME LivenessConstants ==
  /\ Standbys \cap Members = {}
  /\ Responsive \subseteq (Members \cup Standbys)
  /\ MaxSeals \in Nat \ {0}
  /\ MaxBlocks \in Nat \ {0}
  /\ HandoverEnabled \in BOOLEAN

VARIABLES
  ring,        \* current configuration (changes only by handover)
  acked,       \* members of ring that final-acked the CURRENT slot
  sealCount,   \* seals closed so far (the cadence measure)
  liveBlocks,  \* live-tier progress abstraction (reads no ring state)
  version      \* configuration version (increments on handover)

vars == <<ring, acked, sealCount, liveBlocks, version>>

TypeInvariant ==
  /\ ring \subseteq (Members \cup Standbys)
  /\ acked \subseteq ring
  /\ sealCount \in 0..MaxSeals
  /\ liveBlocks \in 0..MaxBlocks
  /\ version \in Nat

Init ==
  /\ ring = Members
  /\ acked = {}
  /\ sealCount = 0
  /\ liveBlocks = 0
  /\ version = 0

(* A responsive ring member final-acks the current slot.  Unresponsive    *)
(* members simply never take this action — silence is the absence of a    *)
(* step, not a message (spec §10's discipline holds even in the liveness  *)
(* model).                                                                 *)
Ack(m) ==
  /\ m \in ring
  /\ m \in Responsive
  /\ m \notin acked
  /\ sealCount < MaxSeals
  /\ acked' = acked \cup {m}
  /\ UNCHANGED <<ring, sealCount, liveBlocks, version>>

(* The n-of-n close: EVERY current ring member has acked.  Unanimity is    *)
(* the whole point — one silent member freezes this action forever (L2's  *)
(* forced trade, conceded by T4b).                                         *)
SealClose ==
  /\ acked = ring
  /\ ring # {}
  /\ sealCount < MaxSeals
  /\ sealCount' = sealCount + 1
  /\ acked' = {}
  /\ UNCHANGED <<ring, liveBlocks, version>>

(* The live tier produces blocks reading NO ring variable: the guard and   *)
(* effect mention only liveBlocks.  A stalled ring cannot disable this     *)
(* action — that is the separation property, structurally.                 *)
LiveBlock ==
  /\ liveBlocks < MaxBlocks
  /\ liveBlocks' = liveBlocks + 1
  /\ UNCHANGED <<ring, acked, sealCount, version>>

(* Assurance-preserving handover (§9), abstracted to its liveness role:    *)
(* an unresponsive member is replaced by a responsive standby and the      *)
(* configuration version advances.  Enabled only when the deployment       *)
(* provides the ceremony (HandoverEnabled) — the mutation drill disables   *)
(* it to prove the cadence property fails for the right reason.            *)
Handover(m, sb) ==
  /\ HandoverEnabled
  /\ m \in ring
  /\ m \notin Responsive
  /\ sb \in Standbys
  /\ sb \in Responsive
  /\ sb \notin ring
  /\ ring' = (ring \ {m}) \cup {sb}
  /\ acked' = acked \ {m}
  /\ version' = version + 1
  /\ UNCHANGED <<sealCount, liveBlocks>>

(* Terminal self-loop so a finished run is quiescence, not deadlock.       *)
Terminating ==
  /\ sealCount = MaxSeals
  /\ liveBlocks = MaxBlocks
  /\ UNCHANGED vars

SomeAck == \E m \in Members \cup Standbys : Ack(m)
SomeHandover == \E m \in Members, sb \in Standbys : Handover(m, sb)

Next ==
  \/ SomeAck
  \/ SealClose
  \/ LiveBlock
  \/ SomeHandover
  \/ Terminating

(* Fairness IS the A5 abstraction: post-GST, enabled progress steps        *)
(* eventually happen.  Weak fairness per responsive participant's ack,     *)
(* plus seal assembly, live production, and the handover ceremony when     *)
(* available.                                                              *)
LivenessSpec ==
  /\ Init
  /\ [][Next]_vars
  /\ \A m \in Members \cup Standbys : WF_vars(Ack(m))
  /\ WF_vars(SealClose)
  /\ WF_vars(LiveBlock)
  /\ WF_vars(SomeHandover)

(* The cadence property (T4b shape): seals actually reach the target —    *)
(* positive seals, not merely eventual aborts.                             *)
SealCadenceReached == <>(sealCount = MaxSeals)

(* The separation property: the live tier reaches its target regardless    *)
(* of ring state — checked GREEN in every configuration including the      *)
(* mutation drill where cadence is RED.                                    *)
LiveTierProgressReached == <>(liveBlocks = MaxBlocks)

====
