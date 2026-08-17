---- MODULE BoundaryRing ----
(***************************************************************************)
(* AFT-CB P2.1 — the Boundary Ring action-level uniqueness kernel.         *)
(*                                                                         *)
(* Models one signer configuration (Ring) forming Unanimous Boundary      *)
(* Closes per slot.  The adversary schedules all delivery (no synchrony    *)
(* appears anywhere) and emits arbitrary well-signed messages for corrupt  *)
(* members — the ONLY exclusion is forging an honest member's signature   *)
(* (A1), modeled by HonestFinalAck being the sole producer of honest ack   *)
(* records.  Honest final-acks are guarded by a durable single-entry       *)
(* journal (A3).  Uniqueness is DERIVED from the inductive invariant under *)
(* the Minimal Honesty Axiom (A2) — no admitted-equals-canonical           *)
(* definition exists in this module (the Q2 defect class this kernel       *)
(* exists to kill).                                                        *)
(*                                                                         *)
(* Spec source: specs/common_boundary.md §§0–2, §11–§12; theorem T1 in    *)
(* specs/common_boundary_theorems.md.  The TLAPS discharge lives in        *)
(* BoundaryRingProof.tla; the TLC configuration explores n = 3 with        *)
(* exactly one honest member (the MHA corner).                             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Ring,           \* the signer configuration C_v
  HonestMembers,  \* the honest subset (MHA: nonempty — assumed in the proof)
  Slots,          \* seal slots s
  Roots,          \* candidate boundary roots
  Artifacts,      \* submittable artifacts (COLLECT/RECONCILE structure)
  NoRoot          \* journal sentinel: "no final-ack recorded for this slot"

ASSUME ConstantAssumptions ==
  /\ HonestMembers \subseteq Ring
  /\ NoRoot \notin Roots

VARIABLES
  delivered,  \* subset of Artifacts \X Ring: what the adversary delivered where
  declared,   \* [Ring -> [Slots -> SUBSET Artifacts]]: declared sets
  journal,    \* [HonestMembers -> [Slots -> Roots \cup {NoRoot}]]: A3 journal
  acks,       \* subset of Ring \X Slots \X Roots: final-ack shares in existence
  closes      \* subset of Slots \X Roots: assembled UBCs

vars == <<delivered, declared, journal, acks, closes>>

TypeOK ==
  /\ delivered \subseteq Artifacts \X Ring
  /\ declared \in [Ring -> [Slots -> SUBSET Artifacts]]
  /\ journal \in [HonestMembers -> [Slots -> Roots \cup {NoRoot}]]
  /\ acks \subseteq Ring \X Slots \X Roots
  /\ closes \subseteq Slots \X Roots

Init ==
  /\ delivered = {}
  /\ declared = [m \in Ring |-> [s \in Slots |-> {}]]
  /\ journal = [m \in HonestMembers |-> [s \in Slots |-> NoRoot]]
  /\ acks = {}
  /\ closes = {}

(***************************************************************************)
(* COLLECT: the adversary schedules delivery of any artifact to any        *)
(* member, in any order, at any time.  No fairness, no bound — this is    *)
(* where asynchrony lives.                                                 *)
(***************************************************************************)
Deliver(a, m) ==
  /\ delivered' = delivered \cup {<<a, m>>}
  /\ UNCHANGED <<declared, journal, acks, closes>>

(***************************************************************************)
(* RECONCILE/DECLARE: an honest member's declared set for a slot is drawn  *)
(* from what it actually received (spec §3.1: cutoff is local — the       *)
(* declared set is whatever was delivered when the member declares).       *)
(* Corrupt members' declared sets are set arbitrarily by the adversary.    *)
(***************************************************************************)
HonestDeclare(m, s, A) ==
  /\ m \in HonestMembers
  /\ A \subseteq {a \in Artifacts : <<a, m>> \in delivered}
  /\ declared' = [declared EXCEPT ![m] = [declared[m] EXCEPT ![s] = A]]
  /\ UNCHANGED <<delivered, journal, acks, closes>>

ByzantineDeclare(m, s, A) ==
  /\ m \in Ring \ HonestMembers
  /\ A \subseteq Artifacts
  /\ declared' = [declared EXCEPT ![m] = [declared[m] EXCEPT ![s] = A]]
  /\ UNCHANGED <<delivered, journal, acks, closes>>

(***************************************************************************)
(* FINAL-ACK, honest: journal-guarded (A3).  The journal entry is written  *)
(* in the same atomic step that lets the share exist — spec §2.1's        *)
(* "journal before the share leaves the process".  The guard              *)
(* journal[m][s] = NoRoot is the single-final-ack discipline: once a root  *)
(* is journaled for (m, s), no second honest share for that slot can ever  *)
(* be produced (recovery replays bytes; it never re-decides — §2.2).      *)
(***************************************************************************)
HonestFinalAck(m, s, r) ==
  /\ m \in HonestMembers
  /\ r \in Roots
  /\ s \in Slots
  /\ journal[m][s] = NoRoot
  /\ journal' = [journal EXCEPT ![m] = [journal[m] EXCEPT ![s] = r]]
  /\ acks' = acks \cup {<<m, s, r>>}
  /\ UNCHANGED <<delivered, declared, closes>>

(***************************************************************************)
(* The unconstrained Byzantine action: a corrupt member emits ANY          *)
(* well-formed signed message, for any slot, any root, any number of       *)
(* times, on any schedule.  Forging an honest signature is the only        *)
(* exclusion (A1): m ranges over corrupt members only.  No journal binds   *)
(* corrupt members.                                                        *)
(***************************************************************************)
ByzantineEmit(m, s, r) ==
  /\ m \in Ring \ HonestMembers
  /\ s \in Slots
  /\ r \in Roots
  /\ acks' = acks \cup {<<m, s, r>>}
  /\ UNCHANGED <<delivered, declared, journal, closes>>

(***************************************************************************)
(* CLOSE: anyone (the adversary included) may assemble a UBC from shares   *)
(* that exist — n-of-n: EVERY ring member's share over this exact          *)
(* (slot, root).  There is no smaller quorum anywhere in this module (the  *)
(* (n-1)-close mutation drill targets exactly this conjunct).              *)
(***************************************************************************)
CloseAct(s, r) ==
  /\ s \in Slots
  /\ r \in Roots
  /\ \A m \in Ring : <<m, s, r>> \in acks
  /\ closes' = closes \cup {<<s, r>>}
  /\ UNCHANGED <<delivered, declared, journal, acks>>

Next ==
  \/ \E a \in Artifacts, m \in Ring : Deliver(a, m)
  \/ \E m \in Ring, s \in Slots, A \in SUBSET Artifacts :
       HonestDeclare(m, s, A) \/ ByzantineDeclare(m, s, A)
  \/ \E m \in Ring, s \in Slots, r \in Roots :
       HonestFinalAck(m, s, r) \/ ByzantineEmit(m, s, r)
  \/ \E s \in Slots, r \in Roots : CloseAct(s, r)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The derived property.  Uniqueness is NOT assumed anywhere above: no     *)
(* definition equates "admitted" with "canonical"; closes is an ordinary   *)
(* set any adversary schedule can try to populate twice.                   *)
(***************************************************************************)
Uniqueness ==
  \A s \in Slots, r1 \in Roots, r2 \in Roots :
    (<<s, r1>> \in closes /\ <<s, r2>> \in closes) => r1 = r2

(***************************************************************************)
(* The inductive invariant (discharged in BoundaryRingProof.tla):          *)
(* an honest share always matches the journal entry (so an honest member   *)
(* has at most one share per slot), and every close carries every          *)
(* member's share.  Uniqueness follows under MHA.                          *)
(***************************************************************************)
Inv ==
  /\ TypeOK
  /\ \A m \in HonestMembers, s \in Slots, r \in Roots :
       (<<m, s, r>> \in acks) => journal[m][s] = r
  /\ \A s \in Slots, r \in Roots :
       (<<s, r>> \in closes) => \A m \in Ring : <<m, s, r>> \in acks

====
