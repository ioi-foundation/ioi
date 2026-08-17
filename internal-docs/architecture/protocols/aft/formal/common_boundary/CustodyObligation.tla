---- MODULE CustodyObligation ----
(***************************************************************************)
(* AFT-CB P2.4 — validate-and-hold as a signing obligation (T3), the       *)
(* retention/succession discipline, and the OPTIONAL audit lane.           *)
(*                                                                         *)
(* The obligation (spec §4): an honest member final-acks a boundary only   *)
(* having OBTAINED the full byte set, and the ack commits it to RETAIN and *)
(* SERVE those bytes — so a close implies close-time replication at every  *)
(* compliant signer, and one honest signer (A2, stated as a theorem        *)
(* condition) yields conditional availability deterministically.           *)
(*                                                                         *)
(* Pairwise audits are OPTIONAL enforcement actions producing slashing     *)
(* evidence that NOTHING consumes as a close precondition: the audit       *)
(* variable is written by the audit action alone and read by no guard of   *)
(* any close-path action — mirroring P2.3's silence-record discipline.     *)
(* The zero-audit reachability witness (a trace that closes a slot with    *)
(* auditEvidence = {}) is produced by TLC via the NoCloseEver violation    *)
(* run recorded in the leg ledger.                                         *)
(*                                                                         *)
(* Succession (spec §6): custody releases only RECONSTRUCT-BEFORE-RELEASE  *)
(* — an honest holder may drop a slot's bytes (and its bond may release)   *)
(* only once a successor member has reconstructed full custody of them.    *)
(*                                                                         *)
(* Adversary: structural (the P2.3 pattern) — corrupt members' acks are    *)
(* always available and their storage is arbitrary (they may sign without  *)
(* holding and delete at will, which is why availability quantifies over   *)
(* honest holders only).  Deletion by the other n−1 is harmless BY         *)
(* THEOREM, not by hope.                                                   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Ring,           \* the signer configuration
  HonestMembers,  \* honest subset (MHA enters theorems as a condition)
  Slots,
  Artifacts,      \* the byte universe; a boundary is a nonempty subset
  NoBoundary      \* journal sentinel

ASSUME CustodyConstants ==
  /\ HonestMembers \subseteq Ring

Boundaries == (SUBSET Artifacts) \ {{}}

VARIABLES
  delivered,      \* Artifacts \X Ring: adversary-scheduled delivery
  holds,          \* [HonestMembers -> SUBSET Artifacts]: bytes actually held
  journal,        \* [HonestMembers -> [Slots -> Boundaries \cup {NoBoundary}]]
  acks,           \* honest final-acks <<m, s, B>>
  retained,       \* [HonestMembers -> [Slots -> SUBSET Artifacts]]: serving custody
  closes,         \* closed slots <<s, B>>
  reconstructed,  \* succession receipts <<successor, s>>: full custody rebuilt
  bondReleased,   \* [HonestMembers -> BOOLEAN]
  auditEvidence   \* audit-lane records <<auditor, subject, s>> — never load-bearing

vars == <<delivered, holds, journal, acks, retained, closes, reconstructed,
          bondReleased, auditEvidence>>

AckedBy(m, s, B) ==
  IF m \in HonestMembers THEN <<m, s, B>> \in acks ELSE TRUE

TypeOK ==
  /\ delivered \subseteq Artifacts \X Ring
  /\ holds \in [HonestMembers -> SUBSET Artifacts]
  /\ journal \in [HonestMembers -> [Slots -> Boundaries \cup {NoBoundary}]]
  /\ acks \subseteq HonestMembers \X Slots \X Boundaries
  /\ retained \in [HonestMembers -> [Slots -> SUBSET Artifacts]]
  /\ closes \subseteq Slots \X Boundaries
  /\ reconstructed \subseteq HonestMembers \X Slots
  /\ bondReleased \in [HonestMembers -> BOOLEAN]
  /\ auditEvidence \subseteq Ring \X Ring \X Slots

Init ==
  /\ delivered = {}
  /\ holds = [m \in HonestMembers |-> {}]
  /\ journal = [m \in HonestMembers |-> [s \in Slots |-> NoBoundary]]
  /\ acks = {}
  /\ retained = [m \in HonestMembers |-> [s \in Slots |-> {}]]
  /\ closes = {}
  /\ reconstructed = {}
  /\ bondReleased = [m \in HonestMembers |-> FALSE]
  /\ auditEvidence = {}

Deliver(a, m) ==
  /\ delivered' = delivered \cup {<<a, m>>}
  /\ UNCHANGED <<holds, journal, acks, retained, closes, reconstructed,
                 bondReleased, auditEvidence>>

(* An honest member obtains bytes it was actually delivered.               *)
Fetch(m, a) ==
  /\ m \in HonestMembers
  /\ <<a, m>> \in delivered
  /\ holds' = [holds EXCEPT ![m] = holds[m] \cup {a}]
  /\ UNCHANGED <<delivered, journal, acks, retained, closes, reconstructed,
                 bondReleased, auditEvidence>>

(* VALIDATE-AND-HOLD: the guard B \subseteq holds[m] is the obligation —  *)
(* the member has OBTAINED every byte of the boundary it signs — and the   *)
(* effect commits it to retain/serve (retained[m][s] = B).  The journal    *)
(* keeps single-final-ack (A3).  The mutation drill removes the holds      *)
(* guard and the T3-shaped invariant goes red.                             *)
HonestFinalAck(m, s, B) ==
  /\ m \in HonestMembers
  /\ ~bondReleased[m]   \* a departed member signs nothing new
  /\ s \in Slots /\ B \in Boundaries
  /\ B \subseteq holds[m]
  /\ journal[m][s] = NoBoundary
  /\ journal' = [journal EXCEPT ![m] = [journal[m] EXCEPT ![s] = B]]
  /\ acks' = acks \cup {<<m, s, B>>}
  /\ retained' = [retained EXCEPT ![m] = [retained[m] EXCEPT ![s] = B]]
  /\ UNCHANGED <<delivered, holds, closes, reconstructed, bondReleased,
                 auditEvidence>>

(* n-of-n close: honest acks are state; corrupt signatures always          *)
(* available (they may sign never having held a byte — that is the fault   *)
(* model, and why the theorem leans on the honest signer only).            *)
CloseSlot(s, B) ==
  /\ s \in Slots /\ B \in Boundaries
  /\ \A m \in Ring : AckedBy(m, s, B)
  /\ closes' = closes \cup {<<s, B>>}
  /\ UNCHANGED <<delivered, holds, journal, acks, retained, reconstructed,
                 bondReleased, auditEvidence>>

(* Succession: a successor honest member reconstructs FULL custody of a    *)
(* slot's closed boundary from bytes it actually holds.  Reconstruction    *)
(* ADDS custody (union) — it never shrinks anyone's serving set; custody   *)
(* drops ride bond release, outside this kernel's mutation surface.        *)
Reconstruct(succ, s, B) ==
  /\ succ \in HonestMembers
  /\ ~bondReleased[succ]   \* a departed member takes on no new custody
  /\ <<s, B>> \in closes
  /\ B \subseteq holds[succ]
  /\ retained' = [retained EXCEPT ![succ] =
       [retained[succ] EXCEPT ![s] = retained[succ][s] \cup B]]
  /\ reconstructed' = reconstructed \cup {<<succ, s>>}
  /\ UNCHANGED <<delivered, holds, journal, acks, closes, bondReleased,
                 auditEvidence>>

(* RECONSTRUCT-BEFORE-RELEASE: an honest member's bond releases only when  *)
(* every slot it retains custody for has a DIFFERENT reconstructed         *)
(* successor.  (Custody drop rides bond release; the invariant below is    *)
(* what the mutation targets.)                                             *)
ReleaseBond(m) ==
  /\ m \in HonestMembers
  /\ \A s \in Slots :
       (retained[m][s] # {}) =>
         \E succ \in HonestMembers : succ # m /\ <<succ, s>> \in reconstructed
  /\ bondReleased' = [bondReleased EXCEPT ![m] = TRUE]
  /\ UNCHANGED <<delivered, holds, journal, acks, retained, closes,
                 reconstructed, auditEvidence>>

(* The OPTIONAL audit lane: an auditor challenges a subject over a slot    *)
(* and a record is minted.  No close-path guard reads auditEvidence —     *)
(* audits produce slashing evidence, never availability.                   *)
Audit(auditor, subject, s) ==
  /\ auditor \in Ring /\ subject \in Ring /\ s \in Slots
  /\ auditEvidence' = auditEvidence \cup {<<auditor, subject, s>>}
  /\ UNCHANGED <<delivered, holds, journal, acks, retained, closes,
                 reconstructed, bondReleased>>

Next ==
  \/ \E a \in Artifacts, m \in Ring : Deliver(a, m)
  \/ \E m \in HonestMembers, a \in Artifacts : Fetch(m, a)
  \/ \E m \in HonestMembers, s \in Slots, B \in Boundaries :
       HonestFinalAck(m, s, B)
  \/ \E s \in Slots, B \in Boundaries : CloseSlot(s, B)
  \/ \E succ \in HonestMembers, s \in Slots, B \in Boundaries :
       Reconstruct(succ, s, B)
  \/ \E m \in HonestMembers : ReleaseBond(m)
  \/ \E auditor \in Ring, subject \in Ring, s \in Slots :
       Audit(auditor, subject, s)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The T3-shaped invariant: every honest ack carries full custody — the    *)
(* acked boundary is retained by the acker (or a reconstructed successor   *)
(* stands in for it once released; in this kernel retained never shrinks,  *)
(* so the direct form holds).  From it: a closed slot with one honest ring *)
(* member is AVAILABLE — some honest member retains every byte.            *)
(***************************************************************************)
CustodyInvariant ==
  \A m \in HonestMembers, s \in Slots, B \in Boundaries :
    (<<m, s, B>> \in acks) => B \subseteq retained[m][s]

ConditionalAvailability ==
  \A s \in Slots, B \in Boundaries :
    (<<s, B>> \in closes /\ Ring \cap HonestMembers # {}) =>
      \E m \in HonestMembers : B \subseteq retained[m][s]

ReleaseDiscipline ==
  \A m \in HonestMembers :
    bondReleased[m] =>
      \A s \in Slots :
        (retained[m][s] # {}) =>
          \E succ \in HonestMembers : succ # m /\ <<succ, s>> \in reconstructed

HonestAckJournal ==
  \A m \in HonestMembers, s \in Slots, B \in Boundaries :
    (<<m, s, B>> \in acks) => journal[m][s] = B

(* The T3 truth the validate-and-hold guard protects: every byte a member  *)
(* CLAIMS custody of (retained) is a byte it actually HOLDS and can serve. *)
(* The leg's mutation drill removes the guard and THIS invariant goes red  *)
(* — a member would then claim custody of bytes it never obtained.         *)
RetainedBacked ==
  \A m \in HonestMembers, s \in Slots : retained[m][s] \subseteq holds[m]

Inv ==
  /\ TypeOK
  /\ HonestAckJournal
  /\ RetainedBacked
  /\ CustodyInvariant
  /\ \A s \in Slots, B \in Boundaries :
       (<<s, B>> \in closes) => \A m \in Ring : AckedBy(m, s, B)
  /\ ReleaseDiscipline


(* WITNESS-ONLY definition for the zero-audit reachability run: TLC        *)
(* violating this invariant yields a shortest trace that closes a slot —  *)
(* and a shortest trace contains no Audit step, which IS the required      *)
(* witness that audits are not load-bearing for a close.                   *)
NoCloseEver == closes = {}

====
