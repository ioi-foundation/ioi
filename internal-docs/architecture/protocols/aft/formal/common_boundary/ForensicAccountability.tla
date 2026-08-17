---- MODULE ForensicAccountability ----
(***************************************************************************)
(* AFT-CB P2.6 — forensic accountability (T7), proven against the          *)
(* WIRE-LEVEL certificate format.                                          *)
(*                                                                         *)
(* The wire format is part of the theorem (spec §12): a seal certificate   *)
(* is a bitmap multisig — a record carrying, for EVERY ring member, that   *)
(* member's individually verifiable signature share over the exact         *)
(* domain-separated tuple.  Assembly is impossible without all n shares,   *)
(* and decomposition back into per-member shares is total: any holder of   *)
(* two conflicting certificates extracts, for every member, a pair of      *)
(* conflicting shares — a self-contained conviction (T7), covering every   *)
(* participant necessary for the violation (all n; the L9 maximum).        *)
(*                                                                         *)
(* The mutation drill swaps the encoding for an attribution-destroying     *)
(* OPAQUE AGGREGATE — a certificate that proves "the ring signed" while    *)
(* decomposing into nobody — and the attributability invariant goes red:   *)
(* exactly the trade the spec's §12.4 forbids on any seal path.            *)
(*                                                                         *)
(* The staged double-seal gate runs at the ALL-BYZANTINE configuration     *)
(* (HonestMembers = {}): both conflicting certificates assemble (nothing   *)
(* stops an all-corrupt ring from double-sealing — that is above the       *)
(* fault threshold), and TLC's DoubleSealReached violation trace IS the    *)
(* extraction witness: the full necessary-participant set, recorded in     *)
(* the leg ledger.                                                         *)
(*                                                                         *)
(* Adversary: structural (P2.3's pattern).  Corrupt members' shares over   *)
(* any tuple are always available; honest shares exist only via the        *)
(* journal-guarded honest ack (A3), which is why conflicting certificates  *)
(* under MHA are impossible (P2.1's theorem, restated here over the wire   *)
(* structure as CertUniqueness).                                           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Ring,
  HonestMembers,
  Slots,
  Roots,
  NoRoot

ASSUME ForensicConstants ==
  /\ HonestMembers \subseteq Ring

(* A wire-level share: member m's signature over the domain-separated      *)
(* tuple (slot, root).  A certificate is bitmap-complete: it embeds the    *)
(* share of EVERY member over ITS OWN (slot, root) — the record structure  *)
(* IS the format; there is nothing else on the wire.                       *)
Share(m, s, r) == <<m, s, r>>

Cert(s, r) == [slot |-> s, root |-> r,
               shares |-> {Share(m, s, r) : m \in Ring}]

VARIABLES
  journal,   \* [HonestMembers -> [Slots -> Roots \cup {NoRoot}]] (A3)
  hshares,   \* honest shares in existence
  certs      \* assembled certificates (wire records)

vars == <<journal, hshares, certs>>

ShareAvailable(m, s, r) ==
  IF m \in HonestMembers THEN Share(m, s, r) \in hshares ELSE TRUE

TypeOK ==
  /\ journal \in [HonestMembers -> [Slots -> Roots \cup {NoRoot}]]
  /\ hshares \subseteq HonestMembers \X Slots \X Roots
  /\ certs \subseteq [slot : Slots, root : Roots,
                      shares : SUBSET (Ring \X Slots \X Roots)]

Init ==
  /\ journal = [m \in HonestMembers |-> [s \in Slots |-> NoRoot]]
  /\ hshares = {}
  /\ certs = {}

HonestSign(m, s, r) ==
  /\ m \in HonestMembers
  /\ s \in Slots /\ r \in Roots
  /\ journal[m][s] = NoRoot
  /\ journal' = [journal EXCEPT ![m] = [journal[m] EXCEPT ![s] = r]]
  /\ hshares' = hshares \cup {Share(m, s, r)}
  /\ UNCHANGED certs

(* Assembly: anyone may assemble the bitmap-complete certificate once      *)
(* every member's share over the exact tuple is available (corrupt         *)
(* members' shares always are — A1 excludes only forging honest ones).     *)
Assemble(s, r) ==
  /\ s \in Slots /\ r \in Roots
  /\ \A m \in Ring : ShareAvailable(m, s, r)
  /\ certs' = certs \cup {Cert(s, r)}
  /\ UNCHANGED <<journal, hshares>>

Next ==
  \/ \E m \in Ring, s \in Slots, r \in Roots : HonestSign(m, s, r)
  \/ \E s \in Slots, r \in Roots : Assemble(s, r)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE EXTRACTION PROCEDURE (spec §12.5), specified over the wire records: *)
(* given two certificates for one slot with different roots, the           *)
(* extracted set is every member exhibiting a share in BOTH — a pair of    *)
(* signatures by one key over conflicting tuples, each pair a              *)
(* self-contained conviction.                                              *)
(***************************************************************************)
ExtractedSet(c1, c2) ==
  {m \in Ring : /\ Share(m, c1.slot, c1.root) \in c1.shares
                /\ Share(m, c2.slot, c2.root) \in c2.shares}

Conflicting(c1, c2) ==
  /\ c1.slot = c2.slot
  /\ c1.root # c2.root

(* T7 at the wire level: ANY two conflicting certificates decompose into   *)
(* conflicting share pairs for EVERY ring member — the full necessary-     *)
(* participant set (n-of-n makes each member necessary; L9 makes all-n     *)
(* the maximum any protocol can attribute).                                *)
AttributionComplete ==
  \A c1 \in certs, c2 \in certs :
    Conflicting(c1, c2) => ExtractedSet(c1, c2) = Ring

(* P2.1's uniqueness, restated over the wire structure: under MHA (as a    *)
(* condition), conflicting certificates cannot both assemble.              *)
CertUniqueness ==
  \A c1 \in certs, c2 \in certs :
    (Conflicting(c1, c2)) => HonestMembers = {}

(* Reachability witness target for the all-Byzantine staged double-seal:   *)
(* TLC violating this invariant produces the trace in which both           *)
(* conflicting certificates assemble and the extraction yields all n.      *)
DoubleSealReached ==
  ~\E c1 \in certs, c2 \in certs : Conflicting(c1, c2)

Inv ==
  /\ TypeOK
  /\ \A m \in HonestMembers, s \in Slots, r \in Roots :
       (Share(m, s, r) \in hshares) => journal[m][s] = r
  /\ \A c \in certs :
       /\ c.shares = {Share(m, c.slot, c.root) : m \in Ring}
       /\ \A m \in HonestMembers : Share(m, c.slot, c.root) \in hshares

====
