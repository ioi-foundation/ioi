---- MODULE ForensicAccountabilityProof ----
(***************************************************************************)
(* AFT-CB P2.6 — TLAPS discharge of T7 over the wire format: attribution   *)
(* completeness is a consequence of the bitmap-complete record structure,  *)
(* and certificate uniqueness under MHA restates P2.1's theorem over the   *)
(* wire.  The extraction procedure is ExtractedSet, and the theorem says   *)
(* it returns ALL of Ring on any conflicting pair.                         *)
(***************************************************************************)
EXTENDS ForensicAccountability, TLAPS

ASSUME NoRootOutsideRootsF == NoRoot \notin Roots

LEMMA FInvInit == Init => Inv
  BY ForensicConstants DEF Init, Inv, TypeOK

LEMMA FInvNext == Inv /\ [Next]_vars => Inv'
<1>1. SUFFICES ASSUME Inv, [Next]_vars PROVE Inv'
  OBVIOUS
<1>2. CASE UNCHANGED vars
  BY <1>1, <1>2 DEF Inv, TypeOK, vars
<1>3. ASSUME NEW m \in Ring, NEW s \in Slots, NEW r \in Roots,
             HonestSign(m, s, r)
      PROVE Inv'
  <2>1. m \in HonestMembers /\ journal[m][s] = NoRoot
    BY <1>3 DEF HonestSign
  <2>2. TypeOK'
    BY <1>1, <1>3, <2>1, ForensicConstants DEF Inv, TypeOK, HonestSign, Share
  <2>3. \A mm \in HonestMembers, ss \in Slots, rr \in Roots :
          (Share(mm, ss, rr) \in hshares') => journal'[mm][ss] = rr
    <3>1. SUFFICES ASSUME NEW mm \in HonestMembers, NEW ss \in Slots,
                          NEW rr \in Roots, Share(mm, ss, rr) \in hshares'
          PROVE journal'[mm][ss] = rr
      OBVIOUS
    <3>2. hshares' = hshares \cup {Share(m, s, r)}
      BY <1>3 DEF HonestSign
    <3>3. CASE Share(mm, ss, rr) = Share(m, s, r)
      <4>1. mm = m /\ ss = s /\ rr = r
        BY <3>3 DEF Share
      <4>2. journal'[m][s] = r
        BY <1>1, <1>3, <2>1 DEF Inv, TypeOK, HonestSign
      <4> QED BY <4>1, <4>2
    <3>4. CASE Share(mm, ss, rr) \in hshares
      <4>1. journal[mm][ss] = rr
        BY <1>1, <3>4 DEF Inv
      <4>2. CASE mm = m /\ ss = s
        <5>1. journal[m][s] = rr
          BY <4>1, <4>2
        <5>2. rr # NoRoot
          BY <3>1, NoRootOutsideRootsF
        <5> QED BY <2>1, <5>1, <5>2
      <4>3. CASE ~(mm = m /\ ss = s)
        <5>1. journal'[mm][ss] = journal[mm][ss]
          BY <1>1, <1>3, <2>1, <4>3 DEF Inv, TypeOK, HonestSign
        <5> QED BY <4>1, <5>1
      <4> QED BY <4>2, <4>3
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2>4. \A c \in certs' :
          /\ c.shares = {Share(mm, c.slot, c.root) : mm \in Ring}
          /\ \A mm \in HonestMembers : Share(mm, c.slot, c.root) \in hshares'
    <3>1. certs' = certs
      BY <1>3 DEF HonestSign
    <3>2. hshares \subseteq hshares'
      BY <1>3 DEF HonestSign
    <3> QED BY <1>1, <3>1, <3>2 DEF Inv
  <2> QED BY <2>2, <2>3, <2>4 DEF Inv
<1>4. ASSUME NEW s \in Slots, NEW r \in Roots, Assemble(s, r)
      PROVE Inv'
  <2>1. TypeOK'
    <3>1. Cert(s, r) \in [slot : Slots, root : Roots,
                          shares : SUBSET (Ring \X Slots \X Roots)]
      BY <1>4 DEF Cert, Share
    <3> QED BY <1>1, <1>4, <3>1 DEF Inv, TypeOK, Assemble
  <2>2. \A mm \in HonestMembers, ss \in Slots, rr \in Roots :
          (Share(mm, ss, rr) \in hshares') => journal'[mm][ss] = rr
    BY <1>1, <1>4 DEF Inv, Assemble
  <2>3. \A c \in certs' :
          /\ c.shares = {Share(mm, c.slot, c.root) : mm \in Ring}
          /\ \A mm \in HonestMembers : Share(mm, c.slot, c.root) \in hshares'
    <3>1. SUFFICES ASSUME NEW c \in certs'
          PROVE /\ c.shares = {Share(mm, c.slot, c.root) : mm \in Ring}
                /\ \A mm \in HonestMembers :
                     Share(mm, c.slot, c.root) \in hshares'
      OBVIOUS
    <3>2. certs' = certs \cup {Cert(s, r)} /\ hshares' = hshares
      BY <1>4 DEF Assemble
    <3>3. CASE c \in certs
      BY <1>1, <3>2, <3>3 DEF Inv
    <3>4. CASE c = Cert(s, r)
      <4>1. c.shares = {Share(mm, s, r) : mm \in Ring}
            /\ c.slot = s /\ c.root = r
        BY <3>4 DEF Cert
      <4>2. \A mm \in HonestMembers : Share(mm, s, r) \in hshares
        <5>1. \A mm \in Ring : ShareAvailable(mm, s, r)
          BY <1>4 DEF Assemble
        <5> QED BY <5>1, ForensicConstants DEF ShareAvailable
      <4> QED BY <3>2, <4>1, <4>2
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2> QED BY <2>1, <2>2, <2>3 DEF Inv
<1>5. QED
  BY <1>1, <1>2, <1>3, <1>4 DEF Next, vars

(***************************************************************************)
(* T7: any two conflicting wire certificates decompose into conflicting    *)
(* share pairs for EVERY ring member — the extraction procedure returns    *)
(* the full necessary-participant set.  Purely structural: the record      *)
(* format guarantees it, which is exactly why the format is part of the    *)
(* theorem and an opaque aggregate destroys it (the mutation drill).       *)
(***************************************************************************)
LEMMA InvAttribution == Inv => AttributionComplete
<1>1. SUFFICES ASSUME Inv, NEW c1 \in certs, NEW c2 \in certs,
                      Conflicting(c1, c2)
      PROVE ExtractedSet(c1, c2) = Ring
  BY DEF AttributionComplete
<1>2. c1.shares = {Share(mm, c1.slot, c1.root) : mm \in Ring}
      /\ c2.shares = {Share(mm, c2.slot, c2.root) : mm \in Ring}
  BY <1>1 DEF Inv
<1>3. \A m \in Ring : /\ Share(m, c1.slot, c1.root) \in c1.shares
                      /\ Share(m, c2.slot, c2.root) \in c2.shares
  BY <1>2
<1>4. QED
  BY <1>3 DEF ExtractedSet

(***************************************************************************)
(* Certificate uniqueness under MHA, restated over the wire: a conflicting *)
(* pair requires an honest member's shares over two roots at one slot,     *)
(* which the journal forbids — so conflict implies zero honest members.    *)
(***************************************************************************)
LEMMA InvCertUniqueness == Inv => CertUniqueness
<1>1. SUFFICES ASSUME Inv, NEW c1 \in certs, NEW c2 \in certs,
                      Conflicting(c1, c2)
      PROVE HonestMembers = {}
  BY DEF CertUniqueness
<1>2. SUFFICES ASSUME NEW h \in HonestMembers PROVE FALSE
  OBVIOUS
<1>3. Share(h, c1.slot, c1.root) \in hshares
      /\ Share(h, c2.slot, c2.root) \in hshares
  BY <1>1, <1>2 DEF Inv
<1>4. journal[h][c1.slot] = c1.root /\ journal[h][c2.slot] = c2.root
  <2>1. c1.slot \in Slots /\ c1.root \in Roots
        /\ c2.slot \in Slots /\ c2.root \in Roots
    BY <1>1 DEF Inv, TypeOK
  <2> QED BY <1>1, <1>2, <1>3, <2>1 DEF Inv
<1>5. c1.slot = c2.slot /\ c1.root # c2.root
  BY <1>1 DEF Conflicting
<1>6. QED
  BY <1>4, <1>5

THEOREM ForensicSafety ==
  Spec => [](AttributionComplete /\ CertUniqueness)
<1>1. Init => Inv
  BY FInvInit
<1>2. Inv /\ [Next]_vars => Inv'
  BY FInvNext
<1>3. Spec => []Inv
  BY <1>1, <1>2, PTL DEF Spec
<1>4. Inv => (AttributionComplete /\ CertUniqueness)
  BY InvAttribution, InvCertUniqueness
<1>5. QED
  BY <1>3, <1>4, PTL

====
