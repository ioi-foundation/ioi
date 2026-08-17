---- MODULE CustodyObligationProof ----
(***************************************************************************)
(* AFT-CB P2.4 — TLAPS discharge: the custody invariant is inductive, and  *)
(* conditional availability (T3's shape) follows with MHA as an explicit   *)
(* theorem condition.  No proof step mentions auditEvidence: the audit     *)
(* lane is not load-bearing, by the shape of the proof itself.             *)
(***************************************************************************)
EXTENDS CustodyObligation, TLAPS

ASSUME NoBoundaryOutsideBoundaries == NoBoundary \notin Boundaries

LEMMA CInvInit == Init => Inv
  BY CustodyConstants DEF Init, Inv, TypeOK, HonestAckJournal,
     RetainedBacked, CustodyInvariant, ReleaseDiscipline, AckedBy

LEMMA CInvNext == Inv /\ [Next]_vars => Inv'
<1>1. SUFFICES ASSUME Inv, [Next]_vars PROVE Inv'
  OBVIOUS
<1>2. CASE UNCHANGED vars
  BY <1>1, <1>2 DEF Inv, TypeOK, HonestAckJournal, RetainedBacked,
     CustodyInvariant, ReleaseDiscipline, AckedBy, vars
<1>3. ASSUME NEW a \in Artifacts, NEW m \in Ring, Deliver(a, m)
      PROVE Inv'
  BY <1>1, <1>3 DEF Inv, TypeOK, HonestAckJournal, RetainedBacked,
     CustodyInvariant, ReleaseDiscipline, AckedBy, Deliver
<1>4. ASSUME NEW m \in HonestMembers, NEW a \in Artifacts, Fetch(m, a)
      PROVE Inv'
  <2>1. TypeOK'
    BY <1>1, <1>4, CustodyConstants DEF Inv, TypeOK, Fetch
  <2>2. HonestAckJournal'
    BY <1>1, <1>4 DEF Inv, HonestAckJournal, Fetch
  <2>3. CustodyInvariant'
    BY <1>1, <1>4 DEF Inv, CustodyInvariant, Fetch
  <2>4. (\A s2 \in Slots, B2 \in Boundaries :
          (<<s2, B2>> \in closes') => \A mm \in Ring : AckedBy(mm, s2, B2)')
    BY <1>1, <1>4 DEF Inv, AckedBy, Fetch
  <2>5. ReleaseDiscipline'
    BY <1>1, <1>4 DEF Inv, ReleaseDiscipline, Fetch
  <2>6. RetainedBacked'
    <3>1. SUFFICES ASSUME NEW mm \in HonestMembers, NEW ss \in Slots
          PROVE retained'[mm][ss] \subseteq holds'[mm]
      BY DEF RetainedBacked
    <3>2. retained' = retained
      BY <1>4 DEF Fetch
    <3>3. holds[mm] \subseteq holds'[mm]
      BY <1>1, <1>4, CustodyConstants DEF Inv, TypeOK, Fetch
    <3>4. retained[mm][ss] \subseteq holds[mm]
      BY <1>1, <3>1 DEF Inv, RetainedBacked
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2> QED BY <2>1, <2>2, <2>3, <2>4, <2>5, <2>6 DEF Inv
<1>5. ASSUME NEW m \in HonestMembers, NEW s \in Slots, NEW B \in Boundaries,
             HonestFinalAck(m, s, B)
      PROVE Inv'
  <2>1. B \subseteq holds[m] /\ journal[m][s] = NoBoundary
    BY <1>5 DEF HonestFinalAck
  <2>2. TypeOK'
    BY <1>1, <1>5, <2>1, CustodyConstants
       DEF Inv, TypeOK, HonestFinalAck
  <2>3. HonestAckJournal'
    <3>1. SUFFICES ASSUME NEW mm \in HonestMembers, NEW ss \in Slots,
                          NEW BB \in Boundaries, <<mm, ss, BB>> \in acks'
          PROVE journal'[mm][ss] = BB
      BY DEF HonestAckJournal
    <3>2. acks' = acks \cup {<<m, s, B>>}
      BY <1>5 DEF HonestFinalAck
    <3>3. CASE <<mm, ss, BB>> = <<m, s, B>>
      <4>1. journal'[m][s] = B
        BY <1>1, <1>5, <2>1 DEF Inv, TypeOK, HonestFinalAck
      <4> QED BY <3>3, <4>1
    <3>4. CASE <<mm, ss, BB>> \in acks
      <4>1. journal[mm][ss] = BB
        BY <1>1, <3>4 DEF Inv, HonestAckJournal
      <4>2. CASE mm = m /\ ss = s
        <5>1. journal[m][s] = BB
          BY <4>1, <4>2
        <5>2. BB # NoBoundary
          BY <3>1, NoBoundaryOutsideBoundaries
        <5> QED BY <2>1, <5>1, <5>2
      <4>3. CASE ~(mm = m /\ ss = s)
        <5>1. journal'[mm][ss] = journal[mm][ss]
          BY <1>1, <1>5, <2>1, <4>3 DEF Inv, TypeOK, HonestFinalAck
        <5> QED BY <4>1, <5>1
      <4> QED BY <4>2, <4>3
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2>4. CustodyInvariant'
    <3>1. SUFFICES ASSUME NEW mm \in HonestMembers, NEW ss \in Slots,
                          NEW BB \in Boundaries, <<mm, ss, BB>> \in acks'
          PROVE BB \subseteq retained'[mm][ss]
      BY DEF CustodyInvariant
    <3>2. acks' = acks \cup {<<m, s, B>>}
      BY <1>5 DEF HonestFinalAck
    <3>3. CASE <<mm, ss, BB>> = <<m, s, B>>
      <4>1. retained'[m][s] = B
        BY <1>1, <1>5, CustodyConstants DEF Inv, TypeOK, HonestFinalAck
      <4> QED BY <3>3, <4>1
    <3>4. CASE <<mm, ss, BB>> \in acks
      <4>1. BB \subseteq retained[mm][ss]
        BY <1>1, <3>4 DEF Inv, CustodyInvariant
      <4>2. CASE mm = m /\ ss = s
        <5>1. journal[m][s] = BB
          BY <1>1, <3>4, <4>2 DEF Inv, HonestAckJournal
        <5>2. BB # NoBoundary
          BY <3>1, NoBoundaryOutsideBoundaries
        <5> QED BY <2>1, <5>1, <5>2
      <4>3. CASE ~(mm = m /\ ss = s)
        <5>1. retained'[mm][ss] = retained[mm][ss]
          BY <1>1, <1>5, CustodyConstants, <4>3
             DEF Inv, TypeOK, HonestFinalAck
        <5> QED BY <4>1, <5>1
      <4> QED BY <4>2, <4>3
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2>5. (\A s2 \in Slots, B2 \in Boundaries :
          (<<s2, B2>> \in closes') => \A mm \in Ring : AckedBy(mm, s2, B2)')
    BY <1>1, <1>5 DEF Inv, AckedBy, HonestFinalAck
  <2>6. ReleaseDiscipline'
    BY <1>1, <1>5, CustodyConstants
       DEF Inv, TypeOK, ReleaseDiscipline, HonestFinalAck
  <2>7. RetainedBacked'
    BY <1>1, <1>5, <2>1, CustodyConstants
       DEF Inv, TypeOK, RetainedBacked, HonestFinalAck
  <2> QED BY <2>2, <2>3, <2>4, <2>5, <2>6, <2>7 DEF Inv
<1>6. ASSUME NEW s \in Slots, NEW B \in Boundaries, CloseSlot(s, B)
      PROVE Inv'
  <2>1. TypeOK'
    BY <1>1, <1>6 DEF Inv, TypeOK, CloseSlot
  <2>2. HonestAckJournal'
    BY <1>1, <1>6 DEF Inv, HonestAckJournal, CloseSlot
  <2>3. CustodyInvariant'
    BY <1>1, <1>6 DEF Inv, CustodyInvariant, CloseSlot
  <2>4. (\A s2 \in Slots, B2 \in Boundaries :
          (<<s2, B2>> \in closes') => \A mm \in Ring : AckedBy(mm, s2, B2)')
    <3>1. SUFFICES ASSUME NEW s2 \in Slots, NEW B2 \in Boundaries,
                          <<s2, B2>> \in closes', NEW mm \in Ring
          PROVE AckedBy(mm, s2, B2)'
      OBVIOUS
    <3>2. closes' = closes \cup {<<s, B>>} /\ acks' = acks
      BY <1>6 DEF CloseSlot
    <3>3. CASE <<s2, B2>> \in closes
      BY <1>1, <3>2, <3>3 DEF Inv, AckedBy
    <3>4. CASE <<s2, B2>> = <<s, B>>
      BY <1>6, <3>2, <3>4 DEF CloseSlot, AckedBy
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2>5. ReleaseDiscipline'
    BY <1>1, <1>6 DEF Inv, ReleaseDiscipline, CloseSlot
  <2>6. RetainedBacked'
    BY <1>1, <1>6 DEF Inv, RetainedBacked, CloseSlot
  <2> QED BY <2>1, <2>2, <2>3, <2>4, <2>5, <2>6 DEF Inv
<1>7. ASSUME NEW succ \in HonestMembers, NEW s \in Slots, NEW B \in Boundaries,
             Reconstruct(succ, s, B)
      PROVE Inv'
  <2>1. TypeOK'
    BY <1>1, <1>7, CustodyConstants DEF Inv, TypeOK, Reconstruct
  <2>2. CustodyInvariant'
    <3>1. SUFFICES ASSUME NEW mm \in HonestMembers, NEW ss \in Slots,
                          NEW BB \in Boundaries, <<mm, ss, BB>> \in acks'
          PROVE BB \subseteq retained'[mm][ss]
      BY DEF CustodyInvariant
    <3>2. acks' = acks
      BY <1>7 DEF Reconstruct
    <3>3. BB \subseteq retained[mm][ss]
      BY <1>1, <3>1, <3>2 DEF Inv, CustodyInvariant
    <3>4. retained[mm][ss] \subseteq retained'[mm][ss]
      (* Reconstruction only ever UNIONs custody in, so every member's      *)
      (* serving set is monotone under this action.                         *)
      BY <1>1, <1>7, CustodyConstants DEF Inv, TypeOK, Reconstruct
    <3> QED BY <3>3, <3>4
  <2>3. HonestAckJournal'
    BY <1>1, <1>7 DEF Inv, HonestAckJournal, Reconstruct
  <2>4. (\A s2 \in Slots, B2 \in Boundaries :
          (<<s2, B2>> \in closes') => \A mm \in Ring : AckedBy(mm, s2, B2)')
    BY <1>1, <1>7 DEF Inv, AckedBy, Reconstruct
  <2>5. ReleaseDiscipline'
    BY <1>1, <1>7, CustodyConstants
       DEF Inv, TypeOK, ReleaseDiscipline, Reconstruct
  <2>6. RetainedBacked'
    BY <1>1, <1>7, CustodyConstants
       DEF Inv, TypeOK, RetainedBacked, Reconstruct
  <2> QED BY <2>1, <2>2, <2>3, <2>4, <2>5, <2>6 DEF Inv
<1>8. ASSUME NEW m \in HonestMembers, ReleaseBond(m)
      PROVE Inv'
  <2>1. TypeOK'
    BY <1>1, <1>8, CustodyConstants DEF Inv, TypeOK, ReleaseBond
  <2>2. HonestAckJournal'
    BY <1>1, <1>8 DEF Inv, HonestAckJournal, ReleaseBond
  <2>3. CustodyInvariant'
    BY <1>1, <1>8 DEF Inv, CustodyInvariant, ReleaseBond
  <2>4. (\A s2 \in Slots, B2 \in Boundaries :
          (<<s2, B2>> \in closes') => \A mm \in Ring : AckedBy(mm, s2, B2)')
    BY <1>1, <1>8 DEF Inv, AckedBy, ReleaseBond
  <2>5. ReleaseDiscipline'
    <3>1. SUFFICES ASSUME NEW mm \in HonestMembers, bondReleased'[mm],
                          NEW ss \in Slots, retained'[mm][ss] # {}
          PROVE \E succ \in HonestMembers :
                  succ # mm /\ <<succ, ss>> \in reconstructed'
      BY DEF ReleaseDiscipline
    <3>2. /\ bondReleased' = [bondReleased EXCEPT ![m] = TRUE]
          /\ retained' = retained /\ reconstructed' = reconstructed
      BY <1>8 DEF ReleaseBond
    <3>3. CASE mm = m
      BY <1>1, <1>8, <3>1, <3>2, <3>3, CustodyConstants
         DEF Inv, TypeOK, ReleaseBond
    <3>4. CASE mm # m
      <4>1. bondReleased[mm]
        BY <1>1, <3>1, <3>2, <3>4, CustodyConstants DEF Inv, TypeOK
      <4> QED BY <1>1, <3>1, <3>2, <4>1 DEF Inv, ReleaseDiscipline
    <3> QED BY <3>1, <3>3, <3>4
  <2>6. RetainedBacked'
    BY <1>1, <1>8 DEF Inv, RetainedBacked, ReleaseBond
  <2> QED BY <2>1, <2>2, <2>3, <2>4, <2>5, <2>6 DEF Inv
<1>9. ASSUME NEW auditor \in Ring, NEW subject \in Ring, NEW s \in Slots,
             Audit(auditor, subject, s)
      PROVE Inv'
  BY <1>1, <1>9 DEF Inv, TypeOK, HonestAckJournal, RetainedBacked,
     CustodyInvariant, ReleaseDiscipline, AckedBy, Audit
<1>10. QED
  BY <1>1, <1>2, <1>3, <1>4, <1>5, <1>6, <1>7, <1>8, <1>9 DEF Next, vars

LEMMA InvAvailability == Inv => ConditionalAvailability
<1>1. SUFFICES ASSUME Inv, NEW s \in Slots, NEW B \in Boundaries,
                      <<s, B>> \in closes, Ring \cap HonestMembers # {}
      PROVE \E m \in HonestMembers : B \subseteq retained[m][s]
  BY DEF ConditionalAvailability
<1>2. PICK h \in Ring \cap HonestMembers : TRUE
  BY <1>1
<1>3. AckedBy(h, s, B)
  BY <1>1, <1>2 DEF Inv
<1>4. <<h, s, B>> \in acks
  BY <1>2, <1>3 DEF AckedBy
<1>5. B \subseteq retained[h][s]
  BY <1>1, <1>2, <1>4 DEF Inv, CustodyInvariant
<1>6. QED
  BY <1>2, <1>5

THEOREM CustodySafety ==
  Spec => [](ConditionalAvailability /\ ReleaseDiscipline)
<1>1. Init => Inv
  BY CInvInit
<1>2. Inv /\ [Next]_vars => Inv'
  BY CInvNext
<1>3. Spec => []Inv
  BY <1>1, <1>2, PTL DEF Spec
<1>4. Inv => (ConditionalAvailability /\ ReleaseDiscipline)
  BY InvAvailability DEF Inv
<1>5. QED
  BY <1>3, <1>4, PTL

====
