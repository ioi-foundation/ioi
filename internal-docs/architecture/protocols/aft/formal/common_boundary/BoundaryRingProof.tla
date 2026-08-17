---- MODULE BoundaryRingProof ----
(***************************************************************************)
(* AFT-CB P2.1 — TLAPS discharge of Boundary Ring uniqueness (T1).         *)
(*                                                                         *)
(* Structure: Init => Inv; Inv /\ [Next]_vars => Inv'; Inv /\ MHA =>       *)
(* Uniqueness; composed to THEOREM Spec => []Uniqueness under the MHA      *)
(* constant assumption.  Uniqueness is derived, never defined into         *)
(* existence.                                                              *)
(***************************************************************************)
EXTENDS BoundaryRing, TLAPS

ASSUME MHA == HonestMembers # {}

LEMMA InvInit == Init => Inv
  BY ConstantAssumptions DEF Init, Inv, TypeOK

LEMMA InvNext == Inv /\ [Next]_vars => Inv'
<1>1. SUFFICES ASSUME Inv, [Next]_vars PROVE Inv'
  OBVIOUS
<1>2. CASE UNCHANGED vars
  BY <1>1, <1>2 DEF Inv, TypeOK, vars
<1>3. ASSUME NEW a \in Artifacts, NEW m \in Ring, Deliver(a, m)
      PROVE Inv'
  BY <1>1, <1>3 DEF Inv, TypeOK, Deliver
<1>4. ASSUME NEW m \in Ring, NEW s \in Slots, NEW A \in SUBSET Artifacts,
             HonestDeclare(m, s, A)
      PROVE Inv'
  BY <1>1, <1>4 DEF Inv, TypeOK, HonestDeclare
<1>5. ASSUME NEW m \in Ring, NEW s \in Slots, NEW A \in SUBSET Artifacts,
             ByzantineDeclare(m, s, A)
      PROVE Inv'
  BY <1>1, <1>5 DEF Inv, TypeOK, ByzantineDeclare
<1>6. ASSUME NEW m \in Ring, NEW s \in Slots, NEW r \in Roots,
             HonestFinalAck(m, s, r)
      PROVE Inv'
  <2>1. m \in HonestMembers /\ journal[m][s] = NoRoot
    BY <1>6 DEF HonestFinalAck
  <2>2. TypeOK'
    BY <1>1, <1>6, <2>1 DEF Inv, TypeOK, HonestFinalAck
  <2>3. \A mm \in HonestMembers, ss \in Slots, rr \in Roots :
          (<<mm, ss, rr>> \in acks') => journal'[mm][ss] = rr
    <3>1. SUFFICES ASSUME NEW mm \in HonestMembers, NEW ss \in Slots,
                          NEW rr \in Roots, <<mm, ss, rr>> \in acks'
          PROVE journal'[mm][ss] = rr
      OBVIOUS
    <3>2. acks' = acks \cup {<<m, s, r>>}
      BY <1>6 DEF HonestFinalAck
    <3>3. CASE <<mm, ss, rr>> = <<m, s, r>>
      <4>1. mm = m /\ ss = s /\ rr = r
        BY <3>3
      <4>2. journal'[m][s] = r
        BY <1>1, <1>6, <2>1 DEF Inv, TypeOK, HonestFinalAck
      <4> QED BY <4>1, <4>2
    <3>4. CASE <<mm, ss, rr>> \in acks
      <4>1. journal[mm][ss] = rr
        BY <1>1, <3>4 DEF Inv
      <4>2. CASE mm = m /\ ss = s
        <5>1. journal[m][s] = rr
          BY <4>1, <4>2
        <5>2. rr \in Roots /\ NoRoot \notin Roots
          BY <3>1, ConstantAssumptions
        <5>3. FALSE
          BY <2>1, <5>1, <5>2
        <5> QED BY <5>3
      <4>3. CASE ~(mm = m /\ ss = s)
        <5>1. journal'[mm][ss] = journal[mm][ss]
          BY <1>1, <1>6, <2>1, <4>3 DEF Inv, TypeOK, HonestFinalAck
        <5> QED BY <4>1, <5>1
      <4> QED BY <4>2, <4>3
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2>4. \A ss \in Slots, rr \in Roots :
          (<<ss, rr>> \in closes') => \A mm \in Ring : <<mm, ss, rr>> \in acks'
    BY <1>1, <1>6 DEF Inv, HonestFinalAck
  <2> QED BY <2>2, <2>3, <2>4 DEF Inv
<1>7. ASSUME NEW m \in Ring, NEW s \in Slots, NEW r \in Roots,
             ByzantineEmit(m, s, r)
      PROVE Inv'
  <2>1. m \notin HonestMembers
    BY <1>7 DEF ByzantineEmit
  <2>2. TypeOK'
    BY <1>1, <1>7 DEF Inv, TypeOK, ByzantineEmit
  <2>3. \A mm \in HonestMembers, ss \in Slots, rr \in Roots :
          (<<mm, ss, rr>> \in acks') => journal'[mm][ss] = rr
    BY <1>1, <1>7, <2>1 DEF Inv, ByzantineEmit
  <2>4. \A ss \in Slots, rr \in Roots :
          (<<ss, rr>> \in closes') => \A mm \in Ring : <<mm, ss, rr>> \in acks'
    BY <1>1, <1>7 DEF Inv, ByzantineEmit
  <2> QED BY <2>2, <2>3, <2>4 DEF Inv
<1>8. ASSUME NEW s \in Slots, NEW r \in Roots, CloseAct(s, r)
      PROVE Inv'
  <2>1. TypeOK'
    BY <1>1, <1>8 DEF Inv, TypeOK, CloseAct
  <2>2. \A mm \in HonestMembers, ss \in Slots, rr \in Roots :
          (<<mm, ss, rr>> \in acks') => journal'[mm][ss] = rr
    BY <1>1, <1>8 DEF Inv, CloseAct
  <2>3. \A ss \in Slots, rr \in Roots :
          (<<ss, rr>> \in closes') => \A mm \in Ring : <<mm, ss, rr>> \in acks'
    <3>1. SUFFICES ASSUME NEW ss \in Slots, NEW rr \in Roots,
                          <<ss, rr>> \in closes'
          PROVE \A mm \in Ring : <<mm, ss, rr>> \in acks'
      OBVIOUS
    <3>2. closes' = closes \cup {<<s, r>>} /\ acks' = acks
      BY <1>8 DEF CloseAct
    <3>3. CASE <<ss, rr>> \in closes
      BY <1>1, <3>2, <3>3 DEF Inv
    <3>4. CASE <<ss, rr>> = <<s, r>>
      BY <1>8, <3>2, <3>4 DEF CloseAct
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2> QED BY <2>1, <2>2, <2>3 DEF Inv
<1>9. QED
  BY <1>1, <1>2, <1>3, <1>4, <1>5, <1>6, <1>7, <1>8 DEF Next, vars

LEMMA InvUniqueness == Inv => Uniqueness
<1>1. SUFFICES ASSUME Inv, NEW s \in Slots, NEW r1 \in Roots, NEW r2 \in Roots,
                      <<s, r1>> \in closes, <<s, r2>> \in closes
      PROVE r1 = r2
  BY DEF Uniqueness
<1>2. PICK h \in HonestMembers : TRUE
  BY MHA
<1>3. h \in Ring
  BY ConstantAssumptions
<1>4. <<h, s, r1>> \in acks /\ <<h, s, r2>> \in acks
  BY <1>1, <1>3 DEF Inv
<1>5. journal[h][s] = r1 /\ journal[h][s] = r2
  BY <1>1, <1>2, <1>4 DEF Inv
<1>6. QED
  BY <1>5

THEOREM BoundaryUniqueness == Spec => []Uniqueness
<1>1. Init => Inv
  BY InvInit
<1>2. Inv /\ [Next]_vars => Inv'
  BY InvNext
<1>3. Spec => []Inv
  BY <1>1, <1>2, PTL DEF Spec
<1>4. Inv => Uniqueness
  BY InvUniqueness
<1>5. QED
  BY <1>3, <1>4, PTL

====
