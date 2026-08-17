---- MODULE MembershipTransitionProof ----
(***************************************************************************)
(* AFT-CB P2.3 — TLAPS discharge: T5a lineage uniqueness under             *)
(* per-configuration MHA (stated as a theorem CONDITION, not a global      *)
(* assumption), the signature-justification invariant (the no-silence      *)
(* assertion), and the A6-conditional bootstrap-freshness statement —      *)
(* conditionality in the theorem, never in prose.                          *)
(***************************************************************************)
EXTENDS MembershipTransition, TLAPS

(* Assumed here rather than in the model module: TLC cannot evaluate this  *)
(* membership test over a model value, while its model-value semantics     *)
(* already make it true; tlapm consumes it for the journal-conflict step.  *)
ASSUME NoSuccOutsideConfigs == NoSucc \notin Configs

LEMMA MInvInit == Init => Inv
  BY MembershipConstants DEF Init, Inv, TypeOK, TransitionsJustified

LEMMA MInvNext == Inv /\ [Next]_vars => Inv'
<1>1. SUFFICES ASSUME Inv, [Next]_vars PROVE Inv'
  OBVIOUS
<1>2. CASE UNCHANGED vars
  BY <1>1, <1>2 DEF Inv, TypeOK, TransitionsJustified, AckedBy, AcceptedBy,
     vars
<1>3. ASSUME NEW m \in AllMembers, NEW l \in Lineages, NEW v \in Versions,
             NEW succ \in Configs, HonestTransitionAck(m, l, v, succ)
      PROVE Inv'
  <2>1. m \in HonestMembers /\ tjournal[m][l][v] = NoSucc
    BY <1>3 DEF HonestTransitionAck
  <2>2. TypeOK'
    BY <1>1, <1>3, <2>1 DEF Inv, TypeOK, HonestTransitionAck
  <2>3. \A mm \in HonestMembers, ll \in Lineages, vv \in Versions,
          ss \in Configs :
          (<<mm, ll, vv, ss>> \in tacks') => tjournal'[mm][ll][vv] = ss
    <3>1. SUFFICES ASSUME NEW mm \in HonestMembers, NEW ll \in Lineages,
                          NEW vv \in Versions, NEW ss \in Configs,
                          <<mm, ll, vv, ss>> \in tacks'
          PROVE tjournal'[mm][ll][vv] = ss
      OBVIOUS
    <3>2. tacks' = tacks \cup {<<m, l, v, succ>>}
      BY <1>3 DEF HonestTransitionAck
    <3>3. CASE <<mm, ll, vv, ss>> = <<m, l, v, succ>>
      <4>1. mm = m /\ ll = l /\ vv = v /\ ss = succ
        BY <3>3
      <4>2. tjournal'[m][l][v] = succ
        BY <1>1, <1>3, <2>1 DEF Inv, TypeOK, HonestTransitionAck
      <4> QED BY <4>1, <4>2
    <3>4. CASE <<mm, ll, vv, ss>> \in tacks
      <4>1. tjournal[mm][ll][vv] = ss
        BY <1>1, <3>4 DEF Inv
      <4>2. CASE mm = m /\ ll = l /\ vv = v
        <5>1. tjournal[m][l][v] = ss
          BY <4>1, <4>2
        <5>2. tjournal[m][l][v] = NoSucc
          BY <2>1
        <5>3. ss # NoSucc
          BY <3>1, NoSuccOutsideConfigs
        <5> QED BY <5>1, <5>2, <5>3
      <4>3. CASE ~(mm = m /\ ll = l /\ vv = v)
        <5>1. tjournal'[mm][ll][vv] = tjournal[mm][ll][vv]
          BY <1>1, <1>3, <2>1, <4>3 DEF Inv, TypeOK, HonestTransitionAck
        <5> QED BY <4>1, <5>1
      <4> QED BY <4>2, <4>3
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2>4. TransitionsJustified'
    <3>1. SUFFICES ASSUME NEW ll \in Lineages, NEW vv \in Versions,
                          NEW pp \in Configs, NEW ss \in Configs,
                          <<ll, vv, pp, ss>> \in transitions'
          PROVE /\ \A mm \in pp : AckedBy(mm, ll, vv, ss)'
                /\ \A mm \in ss : AcceptedBy(mm, ll, vv, ss)'
      BY DEF TransitionsJustified
    <3>2. transitions' = transitions /\ tacks' = tacks \cup {<<m, l, v, succ>>}
          /\ taccepts' = taccepts
      BY <1>3 DEF HonestTransitionAck
    <3>3. /\ \A mm \in pp : AckedBy(mm, ll, vv, ss)
          /\ \A mm \in ss : AcceptedBy(mm, ll, vv, ss)
      BY <1>1, <3>1, <3>2 DEF Inv, TransitionsJustified
    <3> QED BY <3>1, <3>2, <3>3 DEF AckedBy, AcceptedBy
  <2> QED BY <2>2, <2>3, <2>4 DEF Inv
<1>5. ASSUME NEW m \in AllMembers, NEW l \in Lineages, NEW v \in Versions,
             NEW succ \in Configs, Accept(m, l, v, succ)
      PROVE Inv'
  <2>1. TypeOK'
    BY <1>1, <1>5 DEF Inv, TypeOK, Accept
  <2>2. \A mm \in HonestMembers, ll \in Lineages, vv \in Versions,
          ss \in Configs :
          (<<mm, ll, vv, ss>> \in tacks') => tjournal'[mm][ll][vv] = ss
    BY <1>1, <1>5 DEF Inv, Accept
  <2>3. TransitionsJustified'
    <3>1. SUFFICES ASSUME NEW ll \in Lineages, NEW vv \in Versions,
                          NEW pp \in Configs, NEW ss \in Configs,
                          <<ll, vv, pp, ss>> \in transitions'
          PROVE /\ \A mm \in pp : AckedBy(mm, ll, vv, ss)'
                /\ \A mm \in ss : AcceptedBy(mm, ll, vv, ss)'
      BY DEF TransitionsJustified
    <3>2. transitions' = transitions /\ tacks' = tacks
          /\ taccepts' = taccepts \cup {<<m, l, v, succ>>}
      BY <1>5 DEF Accept
    <3>3. /\ \A mm \in pp : AckedBy(mm, ll, vv, ss)
          /\ \A mm \in ss : AcceptedBy(mm, ll, vv, ss)
      BY <1>1, <3>1, <3>2 DEF Inv, TransitionsJustified
    <3> QED BY <3>1, <3>2, <3>3 DEF AckedBy, AcceptedBy
  <2> QED BY <2>1, <2>2, <2>3 DEF Inv
<1>6. ASSUME NEW l \in Lineages, NEW v \in Versions, NEW parent \in Configs,
             NEW succ \in Configs, CloseTransition(l, v, parent, succ)
      PROVE Inv'
  <2>1. TypeOK'
    BY <1>1, <1>6 DEF Inv, TypeOK, CloseTransition
  <2>2. \A mm \in HonestMembers, ll \in Lineages, vv \in Versions,
          ss \in Configs :
          (<<mm, ll, vv, ss>> \in tacks') => tjournal'[mm][ll][vv] = ss
    BY <1>1, <1>6 DEF Inv, TransitionsJustified, CloseTransition
  <2>3. TransitionsJustified'
    BY <1>1, <1>6 DEF Inv, TransitionsJustified, CloseTransition,
       AckedBy, AcceptedBy
  <2> QED BY <2>1, <2>2, <2>3 DEF Inv
<1>7. ASSUME NEW newL \in Lineages, NEW priorL \in Lineages,
             MintRoot(newL, priorL)
      PROVE Inv'
  BY <1>1, <1>7 DEF Inv, TypeOK, TransitionsJustified, AckedBy, AcceptedBy,
     MintRoot
<1>8. ASSUME NEW a \in AllMembers, NEW s \in AllMembers,
             EmitSilenceRecord(a, s)
      PROVE Inv'
  BY <1>1, <1>8 DEF Inv, TypeOK, TransitionsJustified, AckedBy, AcceptedBy,
     EmitSilenceRecord
<1>9. QED
  BY <1>1, <1>2, <1>3, <1>5, <1>6, <1>7, <1>8 DEF Next, vars

(***************************************************************************)
(* T5a: within one lineage, from a common parent configuration that        *)
(* contains at least one honest member (per-configuration MHA as an        *)
(* explicit CONDITION of the statement), closed successors are unique.     *)
(***************************************************************************)
LEMMA InvLineageUniqueness == Inv => LineageUniqueness
<1>1. SUFFICES ASSUME Inv, NEW l \in Lineages, NEW v \in Versions,
                      NEW parent \in Configs,
                      NEW s1 \in Configs, NEW s2 \in Configs,
                      <<l, v, parent, s1>> \in transitions,
                      <<l, v, parent, s2>> \in transitions,
                      parent \cap HonestMembers # {}
      PROVE s1 = s2
  BY DEF LineageUniqueness
<1>2. PICK h \in parent \cap HonestMembers : TRUE
  BY <1>1
<1>3. h \in parent /\ h \in HonestMembers
  BY <1>2
<1>4. <<h, l, v, s1>> \in tacks /\ <<h, l, v, s2>> \in tacks
  BY <1>1, <1>3 DEF Inv, TransitionsJustified, AckedBy
<1>5. tjournal[h][l][v] = s1 /\ tjournal[h][l][v] = s2
  BY <1>1, <1>3, <1>4 DEF Inv
<1>6. QED
  BY <1>5

THEOREM MembershipSafety == Spec => [](LineageUniqueness /\ TransitionsJustified)
<1>1. Init => Inv
  BY MInvInit
<1>2. Inv /\ [Next]_vars => Inv'
  BY MInvNext
<1>3. Spec => []Inv
  BY <1>1, <1>2, PTL DEF Spec
<1>4. Inv => (LineageUniqueness /\ TransitionsJustified)
  BY InvLineageUniqueness DEF Inv
<1>5. QED
  BY <1>3, <1>4, PTL

(***************************************************************************)
(* Bootstrap freshness, A6-conditional IN THE STATEMENT: with a deployed   *)
(* anchor, a verifier that partitions records by lineage id (well-formed   *)
(* histories) obtains per-lineage uniqueness wherever the parent satisfies *)
(* MHA — the anchor's job (selecting the live lineage among the            *)
(* partitions) is exactly the deployed mechanism's own assumption, which   *)
(* is why the implication's hypothesis names it.  With NO anchor deployed  *)
(* the theorem asserts nothing — out-of-model, stated structurally.        *)
(***************************************************************************)
THEOREM BootstrapFreshness ==
  (DeployedAnchor \in Anchors) =>
    (Spec => [](\A l \in Lineages, v \in Versions, parent \in Configs,
                   s1 \in Configs, s2 \in Configs :
                 (/\ <<l, v, parent, s1>> \in transitions
                  /\ <<l, v, parent, s2>> \in transitions
                  /\ parent \cap HonestMembers # {}) => s1 = s2))
<1>1. SUFFICES ASSUME DeployedAnchor \in Anchors PROVE
        Spec => []LineageUniqueness
  BY DEF LineageUniqueness
<1>2. Spec => [](LineageUniqueness /\ TransitionsJustified)
  BY MembershipSafety
<1>3. QED
  BY <1>2, PTL

====
