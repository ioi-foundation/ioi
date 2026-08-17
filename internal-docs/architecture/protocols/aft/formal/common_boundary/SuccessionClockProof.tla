---- MODULE SuccessionClockProof ----
(***************************************************************************)
(* AFT-CB P2.7 — TLAPS discharge of the §16 v3 kernel.                     *)
(*                                                                         *)
(* T5d-v3's safety is BY REFUSAL: the honest-standby guard means no        *)
(* fallback certificate ever commits a rival, so no released effect can    *)
(* face a BINDING rival — the theorem is the guard's inductive             *)
(* preservation, under A2(S_v) modeled structurally (the honest share is   *)
(* necessary, so the guard binds every assembled certificate).  A          *)
(* Byzantine signer padding obs_commit could only ADD rivals — which       *)
(* blocks its own fallback (Binding fires) — the safe direction; the       *)
(* kernel therefore commits the honest union exactly.                      *)
(*                                                                         *)
(* ActivationJustified: activation exists only with the formation policy   *)
(* and the objective chain condition at its own tick — no silence input.   *)
(***************************************************************************)
EXTENDS SuccessionClock, TLAPS

ASSUME NoRootOutsideRootsS == NoRoot \notin Roots

LEMMA SInvInit == Init => Inv
  BY SuccessionConstants DEF Init, Inv, TypeOK, ActivationJustified

LEMMA SInvNext == Inv /\ [Next]_vars => Inv'
<1>1. SUFFICES ASSUME Inv, [Next]_vars PROVE Inv'
  OBVIOUS
<1>2. CASE UNCHANGED vars
  BY <1>1, <1>2 DEF Inv, TypeOK, ActivationJustified, vars
<1>3. CASE Tick
  <2>1. tick < MaxTick /\ tick' = tick + 1
    BY <1>3 DEF Tick
  <2>2. TypeOK'
    BY <1>1, <2>1, <1>3, SuccessionConstants DEF Inv, TypeOK, Tick
  <2>3. (\A fs \in fallbackSeals' : \A rv \in fs.obs : rv = fs.root)
    BY <1>1, <1>3 DEF Inv, Tick
  <2>4. ActivationJustified'
    BY <1>1, <1>3 DEF Inv, ActivationJustified, Tick
  <2> QED BY <2>2, <2>3, <2>4 DEF Inv
<1>4. ASSUME NEW m \in OldRing, NEW r \in Roots, OldAck(m, r)
      PROVE Inv'
  BY <1>1, <1>4 DEF Inv, TypeOK, ActivationJustified, OldAck
<1>5. ASSUME NEW r \in Roots, AssembleOldSeal(r)
      PROVE Inv'
  BY <1>1, <1>5 DEF Inv, TypeOK, ActivationJustified, AssembleOldSeal
<1>6. ASSUME NEW r \in Roots, Submit(r)
      PROVE Inv'
  BY <1>1, <1>6 DEF Inv, TypeOK, ActivationJustified, Submit
<1>7. ASSUME NEW h \in Standby, NEW r \in Roots, Observe(h, r)
      PROVE Inv'
  <2>1. h \in HonestStandby /\ r \in submitted
    BY <1>7 DEF Observe
  <2>2. TypeOK'
    BY <1>1, <1>7, <2>1, SuccessionConstants DEF Inv, TypeOK, Observe
  <2>3. (\A fs \in fallbackSeals' : \A rv \in fs.obs : rv = fs.root)
    BY <1>1, <1>7 DEF Inv, Observe
  <2>4. ActivationJustified'
    BY <1>1, <1>7 DEF Inv, ActivationJustified, Observe
  <2> QED BY <2>2, <2>3, <2>4 DEF Inv
<1>8. CASE Activate
  <2>1. TypeOK'
    BY <1>1, <1>8 DEF Inv, TypeOK, Activate
  <2>2. (\A fs \in fallbackSeals' : \A rv \in fs.obs : rv = fs.root)
    BY <1>1, <1>8 DEF Inv, Activate
  <2>3. ActivationJustified'
    BY <1>1, <1>8 DEF Inv, TypeOK, ActivationJustified, Activate
  <2> QED BY <2>1, <2>2, <2>3 DEF Inv
<1>9. ASSUME NEW r \in Roots, AssembleFallback(r)
      PROVE Inv'
  <2>1. TypeOK'
    <3>1. UNION {observedBy[h] : h \in HonestStandby} \subseteq Roots
      BY <1>1, SuccessionConstants DEF Inv, TypeOK
    <3> QED BY <1>1, <1>9, <3>1 DEF Inv, TypeOK, AssembleFallback
  <2>2. (\A fs \in fallbackSeals' : \A rv \in fs.obs : rv = fs.root)
    <3>1. SUFFICES ASSUME NEW fs \in fallbackSeals', NEW rv \in fs.obs
          PROVE rv = fs.root
      OBVIOUS
    <3>2. fallbackSeals' = fallbackSeals \cup
            {[root |-> r, obs |-> UNION {observedBy[h] : h \in HonestStandby}]}
      BY <1>9 DEF AssembleFallback
    <3>3. CASE fs \in fallbackSeals
      BY <1>1, <3>3 DEF Inv
    <3>4. CASE fs = [root |-> r, obs |-> UNION {observedBy[h] : h \in HonestStandby}]
      <4>1. \A h \in HonestStandby : \A rv2 \in observedBy[h] : rv2 = r
        BY <1>9 DEF AssembleFallback
      <4>2. rv \in UNION {observedBy[h] : h \in HonestStandby}
        BY <3>1, <3>4
      <4>3. rv = r
        BY <4>1, <4>2
      <4> QED BY <3>4, <4>3
    <3> QED BY <3>1, <3>2, <3>3, <3>4
  <2>3. ActivationJustified'
    BY <1>1, <1>9 DEF Inv, ActivationJustified, AssembleFallback
  <2> QED BY <2>1, <2>2, <2>3 DEF Inv
<1>10. ASSUME NEW r \in Roots, Release(r)
      PROVE Inv'
  BY <1>1, <1>10 DEF Inv, TypeOK, ActivationJustified, Release
<1>11. QED
  BY <1>1, <1>2, <1>3, <1>4, <1>5, <1>6, <1>7, <1>8, <1>9, <1>10
  DEF Next, vars

LEMMA InvNoBindingRival == Inv => NoBindingRivalReleased
<1>1. SUFFICES ASSUME Inv, NEW r \in released, NEW rv \in Roots,
                      Binding(rv, r)
      PROVE FALSE
  BY DEF NoBindingRivalReleased
<1>2. PICK fs \in fallbackSeals : fs.root = r /\ rv \in fs.obs /\ rv # r
  BY <1>1 DEF Binding
<1>3. rv = fs.root
  BY <1>1, <1>2 DEF Inv
<1>4. QED
  BY <1>2, <1>3

THEOREM SuccessionSafety ==
  Spec => [](NoBindingRivalReleased /\ ActivationJustified)
<1>1. Init => Inv
  BY SInvInit
<1>2. Inv /\ [Next]_vars => Inv'
  BY SInvNext
<1>3. Spec => []Inv
  BY <1>1, <1>2, PTL DEF Spec
<1>4. Inv => (NoBindingRivalReleased /\ ActivationJustified)
  BY InvNoBindingRival DEF Inv
<1>5. QED
  BY <1>3, <1>4, PTL

====
