------------------- MODULE QuvEffectPreparationProof -------------------
EXTENDS QuvEffectPreparation, TLAPS
ASSUME Profile == /\ SkipBinding = FALSE /\ SkipPreflight = FALSE /\ PreparedBearer = FALSE /\ WriteTerminal = FALSE
Inv == TypeOK /\ PreparationChecked /\ GrantIsOwn /\ ClaimIsOwn /\ TerminalIsNotExecutable /\ TerminalReadOnly
THEOREM PreparationSafety == Spec => []Inv
<1>1. Init => Inv
  BY SMT DEF Init, Inv, TypeOK, PreparationChecked, GrantIsOwn, ClaimIsOwn, TerminalIsNotExecutable, TerminalReadOnly
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, PreparationChecked, GrantIsOwn,
    ClaimIsOwn, TerminalIsNotExecutable, TerminalReadOnly, Next, Prepare, OwnLive, Claim, Crash, vars, inputs
<1> QED BY <1>1, <1>2, PTL DEF Spec
=============================================================================
