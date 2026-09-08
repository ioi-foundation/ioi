--------------------- MODULE QuvLifetimeBudgetProof ---------------------
EXTENDS QuvLifetimeBudget, FiniteSetTheorems, TLAPS
ASSUME Profile == /\ Horizon \in Nat /\ Horizon > 0
                  /\ Attempts \in Nat /\ Attempts > 0
                  /\ RecordBudget \in Nat /\ RecordBudget > 0
                  /\ ReuseEvent = FALSE
Inv == TypeOK /\ ChargedRecordBytes

THEOREM FiniteEventSpace ==
    /\ IsFiniteSet(Universe)
    /\ Cardinality(Universe) = Horizon * (Attempts+3)
<1>1. /\ IsFiniteSet(1..Horizon)
      /\ Cardinality(1..Horizon) = Horizon
  BY Profile, FS_Interval, SMT DEF Profile
<1>2. /\ IsFiniteSet(1..(Attempts+3))
      /\ Cardinality(1..(Attempts+3)) = Attempts+3
  BY Profile, FS_Interval, SMT DEF Profile
<1> QED BY <1>1, <1>2, FS_Product, SMT DEF Universe

THEOREM ChargedPrefixBound == Spec => []Inv
<1>1. Init => Inv
  BY Profile, FS_EmptySet, SMT DEF Profile, Init, Inv, TypeOK, ChargedRecordBytes
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, FS_AddElement, FS_CardinalityType, SMT DEF Profile, Inv, TypeOK, ChargedRecordBytes,
    Next, Record, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec

THEOREM WholeLifetimeBound == Spec => []LifetimeBytes
<1>1. Inv => LifetimeBytes
  BY Profile, FiniteEventSpace, FS_Subset, FS_CardinalityType, SMT DEF Profile, Inv, TypeOK,
    ChargedRecordBytes, LifetimeBytes
<1> QED BY ChargedPrefixBound, <1>1, PTL
=============================================================================
