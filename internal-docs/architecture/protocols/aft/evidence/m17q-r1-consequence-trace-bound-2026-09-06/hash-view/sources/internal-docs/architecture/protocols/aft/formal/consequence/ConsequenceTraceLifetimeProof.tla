----------------- MODULE ConsequenceTraceLifetimeProof -----------------
EXTENDS ConsequenceTraceLifetime, TLAPS
ASSUME Profile == Limit \in Nat /\ ReuseLookup = FALSE
Inv == TypeOK /\ Charge /\ Budget /\ ReadyCharged /\ TraceBound
\* Assumes durable nonrollback reservation and at most one trace edge for each
\* lookup. This proves a count, not byte allocation, service or full refinement.
THEOREM RootedTraceLifetime == Spec => []Inv
<1>1. Init => Inv
  BY Profile, SMT DEF Profile, Init, Inv, TypeOK, Charge, Budget, ReadyCharged, TraceBound, Base
<1>2. Inv /\ [Next]_vars => Inv'
  BY Profile, SMT DEF Profile, Inv, TypeOK, Charge, Budget, ReadyCharged, TraceBound,
    Next, Claim, Start, Outcome, Reserve, Lookup, Crash, Base, vars
<1> QED BY <1>1, <1>2, PTL DEF Spec
\* Fixed adapter representation charges. Assumes two <=512-byte tokens with
\* <=6 JSON bytes per input byte; three 32-byte hash arrays; one u64; <=1024
\* fixed syntax bytes; canonical base64 ML-DSA-44 key/signature lengths.
THEOREM PqEvidenceFormatCharge == 2 * 6 * 512 + 3 * 129 + 20 + 1024 + 1752 + 3228 <= 16384
  BY SMT
THEOREM PqRecordFormatCharge == 2 * 6 * 512 + 3 * 129 + 20 + 1024 + 4 * 16384 + 129 <= 81920
  BY SMT
=============================================================================
