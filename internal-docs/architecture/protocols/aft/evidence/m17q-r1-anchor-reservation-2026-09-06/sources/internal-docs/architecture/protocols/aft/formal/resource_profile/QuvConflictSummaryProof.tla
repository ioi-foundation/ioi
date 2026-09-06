-------------------- MODULE QuvConflictSummaryProof --------------------
EXTENDS Integers, TLAPS

\* Algebraic prerequisite for the first-two retained conflict representation.
\* This is not the complete runtime-refinement or resource/timing theorem.
\* Correct histories contain distinct candidate hashes in linearization order.
Unique(s, n) == \A i, j \in 1..n : s[i] = s[j] => i = j
Uniform(s, n, wanted) == \A i \in 1..n : s[i] = wanted
SummaryLength(n) == IF n < 2 THEN n ELSE 2

THEOREM SummarySize ==
  ASSUME NEW n \in Nat
  PROVE /\ SummaryLength(n) \in 0..2
        /\ (SummaryLength(n) = 0 <=> n = 0)
  BY SMT DEF SummaryLength

\* Owned acceptance of a nonempty family is equivalent to every disclosed
\* candidate equalling the wanted value. Two distinct first entries already
\* refute that predicate for every wanted value, regardless of later entries.
THEOREM OwnedSummaryEquivalence ==
  ASSUME NEW n \in Nat, NEW s, NEW wanted, Unique(s, n)
  PROVE Uniform(s, n, wanted) <=> Uniform(s, SummaryLength(n), wanted)
<1>1. CASE n < 2
  BY <1>1, SMT DEF SummaryLength
<1>2. CASE n >= 2
  <2>1. s[1] # s[2]
    BY <1>2, SMT DEF Unique
  <2>2. ~Uniform(s, n, wanted)
    BY <1>2, <2>1, SMT DEF Uniform
  <2>3. ~Uniform(s, 2, wanted)
    BY <1>2, <2>1, SMT DEF Uniform
  <2> QED BY <1>2, <2>2, <2>3, SMT DEF SummaryLength
<1> QED BY <1>1, <1>2, SMT

\* Unowned acceptance depends on the immutable first entry only. Keeping
\* the first two also preserves that entry; a one-entry projection suffices.
THEOREM NonemptyProjectionPreservesFirstIndex ==
  ASSUME NEW n \in Nat, n > 0
  PROVE 1 \in 1..SummaryLength(n)
  BY SMT DEF SummaryLength
=============================================================================
