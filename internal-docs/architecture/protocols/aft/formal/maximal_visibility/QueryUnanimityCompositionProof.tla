---- MODULE QueryUnanimityCompositionProof ----
(***************************************************************************)
(* AFT QUV M14Q — lift accepted-value uniqueness into prefix-compatible    *)
(* histories and non-conflicting consequence candidates.                   *)
(*                                                                         *)
(* AcceptedUnique is supplied by the M13Q QueryUnanimityProof theorem.      *)
(* HistoryAdmission is the predecessor/next-slot runtime rule.             *)
(* MutationAuthorization is the executor-side QUV-before-effect rule.       *)
(* Physical duplicate suppression for the one stable slot/effect key is    *)
(* separately proved by T10/AtMostOnceExternalization.                      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLAPS

CONSTANTS Candidates, Accepted, Histories, Mutations

ASSUME QLiftAssumptions ==
  /\ Accepted \subseteq Nat \X Candidates
  /\ Histories \subseteq Seq(Candidates)
  /\ Mutations \subseteq Nat \X Candidates
  /\ \A slot \in Nat, x \in Candidates, y \in Candidates :
       (<<slot, x>> \in Accepted /\ <<slot, y>> \in Accepted) => x = y
  /\ \A h \in Histories :
       \A i \in 1..Len(h) : <<i, h[i]>> \in Accepted
  /\ \A slot \in Nat, c \in Candidates :
       <<slot, c>> \in Mutations => <<slot, c>> \in Accepted

PrefixCompatible ==
  \A h1 \in Histories, h2 \in Histories :
    \A i \in Nat :
      (i \in 1..Len(h1) /\ i \in 1..Len(h2)) => h1[i] = h2[i]

NoConflictingMutationCandidates ==
  \A slot \in Nat, x \in Candidates, y \in Candidates :
    (<<slot, x>> \in Mutations /\ <<slot, y>> \in Mutations) => x = y

THEOREM QHistoryPrefixCompatibility == PrefixCompatible
<1>1. SUFFICES ASSUME NEW h1 \in Histories, NEW h2 \in Histories,
                      NEW i \in Nat,
                      i \in 1..Len(h1), i \in 1..Len(h2)
      PROVE h1[i] = h2[i]
  BY DEF PrefixCompatible
<1>2. <<i, h1[i]>> \in Accepted /\ <<i, h2[i]>> \in Accepted
  BY <1>1, QLiftAssumptions
<1> QED BY <1>1, <1>2, QLiftAssumptions

THEOREM QConsequenceCandidateNonConflict == NoConflictingMutationCandidates
<1>1. SUFFICES ASSUME NEW slot \in Nat,
                      NEW x \in Candidates,
                      NEW y \in Candidates,
                      <<slot, x>> \in Mutations,
                      <<slot, y>> \in Mutations
      PROVE x = y
  BY DEF NoConflictingMutationCandidates
<1>2. <<slot, x>> \in Accepted /\ <<slot, y>> \in Accepted
  BY <1>1, QLiftAssumptions
<1> QED BY <1>1, <1>2, QLiftAssumptions

====
