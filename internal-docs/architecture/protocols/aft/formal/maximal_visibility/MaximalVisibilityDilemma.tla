------------------------ MODULE MaximalVisibilityDilemma ------------------------
EXTENDS FiniteSets, Naturals

CONSTANTS Members, Values

ASSUME /\ IsFiniteSet(Members)
       /\ Cardinality(Members) >= 2
       /\ IsFiniteSet(Values)
       /\ Cardinality(Values) >= 2

(*
An accepted proof is abstracted by the configured identities whose
unforgeable acts it needs.  Each value can have an arbitrary acceptance
family, so this is strictly more general than one q-of-n threshold.
*)
AcceptedFamilies == [Values -> SUBSET (SUBSET Members)]

VARIABLE accepted

vars == <<accepted>>

Init == accepted \in AcceptedFamilies

Next == UNCHANGED vars

(* Every possible sole-honest member can produce an accepted proof for every
   valid value while all other members remain silent. *)
SilentNm1EffectLiveness ==
    \A value \in Values :
      \A honest \in Members :
        \E support \in accepted[value] : support \subseteq {honest}

(* Against an unknown n-1 Byzantine set, conflicting accepted proofs must
   share an unforgeable dependency on whichever member is actually honest.
   Since every singleton honest set is admissible, their intersection must be
   the entire configured membership. *)
TransferableNonConflict ==
    \A left_value, right_value \in Values :
      left_value # right_value =>
        \A left_support \in accepted[left_value] :
          \A right_support \in accepted[right_value] :
            left_support \cap right_support = Members

Dilemma == ~(SilentNm1EffectLiveness /\ TransferableNonConflict)

Spec == Init /\ [][Next]_vars

=============================================================================
