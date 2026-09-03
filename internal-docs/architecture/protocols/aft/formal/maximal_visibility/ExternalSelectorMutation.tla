------------------------- MODULE ExternalSelectorMutation -------------------------
EXTENDS FiniteSets

CONSTANTS ClientBytes, CasReceipt

VARIABLE common, externalSupport

vars == <<common, externalSupport>>

(* Replayable client bytes are common proof material, not an authority. *)
Init ==
    /\ common = {ClientBytes}
    /\ externalSupport = {}

(* Mutation: a downstream CAS receipt is fed back into Verify. *)
UseCasReceiptToSelect ==
    /\ externalSupport = {}
    /\ common' = common
    /\ externalSupport' = {CasReceipt}

Next == UseCasReceiptToSelect

ParticipantOnlyVerifier == externalSupport = {}

Spec == Init /\ [][Next]_vars

=============================================================================
