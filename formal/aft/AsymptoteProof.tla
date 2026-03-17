---- MODULE AsymptoteProof ----
EXTENDS Naturals, FiniteSets, TLAPS

CONSTANT Blocks, Slots, Epochs

VARIABLES baseCerts, closeCerts, abortSlots, sealedCerts

vars == <<baseCerts, closeCerts, abortSlots, sealedCerts>>

BaseCertDomain == Slots \X Blocks \X Epochs
CloseCertDomain == Slots \X Blocks \X Epochs
AbortDomain == Slots
SealedCertDomain == Slots \X Blocks \X Epochs

BaseCertEvent(s, b, e) == <<s, b, e>>
CloseCertEvent(s, b, e) == <<s, b, e>>
SealEvent(s, b, e) == <<s, b, e>>

Init ==
  /\ baseCerts = {}
  /\ closeCerts = {}
  /\ abortSlots = {}
  /\ sealedCerts = {}

HasBaseCert(s) ==
  \E b \in Blocks, e \in Epochs : BaseCertEvent(s, b, e) \in baseCerts

HasSealedCert(s) ==
  \E b \in Blocks, e \in Epochs : SealEvent(s, b, e) \in sealedCerts

BaseCertifyStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs :
    /\ ~HasBaseCert(s)
    /\ baseCerts' = baseCerts \cup {BaseCertEvent(s, b, e)}
    /\ UNCHANGED <<closeCerts, abortSlots, sealedCerts>>

CloseStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs :
    /\ BaseCertEvent(s, b, e) \in baseCerts
    /\ closeCerts' = closeCerts \cup {CloseCertEvent(s, b, e)}
    /\ UNCHANGED <<baseCerts, abortSlots, sealedCerts>>

AbortStep ==
  \E s \in Slots :
    /\ HasBaseCert(s)
    /\ ~HasSealedCert(s)
    /\ abortSlots' = abortSlots \cup {s}
    /\ UNCHANGED <<baseCerts, closeCerts, sealedCerts>>

SealStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs :
    /\ BaseCertEvent(s, b, e) \in baseCerts
    /\ CloseCertEvent(s, b, e) \in closeCerts
    /\ s \notin abortSlots
    /\ sealedCerts' = sealedCerts \cup {SealEvent(s, b, e)}
    /\ UNCHANGED <<baseCerts, closeCerts, abortSlots>>

Next ==
  \/ BaseCertifyStep
  \/ CloseStep
  \/ AbortStep
  \/ SealStep

TypeInvariant ==
  /\ baseCerts \subseteq BaseCertDomain
  /\ closeCerts \subseteq CloseCertDomain
  /\ abortSlots \subseteq AbortDomain
  /\ sealedCerts \subseteq SealedCertDomain

NoDualBaseCerts ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ BaseCertEvent(s, b1, e1) \in baseCerts
    /\ BaseCertEvent(s, b2, e2) \in baseCerts
    => /\ b1 = b2
       /\ e1 = e2

CloseAnchored ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    CloseCertEvent(s, b, e) \in closeCerts
    => BaseCertEvent(s, b, e) \in baseCerts

SealedAnchored ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    SealEvent(s, b, e) \in sealedCerts
    => /\ BaseCertEvent(s, b, e) \in baseCerts
       /\ CloseCertEvent(s, b, e) \in closeCerts
       /\ s \notin abortSlots

Invariant ==
  /\ TypeInvariant
  /\ NoDualBaseCerts
  /\ CloseAnchored
  /\ SealedAnchored

BaseSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ BaseCertEvent(s, b1, e1) \in baseCerts
    /\ BaseCertEvent(s, b2, e2) \in baseCerts
    => /\ b1 = b2
       /\ e1 = e2

SealedSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ SealEvent(s, b1, e1) \in sealedCerts
    /\ SealEvent(s, b2, e2) \in sealedCerts
    => /\ b1 = b2
       /\ e1 = e2

AbortDominatesSealed ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    s \in abortSlots => SealEvent(s, b, e) \notin sealedCerts

Spec == Init /\ [][Next]_vars

THEOREM InvariantImpliesBaseSafety == Invariant => BaseSafety
  BY SMTT(50)
     DEF Invariant, BaseSafety, NoDualBaseCerts

THEOREM InvariantImpliesSealedSafety == Invariant => SealedSafety
  BY SMTT(60), InvariantImpliesBaseSafety
     DEF Invariant, SealedSafety, SealedAnchored, BaseSafety

THEOREM InvariantImpliesAbortDominatesSealed == Invariant => AbortDominatesSealed
  BY SMTT(60)
     DEF Invariant, AbortDominatesSealed, SealedAnchored

====
