---- MODULE CanonicalOrderingOmissionTrace ----
EXTENDS CanonicalOrdering

TargetSlot == 1
TargetCert == {"tx1"}
TargetTx == "tx2"

WitnessState ==
  /\ TargetSlot \in closedCutoffs
  /\ bulletin[TargetSlot] = {"tx1", "tx2"}
  /\ CertEvent(TargetSlot, TargetCert) \in candidateCerts
  /\ OmissionEvent(TargetSlot, TargetCert, TargetTx) \in omissionProofs
  /\ CertEvent(TargetSlot, TargetCert) \notin admittedCerts

NoOmissionDominanceWitness == ~WitnessState

====
