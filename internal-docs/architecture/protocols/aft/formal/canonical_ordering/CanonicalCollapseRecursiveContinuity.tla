---- MODULE CanonicalCollapseRecursiveContinuity ----
EXTENDS Naturals, Sequences, TLC

CONSTANT MaxHeight

Slots == 1..MaxHeight
Genesis == 1
NonGenesisSlots == Slots \ {Genesis}
NullHash == 0

VARIABLES publishedCollapses, publishedProofs, publishedExtensionCertificates, admittedHeaders

vars ==
  <<publishedCollapses, publishedProofs, publishedExtensionCertificates, admittedHeaders>>

RECURSIVE AccumulatorHash(_), ProofHash(_), ProofChain(_)

PayloadHash(s) == <<"payload", s>>

AccumulatorHash(s) ==
  IF s = Genesis
    THEN <<"accum", s, NullHash, PayloadHash(s)>>
    ELSE <<"accum", s, AccumulatorHash(s - 1), PayloadHash(s)>>

Commitment(s) ==
  [height |-> s,
   continuityAccumulatorHash |-> AccumulatorHash(s),
   resultingStateRootHash |-> <<"state", s>>]

CommitmentHash(s) == <<"commitment-hash", Commitment(s)>>

PreviousCommitmentHash(s) ==
  IF s = Genesis THEN NullHash ELSE CommitmentHash(s - 1)

StatementHash(s) ==
  <<"statement-hash", Commitment(s), PreviousCommitmentHash(s), PayloadHash(s)>>

PreviousProofHash(s) ==
  IF s = Genesis THEN NullHash ELSE ProofHash(s - 1)

ProofBytes(s) ==
  <<"hash-pcd-v1", StatementHash(s), PreviousProofHash(s)>>

ProofStep(s) ==
  [commitment |-> Commitment(s),
   previousCommitmentHash |-> PreviousCommitmentHash(s),
   payloadHash |-> PayloadHash(s),
   previousProofHash |-> PreviousProofHash(s),
   proofBytes |-> ProofBytes(s)]

ProofHash(s) == <<"proof-hash", ProofStep(s)>>

ProofChain(s) ==
  IF s = Genesis
    THEN <<ProofStep(s)>>
    ELSE Append(ProofChain(s - 1), ProofStep(s))

ExtensionCertificate(s) ==
  [coveredHeight |-> s,
   predecessorCommitment |-> Commitment(s - 1),
   predecessorProofHash |-> ProofHash(s - 1)]

Last(seq) == seq[Len(seq)]

Init ==
  /\ publishedCollapses = {}
  /\ publishedProofs = {}
  /\ publishedExtensionCertificates = {}
  /\ admittedHeaders = {}

PublishCollapseStep ==
  \E s \in Slots :
    /\ s \notin publishedCollapses
    /\ publishedCollapses' = publishedCollapses \cup {s}
    /\ UNCHANGED <<publishedProofs, publishedExtensionCertificates, admittedHeaders>>

PublishRecursiveProofStep ==
  \E s \in Slots :
    /\ s \in publishedCollapses
    /\ s \notin publishedProofs
    /\ IF s = Genesis THEN TRUE ELSE s - 1 \in publishedProofs
    /\ publishedProofs' = publishedProofs \cup {s}
    /\ UNCHANGED <<publishedCollapses, publishedExtensionCertificates, admittedHeaders>>

PublishExtensionCertificateStep ==
  \E s \in NonGenesisSlots :
    /\ s \in publishedCollapses
    /\ s - 1 \in publishedProofs
    /\ s \notin publishedExtensionCertificates
    /\ publishedExtensionCertificates' = publishedExtensionCertificates \cup {s}
    /\ UNCHANGED <<publishedCollapses, publishedProofs, admittedHeaders>>

AdmitHeaderStep ==
  \E s \in Slots :
    /\ s \in publishedCollapses
    /\ s \notin admittedHeaders
    /\ IF s = Genesis THEN TRUE ELSE s \in publishedExtensionCertificates
    /\ admittedHeaders' = admittedHeaders \cup {s}
    /\ UNCHANGED <<publishedCollapses, publishedProofs, publishedExtensionCertificates>>

Next ==
  \/ PublishCollapseStep
  \/ PublishRecursiveProofStep
  \/ PublishExtensionCertificateStep
  \/ AdmitHeaderStep

TypeInvariant ==
  /\ publishedCollapses \subseteq Slots
  /\ publishedProofs \subseteq Slots
  /\ publishedExtensionCertificates \subseteq NonGenesisSlots
  /\ admittedHeaders \subseteq Slots

RecursiveProofSoundness ==
  \A s \in publishedProofs :
    /\ s \in publishedCollapses
    /\ IF s = Genesis THEN TRUE ELSE s - 1 \in publishedProofs
    /\ LET step == ProofStep(s) IN
         /\ step.commitment = Commitment(s)
         /\ step.previousCommitmentHash = PreviousCommitmentHash(s)
         /\ step.payloadHash = PayloadHash(s)
         /\ step.previousProofHash = PreviousProofHash(s)
         /\ step.proofBytes = ProofBytes(s)
         /\ step.commitment.continuityAccumulatorHash = AccumulatorHash(s)

RecursiveProofChainSoundness ==
  \A s \in publishedProofs :
    /\ Len(ProofChain(s)) = s
    /\ Last(ProofChain(s)) = ProofStep(s)
    /\ IF s = Genesis
         THEN TRUE
         ELSE /\ ProofChain(s)[Len(ProofChain(s)) - 1] = ProofStep(s - 1)

ExtensionCertificateSoundness ==
  \A s \in publishedExtensionCertificates :
    /\ s \in NonGenesisSlots
    /\ s - 1 \in publishedProofs
    /\ ExtensionCertificate(s).coveredHeight = s
    /\ ExtensionCertificate(s).predecessorCommitment = Commitment(s - 1)
    /\ ExtensionCertificate(s).predecessorProofHash = ProofHash(s - 1)

HeaderAdmissionSoundness ==
  \A s \in admittedHeaders :
    /\ s \in publishedCollapses
    /\ IF s = Genesis
         THEN TRUE
         ELSE /\ s \in publishedExtensionCertificates
              /\ s - 1 \in publishedProofs
              /\ ExtensionCertificate(s).predecessorCommitment = Commitment(s - 1)
              /\ ExtensionCertificate(s).predecessorProofHash = ProofHash(s - 1)

Invariant ==
  /\ TypeInvariant
  /\ RecursiveProofSoundness
  /\ RecursiveProofChainSoundness
  /\ ExtensionCertificateSoundness
  /\ HeaderAdmissionSoundness

Spec == Init /\ [][Next]_vars

====
