---- MODULE CanonicalOrderingProof ----
EXTENDS Naturals, FiniteSets, TLAPS

CONSTANT Slots, Transactions

VARIABLES bulletins, closedCutoffs, admittedCerts, omissionProofs, recoveredSets

vars == <<bulletins, closedCutoffs, admittedCerts, omissionProofs, recoveredSets>>

CertEvent(s, c) == <<s, c>>
OmissionEvent(s, c, tx) == <<s, c, tx>>

CanonicalSet(s) == bulletins[s]
RecoverableSet(s) == IF s \in closedCutoffs THEN CanonicalSet(s) ELSE {}

BulletinDomain == [Slots -> SUBSET Transactions]
CutoffDomain == SUBSET Slots
CertDomain == Slots \X (SUBSET Transactions)
OmissionDomain == Slots \X (SUBSET Transactions) \X Transactions
RecoveredDomain == [Slots -> SUBSET Transactions]

TypeInvariant ==
  /\ bulletins \in BulletinDomain
  /\ closedCutoffs \in CutoffDomain
  /\ admittedCerts \subseteq CertDomain
  /\ omissionProofs \subseteq OmissionDomain
  /\ recoveredSets \in RecoveredDomain

CertifiedSoundness ==
  \A s \in Slots, c \in SUBSET Transactions :
    CertEvent(s, c) \in admittedCerts
    => /\ s \in closedCutoffs
       /\ c = CanonicalSet(s)

OmissionSoundness ==
  \A s \in Slots, c \in SUBSET Transactions, tx \in Transactions :
    OmissionEvent(s, c, tx) \in omissionProofs
    => /\ s \in closedCutoffs
       /\ tx \in CanonicalSet(s)
       /\ tx \notin c

RecoveredSoundness ==
  \A s \in Slots :
    recoveredSets[s] = RecoverableSet(s)

Invariant ==
  /\ TypeInvariant
  /\ CertifiedSoundness
  /\ OmissionSoundness
  /\ RecoveredSoundness

CertifiedUniqueness ==
  \A s \in Slots, c1 \in SUBSET Transactions, c2 \in SUBSET Transactions :
    /\ CertEvent(s, c1) \in admittedCerts
    /\ CertEvent(s, c2) \in admittedCerts
    => c1 = c2

Recoverability ==
  \A s \in Slots, c \in SUBSET Transactions :
    CertEvent(s, c) \in admittedCerts
    => recoveredSets[s] = c

OmissionDominates ==
  \A s \in Slots, c \in SUBSET Transactions, tx \in Transactions :
    OmissionEvent(s, c, tx) \in omissionProofs
    => CertEvent(s, c) \notin admittedCerts

THEOREM InvariantImpliesCertifiedUniqueness ==
  Invariant => CertifiedUniqueness
  BY SMTT(60)
     DEF Invariant, CertifiedUniqueness, CertifiedSoundness

THEOREM InvariantImpliesRecoverability ==
  Invariant => Recoverability
  BY SMTT(60)
     DEF Invariant, Recoverability, CertifiedSoundness, RecoveredSoundness, RecoverableSet

THEOREM InvariantImpliesOmissionDominates ==
  Invariant => OmissionDominates
  BY SMTT(60)
     DEF Invariant, OmissionDominates, CertifiedSoundness, OmissionSoundness

====
