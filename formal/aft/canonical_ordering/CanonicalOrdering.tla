---- MODULE CanonicalOrdering ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANT Slots, Transactions

VARIABLES bulletin, closedCutoffs, availabilityCerts, bulletinCloses, candidateCerts, admittedCerts, omissionProofs, recoveredSets

vars ==
  <<bulletin, closedCutoffs, availabilityCerts, bulletinCloses, candidateCerts, admittedCerts, omissionProofs, recoveredSets>>

CertEvent(s, c) == <<s, c>>
OmissionEvent(s, c, tx) == <<s, c, tx>>

CanonicalSet(s) == bulletin[s]
RecoverableSet(s) == IF s \in bulletinCloses THEN CanonicalSet(s) ELSE {}

BulletinDomain == [Slots -> SUBSET Transactions]
CutoffDomain == SUBSET Slots
AvailabilityDomain == SUBSET Slots
BulletinCloseDomain == SUBSET Slots
CertDomain == Slots \X (SUBSET Transactions)
OmissionDomain == Slots \X (SUBSET Transactions) \X Transactions
RecoveredDomain == [Slots -> SUBSET Transactions]

Init ==
  /\ bulletin = [s \in Slots |-> {}]
  /\ closedCutoffs = {}
  /\ availabilityCerts = {}
  /\ bulletinCloses = {}
  /\ candidateCerts = {}
  /\ admittedCerts = {}
  /\ omissionProofs = {}
  /\ recoveredSets = [s \in Slots |-> {}]

PublishStep ==
  \E s \in Slots, tx \in Transactions :
    /\ s \notin closedCutoffs
    /\ tx \notin bulletin[s]
    /\ bulletin' = [bulletin EXCEPT ![s] = @ \cup {tx}]
    /\ UNCHANGED <<closedCutoffs, availabilityCerts, bulletinCloses, candidateCerts, admittedCerts, omissionProofs, recoveredSets>>

CloseCutoffStep ==
  \E s \in Slots :
    /\ s \notin closedCutoffs
    /\ closedCutoffs' = closedCutoffs \cup {s}
    /\ UNCHANGED <<bulletin, availabilityCerts, bulletinCloses, candidateCerts, admittedCerts, omissionProofs, recoveredSets>>

AvailabilityCertifyStep ==
  \E s \in Slots :
    /\ s \in closedCutoffs
    /\ s \notin availabilityCerts
    /\ availabilityCerts' = availabilityCerts \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, bulletinCloses, candidateCerts, admittedCerts, omissionProofs, recoveredSets>>

CanonicalBulletinCloseStep ==
  \E s \in Slots :
    /\ s \in availabilityCerts
    /\ s \notin bulletinCloses
    /\ bulletinCloses' = bulletinCloses \cup {s}
    /\ recoveredSets' = [recoveredSets EXCEPT ![s] = CanonicalSet(s)]
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts, candidateCerts, admittedCerts, omissionProofs>>

CandidateCertifyStep ==
  \E s \in Slots :
    \E c \in SUBSET bulletin[s] :
      /\ s \in bulletinCloses
      /\ CertEvent(s, c) \notin candidateCerts
      /\ candidateCerts' = candidateCerts \cup {CertEvent(s, c)}
      /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts, bulletinCloses, admittedCerts, omissionProofs, recoveredSets>>

ProveOmissionStep ==
  \E s \in Slots, c \in SUBSET Transactions, tx \in Transactions :
    /\ CertEvent(s, c) \in candidateCerts
    /\ tx \in CanonicalSet(s)
    /\ tx \notin c
    /\ OmissionEvent(s, c, tx) \notin omissionProofs
    /\ omissionProofs' = omissionProofs \cup {OmissionEvent(s, c, tx)}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts, bulletinCloses, candidateCerts, admittedCerts, recoveredSets>>

AdmitCertStep ==
  \E s \in Slots :
    \E c \in SUBSET Transactions :
      /\ CertEvent(s, c) \in candidateCerts
      /\ s \in bulletinCloses
      /\ c = CanonicalSet(s)
      /\ ~(\E tx \in Transactions : OmissionEvent(s, c, tx) \in omissionProofs)
      /\ CertEvent(s, c) \notin admittedCerts
      /\ admittedCerts' = admittedCerts \cup {CertEvent(s, c)}
      /\ recoveredSets' = [recoveredSets EXCEPT ![s] = c]
      /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts, bulletinCloses, candidateCerts, omissionProofs>>

Next ==
  \/ PublishStep
  \/ CloseCutoffStep
  \/ AvailabilityCertifyStep
  \/ CanonicalBulletinCloseStep
  \/ CandidateCertifyStep
  \/ ProveOmissionStep
  \/ AdmitCertStep

TypeInvariant ==
  /\ bulletin \in BulletinDomain
  /\ closedCutoffs \in CutoffDomain
  /\ availabilityCerts \in AvailabilityDomain
  /\ bulletinCloses \in BulletinCloseDomain
  /\ candidateCerts \subseteq CertDomain
  /\ admittedCerts \subseteq CertDomain
  /\ omissionProofs \subseteq OmissionDomain
  /\ recoveredSets \in RecoveredDomain

AvailabilityCertSoundness ==
  \A s \in Slots :
    s \in availabilityCerts => s \in closedCutoffs

CanonicalBulletinCloseSoundness ==
  \A s \in Slots :
    s \in bulletinCloses => /\ s \in availabilityCerts
                           /\ recoveredSets[s] = CanonicalSet(s)

AdmittedSoundness ==
  \A s \in Slots, c \in SUBSET Transactions :
    CertEvent(s, c) \in admittedCerts
    => /\ s \in bulletinCloses
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

AdmittedUniqueness ==
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

Invariant ==
  /\ TypeInvariant
  /\ AvailabilityCertSoundness
  /\ CanonicalBulletinCloseSoundness
  /\ AdmittedSoundness
  /\ OmissionSoundness
  /\ RecoveredSoundness
  /\ AdmittedUniqueness
  /\ Recoverability
  /\ OmissionDominates

Spec == Init /\ [][Next]_vars

====
