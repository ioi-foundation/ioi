---- MODULE AsymptoteProof ----
EXTENDS Naturals, FiniteSets, TLAPS

CONSTANT Blocks, Slots, Epochs, TranscriptRoots, ChallengeRoots, EmptyChallengeRoot

ASSUME EmptyChallengeRoot \in ChallengeRoots

VARIABLES baseCerts, transcriptSurfaces, challengeSurfaces,
          canonicalCloses, canonicalAborts, sealedCerts

vars ==
  <<baseCerts, transcriptSurfaces, challengeSurfaces,
    canonicalCloses, canonicalAborts, sealedCerts>>

BaseCertDomain == Slots \X Blocks \X Epochs
TranscriptSurfaceDomain == Slots \X Blocks \X Epochs \X TranscriptRoots
ChallengeSurfaceDomain == Slots \X Blocks \X Epochs \X ChallengeRoots
CanonicalCloseDomain == Slots \X Blocks \X Epochs \X TranscriptRoots
CanonicalAbortDomain ==
  Slots \X Blocks \X Epochs \X TranscriptRoots \X (ChallengeRoots \ {EmptyChallengeRoot})
SealedCertDomain == Slots \X Blocks \X Epochs

BaseCertEvent(s, b, e) == <<s, b, e>>
TranscriptSurfaceEvent(s, b, e, t) == <<s, b, e, t>>
ChallengeSurfaceEvent(s, b, e, c) == <<s, b, e, c>>
CanonicalCloseEvent(s, b, e, t) == <<s, b, e, t>>
CanonicalAbortEvent(s, b, e, t, c) == <<s, b, e, t, c>>
SealEvent(s, b, e) == <<s, b, e>>

Init ==
  /\ baseCerts = {}
  /\ transcriptSurfaces = {}
  /\ challengeSurfaces = {}
  /\ canonicalCloses = {}
  /\ canonicalAborts = {}
  /\ sealedCerts = {}

HasBaseCert(s) ==
  \E b \in Blocks, e \in Epochs : BaseCertEvent(s, b, e) \in baseCerts

HasTranscriptSurface(s) ==
  \E b \in Blocks, e \in Epochs, t \in TranscriptRoots :
    TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces

HasChallengeSurface(s) ==
  \E b \in Blocks, e \in Epochs, c \in ChallengeRoots :
    ChallengeSurfaceEvent(s, b, e, c) \in challengeSurfaces

HasCanonicalOutcome(s) ==
  \/ \E b \in Blocks, e \in Epochs, t \in TranscriptRoots :
       CanonicalCloseEvent(s, b, e, t) \in canonicalCloses
  \/ \E b \in Blocks, e \in Epochs, t \in TranscriptRoots,
        c \in ChallengeRoots \ {EmptyChallengeRoot} :
       CanonicalAbortEvent(s, b, e, t, c) \in canonicalAborts

HasCanonicalAbort(s) ==
  \E b \in Blocks, e \in Epochs, t \in TranscriptRoots,
    c \in ChallengeRoots \ {EmptyChallengeRoot} :
    CanonicalAbortEvent(s, b, e, t, c) \in canonicalAborts

BaseCertifyStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs :
    /\ ~HasBaseCert(s)
    /\ baseCerts' = baseCerts \cup {BaseCertEvent(s, b, e)}
    /\ UNCHANGED <<transcriptSurfaces, challengeSurfaces,
                  canonicalCloses, canonicalAborts, sealedCerts>>

TranscriptSurfaceStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots :
    /\ BaseCertEvent(s, b, e) \in baseCerts
    /\ ~HasTranscriptSurface(s)
    /\ transcriptSurfaces' =
         transcriptSurfaces \cup {TranscriptSurfaceEvent(s, b, e, t)}
    /\ UNCHANGED <<baseCerts, challengeSurfaces, canonicalCloses,
                  canonicalAborts, sealedCerts>>

ChallengeSurfaceStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots,
     c \in ChallengeRoots :
    /\ TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
    /\ ~HasChallengeSurface(s)
    /\ challengeSurfaces' =
         challengeSurfaces \cup {ChallengeSurfaceEvent(s, b, e, c)}
    /\ UNCHANGED <<baseCerts, transcriptSurfaces, canonicalCloses,
                  canonicalAborts, sealedCerts>>

CanonicalCloseStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots :
    /\ TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
    /\ ChallengeSurfaceEvent(s, b, e, EmptyChallengeRoot) \in challengeSurfaces
    /\ ~HasCanonicalOutcome(s)
    /\ canonicalCloses' = canonicalCloses \cup {CanonicalCloseEvent(s, b, e, t)}
    /\ UNCHANGED <<baseCerts, transcriptSurfaces, challengeSurfaces,
                  canonicalAborts, sealedCerts>>

CanonicalAbortStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots,
     c \in ChallengeRoots \ {EmptyChallengeRoot} :
    /\ TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
    /\ ChallengeSurfaceEvent(s, b, e, c) \in challengeSurfaces
    /\ ~HasCanonicalOutcome(s)
    /\ canonicalAborts' =
         canonicalAborts \cup {CanonicalAbortEvent(s, b, e, t, c)}
    /\ UNCHANGED <<baseCerts, transcriptSurfaces, challengeSurfaces,
                  canonicalCloses, sealedCerts>>

SealStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots :
    /\ CanonicalCloseEvent(s, b, e, t) \in canonicalCloses
    /\ ~HasCanonicalAbort(s)
    /\ sealedCerts' = sealedCerts \cup {SealEvent(s, b, e)}
    /\ UNCHANGED <<baseCerts, transcriptSurfaces, challengeSurfaces,
                  canonicalCloses, canonicalAborts>>

Next ==
  \/ BaseCertifyStep
  \/ TranscriptSurfaceStep
  \/ ChallengeSurfaceStep
  \/ CanonicalCloseStep
  \/ CanonicalAbortStep
  \/ SealStep

TypeInvariant ==
  /\ baseCerts \subseteq BaseCertDomain
  /\ transcriptSurfaces \subseteq TranscriptSurfaceDomain
  /\ challengeSurfaces \subseteq ChallengeSurfaceDomain
  /\ canonicalCloses \subseteq CanonicalCloseDomain
  /\ canonicalAborts \subseteq CanonicalAbortDomain
  /\ sealedCerts \subseteq SealedCertDomain

NoDualBaseCerts ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ BaseCertEvent(s, b1, e1) \in baseCerts
    /\ BaseCertEvent(s, b2, e2) \in baseCerts
    => /\ b1 = b2
       /\ e1 = e2

NoDualTranscriptSurfaces ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs,
     t1 \in TranscriptRoots, t2 \in TranscriptRoots :
    /\ TranscriptSurfaceEvent(s, b1, e1, t1) \in transcriptSurfaces
    /\ TranscriptSurfaceEvent(s, b2, e2, t2) \in transcriptSurfaces
    => /\ b1 = b2
       /\ e1 = e2
       /\ t1 = t2

NoDualChallengeSurfaces ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs,
     c1 \in ChallengeRoots, c2 \in ChallengeRoots :
    /\ ChallengeSurfaceEvent(s, b1, e1, c1) \in challengeSurfaces
    /\ ChallengeSurfaceEvent(s, b2, e2, c2) \in challengeSurfaces
    => /\ b1 = b2
       /\ e1 = e2
       /\ c1 = c2

NoDualCanonicalCloses ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs,
     t1 \in TranscriptRoots, t2 \in TranscriptRoots :
    /\ CanonicalCloseEvent(s, b1, e1, t1) \in canonicalCloses
    /\ CanonicalCloseEvent(s, b2, e2, t2) \in canonicalCloses
    => /\ b1 = b2
       /\ e1 = e2
       /\ t1 = t2

NoDualCanonicalAborts ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs,
     t1 \in TranscriptRoots, t2 \in TranscriptRoots,
     c1 \in ChallengeRoots \ {EmptyChallengeRoot},
     c2 \in ChallengeRoots \ {EmptyChallengeRoot} :
    /\ CanonicalAbortEvent(s, b1, e1, t1, c1) \in canonicalAborts
    /\ CanonicalAbortEvent(s, b2, e2, t2, c2) \in canonicalAborts
    => /\ b1 = b2
       /\ e1 = e2
       /\ t1 = t2
       /\ c1 = c2

TranscriptAnchored ==
  \A s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots :
    TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
    => BaseCertEvent(s, b, e) \in baseCerts

ChallengeAnchored ==
  \A s \in Slots, b \in Blocks, e \in Epochs, c \in ChallengeRoots :
    ChallengeSurfaceEvent(s, b, e, c) \in challengeSurfaces
    => \E t \in TranscriptRoots :
         TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces

CanonicalCloseAnchored ==
  \A s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots :
    CanonicalCloseEvent(s, b, e, t) \in canonicalCloses
    => /\ TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
       /\ ChallengeSurfaceEvent(s, b, e, EmptyChallengeRoot) \in challengeSurfaces

CanonicalAbortAnchored ==
  \A s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots,
     c \in ChallengeRoots \ {EmptyChallengeRoot} :
    CanonicalAbortEvent(s, b, e, t, c) \in canonicalAborts
    => /\ TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
       /\ ChallengeSurfaceEvent(s, b, e, c) \in challengeSurfaces

SealedAnchored ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    SealEvent(s, b, e) \in sealedCerts
    => /\ \E t \in TranscriptRoots : CanonicalCloseEvent(s, b, e, t) \in canonicalCloses
       /\ ~HasCanonicalAbort(s)

CloseAbortExclusive ==
  \A s \in Slots, b1 \in Blocks, e1 \in Epochs, t1 \in TranscriptRoots,
     b2 \in Blocks, e2 \in Epochs, t2 \in TranscriptRoots,
     c \in ChallengeRoots \ {EmptyChallengeRoot} :
    /\ CanonicalCloseEvent(s, b1, e1, t1) \in canonicalCloses
    /\ CanonicalAbortEvent(s, b2, e2, t2, c) \in canonicalAborts
    => FALSE

Invariant ==
  /\ TypeInvariant
  /\ NoDualBaseCerts
  /\ NoDualTranscriptSurfaces
  /\ NoDualChallengeSurfaces
  /\ NoDualCanonicalCloses
  /\ NoDualCanonicalAborts
  /\ TranscriptAnchored
  /\ ChallengeAnchored
  /\ CanonicalCloseAnchored
  /\ CanonicalAbortAnchored
  /\ CloseAbortExclusive
  /\ SealedAnchored

BaseSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ BaseCertEvent(s, b1, e1) \in baseCerts
    /\ BaseCertEvent(s, b2, e2) \in baseCerts
    => /\ b1 = b2
       /\ e1 = e2

CanonicalCloseSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs,
     t1 \in TranscriptRoots, t2 \in TranscriptRoots :
    /\ CanonicalCloseEvent(s, b1, e1, t1) \in canonicalCloses
    /\ CanonicalCloseEvent(s, b2, e2, t2) \in canonicalCloses
    => /\ b1 = b2
       /\ e1 = e2
       /\ t1 = t2

SealedSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ SealEvent(s, b1, e1) \in sealedCerts
    /\ SealEvent(s, b2, e2) \in sealedCerts
    => /\ b1 = b2
       /\ e1 = e2

AbortDominatesSealed ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    HasCanonicalAbort(s) => SealEvent(s, b, e) \notin sealedCerts

Spec == Init /\ [][Next]_vars

THEOREM InvariantImpliesBaseSafety == Invariant => BaseSafety
  BY SMTT(50)
     DEF Invariant, BaseSafety, NoDualBaseCerts

THEOREM InvariantImpliesCanonicalCloseSafety == Invariant => CanonicalCloseSafety
  BY SMTT(60)
     DEF Invariant, CanonicalCloseSafety, NoDualCanonicalCloses

THEOREM InvariantImpliesCloseAbortExclusive == Invariant => CloseAbortExclusive
  BY SMTT(20)
     DEF Invariant, CloseAbortExclusive

THEOREM InvariantImpliesSealedSafety == Invariant => SealedSafety
  BY SMTT(60), InvariantImpliesCanonicalCloseSafety
     DEF Invariant, SealedSafety, SealedAnchored, CanonicalCloseSafety

THEOREM InvariantImpliesAbortDominatesSealed == Invariant => AbortDominatesSealed
  BY SMTT(60)
     DEF Invariant, AbortDominatesSealed, SealedAnchored

====
