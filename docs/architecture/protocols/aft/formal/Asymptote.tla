---- MODULE Asymptote ----
EXTENDS Naturals, FiniteSets, TLC, TLAPS

CONSTANT Validators, Blocks, Slots, Epochs, ValidatorQuorum,
          TranscriptRoots, ChallengeRoots, EmptyChallengeRoot

ASSUME EmptyChallengeRoot \in ChallengeRoots
ASSUME ValidatorQuorumIntersection ==
  \A S, T \in SUBSET Validators :
    /\ Cardinality(S) >= ValidatorQuorum
    /\ Cardinality(T) >= ValidatorQuorum
    => S \cap T # {}

CollapsePending == 0
CollapseBase == 1
CollapseObservation == 2
CollapseAbort == 3
CollapseSealed == 4

CollapseStates ==
  {CollapsePending, CollapseBase, CollapseObservation, CollapseAbort, CollapseSealed}

VARIABLES validatorVotes, baseCerts, transcriptSurfaces, challengeSurfaces,
          canonicalCloses, canonicalAborts, sealedFinal, collapseState

vars ==
  <<validatorVotes, baseCerts, transcriptSurfaces, challengeSurfaces,
    canonicalCloses, canonicalAborts, sealedFinal, collapseState>>

ValidatorVoteEvent(v, s, b, e) == <<v, s, b, e>>
BaseCertEvent(s, b, e, q) == <<s, b, e, q>>
TranscriptSurfaceEvent(s, b, e, t) == <<s, b, e, t>>
ChallengeSurfaceEvent(s, b, e, c) == <<s, b, e, c>>
CanonicalCloseEvent(s, b, e, t) == <<s, b, e, t>>
CanonicalAbortEvent(s, b, e, t, c) == <<s, b, e, t, c>>
SealEvent(s, b, e) == <<s, b, e>>

ValidatorVoteDomain == Validators \X Slots \X Blocks \X Epochs
BaseCertDomain == Slots \X Blocks \X Epochs \X (SUBSET Validators)
TranscriptSurfaceDomain == Slots \X Blocks \X Epochs \X TranscriptRoots
ChallengeSurfaceDomain == Slots \X Blocks \X Epochs \X ChallengeRoots
CanonicalCloseDomain == Slots \X Blocks \X Epochs \X TranscriptRoots
CanonicalAbortDomain ==
  Slots \X Blocks \X Epochs \X TranscriptRoots \X (ChallengeRoots \ {EmptyChallengeRoot})
SealedCertDomain == Slots \X Blocks \X Epochs

Init ==
  /\ validatorVotes = {}
  /\ baseCerts = {}
  /\ transcriptSurfaces = {}
  /\ challengeSurfaces = {}
  /\ canonicalCloses = {}
  /\ canonicalAborts = {}
  /\ sealedFinal = {}
  /\ collapseState = [s \in Slots |-> CollapsePending]

HasValidatorVote(v, s) ==
  \E b \in Blocks, e \in Epochs : ValidatorVoteEvent(v, s, b, e) \in validatorVotes

HasBaseCert(s) ==
  \E b \in Blocks, e \in Epochs, q \in SUBSET Validators :
    BaseCertEvent(s, b, e, q) \in baseCerts

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

ValidatorVoteStep ==
  \E v \in Validators, s \in Slots, b \in Blocks, e \in Epochs :
    /\ ~HasValidatorVote(v, s)
    /\ validatorVotes' = validatorVotes \cup {ValidatorVoteEvent(v, s, b, e)}
    /\ UNCHANGED <<baseCerts, transcriptSurfaces, challengeSurfaces,
                  canonicalCloses, canonicalAborts, sealedFinal, collapseState>>

EligibleValidators(s, b, e) ==
  {v \in Validators : ValidatorVoteEvent(v, s, b, e) \in validatorVotes}

BaseFinalizeStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, q \in SUBSET Validators :
    /\ q = EligibleValidators(s, b, e)
    /\ Cardinality(q) >= ValidatorQuorum
    /\ baseCerts' = baseCerts \cup {BaseCertEvent(s, b, e, q)}
    /\ collapseState' = [collapseState EXCEPT ![s] = CollapseBase]
    /\ UNCHANGED <<validatorVotes, transcriptSurfaces, challengeSurfaces,
                  canonicalCloses, canonicalAborts, sealedFinal>>

TranscriptSurfaceStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, q \in SUBSET Validators,
     t \in TranscriptRoots :
    /\ BaseCertEvent(s, b, e, q) \in baseCerts
    /\ collapseState[s] \in {CollapseBase, CollapseObservation}
    /\ ~HasTranscriptSurface(s)
    /\ transcriptSurfaces' =
         transcriptSurfaces \cup {TranscriptSurfaceEvent(s, b, e, t)}
    /\ collapseState' = [collapseState EXCEPT ![s] = CollapseObservation]
    /\ UNCHANGED <<validatorVotes, baseCerts, challengeSurfaces,
                  canonicalCloses, canonicalAborts, sealedFinal>>

ChallengeSurfaceStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots,
     c \in ChallengeRoots :
    /\ TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
    /\ collapseState[s] = CollapseObservation
    /\ ~HasChallengeSurface(s)
    /\ challengeSurfaces' =
         challengeSurfaces \cup {ChallengeSurfaceEvent(s, b, e, c)}
    /\ collapseState' = [collapseState EXCEPT ![s] = CollapseObservation]
    /\ UNCHANGED <<validatorVotes, baseCerts, transcriptSurfaces,
                  canonicalCloses, canonicalAborts, sealedFinal>>

CanonicalCloseStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots :
    /\ TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
    /\ ChallengeSurfaceEvent(s, b, e, EmptyChallengeRoot) \in challengeSurfaces
    /\ collapseState[s] = CollapseObservation
    /\ ~HasCanonicalOutcome(s)
    /\ canonicalCloses' = canonicalCloses \cup {CanonicalCloseEvent(s, b, e, t)}
    /\ UNCHANGED <<validatorVotes, baseCerts, transcriptSurfaces,
                  challengeSurfaces, canonicalAborts, sealedFinal, collapseState>>

CanonicalAbortStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots,
     c \in ChallengeRoots \ {EmptyChallengeRoot} :
    /\ TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
    /\ ChallengeSurfaceEvent(s, b, e, c) \in challengeSurfaces
    /\ ~HasCanonicalOutcome(s)
    /\ canonicalAborts' =
         canonicalAborts \cup {CanonicalAbortEvent(s, b, e, t, c)}
    /\ collapseState' = [collapseState EXCEPT ![s] = CollapseAbort]
    /\ UNCHANGED <<validatorVotes, baseCerts, transcriptSurfaces,
                  challengeSurfaces, canonicalCloses, sealedFinal>>

SealStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots :
    /\ CanonicalCloseEvent(s, b, e, t) \in canonicalCloses
    /\ ~HasCanonicalAbort(s)
    /\ sealedFinal' = sealedFinal \cup {SealEvent(s, b, e)}
    /\ collapseState' = [collapseState EXCEPT ![s] = CollapseSealed]
    /\ UNCHANGED <<validatorVotes, baseCerts, transcriptSurfaces,
                  challengeSurfaces, canonicalCloses, canonicalAborts>>

StutterStep == UNCHANGED vars

Next ==
  \/ ValidatorVoteStep
  \/ BaseFinalizeStep
  \/ TranscriptSurfaceStep
  \/ ChallengeSurfaceStep
  \/ CanonicalCloseStep
  \/ CanonicalAbortStep
  \/ SealStep
  \/ StutterStep

TypeInvariant ==
  /\ validatorVotes \subseteq ValidatorVoteDomain
  /\ baseCerts \subseteq BaseCertDomain
  /\ transcriptSurfaces \subseteq TranscriptSurfaceDomain
  /\ challengeSurfaces \subseteq ChallengeSurfaceDomain
  /\ canonicalCloses \subseteq CanonicalCloseDomain
  /\ canonicalAborts \subseteq CanonicalAbortDomain
  /\ sealedFinal \subseteq SealedCertDomain
  /\ collapseState \in [Slots -> CollapseStates]

NoDualValidatorVotes ==
  \A v \in Validators, s \in Slots, b1 \in Blocks, b2 \in Blocks,
     e1 \in Epochs, e2 \in Epochs :
    /\ ValidatorVoteEvent(v, s, b1, e1) \in validatorVotes
    /\ ValidatorVoteEvent(v, s, b2, e2) \in validatorVotes
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

BaseCertSoundness ==
  \A s \in Slots, b \in Blocks, e \in Epochs, q \in SUBSET Validators :
    BaseCertEvent(s, b, e, q) \in baseCerts
    => /\ Cardinality(q) >= ValidatorQuorum
       /\ \A v \in q : ValidatorVoteEvent(v, s, b, e) \in validatorVotes

TranscriptAnchored ==
  \A s \in Slots, b \in Blocks, e \in Epochs, t \in TranscriptRoots :
    TranscriptSurfaceEvent(s, b, e, t) \in transcriptSurfaces
    => \E q \in SUBSET Validators : BaseCertEvent(s, b, e, q) \in baseCerts

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
    SealEvent(s, b, e) \in sealedFinal
    => /\ \E t \in TranscriptRoots : CanonicalCloseEvent(s, b, e, t) \in canonicalCloses
       /\ ~HasCanonicalAbort(s)

BaseSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs,
     q1 \in SUBSET Validators, q2 \in SUBSET Validators :
    /\ BaseCertEvent(s, b1, e1, q1) \in baseCerts
    /\ BaseCertEvent(s, b2, e2, q2) \in baseCerts
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

AbortDominatesClose ==
  \A s \in Slots :
    HasCanonicalAbort(s)
    => ~(\E b \in Blocks, e \in Epochs, t \in TranscriptRoots :
           CanonicalCloseEvent(s, b, e, t) \in canonicalCloses)

SealedSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ SealEvent(s, b1, e1) \in sealedFinal
    /\ SealEvent(s, b2, e2) \in sealedFinal
    => /\ b1 = b2
       /\ e1 = e2

AbortDominatesSealed ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    HasCanonicalAbort(s) => SealEvent(s, b, e) \notin sealedFinal

MonotoneCollapse ==
  /\ \A s \in Slots :
       collapseState[s] = CollapseSealed => \E b \in Blocks, e \in Epochs :
         SealEvent(s, b, e) \in sealedFinal
  /\ \A s \in Slots :
       collapseState[s] = CollapseAbort => HasCanonicalAbort(s)

Spec == Init /\ [][Next]_vars

====
