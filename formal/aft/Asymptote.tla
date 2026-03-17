---- MODULE Asymptote ----
EXTENDS Naturals, FiniteSets, TLC, TLAPS

CONSTANT Validators, Blocks, Slots, Epochs, ValidatorQuorum, Round1Samples, Round2Samples

Rounds == {1, 2}

ASSUME Round1Samples \subseteq Validators
ASSUME Round2Samples \subseteq Validators

ObserversFor(s, r) ==
  IF r = 1 THEN Round1Samples
  ELSE IF r = 2 THEN Round2Samples
  ELSE {}

ASSUME ValidatorQuorumIntersection ==
  \A S, T \in SUBSET Validators :
    /\ Cardinality(S) >= ValidatorQuorum
    /\ Cardinality(T) >= ValidatorQuorum
    => S \cap T # {}
ASSUME DistinctObserverAssignments ==
  \A s \in Slots, r1 \in Rounds, r2 \in Rounds, v \in Validators :
    /\ v \in ObserversFor(s, r1)
    /\ v \in ObserversFor(s, r2)
    => r1 = r2

OkVerdict == 0
VetoVerdict == 1
Verdicts == {OkVerdict, VetoVerdict}

CollapsePending == 0
CollapseBase == 1
CollapseSealing == 2
CollapseAbort == 3
CollapseSealed == 4
CollapseEscalated == 5
CollapseInvalid == 6

CollapseStates ==
  {CollapsePending, CollapseBase, CollapseSealing, CollapseAbort, CollapseSealed,
   CollapseEscalated, CollapseInvalid}

VARIABLES validatorVotes, baseCerts, observerVerdicts, closeCerts, abortSlots,
          sealedFinal, collapseState

vars ==
  <<validatorVotes, baseCerts, observerVerdicts, closeCerts, abortSlots,
    sealedFinal, collapseState>>

ValidatorVoteEvent(v, s, b, e) == <<v, s, b, e>>
BaseCertEvent(s, b, e, q) == <<s, b, e, q>>
ObserverVerdictEvent(v, s, r, b, e, d) == <<v, s, r, b, e, d>>
CloseCertEvent(s, b, e) == <<s, b, e>>
SealEvent(s, b, e) == <<s, b, e>>

ValidatorVoteDomain == Validators \X Slots \X Blocks \X Epochs
BaseCertDomain == Slots \X Blocks \X Epochs \X (SUBSET Validators)
ObserverVerdictDomain == Validators \X Slots \X Rounds \X Blocks \X Epochs \X Verdicts
CloseCertDomain == Slots \X Blocks \X Epochs
AbortDomain == Slots
SealedCertDomain == Slots \X Blocks \X Epochs

Init ==
  /\ validatorVotes = {}
  /\ baseCerts = {}
  /\ observerVerdicts = {}
  /\ closeCerts = {}
  /\ abortSlots = {}
  /\ sealedFinal = {}
  /\ collapseState = [s \in Slots |-> CollapsePending]

HasValidatorVote(v, s) ==
  \E b \in Blocks, e \in Epochs : ValidatorVoteEvent(v, s, b, e) \in validatorVotes

HasObserverVerdict(v, s, r) ==
  \E b \in Blocks, e \in Epochs, d \in Verdicts :
    ObserverVerdictEvent(v, s, r, b, e, d) \in observerVerdicts

ValidatorVoteStep ==
  \E v \in Validators, s \in Slots, b \in Blocks, e \in Epochs :
    /\ ~HasValidatorVote(v, s)
    /\ validatorVotes' = validatorVotes \cup {ValidatorVoteEvent(v, s, b, e)}
    /\ UNCHANGED <<baseCerts, observerVerdicts, closeCerts, abortSlots,
                  sealedFinal, collapseState>>

EligibleValidators(s, b, e) ==
  {v \in Validators : ValidatorVoteEvent(v, s, b, e) \in validatorVotes}

BaseFinalizeStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, q \in SUBSET Validators :
    /\ q = EligibleValidators(s, b, e)
    /\ Cardinality(q) >= ValidatorQuorum
    /\ baseCerts' = baseCerts \cup {BaseCertEvent(s, b, e, q)}
    /\ collapseState' = [collapseState EXCEPT ![s] = CollapseBase]
    /\ UNCHANGED <<validatorVotes, observerVerdicts, closeCerts, abortSlots,
                  sealedFinal>>

ObserverVerdictStep ==
  \E v \in Validators, s \in Slots, r \in Rounds, b \in Blocks, e \in Epochs, d \in Verdicts :
    /\ v \in ObserversFor(s, r)
    /\ collapseState[s] \in {CollapseBase, CollapseSealing}
    /\ ~HasObserverVerdict(v, s, r)
    /\ \E q \in SUBSET Validators : BaseCertEvent(s, b, e, q) \in baseCerts
    /\ observerVerdicts' =
         observerVerdicts \cup {ObserverVerdictEvent(v, s, r, b, e, d)}
    /\ abortSlots' = IF d = VetoVerdict THEN abortSlots \cup {s} ELSE abortSlots
    /\ collapseState' =
         [collapseState EXCEPT ![s] =
            IF d = VetoVerdict THEN CollapseAbort ELSE CollapseSealing]
    /\ UNCHANGED <<validatorVotes, baseCerts, closeCerts, sealedFinal>>

CloseReady(s, b, e) ==
  /\ \E q \in SUBSET Validators : BaseCertEvent(s, b, e, q) \in baseCerts
  /\ \A r \in Rounds :
       \A v \in ObserversFor(s, r) :
         \E d \in Verdicts : ObserverVerdictEvent(v, s, r, b, e, d) \in observerVerdicts

CloseStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs :
    /\ CloseReady(s, b, e)
    /\ closeCerts' = closeCerts \cup {CloseCertEvent(s, b, e)}
    /\ collapseState' =
         [collapseState EXCEPT ![s] =
            IF s \in abortSlots THEN CollapseAbort ELSE CollapseSealing]
    /\ UNCHANGED <<validatorVotes, baseCerts, observerVerdicts, abortSlots,
                  sealedFinal>>

SealReady(s, b, e) ==
  /\ CloseCertEvent(s, b, e) \in closeCerts
  /\ s \notin abortSlots
  /\ \A r \in Rounds :
       \A v \in ObserversFor(s, r) :
         ObserverVerdictEvent(v, s, r, b, e, OkVerdict) \in observerVerdicts

SealStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs :
    /\ SealReady(s, b, e)
    /\ sealedFinal' = sealedFinal \cup {SealEvent(s, b, e)}
    /\ collapseState' = [collapseState EXCEPT ![s] = CollapseSealed]
    /\ UNCHANGED <<validatorVotes, baseCerts, observerVerdicts, closeCerts,
                  abortSlots>>

Next ==
  \/ ValidatorVoteStep
  \/ BaseFinalizeStep
  \/ ObserverVerdictStep
  \/ CloseStep
  \/ SealStep

TypeInvariant ==
  /\ validatorVotes \subseteq ValidatorVoteDomain
  /\ baseCerts \subseteq BaseCertDomain
  /\ observerVerdicts \subseteq ObserverVerdictDomain
  /\ closeCerts \subseteq CloseCertDomain
  /\ abortSlots \subseteq AbortDomain
  /\ sealedFinal \subseteq SealedCertDomain
  /\ collapseState \in [Slots -> CollapseStates]

NoDualValidatorVotes ==
  \A v \in Validators, s \in Slots, b1 \in Blocks, b2 \in Blocks,
     e1 \in Epochs, e2 \in Epochs :
    /\ ValidatorVoteEvent(v, s, b1, e1) \in validatorVotes
    /\ ValidatorVoteEvent(v, s, b2, e2) \in validatorVotes
    => /\ b1 = b2
       /\ e1 = e2

NoDualObserverVerdicts ==
  \A v \in Validators, s \in Slots, r \in Rounds, b1 \in Blocks, b2 \in Blocks,
     e1 \in Epochs, e2 \in Epochs, d1 \in Verdicts, d2 \in Verdicts :
    /\ ObserverVerdictEvent(v, s, r, b1, e1, d1) \in observerVerdicts
    /\ ObserverVerdictEvent(v, s, r, b2, e2, d2) \in observerVerdicts
    => /\ b1 = b2
       /\ e1 = e2
       /\ d1 = d2

BaseCertSoundness ==
  \A s \in Slots, b \in Blocks, e \in Epochs, q \in SUBSET Validators :
    BaseCertEvent(s, b, e, q) \in baseCerts
    => /\ Cardinality(q) >= ValidatorQuorum
       /\ \A v \in q : ValidatorVoteEvent(v, s, b, e) \in validatorVotes

CloseCertSoundness ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    CloseCertEvent(s, b, e) \in closeCerts
    => /\ \E q \in SUBSET Validators : BaseCertEvent(s, b, e, q) \in baseCerts
       /\ \A r \in Rounds :
            \A v \in ObserversFor(s, r) :
              \E d \in Verdicts : ObserverVerdictEvent(v, s, r, b, e, d) \in observerVerdicts

AbortSoundness ==
  \A s \in Slots :
    s \in abortSlots
    => \E v \in Validators, r \in Rounds, b \in Blocks, e \in Epochs :
         /\ v \in ObserversFor(s, r)
         /\ ObserverVerdictEvent(v, s, r, b, e, VetoVerdict) \in observerVerdicts

SealedAnchored ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    SealEvent(s, b, e) \in sealedFinal
    => /\ CloseCertEvent(s, b, e) \in closeCerts
       /\ s \notin abortSlots
       /\ \A r \in Rounds :
            \A v \in ObserversFor(s, r) :
              ObserverVerdictEvent(v, s, r, b, e, OkVerdict) \in observerVerdicts

BaseSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs,
     q1 \in SUBSET Validators, q2 \in SUBSET Validators :
    /\ BaseCertEvent(s, b1, e1, q1) \in baseCerts
    /\ BaseCertEvent(s, b2, e2, q2) \in baseCerts
    => /\ b1 = b2
       /\ e1 = e2

SealedSafety ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ SealEvent(s, b1, e1) \in sealedFinal
    /\ SealEvent(s, b2, e2) \in sealedFinal
    => /\ b1 = b2
       /\ e1 = e2

AbortDominatesSealed ==
  \A s \in Slots, b \in Blocks, e \in Epochs :
    s \in abortSlots => SealEvent(s, b, e) \notin sealedFinal

MonotoneCollapse ==
  /\ \A s \in Slots :
       collapseState[s] = CollapseSealed => \E b \in Blocks, e \in Epochs :
         SealEvent(s, b, e) \in sealedFinal
  /\ \A s \in Slots :
       collapseState[s] = CollapseAbort => s \in abortSlots

Spec == Init /\ [][Next]_vars

====
