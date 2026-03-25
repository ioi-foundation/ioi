---- MODULE NestedGuardianRecovery ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANT Witnesses, Blocks, Slots, SmallCommitteeSlot, SmallRecoveryThreshold,
         LargeRecoveryThreshold, SmallRecoveryCommittee, LargeRecoveryCommittee

RecoveryThreshold(s) ==
  IF s = SmallCommitteeSlot THEN SmallRecoveryThreshold ELSE LargeRecoveryThreshold

InitialRecoveryCommittee(s) ==
  IF s = SmallCommitteeSlot THEN SmallRecoveryCommittee ELSE LargeRecoveryCommittee

ASSUME Slots \subseteq Nat
ASSUME SmallCommitteeSlot \in Slots
ASSUME SmallRecoveryCommittee \subseteq Witnesses
ASSUME LargeRecoveryCommittee \subseteq Witnesses
ASSUME \A s \in Slots :
  /\ RecoveryThreshold(s) >= 2
  /\ RecoveryThreshold(s) <= Cardinality(InitialRecoveryCommittee(s))

VARIABLES witnessOnline, shareReceipts, shareConflicts, windowClosed, missingShareClaims,
          missingThresholdCertificates, recovered, recoveredSurfaces,
          recoveryConflicts, aborted

vars ==
  <<witnessOnline, shareReceipts, shareConflicts, windowClosed, missingShareClaims,
    missingThresholdCertificates, recovered, recoveredSurfaces,
    recoveryConflicts, aborted>>

ShareReceipt(w, s, b) == <<w, s, b>>
ShareConflict(w, s, pair) == <<w, s, pair>>
MissingShare(w, s) == <<w, s>>
MissingThresholdCertificate(s, supporters) == <<s, supporters>>
Recovery(s, b) == <<s, b>>
RecoveredSurface(s, b) == <<s, b>>
RecoveryConflict(s, pair) == <<s, pair>>

Committee(s) == InitialRecoveryCommittee(s)

BlockPairs == {pair \in SUBSET Blocks : Cardinality(pair) = 2}

ShareReceiptDomain ==
  {ShareReceipt(w, s, b) : w \in Witnesses, s \in Slots, b \in Blocks}
ShareConflictDomain ==
  {ShareConflict(w, s, pair) : w \in Witnesses, s \in Slots, pair \in BlockPairs}
MissingShareDomain ==
  {MissingShare(w, s) : w \in Witnesses, s \in Slots}
MissingThresholdCertificateDomain ==
  {MissingThresholdCertificate(s, supporters) :
      s \in Slots, supporters \in SUBSET Witnesses}
RecoveryDomain ==
  {Recovery(s, b) : s \in Slots, b \in Blocks}
RecoveredSurfaceDomain ==
  {RecoveredSurface(s, b) : s \in Slots, b \in Blocks}
RecoveryConflictDomain ==
  {RecoveryConflict(s, pair) : s \in Slots, pair \in BlockPairs}

HasPredecessor(s) == \E prev \in Slots : prev + 1 = s
Predecessor(s) == CHOOSE prev \in Slots : prev + 1 = s
SlotResolved(s) ==
  \/ \E b \in Blocks : RecoveredSurface(s, b) \in recoveredSurfaces
  \/ s \in aborted

HasMissingThresholdCertificate(s) ==
  \E supporters \in SUBSET Committee(s) :
    MissingThresholdCertificate(s, supporters) \in missingThresholdCertificates
HasRecoveryConflict(s) ==
  \E pair \in BlockPairs : RecoveryConflict(s, pair) \in recoveryConflicts
PredecessorWindowClosed(s) ==
  IF HasPredecessor(s) THEN windowClosed[Predecessor(s)] ELSE TRUE
PredecessorResolved(s) ==
  IF HasPredecessor(s)
    THEN \/ \E prevBlock \in Blocks :
               RecoveredSurface(Predecessor(s), prevBlock) \in recoveredSurfaces
            \/ Predecessor(s) \in aborted
    ELSE TRUE

WitnessConflicted(w, s) ==
  \E pair \in BlockPairs : ShareConflict(w, s, pair) \in shareConflicts

EligibleReceipters(s, b) ==
  {w \in Witnesses : ShareReceipt(w, s, b) \in shareReceipts}
  \ {w \in Witnesses : WitnessConflicted(w, s)}

MissingClaimants(s) ==
  {w \in Witnesses : MissingShare(w, s) \in missingShareClaims}

RecoverySupporters(s, b) ==
  {w \in Witnesses : ShareReceipt(w, s, b) \in shareReceipts}

MinSlot == CHOOSE s \in Slots : \A t \in Slots : s <= t

ResolvedInterval(start, end) ==
  /\ start \in Slots
  /\ end \in Slots
  /\ start <= end
  /\ \A s \in Slots :
       /\ start <= s
       /\ s <= end
       => SlotResolved(s)

IntervalsOverlapOrTouch(leftStart, leftEnd, rightStart, rightEnd) ==
  /\ leftStart \in Slots
  /\ leftEnd \in Slots
  /\ rightStart \in Slots
  /\ rightEnd \in Slots
  /\ leftStart <= leftEnd
  /\ rightStart <= rightEnd
  /\ leftStart <= rightStart
  /\ rightStart <= leftEnd + 1

IntervalUnionEnd(leftEnd, rightEnd) ==
  IF leftEnd >= rightEnd THEN leftEnd ELSE rightEnd

Init ==
  /\ witnessOnline = [w \in Witnesses |-> TRUE]
  /\ shareReceipts = {}
  /\ shareConflicts = {}
  /\ windowClosed = [s \in Slots |-> FALSE]
  /\ missingShareClaims = {}
  /\ missingThresholdCertificates = {}
  /\ recovered = {}
  /\ recoveredSurfaces = {}
  /\ recoveryConflicts = {}
  /\ aborted = {}

CanIssueShare(w, s, b) ==
  /\ w \in Committee(s)
  /\ s \in Slots
  /\ b \in Blocks
  /\ witnessOnline[w]
  /\ PredecessorWindowClosed(s)
  /\ ~windowClosed[s]
  /\ ShareReceipt(w, s, b) \notin shareReceipts

IssueShare(w, s, b) ==
  /\ CanIssueShare(w, s, b)
  /\ LET conflictingBlocks ==
         {existing \in Blocks :
            /\ existing # b
            /\ ShareReceipt(w, s, existing) \in shareReceipts}
     IN shareConflicts' =
          shareConflicts \cup
            {ShareConflict(w, s, {existing, b}) : existing \in conflictingBlocks}
  /\ shareReceipts' = shareReceipts \cup {ShareReceipt(w, s, b)}
  /\ UNCHANGED <<witnessOnline, windowClosed, missingShareClaims,
                 missingThresholdCertificates, recovered, recoveredSurfaces,
                 recoveryConflicts, aborted>>

CloseWindow(s) ==
  /\ s \in Slots
  /\ PredecessorWindowClosed(s)
  /\ ~windowClosed[s]
  /\ windowClosed' = [windowClosed EXCEPT ![s] = TRUE]
  /\ UNCHANGED <<witnessOnline, shareReceipts, shareConflicts, missingShareClaims,
                 missingThresholdCertificates, recovered, recoveredSurfaces,
                 recoveryConflicts, aborted>>

WitnessOutage(w) ==
  /\ w \in Witnesses
  /\ witnessOnline[w]
  /\ witnessOnline' = [witnessOnline EXCEPT ![w] = FALSE]
  /\ UNCHANGED <<shareReceipts, shareConflicts, windowClosed, missingShareClaims,
                 missingThresholdCertificates, recovered, recoveredSurfaces,
                 recoveryConflicts, aborted>>

WitnessRecovery(w) ==
  /\ w \in Witnesses
  /\ ~witnessOnline[w]
  /\ witnessOnline' = [witnessOnline EXCEPT ![w] = TRUE]
  /\ UNCHANGED <<shareReceipts, shareConflicts, windowClosed, missingShareClaims,
                 missingThresholdCertificates, recovered, recoveredSurfaces,
                 recoveryConflicts, aborted>>

CanIssueMissingShare(w, s) ==
  /\ w \in Committee(s)
  /\ s \in Slots
  /\ windowClosed[s]
  /\ \A b \in Blocks : ShareReceipt(w, s, b) \notin shareReceipts
  /\ MissingShare(w, s) \notin missingShareClaims

IssueMissingShare(w, s) ==
  /\ CanIssueMissingShare(w, s)
  /\ missingShareClaims' = missingShareClaims \cup {MissingShare(w, s)}
  /\ UNCHANGED <<witnessOnline, shareReceipts, shareConflicts, windowClosed,
                 missingThresholdCertificates, recovered, recoveredSurfaces,
                 recoveryConflicts, aborted>>

CanCertifyMissingThreshold(s, supporters) ==
  /\ s \in Slots
  /\ supporters \subseteq Committee(s)
  /\ supporters \subseteq MissingClaimants(s)
  /\ windowClosed[s]
  /\ Cardinality(supporters) > Cardinality(Committee(s)) - RecoveryThreshold(s)
  /\ MissingThresholdCertificate(s, supporters) \notin missingThresholdCertificates
  /\ ~(\E existing \in SUBSET Witnesses :
         MissingThresholdCertificate(s, existing) \in missingThresholdCertificates)

CertifyMissingThreshold(s, supporters) ==
  /\ CanCertifyMissingThreshold(s, supporters)
  /\ missingThresholdCertificates' =
       missingThresholdCertificates \cup {MissingThresholdCertificate(s, supporters)}
  /\ recoveredSurfaces' = recoveredSurfaces \ {RecoveredSurface(s, b) : b \in Blocks}
  /\ UNCHANGED <<witnessOnline, shareReceipts, shareConflicts, windowClosed,
                 missingShareClaims, recovered,
                 recoveryConflicts, aborted>>

CanRecover(s, b) ==
  /\ s \in Slots
  /\ b \in Blocks
  /\ PredecessorWindowClosed(s)
  /\ Cardinality(RecoverySupporters(s, b)) >= RecoveryThreshold(s)
  /\ s \notin aborted
  /\ \A other \in Blocks : Recovery(s, other) \notin recovered
  /\ Recovery(s, b) \notin recovered

RecoverSlot(s, b) ==
  /\ CanRecover(s, b)
  /\ recovered' = recovered \cup {Recovery(s, b)}
  /\ UNCHANGED <<witnessOnline, shareReceipts, shareConflicts, windowClosed,
                 missingShareClaims, missingThresholdCertificates, recoveredSurfaces,
                 recoveryConflicts, aborted>>

CanExtractRecoveredSurface(s, b) ==
  /\ Recovery(s, b) \in recovered
  /\ windowClosed[s]
  /\ s \notin aborted
  /\ ~HasMissingThresholdCertificate(s)
  /\ ~HasRecoveryConflict(s)
  /\ RecoveredSurface(s, b) \notin recoveredSurfaces
  /\ \A other \in Blocks :
       RecoveredSurface(s, other) \in recoveredSurfaces => other = b
  /\ PredecessorResolved(s)

ExtractRecoveredSurface(s, b) ==
  /\ CanExtractRecoveredSurface(s, b)
  /\ recoveredSurfaces' = recoveredSurfaces \cup {RecoveredSurface(s, b)}
  /\ UNCHANGED <<witnessOnline, shareReceipts, shareConflicts, windowClosed,
                 missingShareClaims, missingThresholdCertificates, recovered,
                 recoveryConflicts, aborted>>

CanCertifyRecoveryConflict(s, pair) ==
  /\ s \in Slots
  /\ pair \in BlockPairs
  /\ \A b \in pair : Cardinality(RecoverySupporters(s, b)) >= RecoveryThreshold(s)
  /\ RecoveryConflict(s, pair) \notin recoveryConflicts

CertifyRecoveryConflict(s, pair) ==
  /\ CanCertifyRecoveryConflict(s, pair)
  /\ recoveryConflicts' = recoveryConflicts \cup {RecoveryConflict(s, pair)}
  /\ recoveredSurfaces' = recoveredSurfaces \ {RecoveredSurface(s, b) : b \in Blocks}
  /\ UNCHANGED <<witnessOnline, shareReceipts, shareConflicts, windowClosed,
                 missingShareClaims, missingThresholdCertificates, recovered, aborted>>

CanDeclareMissingAbort(s) ==
  /\ s \in Slots
  /\ PredecessorResolved(s)
  /\ \E supporters \in SUBSET Committee(s) :
       MissingThresholdCertificate(s, supporters) \in missingThresholdCertificates
  /\ s \notin aborted

DeclareMissingAbort(s) ==
  /\ CanDeclareMissingAbort(s)
  /\ aborted' = aborted \cup {s}
  /\ recoveredSurfaces' = recoveredSurfaces \ {RecoveredSurface(s, b) : b \in Blocks}
  /\ UNCHANGED <<witnessOnline, shareReceipts, shareConflicts, windowClosed,
                 missingShareClaims, missingThresholdCertificates, recovered, recoveryConflicts>>

CanDeclareRecoveryConflictAbort(s) ==
  /\ s \in Slots
  /\ PredecessorResolved(s)
  /\ \E pair \in BlockPairs : RecoveryConflict(s, pair) \in recoveryConflicts
  /\ s \notin aborted

DeclareRecoveryConflictAbort(s) ==
  /\ CanDeclareRecoveryConflictAbort(s)
  /\ aborted' = aborted \cup {s}
  /\ recovered' = recovered \ {Recovery(s, b) : b \in Blocks}
  /\ recoveredSurfaces' = recoveredSurfaces \ {RecoveredSurface(s, b) : b \in Blocks}
  /\ UNCHANGED <<witnessOnline, shareReceipts, shareConflicts, windowClosed,
                 missingShareClaims, missingThresholdCertificates, recoveryConflicts>>

Next ==
  \/ \E w \in Witnesses, s \in Slots, b \in Blocks : IssueShare(w, s, b)
  \/ \E s \in Slots : CloseWindow(s)
  \/ \E w \in Witnesses : WitnessOutage(w)
  \/ \E w \in Witnesses : WitnessRecovery(w)
  \/ \E w \in Witnesses, s \in Slots : IssueMissingShare(w, s)
  \/ \E s \in Slots :
       \E supporters \in SUBSET Committee(s) :
         CertifyMissingThreshold(s, supporters)
  \/ \E s \in Slots, b \in Blocks : RecoverSlot(s, b)
  \/ \E s \in Slots, b \in Blocks : ExtractRecoveredSurface(s, b)
  \/ \E s \in Slots, pair \in BlockPairs : CertifyRecoveryConflict(s, pair)
  \/ \E s \in Slots : DeclareMissingAbort(s)
  \/ \E s \in Slots : DeclareRecoveryConflictAbort(s)

NoAvailabilityChurn ==
  witnessOnline' = witnessOnline

TouchesSlot(s) ==
  \/ windowClosed[s] # windowClosed'[s]
  \/ \E w \in Witnesses, b \in Blocks :
       ShareReceipt(w, s, b) \in (shareReceipts' \ shareReceipts)
  \/ \E w \in Witnesses, pair \in BlockPairs :
       ShareConflict(w, s, pair) \in (shareConflicts' \ shareConflicts)
  \/ \E w \in Witnesses :
       MissingShare(w, s) \in (missingShareClaims' \ missingShareClaims)
  \/ \E supporters \in SUBSET Witnesses :
       MissingThresholdCertificate(s, supporters)
         \in (missingThresholdCertificates' \ missingThresholdCertificates)
  \/ \E b \in Blocks :
       Recovery(s, b) \in (recovered' \ recovered)
  \/ \E b \in Blocks :
       RecoveredSurface(s, b) \in (recoveredSurfaces' \ recoveredSurfaces)
  \/ \E pair \in BlockPairs :
       RecoveryConflict(s, pair) \in (recoveryConflicts' \ recoveryConflicts)
  \/ s \in (aborted' \ aborted)

RecoveredPrefixSeriality ==
  \A s \in Slots :
    TouchesSlot(s)
      => \A prev \in Slots :
           prev < s => SlotResolved(prev)

BoundedRecoveredPrefixSlice ==
  /\ NoAvailabilityChurn
  /\ RecoveredPrefixSeriality

RecoveredOnlyPrefixSlice ==
  /\ BoundedRecoveredPrefixSlice
  /\ shareConflicts' = shareConflicts
  /\ missingShareClaims' = missingShareClaims
  /\ missingThresholdCertificates' = missingThresholdCertificates
  /\ recoveryConflicts' = recoveryConflicts
  /\ aborted' = aborted

Symmetry ==
  Permutations(Witnesses)

TypeInvariant ==
  /\ witnessOnline \in [Witnesses -> BOOLEAN]
  /\ shareReceipts \subseteq ShareReceiptDomain
  /\ shareConflicts \subseteq ShareConflictDomain
  /\ windowClosed \in [Slots -> BOOLEAN]
  /\ missingShareClaims \subseteq MissingShareDomain
  /\ missingThresholdCertificates \subseteq MissingThresholdCertificateDomain
  /\ recovered \subseteq RecoveryDomain
  /\ recoveredSurfaces \subseteq RecoveredSurfaceDomain
  /\ recoveryConflicts \subseteq RecoveryConflictDomain
  /\ aborted \subseteq Slots

ShareReceiptsAssigned ==
  \A w \in Witnesses, s \in Slots, b \in Blocks :
    ShareReceipt(w, s, b) \in shareReceipts
    => w \in Committee(s)

MissingSharesAssigned ==
  \A w \in Witnesses, s \in Slots :
    MissingShare(w, s) \in missingShareClaims
    => w \in Committee(s)

DualReceiptsMaterializeConflict ==
  \A w \in Witnesses, s \in Slots, b1 \in Blocks, b2 \in Blocks :
    /\ ShareReceipt(w, s, b1) \in shareReceipts
    /\ ShareReceipt(w, s, b2) \in shareReceipts
    /\ b1 # b2
    => ShareConflict(w, s, {b1, b2}) \in shareConflicts

ShareConflictsSound ==
  \A w \in Witnesses, s \in Slots, pair \in BlockPairs :
    ShareConflict(w, s, pair) \in shareConflicts
    => /\ w \in Committee(s)
       /\ \A b \in pair : ShareReceipt(w, s, b) \in shareReceipts

RecoveredSoundness ==
  \A s \in Slots, b \in Blocks :
    Recovery(s, b) \in recovered
    => Cardinality(RecoverySupporters(s, b)) >= RecoveryThreshold(s)

RecoveryConflictsSound ==
  \A s \in Slots, pair \in BlockPairs :
    RecoveryConflict(s, pair) \in recoveryConflicts
    => \A b \in pair : Cardinality(RecoverySupporters(s, b)) >= RecoveryThreshold(s)

MissingThresholdCertificatesSound ==
  \A s \in Slots, supporters \in SUBSET Witnesses :
    MissingThresholdCertificate(s, supporters) \in missingThresholdCertificates
    => /\ supporters \subseteq MissingClaimants(s)
       /\ supporters \subseteq Committee(s)
       /\ windowClosed[s]
       /\ Cardinality(supporters) > Cardinality(Committee(s)) - RecoveryThreshold(s)

AbortSoundness ==
  \A s \in Slots :
    s \in aborted
    => \/ \E supporters \in SUBSET Committee(s) :
            /\ MissingThresholdCertificate(s, supporters) \in missingThresholdCertificates
            /\ Cardinality(supporters) > Cardinality(Committee(s)) - RecoveryThreshold(s)
       \/ \E pair \in BlockPairs :
            RecoveryConflict(s, pair) \in recoveryConflicts

RecoveredUniqueness ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks :
    /\ Recovery(s, b1) \in recovered
    /\ Recovery(s, b2) \in recovered
    => b1 = b2

RecoveryAbortExclusive ==
  \A s \in Slots, b \in Blocks :
    /\ Recovery(s, b) \in recovered
    => s \notin aborted

RecoveredSurfaceSound ==
  \A s \in Slots, b \in Blocks :
    RecoveredSurface(s, b) \in recoveredSurfaces
    => /\ Recovery(s, b) \in recovered
       /\ windowClosed[s]
       /\ ~HasMissingThresholdCertificate(s)
       /\ ~HasRecoveryConflict(s)
       /\ s \notin aborted

RecoveredSurfaceUniqueness ==
  \A s \in Slots, b1 \in Blocks, b2 \in Blocks :
    /\ RecoveredSurface(s, b1) \in recoveredSurfaces
    /\ RecoveredSurface(s, b2) \in recoveredSurfaces
    => b1 = b2

RecoveredSurfacePrefix ==
  \A s \in Slots, b \in Blocks :
    /\ RecoveredSurface(s, b) \in recoveredSurfaces
    /\ HasPredecessor(s)
    => \/ \E prevBlock \in Blocks :
             RecoveredSurface(Predecessor(s), prevBlock) \in recoveredSurfaces
       \/ Predecessor(s) \in aborted

RecoveredSurfaceAbortExclusive ==
  \A s \in Slots, b \in Blocks :
    RecoveredSurface(s, b) \in recoveredSurfaces
    => s \notin aborted

AbortPrefix ==
  \A s \in Slots :
    /\ s \in aborted
    /\ HasPredecessor(s)
    => PredecessorResolved(s)

\* This executable archival abstraction intentionally has no mutable "latest
\* activation" index. Historical replay is sound only when the currently
\* resolved prefix can be rooted from the canonical bootstrap side and composed
\* by exact-overlap interval closure alone.
RecoveredHistoricalBootstrapClosure ==
  \A s \in Slots :
    SlotResolved(s) => ResolvedInterval(MinSlot, s)

RecoveredHistoricalIntervalComposition ==
  \A a, b, c, d \in Slots :
    /\ ResolvedInterval(a, b)
    /\ ResolvedInterval(c, d)
    /\ IntervalsOverlapOrTouch(a, b, c, d)
    => ResolvedInterval(a, IntervalUnionEnd(b, d))

RecoveredHistoricalIndexFreeReplay ==
  /\ RecoveredHistoricalBootstrapClosure
  /\ RecoveredHistoricalIntervalComposition

Invariant ==
  /\ TypeInvariant
  /\ ShareReceiptsAssigned
  /\ MissingSharesAssigned
  /\ DualReceiptsMaterializeConflict
  /\ ShareConflictsSound
  /\ RecoveredSoundness
  /\ RecoveryConflictsSound
  /\ MissingThresholdCertificatesSound
  /\ AbortSoundness
  /\ RecoveredUniqueness
  /\ RecoveryAbortExclusive
  /\ RecoveredSurfaceSound
  /\ RecoveredSurfaceUniqueness
  /\ RecoveredSurfacePrefix
  /\ RecoveredSurfaceAbortExclusive
  /\ AbortPrefix
  /\ RecoveredHistoricalIndexFreeReplay

Spec == Init /\ [][Next]_vars

====
