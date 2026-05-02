---- MODULE CanonicalOrderingRetrievability ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Slots, Transactions

VARIABLES bulletin,
          closedCutoffs,
          availabilityCerts,
          retrievabilityProfiles,
          shardManifests,
          custodyAssignments,
          custodyReceipts,
          custodyResponses,
          retrievabilityChallenges,
          bulletinCloses,
          extractedSurfaces,
          historicalRetrievabilitySurfaces,
          reconstructionCertificates,
          reconstructionAborts

vars ==
  <<bulletin, closedCutoffs, availabilityCerts, retrievabilityProfiles,
    shardManifests, custodyAssignments, custodyReceipts, custodyResponses,
    retrievabilityChallenges, bulletinCloses, extractedSurfaces,
    historicalRetrievabilitySurfaces, reconstructionCertificates,
    reconstructionAborts>>

Challenge(slot, kind) == [slot |-> slot, kind |-> kind]
ExtractEvent(slot, surface) == <<slot, surface>>

HasChallenge(slot) == \E ch \in retrievabilityChallenges : ch.slot = slot
HasExtraction(slot) == \E e \in extractedSurfaces : e[1] = slot
HasReconstructionCertificate(slot) == slot \in reconstructionCertificates
HasHistoricalRetrievability(slot) == slot \in historicalRetrievabilitySurfaces

BulletinDomain == [Slots -> SUBSET Transactions]
SlotSet == SUBSET Slots
ChallengeKinds == {
  "missing_profile",
  "missing_manifest",
  "contradictory_manifest",
  "missing_assignment",
  "contradictory_assignment",
  "missing_receipt",
  "contradictory_receipt",
  "missing_response",
  "invalid_response",
  "missing_entries",
  "invalid_surface"
}
ChallengeDomain == [slot : Slots, kind : ChallengeKinds]
ExtractedSurfaceDomain == Slots \X (SUBSET Transactions)

Init ==
  /\ bulletin = [s \in Slots |-> {}]
  /\ closedCutoffs = {}
  /\ availabilityCerts = {}
  /\ retrievabilityProfiles = {}
  /\ shardManifests = {}
  /\ custodyAssignments = {}
  /\ custodyReceipts = {}
  /\ custodyResponses = {}
  /\ retrievabilityChallenges = {}
  /\ bulletinCloses = {}
  /\ extractedSurfaces = {}
  /\ historicalRetrievabilitySurfaces = {}
  /\ reconstructionCertificates = {}
  /\ reconstructionAborts = {}

PublishStep ==
  \E s \in Slots, tx \in Transactions :
    /\ s \notin closedCutoffs
    /\ tx \notin bulletin[s]
    /\ bulletin' = [bulletin EXCEPT ![s] = @ \cup {tx}]
    /\ UNCHANGED <<closedCutoffs, availabilityCerts, retrievabilityProfiles,
                   shardManifests, custodyAssignments, custodyReceipts,
                   custodyResponses, retrievabilityChallenges, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

CloseCutoffStep ==
  \E s \in Slots :
    /\ s \notin closedCutoffs
    /\ closedCutoffs' = closedCutoffs \cup {s}
    /\ UNCHANGED <<bulletin, availabilityCerts, retrievabilityProfiles,
                   shardManifests, custodyAssignments, custodyReceipts,
                   custodyResponses, retrievabilityChallenges, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

AvailabilityCertifyStep ==
  \E s \in Slots :
    /\ s \in closedCutoffs
    /\ s \notin availabilityCerts
    /\ availabilityCerts' = availabilityCerts \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, retrievabilityProfiles,
                   shardManifests, custodyAssignments, custodyReceipts,
                   custodyResponses, retrievabilityChallenges, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

PublishProfileStep ==
  \E s \in Slots :
    /\ s \in availabilityCerts
    /\ s \notin retrievabilityProfiles
    /\ retrievabilityProfiles' = retrievabilityProfiles \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts, shardManifests,
                   custodyAssignments, custodyReceipts, custodyResponses,
                   retrievabilityChallenges, bulletinCloses, extractedSurfaces,
                   historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

PublishManifestStep ==
  \E s \in Slots :
    /\ s \in retrievabilityProfiles
    /\ s \notin shardManifests
    /\ shardManifests' = shardManifests \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, custodyAssignments, custodyReceipts,
                   custodyResponses, retrievabilityChallenges, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

PublishCustodyAssignmentStep ==
  \E s \in Slots :
    /\ s \in shardManifests
    /\ s \notin custodyAssignments
    /\ custodyAssignments' = custodyAssignments \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyReceipts,
                   custodyResponses, retrievabilityChallenges, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

PublishCustodyReceiptStep ==
  \E s \in Slots :
    /\ s \in shardManifests
    /\ s \notin custodyReceipts
    /\ custodyReceipts' = custodyReceipts \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyResponses, retrievabilityChallenges, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

PublishCustodyResponseStep ==
  \E s \in Slots :
    /\ s \in custodyAssignments
    /\ s \in custodyReceipts
    /\ s \notin custodyResponses
    /\ custodyResponses' = custodyResponses \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, retrievabilityChallenges, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

CanonicalBulletinCloseStep ==
  \E s \in Slots :
    /\ s \in availabilityCerts
    /\ s \in retrievabilityProfiles
    /\ s \in shardManifests
    /\ s \in custodyAssignments
    /\ s \in custodyReceipts
    /\ ~HasChallenge(s)
    /\ s \notin bulletinCloses
    /\ bulletinCloses' = bulletinCloses \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, retrievabilityChallenges,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeMissingProfileStep ==
  \E s \in Slots :
    /\ s \in availabilityCerts
    /\ s \notin retrievabilityProfiles
    /\ s \notin bulletinCloses
    /\ Challenge(s, "missing_profile") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "missing_profile")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeMissingManifestStep ==
  \E s \in Slots :
    /\ s \in retrievabilityProfiles
    /\ s \notin shardManifests
    /\ s \notin bulletinCloses
    /\ Challenge(s, "missing_manifest") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "missing_manifest")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeContradictoryManifestStep ==
  \E s \in Slots :
    /\ s \in shardManifests
    /\ s \notin bulletinCloses
    /\ Challenge(s, "contradictory_manifest") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "contradictory_manifest")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeMissingAssignmentStep ==
  \E s \in Slots :
    /\ s \in shardManifests
    /\ s \in custodyReceipts
    /\ s \notin custodyAssignments
    /\ s \notin bulletinCloses
    /\ Challenge(s, "missing_assignment") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "missing_assignment")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeContradictoryAssignmentStep ==
  \E s \in Slots :
    /\ s \in custodyAssignments
    /\ s \notin bulletinCloses
    /\ Challenge(s, "contradictory_assignment") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "contradictory_assignment")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeMissingReceiptStep ==
  \E s \in Slots :
    /\ s \in custodyAssignments
    /\ s \notin custodyReceipts
    /\ s \notin bulletinCloses
    /\ Challenge(s, "missing_receipt") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "missing_receipt")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeContradictoryReceiptStep ==
  \E s \in Slots :
    /\ s \in custodyAssignments
    /\ s \in custodyReceipts
    /\ s \notin bulletinCloses
    /\ Challenge(s, "contradictory_receipt") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "contradictory_receipt")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeMissingResponseStep ==
  \E s \in Slots :
    /\ s \in custodyAssignments
    /\ s \in custodyReceipts
    /\ s \notin custodyResponses
    /\ s \notin bulletinCloses
    /\ Challenge(s, "missing_response") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "missing_response")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeInvalidResponseStep ==
  \E s \in Slots :
    /\ s \in custodyResponses
    /\ s \notin bulletinCloses
    /\ Challenge(s, "invalid_response") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "invalid_response")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeMissingEntriesStep ==
  \E s \in Slots :
    /\ s \in custodyResponses
    /\ bulletin[s] = {}
    /\ s \notin bulletinCloses
    /\ Challenge(s, "missing_entries") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "missing_entries")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ChallengeInvalidSurfaceStep ==
  \E s \in Slots :
    /\ s \in custodyResponses
    /\ bulletin[s] # {}
    /\ s \notin bulletinCloses
    /\ Challenge(s, "invalid_surface") \notin retrievabilityChallenges
    /\ retrievabilityChallenges' =
         retrievabilityChallenges \cup {Challenge(s, "invalid_surface")}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, bulletinCloses,
                   extractedSurfaces, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

ReconstructionCertifyStep ==
  \E s \in Slots :
    /\ s \in bulletinCloses
    /\ s \in custodyAssignments
    /\ s \in custodyReceipts
    /\ s \in custodyResponses
    /\ ~HasChallenge(s)
    /\ ~HasReconstructionCertificate(s)
    /\ s \notin reconstructionAborts
    /\ reconstructionCertificates' = reconstructionCertificates \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, retrievabilityChallenges,
                   bulletinCloses, extractedSurfaces,
                   historicalRetrievabilitySurfaces, reconstructionAborts>>

ExtractStep ==
  \E s \in Slots :
    /\ s \in bulletinCloses
    /\ s \in custodyAssignments
    /\ s \in custodyReceipts
    /\ s \in custodyResponses
    /\ HasReconstructionCertificate(s)
    /\ ~HasChallenge(s)
    /\ ~HasExtraction(s)
    /\ s \notin reconstructionAborts
    /\ extractedSurfaces' =
         extractedSurfaces \cup {ExtractEvent(s, bulletin[s])}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, retrievabilityChallenges,
                   bulletinCloses, historicalRetrievabilitySurfaces,
                   reconstructionCertificates, reconstructionAborts>>

PromoteHistoricalRetrievabilityStep ==
  \E s \in Slots :
    /\ HasExtraction(s)
    /\ HasReconstructionCertificate(s)
    /\ ~HasHistoricalRetrievability(s)
    /\ s \notin reconstructionAborts
    /\ historicalRetrievabilitySurfaces' =
         historicalRetrievabilitySurfaces \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, retrievabilityChallenges,
                   bulletinCloses, extractedSurfaces,
                   reconstructionCertificates, reconstructionAborts>>

AbortStep ==
  \E s \in Slots :
    /\ HasChallenge(s)
    /\ s \notin bulletinCloses
    /\ s \notin reconstructionAborts
    /\ reconstructionAborts' = reconstructionAborts \cup {s}
    /\ UNCHANGED <<bulletin, closedCutoffs, availabilityCerts,
                   retrievabilityProfiles, shardManifests, custodyAssignments,
                   custodyReceipts, custodyResponses, retrievabilityChallenges,
                   bulletinCloses, extractedSurfaces,
                   historicalRetrievabilitySurfaces, reconstructionCertificates>>

Next ==
  \/ PublishStep
  \/ CloseCutoffStep
  \/ AvailabilityCertifyStep
  \/ PublishProfileStep
  \/ PublishManifestStep
  \/ PublishCustodyAssignmentStep
  \/ PublishCustodyReceiptStep
  \/ PublishCustodyResponseStep
  \/ CanonicalBulletinCloseStep
  \/ ChallengeMissingProfileStep
  \/ ChallengeMissingManifestStep
  \/ ChallengeContradictoryManifestStep
  \/ ChallengeMissingAssignmentStep
  \/ ChallengeContradictoryAssignmentStep
  \/ ChallengeMissingReceiptStep
  \/ ChallengeContradictoryReceiptStep
  \/ ChallengeMissingResponseStep
  \/ ChallengeInvalidResponseStep
  \/ ChallengeMissingEntriesStep
  \/ ChallengeInvalidSurfaceStep
  \/ ReconstructionCertifyStep
  \/ ExtractStep
  \/ PromoteHistoricalRetrievabilityStep
  \/ AbortStep

TypeInvariant ==
  /\ bulletin \in BulletinDomain
  /\ closedCutoffs \in SlotSet
  /\ availabilityCerts \in SlotSet
  /\ retrievabilityProfiles \in SlotSet
  /\ shardManifests \in SlotSet
  /\ custodyAssignments \in SlotSet
  /\ custodyReceipts \in SlotSet
  /\ custodyResponses \in SlotSet
  /\ retrievabilityChallenges \subseteq ChallengeDomain
  /\ bulletinCloses \in SlotSet
  /\ extractedSurfaces \subseteq ExtractedSurfaceDomain
  /\ historicalRetrievabilitySurfaces \in SlotSet
  /\ reconstructionCertificates \in SlotSet
  /\ reconstructionAborts \in SlotSet

AvailabilitySoundness ==
  \A s \in Slots : s \in availabilityCerts => s \in closedCutoffs

BulletinCloseRequiresRetrievabilityPlane ==
  \A s \in Slots :
    s \in bulletinCloses
      => /\ s \in availabilityCerts
         /\ s \in retrievabilityProfiles
         /\ s \in shardManifests
         /\ s \in custodyAssignments
         /\ s \in custodyReceipts
         /\ ~HasChallenge(s)

ReconstructionCertificateRequiresProtocolObjects ==
  \A s \in Slots :
    HasReconstructionCertificate(s)
      => /\ s \in bulletinCloses
         /\ s \in retrievabilityProfiles
         /\ s \in shardManifests
         /\ s \in custodyAssignments
         /\ s \in custodyReceipts
         /\ s \in custodyResponses
         /\ ~HasChallenge(s)
         /\ s \notin reconstructionAborts

ExtractionRequiresProtocolObjects ==
  \A e \in extractedSurfaces :
    LET s == e[1]
        surface == e[2]
    IN /\ s \in bulletinCloses
       /\ HasReconstructionCertificate(s)
       /\ s \in retrievabilityProfiles
       /\ s \in shardManifests
       /\ s \in custodyAssignments
       /\ s \in custodyReceipts
       /\ s \in custodyResponses
       /\ ~HasChallenge(s)
       /\ surface = bulletin[s]

HistoricalRetrievabilityRequiresProtocolObjects ==
  \A s \in historicalRetrievabilitySurfaces :
    /\ HasExtraction(s)
    /\ HasReconstructionCertificate(s)
    /\ s \in bulletinCloses
    /\ s \in retrievabilityProfiles
    /\ s \in shardManifests
    /\ s \in custodyAssignments
    /\ s \in custodyReceipts
    /\ s \in custodyResponses
    /\ ~HasChallenge(s)
    /\ s \notin reconstructionAborts

ChallengeDominatesPositiveLane ==
  \A s \in Slots :
    HasChallenge(s) => /\ s \notin bulletinCloses
                       /\ ~HasReconstructionCertificate(s)
                       /\ ~HasExtraction(s)
                       /\ ~HasHistoricalRetrievability(s)

AbortRequiresChallenge ==
  \A s \in Slots : s \in reconstructionAborts => HasChallenge(s)

ResolutionExclusive ==
  \A s \in Slots :
    /\ ~(HasExtraction(s) /\ s \in reconstructionAborts)
    /\ ~(HasReconstructionCertificate(s) /\ s \in reconstructionAborts)
    /\ ~(HasHistoricalRetrievability(s) /\ s \in reconstructionAborts)

Spec == Init /\ [][Next]_vars

=============================================================================
