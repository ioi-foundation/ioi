--------------------------- MODULE GuaranteeMeet ---------------------------
EXTENDS Integers, TLC

\* Certificate-only T6/L-M kernel. Two independently verified constituent
\* labels are enough to model the indistinguishability boundary: a wrapper may
\* report arbitrary coordinates, but the verifier accepts only the exact meet
\* unless new evidence has passed a coordinate-specific transform verifier.

Strengths == 0..2
Coordinates == {"safety", "availability"}

VARIABLES phase,
          leftSafety, rightSafety, leftAvailability, rightAvailability,
          claimedSafety, claimedAvailability,
          transformCoordinate, transformVerified, accepted

vars == <<phase,
          leftSafety, rightSafety, leftAvailability, rightAvailability,
          claimedSafety, claimedAvailability,
          transformCoordinate, transformVerified, accepted>>

Meet(left, right) == IF left <= right THEN left ELSE right
MeetSafety == Meet(leftSafety, rightSafety)
MeetAvailability == Meet(leftAvailability, rightAvailability)

Init ==
    /\ phase = "choose"
    /\ leftSafety = 0
    /\ rightSafety = 0
    /\ leftAvailability = 0
    /\ rightAvailability = 0
    /\ claimedSafety = 0
    /\ claimedAvailability = 0
    /\ transformCoordinate = "safety"
    /\ transformVerified = FALSE
    /\ accepted = FALSE

Choose(ls, rs, la, ra, cs, ca, coordinate, verified) ==
    /\ phase = "choose"
    /\ <<ls, rs, la, ra, cs, ca>> \in
         Strengths \X Strengths \X Strengths \X Strengths \X Strengths \X Strengths
    /\ coordinate \in Coordinates
    /\ verified \in BOOLEAN
    /\ phase' = "verify"
    /\ leftSafety' = ls
    /\ rightSafety' = rs
    /\ leftAvailability' = la
    /\ rightAvailability' = ra
    /\ claimedSafety' = cs
    /\ claimedAvailability' = ca
    /\ transformCoordinate' = coordinate
    /\ transformVerified' = verified
    /\ accepted' = FALSE

ExactMeet ==
    /\ claimedSafety = MeetSafety
    /\ claimedAvailability = MeetAvailability

VerifiedCoordinateTransform ==
    /\ transformVerified
    /\ IF transformCoordinate = "safety"
          THEN claimedAvailability = MeetAvailability
          ELSE claimedSafety = MeetSafety

Verify ==
    /\ phase = "verify"
    /\ phase' = "done"
    /\ accepted' = (ExactMeet \/ VerifiedCoordinateTransform)
    /\ UNCHANGED <<leftSafety, rightSafety,
                    leftAvailability, rightAvailability,
                    claimedSafety, claimedAvailability,
                    transformCoordinate, transformVerified>>

Next ==
    \/ \E ls, rs, la, ra, cs, ca \in Strengths,
          coordinate \in Coordinates, verified \in BOOLEAN :
          Choose(ls, rs, la, ra, cs, ca, coordinate, verified)
    \/ Verify
    \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ phase \in {"choose", "verify", "done"}
    /\ <<leftSafety, rightSafety, leftAvailability, rightAvailability,
          claimedSafety, claimedAvailability>> \in
         Strengths \X Strengths \X Strengths \X Strengths \X Strengths \X Strengths
    /\ transformCoordinate \in Coordinates
    /\ transformVerified \in BOOLEAN
    /\ accepted \in BOOLEAN

NoCertificateOnlyLaundering ==
    (phase = "done" /\ accepted /\ ~transformVerified) => ExactMeet

TransformIsCoordinateLocal ==
    (phase = "done" /\ accepted /\ transformVerified) =>
      IF transformCoordinate = "safety"
        THEN claimedAvailability = MeetAvailability
        ELSE claimedSafety = MeetSafety

=============================================================================
