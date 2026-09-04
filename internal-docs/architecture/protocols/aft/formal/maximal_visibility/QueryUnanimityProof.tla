---- MODULE QueryUnanimityProof ----
(***************************************************************************)
(* AFT QUV M13Q — arbitrary-set proof kernel for online authorization.     *)
(*                                                                         *)
(* Snapshots abstracts the complete, nonce/context-bound responses that    *)
(* Q-A2/Q-A3 require an honest operation to receive from EVERY correct     *)
(* member. SerializationDisclosure is the relational consequence of each  *)
(* correct member's atomic, grow-only write-before-reply state machine: for *)
(* every pair of operations, the later snapshot at a fixed correct member  *)
(* contains the earlier candidate. Byzantine replies are omitted here      *)
(* because they can only add valid candidates and therefore turn accept    *)
(* into reject; they cannot enable either acceptance predicate.             *)
(***************************************************************************)
EXTENDS FiniteSets, TLAPS

CONSTANTS
  Members,
  Correct,
  Candidates,
  ValidCandidates,
  Ops,
  CandidateOf,
  Snapshots,
  FirstWinner,
  Abort

ASSUME QAssumptions ==
  /\ Correct \subseteq Members
  /\ Correct # {}
  /\ ValidCandidates \subseteq Candidates
  /\ Abort \notin Candidates
  /\ CandidateOf \in [Ops -> ValidCandidates]
  /\ Snapshots \in [Ops -> [Correct -> SUBSET ValidCandidates]]
  /\ FirstWinner \in [Correct -> ValidCandidates]
  /\ \A o \in Ops, c \in Correct : CandidateOf[o] \in Snapshots[o][c]
  /\ \A o1 \in Ops, o2 \in Ops, c \in Correct :
       \/ CandidateOf[o1] \in Snapshots[o2][c]
       \/ CandidateOf[o2] \in Snapshots[o1][c]

CorrectSeen(o) == UNION {Snapshots[o][c] : c \in Correct}

OwnedAccept(o) == CorrectSeen(o) = {CandidateOf[o]}

UnownedAccept(o) ==
  \A c \in Correct : FirstWinner[c] = CandidateOf[o]

OwnedOutcome(o) == IF OwnedAccept(o) THEN CandidateOf[o] ELSE Abort

UnownedOutcome(o) == IF UnownedAccept(o) THEN CandidateOf[o] ELSE Abort

THEOREM QOwnedNonConflict ==
  \A o1 \in Ops, o2 \in Ops :
    (OwnedAccept(o1) /\ OwnedAccept(o2)) =>
      CandidateOf[o1] = CandidateOf[o2]
<1>1. SUFFICES ASSUME NEW o1 \in Ops, NEW o2 \in Ops,
                      OwnedAccept(o1), OwnedAccept(o2)
      PROVE CandidateOf[o1] = CandidateOf[o2]
  OBVIOUS
<1>2. PICK c \in Correct : TRUE
  BY QAssumptions
<1>3. \/ CandidateOf[o1] \in Snapshots[o2][c]
       \/ CandidateOf[o2] \in Snapshots[o1][c]
  BY <1>1, <1>2, QAssumptions
<1>4. CASE CandidateOf[o1] \in Snapshots[o2][c]
  <2>1. CandidateOf[o1] \in CorrectSeen(o2)
    BY <1>1, <1>2, <1>4 DEF CorrectSeen
  <2> QED
    BY <1>1, <2>1 DEF OwnedAccept
<1>5. CASE CandidateOf[o2] \in Snapshots[o1][c]
  <2>1. CandidateOf[o2] \in CorrectSeen(o1)
    BY <1>1, <1>2, <1>5 DEF CorrectSeen
  <2> QED
    BY <1>1, <2>1 DEF OwnedAccept
<1> QED BY <1>3, <1>4, <1>5

THEOREM QUnownedNonConflict ==
  \A o1 \in Ops, o2 \in Ops :
    (UnownedAccept(o1) /\ UnownedAccept(o2)) =>
      CandidateOf[o1] = CandidateOf[o2]
<1>1. SUFFICES ASSUME NEW o1 \in Ops, NEW o2 \in Ops,
                      UnownedAccept(o1), UnownedAccept(o2)
      PROVE CandidateOf[o1] = CandidateOf[o2]
  OBVIOUS
<1>2. PICK c \in Correct : TRUE
  BY QAssumptions
<1>3. FirstWinner[c] = CandidateOf[o1]
  BY <1>1, <1>2 DEF UnownedAccept
<1>4. FirstWinner[c] = CandidateOf[o2]
  BY <1>1, <1>2 DEF UnownedAccept
<1> QED BY <1>3, <1>4

THEOREM QOwnedExternalValidity ==
  \A o \in Ops : OwnedAccept(o) => CandidateOf[o] \in ValidCandidates
  BY QAssumptions

THEOREM QUnownedExternalValidity ==
  \A o \in Ops : UnownedAccept(o) => CandidateOf[o] \in ValidCandidates
  BY QAssumptions

THEOREM QOwnedOutcomeTyped ==
  \A o \in Ops : OwnedOutcome(o) \in ValidCandidates \cup {Abort}
  BY QAssumptions DEF OwnedOutcome

THEOREM QUnownedOutcomeTyped ==
  \A o \in Ops : UnownedOutcome(o) \in ValidCandidates \cup {Abort}
  BY QAssumptions DEF UnownedOutcome

THEOREM QOwnedSingleCandidateProgress ==
  \A s \in ValidCandidates :
    ValidCandidates = {s} => \A o \in Ops : OwnedAccept(o)
<1>1. SUFFICES ASSUME NEW s \in ValidCandidates, ValidCandidates = {s},
                      NEW o \in Ops
      PROVE OwnedAccept(o)
  OBVIOUS
<1>2. CandidateOf[o] = s
  BY <1>1, QAssumptions
<1>3. \A c \in Correct : Snapshots[o][c] = {s}
  <2>1. SUFFICES ASSUME NEW c \in Correct PROVE Snapshots[o][c] = {s}
    OBVIOUS
  <2>2. Snapshots[o][c] \subseteq {s}
    BY <1>1, <2>1, QAssumptions
  <2>3. s \in Snapshots[o][c]
    BY <1>1, <1>2, <2>1, QAssumptions
  <2> QED BY <2>2, <2>3
<1>4. CorrectSeen(o) = {s}
  BY <1>1, <1>3, QAssumptions DEF CorrectSeen
<1> QED BY <1>2, <1>4 DEF OwnedAccept

THEOREM QUnownedSingleCandidateProgress ==
  \A s \in ValidCandidates :
    ValidCandidates = {s} => \A o \in Ops : UnownedAccept(o)
  BY QAssumptions DEF UnownedAccept

THEOREM QOwnedOutcomeNonConflict ==
  \A o1 \in Ops, o2 \in Ops :
    (OwnedOutcome(o1) # Abort /\ OwnedOutcome(o2) # Abort) =>
      OwnedOutcome(o1) = OwnedOutcome(o2)
  BY QOwnedNonConflict DEF OwnedOutcome

THEOREM QUnownedOutcomeNonConflict ==
  \A o1 \in Ops, o2 \in Ops :
    (UnownedOutcome(o1) # Abort /\ UnownedOutcome(o2) # Abort) =>
      UnownedOutcome(o1) = UnownedOutcome(o2)
  BY QUnownedNonConflict DEF UnownedOutcome

====
