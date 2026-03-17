---- MODULE NestedGuardianProof ----
EXTENDS Naturals, FiniteSets, TLAPS

CONSTANT Validators, Witnesses, Blocks, Slots, Epochs, QuorumSize, MaxReassignmentDepth,
         InitialWitness

ASSUME InitialWitnessInWitnesses == InitialWitness \in Witnesses
ASSUME MaxReassignmentDepthIsNat == MaxReassignmentDepth \in Nat

ASSUME QuorumIntersection ==
  \A S, T \in SUBSET Validators :
    /\ Cardinality(S) >= QuorumSize
    /\ Cardinality(T) >= QuorumSize
    => S \cap T # {}

VARIABLES votes, witnessCerts, certs, assignedWitness, reassignmentDepth

vars == <<votes, witnessCerts, certs, assignedWitness, reassignmentDepth>>

VoteDomain == Validators \X Slots \X Blocks \X Epochs
WitnessCertDomain == Slots \X Blocks \X Epochs \X Witnesses
CertDomain == Slots \X Blocks \X Epochs \X (SUBSET Validators)

Init ==
  /\ votes = {}
  /\ witnessCerts = {}
  /\ certs = {}
  /\ assignedWitness = [s \in Slots |-> InitialWitness]
  /\ reassignmentDepth = [s \in Slots |-> 0]

HasVote(v, s) ==
  \E b \in Blocks, e \in Epochs : <<v, s, b, e>> \in votes

HasWitnessCert(s) ==
  \E b \in Blocks, e \in Epochs, w \in Witnesses : <<s, b, e, w>> \in witnessCerts

IssueWitnessStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs :
    /\ ~HasWitnessCert(s)
    /\ witnessCerts' = witnessCerts \cup {<<s, b, e, assignedWitness[s]>>}
    /\ UNCHANGED <<votes, certs, assignedWitness, reassignmentDepth>>

ReassignWitnessStep ==
  \E s \in Slots, w \in Witnesses :
    /\ w # assignedWitness[s]
    /\ reassignmentDepth[s] < MaxReassignmentDepth
    /\ assignedWitness' = [assignedWitness EXCEPT ![s] = w]
    /\ reassignmentDepth' = [reassignmentDepth EXCEPT ![s] = @ + 1]
    /\ UNCHANGED <<votes, witnessCerts, certs>>

VoteStep ==
  \E v \in Validators, s \in Slots, b \in Blocks, e \in Epochs :
    /\ ~HasVote(v, s)
    /\ <<s, b, e, assignedWitness[s]>> \in witnessCerts
    /\ votes' = votes \cup {<<v, s, b, e>>}
    /\ UNCHANGED <<witnessCerts, certs, assignedWitness, reassignmentDepth>>

CertifyStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, Q \in SUBSET Validators :
    /\ Cardinality(Q) >= QuorumSize
    /\ <<s, b, e, assignedWitness[s]>> \in witnessCerts
    /\ \A v \in Q : <<v, s, b, e>> \in votes
    /\ certs' = certs \cup {<<s, b, e, Q>>}
    /\ UNCHANGED <<votes, witnessCerts, assignedWitness, reassignmentDepth>>

Next == IssueWitnessStep \/ ReassignWitnessStep \/ VoteStep \/ CertifyStep

TypeInvariant ==
  /\ votes \subseteq VoteDomain
  /\ witnessCerts \subseteq WitnessCertDomain
  /\ certs \subseteq CertDomain
  /\ assignedWitness \in [Slots -> Witnesses]
  /\ reassignmentDepth \in [Slots -> 0..MaxReassignmentDepth]

WitnessAssignmentSoundness ==
  \A s \in Slots : reassignmentDepth[s] <= MaxReassignmentDepth

NoDualVotes ==
  \A v \in Validators, s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ <<v, s, b1, e1>> \in votes
    /\ <<v, s, b2, e2>> \in votes
    => /\ b1 = b2
       /\ e1 = e2

WitnessCertificatesStayAssigned ==
  \A s \in Slots, b \in Blocks, e \in Epochs, w \in Witnesses :
    <<s, b, e, w>> \in witnessCerts
    => assignedWitness[s] = w \/ reassignmentDepth[s] > 0

CertSoundness ==
  \A s \in Slots, b \in Blocks, e \in Epochs, Q \in SUBSET Validators :
    <<s, b, e, Q>> \in certs
    => /\ Cardinality(Q) >= QuorumSize
       /\ \A v \in Q : <<v, s, b, e>> \in votes

Invariant ==
  /\ TypeInvariant
  /\ WitnessAssignmentSoundness
  /\ NoDualVotes
  /\ WitnessCertificatesStayAssigned
  /\ CertSoundness

Safety ==
  \A s \in Slots,
     b1 \in Blocks,
     b2 \in Blocks,
     e1 \in Epochs,
     e2 \in Epochs,
     Q1 \in SUBSET Validators,
     Q2 \in SUBSET Validators :
    /\ <<s, b1, e1, Q1>> \in certs
    /\ <<s, b2, e2, Q2>> \in certs
    => /\ b1 = b2
       /\ e1 = e2

Spec == Init /\ [][Next]_vars

THEOREM InitImpliesTypeInvariant == Init => TypeInvariant
  BY SMTT(30), InitialWitnessInWitnesses, MaxReassignmentDepthIsNat DEF Init, TypeInvariant, VoteDomain,
                WitnessCertDomain, CertDomain

THEOREM InitImpliesWitnessAssignmentSoundness == Init => WitnessAssignmentSoundness
  BY SMTT(30), MaxReassignmentDepthIsNat DEF Init, WitnessAssignmentSoundness

THEOREM InitImpliesNoDualVotes == Init => NoDualVotes
  BY DEF Init, NoDualVotes

THEOREM InitImpliesWitnessCertificatesStayAssigned == Init => WitnessCertificatesStayAssigned
  BY DEF Init, WitnessCertificatesStayAssigned

THEOREM InitImpliesCertSoundness == Init => CertSoundness
  BY DEF Init, CertSoundness

THEOREM InitImpliesInvariant == Init => Invariant
  BY InitImpliesTypeInvariant, InitImpliesWitnessAssignmentSoundness,
     InitImpliesNoDualVotes, InitImpliesWitnessCertificatesStayAssigned,
     InitImpliesCertSoundness DEF Invariant

THEOREM IssueWitnessPreservesInvariant == Invariant /\ IssueWitnessStep => Invariant'
  BY SMTT(30) DEF Invariant, TypeInvariant, WitnessAssignmentSoundness, NoDualVotes,
                WitnessCertificatesStayAssigned, CertSoundness, IssueWitnessStep,
                HasWitnessCert, WitnessCertDomain

THEOREM ReassignWitnessPreservesInvariant == Invariant /\ ReassignWitnessStep => Invariant'
  BY SMTT(30), MaxReassignmentDepthIsNat DEF Invariant, TypeInvariant, WitnessAssignmentSoundness, NoDualVotes,
                WitnessCertificatesStayAssigned, CertSoundness, ReassignWitnessStep

THEOREM VotePreservesInvariant == Invariant /\ VoteStep => Invariant'
  BY SMTT(30) DEF Invariant, TypeInvariant, WitnessAssignmentSoundness, NoDualVotes,
                WitnessCertificatesStayAssigned, CertSoundness, VoteStep, HasVote,
                VoteDomain

THEOREM CertifyPreservesInvariant == Invariant /\ CertifyStep => Invariant'
  BY SMTT(30) DEF Invariant, TypeInvariant, WitnessAssignmentSoundness, NoDualVotes,
                WitnessCertificatesStayAssigned, CertSoundness, CertifyStep, CertDomain

THEOREM StepPreservesInvariant == Invariant /\ Next => Invariant'
  BY IssueWitnessPreservesInvariant, ReassignWitnessPreservesInvariant,
     VotePreservesInvariant, CertifyPreservesInvariant DEF Next

THEOREM StutterPreservesTypeInvariant ==
  TypeInvariant /\ UNCHANGED vars => TypeInvariant'
  BY DEF TypeInvariant, vars

THEOREM StutterPreservesWitnessAssignmentSoundness ==
  WitnessAssignmentSoundness /\ UNCHANGED vars => WitnessAssignmentSoundness'
  BY DEF WitnessAssignmentSoundness, vars

THEOREM StutterPreservesNoDualVotes ==
  NoDualVotes /\ UNCHANGED vars => NoDualVotes'
  BY DEF NoDualVotes, vars

THEOREM StutterPreservesWitnessCertificatesStayAssigned ==
  WitnessCertificatesStayAssigned /\ UNCHANGED vars => WitnessCertificatesStayAssigned'
  BY DEF WitnessCertificatesStayAssigned, vars

THEOREM StutterPreservesCertSoundness ==
  CertSoundness /\ UNCHANGED vars => CertSoundness'
  BY DEF CertSoundness, vars

THEOREM StutterPreservesInvariant == Invariant /\ UNCHANGED vars => Invariant'
  BY StutterPreservesTypeInvariant, StutterPreservesWitnessAssignmentSoundness,
     StutterPreservesNoDualVotes, StutterPreservesWitnessCertificatesStayAssigned,
     StutterPreservesCertSoundness DEF Invariant

THEOREM NextPreservesInvariant == Invariant /\ [Next]_vars => Invariant'
  BY StepPreservesInvariant, StutterPreservesInvariant DEF vars

THEOREM QuorumCertificatesIntersect ==
  \A s \in Slots,
     b1 \in Blocks,
     b2 \in Blocks,
     e1 \in Epochs,
     e2 \in Epochs,
     Q1 \in SUBSET Validators,
     Q2 \in SUBSET Validators :
    /\ Invariant
    /\ <<s, b1, e1, Q1>> \in certs
    /\ <<s, b2, e2, Q2>> \in certs
    => Q1 \cap Q2 # {}
  BY SMTT(60), QuorumIntersection DEF Invariant, CertSoundness

THEOREM InvariantImpliesSafety == Invariant => Safety
  BY SMTT(60), QuorumCertificatesIntersect DEF Invariant, Safety, NoDualVotes,
                CertSoundness

====
