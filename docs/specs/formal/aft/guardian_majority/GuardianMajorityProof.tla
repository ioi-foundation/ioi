---- MODULE GuardianMajorityProof ----
EXTENDS Naturals, FiniteSets, TLAPS

CONSTANT Validators, Blocks, Slots, Epochs, QuorumSize

ASSUME QuorumIntersection ==
  \A S, T \in SUBSET Validators :
    /\ Cardinality(S) >= QuorumSize
    /\ Cardinality(T) >= QuorumSize
    => S \cap T # {}

VARIABLES votes, certs

vars == <<votes, certs>>

VoteDomain == Validators \X Slots \X Blocks \X Epochs
CertDomain == Slots \X Blocks \X Epochs \X (SUBSET Validators)

Init ==
  /\ votes = {}
  /\ certs = {}

HasVote(v, s) ==
  \E b \in Blocks, e \in Epochs : <<v, s, b, e>> \in votes

VoteStep ==
  \E v \in Validators, s \in Slots, b \in Blocks, e \in Epochs :
    /\ ~HasVote(v, s)
    /\ votes' = votes \cup {<<v, s, b, e>>}
    /\ UNCHANGED certs

CertifyStep ==
  \E s \in Slots, b \in Blocks, e \in Epochs, Q \in SUBSET Validators :
    /\ Cardinality(Q) >= QuorumSize
    /\ \A v \in Q : <<v, s, b, e>> \in votes
    /\ certs' = certs \cup {<<s, b, e, Q>>}
    /\ UNCHANGED votes

Next == VoteStep \/ CertifyStep

TypeInvariant ==
  /\ votes \subseteq VoteDomain
  /\ certs \subseteq CertDomain

NoDualVotes ==
  \A v \in Validators, s \in Slots, b1 \in Blocks, b2 \in Blocks, e1 \in Epochs, e2 \in Epochs :
    /\ <<v, s, b1, e1>> \in votes
    /\ <<v, s, b2, e2>> \in votes
    => /\ b1 = b2
       /\ e1 = e2

CertSoundness ==
  \A s \in Slots, b \in Blocks, e \in Epochs, Q \in SUBSET Validators :
    <<s, b, e, Q>> \in certs
    => /\ Cardinality(Q) >= QuorumSize
       /\ \A v \in Q : <<v, s, b, e>> \in votes

Invariant == TypeInvariant /\ NoDualVotes /\ CertSoundness

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
  BY SMTT(30) DEF Init, TypeInvariant, VoteDomain, CertDomain

THEOREM InitImpliesNoDualVotes == Init => NoDualVotes
  BY DEF Init, NoDualVotes

THEOREM InitImpliesCertSoundness == Init => CertSoundness
  BY DEF Init, CertSoundness

THEOREM InitImpliesInvariant == Init => Invariant
  BY InitImpliesTypeInvariant, InitImpliesNoDualVotes,
     InitImpliesCertSoundness DEF Invariant

THEOREM VotePreservesTypeInvariant == TypeInvariant /\ VoteStep => TypeInvariant'
  BY SMTT(30) DEF TypeInvariant, VoteStep, HasVote, VoteDomain, CertDomain

THEOREM VotePreservesNoDualVotes == NoDualVotes /\ VoteStep => NoDualVotes'
  BY SMTT(30) DEF NoDualVotes, VoteStep, HasVote

THEOREM VotePreservesCertSoundness == CertSoundness /\ VoteStep => CertSoundness'
  BY DEF CertSoundness, VoteStep

THEOREM VotePreservesInvariant == Invariant /\ VoteStep => Invariant'
  BY VotePreservesTypeInvariant, VotePreservesNoDualVotes,
     VotePreservesCertSoundness DEF Invariant

THEOREM CertifyPreservesTypeInvariant == TypeInvariant /\ CertifyStep => TypeInvariant'
  BY SMTT(30) DEF TypeInvariant, CertifyStep, VoteDomain, CertDomain

THEOREM CertifyPreservesNoDualVotes == NoDualVotes /\ CertifyStep => NoDualVotes'
  BY DEF NoDualVotes, CertifyStep

THEOREM CertifyPreservesCertSoundness == CertSoundness /\ CertifyStep => CertSoundness'
  BY SMTT(30) DEF CertSoundness, CertifyStep

THEOREM CertifyPreservesInvariant == Invariant /\ CertifyStep => Invariant'
  BY CertifyPreservesTypeInvariant, CertifyPreservesNoDualVotes,
     CertifyPreservesCertSoundness DEF Invariant

THEOREM StepPreservesInvariant == Invariant /\ Next => Invariant'
  BY VotePreservesInvariant, CertifyPreservesInvariant DEF Next

THEOREM StutterPreservesTypeInvariant ==
  TypeInvariant /\ UNCHANGED vars => TypeInvariant'
  BY DEF TypeInvariant, vars

THEOREM StutterPreservesNoDualVotes ==
  NoDualVotes /\ UNCHANGED vars => NoDualVotes'
  BY DEF NoDualVotes, vars

THEOREM StutterPreservesCertSoundness ==
  CertSoundness /\ UNCHANGED vars => CertSoundness'
  BY DEF CertSoundness, vars

THEOREM StutterPreservesInvariant == Invariant /\ UNCHANGED vars => Invariant'
  BY StutterPreservesTypeInvariant, StutterPreservesNoDualVotes,
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
