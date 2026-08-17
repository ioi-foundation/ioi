---- MODULE MembershipTransition ----
(***************************************************************************)
(* AFT-CB P2.3 — membership transitions, the no-silence action set, and    *)
(* typed lineage roots.                                                    *)
(*                                                                         *)
(* Event-driven, versioned configurations: a transition record is closed   *)
(* by the CURRENT configuration's unanimous transition-acks (old-ring      *)
(* unanimity) plus every successor member's acceptance (T5c′) — the only  *)
(* strong-ring transition action in this module.  There is NO calendar     *)
(* epoch anywhere: nothing advances by time.                               *)
(*                                                                         *)
(* Silence records EXIST in this model — the adversary mints attested      *)
(* non-response records freely — and can never justify a transition: the   *)
(* TransitionsJustified invariant states that every closed transition is   *)
(* fully signature-justified (acks + acceptances), which is the spec-level *)
(* no-silence-derived-action assertion the leg demands (spec §10.2).  The  *)
(* mutation drill adds a silence-justified closure action and watches this *)
(* invariant go red.                                                       *)
(*                                                                         *)
(* Re-genesis is a TYPED ROOT: every transition record carries exactly one *)
(* lineage id, roots mint fresh lineage ids, and a well-formed history is  *)
(* single-lineage BY TYPE — a root-crossing history is distinguishable by  *)
(* construction (spec §14.4).  Uniqueness (T5a) quantifies WITHIN one      *)
(* lineage, from a common parent configuration, under per-configuration    *)
(* MHA stated as an explicit theorem condition.                            *)
(*                                                                         *)
(* Bootstrap: the deployed A6 freshness anchor is an EXPLICIT CONSTANT     *)
(* (DeployedAnchor), and the freshness theorem in the proof module is      *)
(* conditional on it IN THE STATEMENT — never in prose.                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  AllMembers,      \* the member universe
  HonestMembers,   \* honest subset (per-config MHA is a theorem condition)
  Lineages,        \* lineage identifiers (roots mint them)
  GenesisLineage,  \* the anchored genesis lineage
  Versions,        \* transition version numbers (event-driven, no epochs)
  NoSucc,          \* journal sentinel
  Anchors,         \* the A6 anchor menu (explicit constants)
  DeployedAnchor,  \* the deployed freshness anchor, or NoAnchor
  NoAnchor

Configs == (SUBSET AllMembers) \ {{}}

ASSUME MembershipConstants ==
  /\ HonestMembers \subseteq AllMembers
  /\ GenesisLineage \in Lineages
  /\ NoAnchor \notin Anchors
  /\ DeployedAnchor \in Anchors \cup {NoAnchor}
\* NoSucc \notin Configs is additionally assumed in the PROOF module only:
\* TLC cannot membership-test a model value against this set of sets, and
\* TLC's own model-value semantics already guarantee the disequality.

VARIABLES
  tjournal,        \* [HonestMembers -> [Lineages -> [Versions -> Configs \cup {NoSucc}]]]
  tacks,           \* HONEST old-ring transition final-acks: <<m, l, v, succ>>
  taccepts,        \* HONEST new-ring seat acceptances: <<m, l, v, succ>>
  transitions,     \* closed records: <<l, v, parent, succ>>
  roots,           \* minted lineage roots: <<newLineage, priorLineage>>
  silenceRecords   \* attested non-response records: <<attester, subject>>

vars == <<tjournal, tacks, taccepts, transitions, roots, silenceRecords>>

(***************************************************************************)
(* The unconstrained adversary, modeled STRUCTURALLY: a corrupt member's   *)
(* signature over ANY transition content is always available (A1 excludes  *)
(* only forging honest signatures), so Byzantine acks and acceptances are  *)
(* not state — they are simply TRUE.  Only honest signatures are state,    *)
(* because only honest members refuse to sign twice (the journal).  This   *)
(* keeps the adversary maximal while keeping the state space enumerable.   *)
(***************************************************************************)
AckedBy(m, l, v, succ) ==
  IF m \in HonestMembers THEN <<m, l, v, succ>> \in tacks ELSE TRUE

AcceptedBy(m, l, v, succ) ==
  IF m \in HonestMembers THEN <<m, l, v, succ>> \in taccepts ELSE TRUE

TypeOK ==
  /\ tjournal \in [HonestMembers -> [Lineages -> [Versions -> Configs \cup {NoSucc}]]]
  /\ tacks \subseteq HonestMembers \X Lineages \X Versions \X Configs
  /\ taccepts \subseteq HonestMembers \X Lineages \X Versions \X Configs
  /\ transitions \subseteq Lineages \X Versions \X Configs \X Configs
  /\ roots \subseteq Lineages \X Lineages
  /\ silenceRecords \subseteq AllMembers \X AllMembers

Init ==
  /\ tjournal = [m \in HonestMembers |-> [l \in Lineages |-> [v \in Versions |-> NoSucc]]]
  /\ tacks = {}
  /\ taccepts = {}
  /\ transitions = {}
  /\ roots = {}
  /\ silenceRecords = {}

(* Old-ring transition final-ack, journal-guarded per (lineage, version):  *)
(* the A3 discipline at the transition layer — an honest member acks at    *)
(* most one successor per version of a lineage, ever.                      *)
HonestTransitionAck(m, l, v, succ) ==
  /\ m \in HonestMembers
  /\ l \in Lineages /\ v \in Versions /\ succ \in Configs
  /\ tjournal[m][l][v] = NoSucc
  /\ tjournal' = [tjournal EXCEPT ![m] =
       [tjournal[m] EXCEPT ![l] = [tjournal[m][l] EXCEPT ![v] = succ]]]
  /\ tacks' = tacks \cup {<<m, l, v, succ>>}
  /\ UNCHANGED <<taccepts, transitions, roots, silenceRecords>>

(* Honest new-ring acceptance of a seat in a successor configuration the   *)
(* member belongs to.  Acceptance is not the safety bottleneck (the old    *)
(* ring's unanimity is), so no journal binds it; corrupt members'          *)
(* acceptances are always available (AcceptedBy).                          *)
Accept(m, l, v, succ) ==
  /\ m \in HonestMembers
  /\ l \in Lineages /\ v \in Versions /\ succ \in Configs
  /\ m \in succ
  /\ taccepts' = taccepts \cup {<<m, l, v, succ>>}
  /\ UNCHANGED <<tjournal, tacks, transitions, roots, silenceRecords>>

(* THE ONLY strong-ring transition action: assurance-preserving handover — *)
(* old-ring unanimity (every parent member's ack, with corrupt signatures  *)
(* always available) AND new-ring acceptance (every successor member's).   *)
(* No other action in this module writes `transitions`; in particular no   *)
(* action consumes silenceRecords.                                         *)
CloseTransition(l, v, parent, succ) ==
  /\ l \in Lineages /\ v \in Versions
  /\ parent \in Configs /\ succ \in Configs
  /\ \A m \in parent : AckedBy(m, l, v, succ)
  /\ \A m \in succ : AcceptedBy(m, l, v, succ)
  /\ transitions' = transitions \cup {<<l, v, parent, succ>>}
  /\ UNCHANGED <<tjournal, tacks, taccepts, roots, silenceRecords>>

(* Anchored re-genesis: a typed lineage ROOT.  It mints a FRESH lineage id *)
(* — never the genesis lineage, never an id already rooted — and records   *)
(* the prior lineage it administratively succeeds.  Nothing about it is a  *)
(* transition: it writes `roots`, not `transitions`, and the lineage seam  *)
(* is visible in the type itself.                                          *)
MintRoot(newL, priorL) ==
  /\ newL \in Lineages /\ priorL \in Lineages
  /\ newL # GenesisLineage
  /\ newL # priorL
  /\ \A p \in Lineages : <<newL, p>> \notin roots
  /\ roots' = roots \cup {<<newL, priorL>>}
  /\ UNCHANGED <<tjournal, tacks, taccepts, transitions, silenceRecords>>

(* Attested non-response records: ANYONE may mint one about ANY member, in *)
(* any quantity — and the state machine gives them no power: no guard of   *)
(* any transition-writing action mentions this variable.                   *)
EmitSilenceRecord(attester, subject) ==
  /\ attester \in AllMembers /\ subject \in AllMembers
  /\ silenceRecords' = silenceRecords \cup {<<attester, subject>>}
  /\ UNCHANGED <<tjournal, tacks, taccepts, transitions, roots>>

Next ==
  \/ \E m \in AllMembers, l \in Lineages, v \in Versions, succ \in Configs :
       HonestTransitionAck(m, l, v, succ) \/ Accept(m, l, v, succ)
  \/ \E l \in Lineages, v \in Versions, parent \in Configs, succ \in Configs :
       CloseTransition(l, v, parent, succ)
  \/ \E newL \in Lineages, priorL \in Lineages : MintRoot(newL, priorL)
  \/ \E a \in AllMembers, s \in AllMembers : EmitSilenceRecord(a, s)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The spec-level no-silence assertion: every closed transition is FULLY   *)
(* justified by signatures — old-ring unanimity and new-ring acceptance —  *)
(* while silence records float freely in the state with no effect.  The    *)
(* silence-mutation drill adds a closure action justified by               *)
(* silenceRecords instead, and this invariant goes red.                    *)
(***************************************************************************)
TransitionsJustified ==
  \A l \in Lineages, v \in Versions, parent \in Configs, succ \in Configs :
    (<<l, v, parent, succ>> \in transitions) =>
      /\ \A m \in parent : AckedBy(m, l, v, succ)
      /\ \A m \in succ : AcceptedBy(m, l, v, succ)

(* T5a at the transition layer: within ONE lineage, from a common parent   *)
(* configuration containing at least one honest member, the closed         *)
(* successor at any version is unique.  Divergence convicts the FULL       *)
(* parent configuration (every member double-acked) — checked by TLC and   *)
(* proven in MembershipTransitionProof.                                    *)
LineageUniqueness ==
  \A l \in Lineages, v \in Versions, parent \in Configs,
     s1 \in Configs, s2 \in Configs :
    (/\ <<l, v, parent, s1>> \in transitions
     /\ <<l, v, parent, s2>> \in transitions
     /\ parent \cap HonestMembers # {}) => s1 = s2

(* Root-crossing distinguishability (spec §14.4): every record carries its *)
(* lineage id in the first component, so a verifier's well-formedness rule *)
(* — a single history holds records of ONE lineage — makes a root-crossing *)
(* history distinguishable by construction.  WellFormedHistory is the      *)
(* verifier's rule; CrossLineageUnclaimed states what the model does NOT   *)
(* claim: uniqueness never quantifies across lineages, and the drill that  *)
(* mutates WellFormedHistory to ignore lineage ids watches a cross-lineage *)
(* "uniqueness" invariant collapse immediately (two lineages may close     *)
(* different successors at the same version, legitimately).                *)
WellFormedHistory(H) ==
  \E l \in Lineages : \A r \in H : r[1] = l

CrossLineageUniquenessWouldBeFalse ==
  \A H \in SUBSET transitions :
    WellFormedHistory(H) =>
      \A r1 \in H, r2 \in H, v \in Versions :
        (r1[2] = v /\ r2[2] = v /\ r1[3] = r2[3]
         /\ r1[3] \cap HonestMembers # {}) => r1[4] = r2[4]

Inv ==
  /\ TypeOK
  /\ \A m \in HonestMembers, l \in Lineages, v \in Versions, succ \in Configs :
       (<<m, l, v, succ>> \in tacks) => tjournal[m][l][v] = succ
  /\ TransitionsJustified

====
