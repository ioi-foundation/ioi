--------------------- MODULE QuvEndToEndRefinement ---------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

(***************************************************************************)
(* QUV-M17Q-005 transition-level composition witness.                      *)
(*                                                                         *)
(* Finite explicit-state model of the QUV end-to-end path over an          *)
(* abstraction of the production state machine: per-member durable         *)
(* conflict stores keyed WITHOUT the predecessor, two-phase authenticated   *)
(* record/anchor durability with crash recovery, expected-predecessor       *)
(* admission with typed refusal, timed executor operations with a rooted    *)
(* reply cutoff, own-head advancement, process-local continuations with     *)
(* absolute expiry and a height fence, T10 claim-before-call stable-key    *)
(* externalization, and successor-root handoff through the successor's own *)
(* live operation.  Executors are the correct relying members themselves:  *)
(* the head-state design advances a frontier only through that member's    *)
(* own live operation.  Byzantine members are silent.  Nonce freshness is  *)
(* abstracted as exact request-context plus start-time binding.  This is   *)
(* NOT a mechanized refinement of the Rust implementation; see README.      *)
(***************************************************************************)

CONSTANTS Correct, Domains, MaxSlot, Delta, Lifetime, MaxTime, MaxHeight,
          MaxGen, AuthorityMode, HandoffEnabled,
          PredecessorInKey, LateReplyAdmitted, SkipExecutorQuv,
          ClaimAfterExpiry, CallBeforeClaim, UnauthenticatedRecovery,
          ResourceIdSplitsKey, ActivateFromBytes

ASSUME Correct # {} /\ Domains # {} /\ MaxSlot >= 1 /\ Delta >= 1 /\ Lifetime >= 0
ASSUME AuthorityMode \in {"owned", "unowned"}

Candidates == {"X", "Y"}
OldRoot == "r0"
Successor == "r1"
Handoff == "handoff"
Init0 == "init"
Stable == "*"
None == "none"

Roots == IF HandoffEnabled THEN {OldRoot, Successor} ELSE {OldRoot}
AllDoms == IF HandoffEnabled THEN Domains \cup {Handoff} ELSE Domains
Values == IF HandoffEnabled THEN Candidates \cup {Successor} ELSE Candidates
Preds == Candidates \cup {Init0}
Rids == {"ra", "rb"}
Slots == 1..MaxSlot
KeyPreds == IF PredecessorInKey THEN Preds ELSE {"any"}
Keys == [root : Roots, dom : AllDoms, slot : Slots, pred : KeyPreds]
KeyOf(root, dom, slot, pred) ==
    [root |-> root, dom |-> dom, slot |-> slot,
     pred |-> IF PredecessorInKey THEN pred ELSE "any"]
EmptyEntry == [cands |-> {}, first |-> None]
EmptyStore == [k \in Keys |-> EmptyEntry]
Entries == [cands : SUBSET Values, first : Values \cup {None}]
SomeDom == CHOOSE d \in Domains : TRUE
SomeMember == CHOOSE c \in Correct : TRUE
SomeKey == CHOOSE k \in Keys : TRUE

\* Replies are uniform records: kind \in {"none", "refused", "snapshot"}.
NoReply == [kind |-> "none", cands |-> {}, first |-> None]
Refused == [kind |-> "refused", cands |-> {}, first |-> None]
Snapshot(entry) == [kind |-> "snapshot", cands |-> entry.cands, first |-> entry.first]
Replies == [kind : {"none", "refused", "snapshot"}, cands : SUBSET Values,
            first : Values \cup {None}]

Requests == [root : Roots, dom : AllDoms, slot : Slots, value : Values,
             pred : Preds, start : 0..MaxTime]
NoRequest == [root |-> OldRoot, dom |-> SomeDom, slot |-> 0, value |-> "X",
              pred |-> Init0, start |-> 0]
\* Sentinels are same-shaped records; slot = 0 / gen = 0 means absent.
Idle == [root |-> OldRoot, dom |-> SomeDom, slot |-> 0, value |-> "X",
         pred |-> Init0, start |-> 0, rid |-> "ra",
         replies |-> [c \in Correct |-> NoReply]]
NoGrant == [root |-> OldRoot, dom |-> SomeDom, slot |-> 0, value |-> "X",
            pred |-> Init0, rid |-> "ra", expires |-> 0, height |-> 0]
NoStaged == [gen |-> 0, auth |-> FALSE, content |-> EmptyStore,
             exec |-> SomeMember, key |-> SomeKey, req |-> NoRequest]
NoInflight == [rid |-> "ra", dom |-> SomeDom, slot |-> 0, claimed |-> FALSE]
StableKeys == [dom : Domains, slot : Slots]
ClaimKeys == [rid : Rids \cup {Stable}, dom : Domains, slot : Slots]

VARIABLES
  now, height,
  \* member durable + volatile state
  anchor, anchorGen, staged, authGen, head, activeRoot, gate, gateLive,
  boundary, bytes, crashed,
  \* executor state
  op, grant, accepted, claims, inflight, calls, register, lateClaim

vars == <<now, height, anchor, anchorGen, staged, authGen, head,
          activeRoot, gate, gateLive, boundary, bytes, crashed,
          op, grant, accepted, claims, inflight, calls, register, lateClaim>>
memberVars == <<anchor, anchorGen, staged, authGen, head, activeRoot, gate,
                gateLive, boundary, bytes, crashed>>
storeVars == <<anchor, anchorGen, staged, authGen>>
execVars == <<op, grant, accepted, claims, inflight, calls, register, lateClaim>>
clockVars == <<now, height>>

Active(e) == op[e].slot # 0
HasGrant(e) == grant[e].slot # 0
HasInflight(e) == inflight[e].slot # 0
IsStaged(c) == staged[c].gen # 0

\* Admitted manifest chain (fixed, documented reduction): every admitted slot
\* binds candidate X; slot 1 binds the initial coordinate and slot s binds the
\* admitted slot s-1 candidate as its online-authorization predecessor.  Y is
\* the competing, never-admitted candidate.
Admitted(dom, s) == "X"
AdmittedPred(dom, s) == IF s = 1 THEN Init0 ELSE Admitted(dom, s - 1)

Init ==
    /\ now = 0 /\ height = 0
    /\ anchor = [c \in Correct |-> EmptyStore]
    /\ anchorGen = [c \in Correct |-> 0]
    /\ staged = [c \in Correct |-> NoStaged]
    /\ authGen = [c \in Correct |-> 0]
    /\ head = [c \in Correct |-> [d \in Domains |-> <<>>]]
    /\ activeRoot = [c \in Correct |-> OldRoot]
    /\ gate = [c \in Correct |-> FALSE]
    /\ gateLive = [c \in Correct |-> FALSE]
    /\ boundary = [c \in Correct |-> FALSE]
    /\ bytes = [c \in Correct |-> FALSE]
    /\ crashed = [c \in Correct |-> FALSE]
    /\ op = [c \in Correct |-> Idle]
    /\ grant = [c \in Correct |-> NoGrant]
    /\ accepted = [c \in Correct |-> {}]
    /\ claims = [c \in Correct |-> {}]
    /\ inflight = [c \in Correct |-> NoInflight]
    /\ calls = [c \in Correct |-> [k \in StableKeys |-> 0]]
    /\ register = {}
    /\ lateClaim = [c \in Correct |-> FALSE]

----------------------------------------------------------------------------
\* Model time and execution height.  Tick encodes Q-A3 as an assumption:
\* time cannot leave an operation's inclusive rooted cutoff instant while a
\* correct member has not yet replied to that operation.  The executor never
\* consults Correct: it waits strictly through the cutoff (Decide below).
Deadline(o) == o.start + Delta
AllCorrectReplied(o) == \A c \in Correct : o.replies[c].kind # "none"
Tick ==
    /\ now < MaxTime
    /\ \A e \in Correct : Active(e) =>
         AllCorrectReplied(op[e]) \/ now < Deadline(op[e])
    /\ now' = now + 1
    /\ UNCHANGED <<height, memberVars, execVars>>
AdvanceHeight ==
    /\ height < MaxHeight /\ height' = height + 1
    /\ UNCHANGED <<now, memberVars, execVars>>

----------------------------------------------------------------------------
\* Member admission: exact root, next slot or retained old slot, and the
\* head-derived expected predecessor.  PredecessorInKey models the pre-schema
\* store in which the request-supplied predecessor is a key component
\* instead of an admission check.
Expected(c, dom, s) == IF s = 1 THEN Init0 ELSE head[c][dom][s - 1]
Admissible(c, o) ==
    /\ o.root = activeRoot[c]
    /\ IF o.dom = Handoff
       THEN boundary[c] /\ o.slot = 1 /\ o.pred = Init0
       ELSE /\ o.slot <= Len(head[c][o.dom]) + 1
            /\ (PredecessorInKey \/ o.pred = Expected(c, o.dom, o.slot))

\* Documented reductions: an executor tries the expected predecessor or one
\* wrong one; delivery ids vary only where the mutation under test reads them.
WrongPred(p) == IF p = Init0 THEN "X" ELSE Init0
BeginPreds(e, dom, slot) ==
    IF dom = Handoff \/ slot > Len(head[e][dom]) + 1 THEN {Init0}
    ELSE {Expected(e, dom, slot), WrongPred(Expected(e, dom, slot))}
BeginRids == IF ResourceIdSplitsKey \/ CallBeforeClaim THEN Rids ELSE {"ra"}

Request(o) == [root |-> o.root, dom |-> o.dom, slot |-> o.slot,
               value |-> o.value, pred |-> o.pred, start |-> o.start]

\* Executor-side crash losses: process-local continuation, live operation and
\* the in-flight call handle are volatile; claims, calls and register are not.
CrashLosses(c) ==
    /\ op' = [op EXCEPT ![c] = Idle]
    /\ grant' = [grant EXCEPT ![c] = NoGrant]
    /\ inflight' = [inflight EXCEPT ![c] = NoInflight]

\* Record: atomic durable processing of one push at member c.  A refusal
\* writes nothing and replies with a typed refusal.  An admitted push stages
\* generation g+1; the write is either authenticated or torn (crash during
\* write leaves unauthenticated bytes that happen to roll the key back).
Record(c, e) ==
    /\ ~crashed[c] /\ ~IsStaged(c)
    /\ Active(e) /\ op[e].replies[c].kind = "none"
    /\ LET o == op[e] IN
       IF ~Admissible(c, o)
       THEN /\ op' = [op EXCEPT ![e].replies[c] = Refused]
            /\ UNCHANGED <<clockVars, memberVars, grant, accepted, claims,
                           inflight, calls, register, lateClaim>>
       ELSE /\ anchorGen[c] < MaxGen
            /\ LET k == KeyOf(o.root, o.dom, o.slot, o.pred)
                   old == anchor[c][k]
                   new == [cands |-> old.cands \cup {o.value},
                           first |-> IF old.first = None THEN o.value ELSE old.first]
                   good == [gen |-> anchorGen[c] + 1, auth |-> TRUE,
                            content |-> [anchor[c] EXCEPT ![k] = new],
                            exec |-> e, key |-> k, req |-> Request(o)]
                   torn == [gen |-> anchorGen[c] + 1, auth |-> FALSE,
                            content |-> [anchor[c] EXCEPT ![k] = EmptyEntry],
                            exec |-> e, key |-> k, req |-> Request(o)]
               IN \/ /\ staged' = [staged EXCEPT ![c] = good]
                     /\ authGen' = [authGen EXCEPT ![c] = anchorGen[c] + 1]
                     /\ UNCHANGED <<crashed, op, grant, inflight>>
                  \/ /\ staged' = [staged EXCEPT ![c] = torn]
                     /\ crashed' = [crashed EXCEPT ![c] = TRUE]
                     /\ CrashLosses(c)
                     /\ UNCHANGED authGen
            /\ UNCHANGED <<clockVars, anchor, anchorGen, head, activeRoot, gate,
                           gateLive, boundary, bytes, accepted, claims, calls,
                           register, lateClaim>>

\* Commit: anchor the authenticated record, then expose the nonce-bound reply
\* to the exact operation it answers.  A reply first observed after the
\* rooted cutoff is discarded unless the LateReplyAdmitted mutation is on.
Commit(c) ==
    /\ ~crashed[c] /\ IsStaged(c) /\ staged[c].auth
    /\ LET s == staged[c]
           e == s.exec
           bound == Active(e) /\ Request(op[e]) = s.req
                    /\ op[e].replies[c].kind = "none"
           timely == LateReplyAdmitted \/ now <= Deadline(s.req)
       IN /\ anchor' = [anchor EXCEPT ![c] = s.content]
          /\ anchorGen' = [anchorGen EXCEPT ![c] = s.gen]
          /\ staged' = [staged EXCEPT ![c] = NoStaged]
          /\ op' = IF bound /\ timely
                   THEN [op EXCEPT ![e].replies[c] = Snapshot(s.content[s.key])]
                   ELSE op
    /\ UNCHANGED <<clockVars, authGen, head, activeRoot, gate, gateLive,
                   boundary, bytes, crashed, grant, accepted, claims, inflight,
                   calls, register, lateClaim>>

Crash(c) ==
    /\ ~crashed[c]
    /\ crashed' = [crashed EXCEPT ![c] = TRUE]
    /\ CrashLosses(c)
    /\ UNCHANGED <<clockVars, storeVars, head, activeRoot, gate, gateLive,
                   boundary, bytes, accepted, claims, calls, register, lateClaim>>

\* Recover: complete the single authenticated g+1 window; drop unauthenticated
\* bytes.  Durable head, claims, calls and the installed gate reload as-is.
Recover(c) ==
    /\ crashed[c]
    /\ crashed' = [crashed EXCEPT ![c] = FALSE]
    /\ IF IsStaged(c) /\ (staged[c].auth \/ UnauthenticatedRecovery)
       THEN /\ anchor' = [anchor EXCEPT ![c] = staged[c].content]
            /\ anchorGen' = [anchorGen EXCEPT ![c] = staged[c].gen]
       ELSE UNCHANGED <<anchor, anchorGen>>
    /\ staged' = [staged EXCEPT ![c] = NoStaged]
    /\ UNCHANGED <<clockVars, authGen, head, activeRoot, gate, gateLive,
                   boundary, bytes, execVars>>

ReachBoundary(c) ==
    /\ HandoffEnabled /\ ~boundary[c]
    /\ boundary' = [boundary EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<clockVars, storeVars, head, activeRoot, gate, gateLive,
                   bytes, crashed, execVars>>

\* Handoff transcript bytes reach c from a member that installed the gate.
ReceiveBytes(c) ==
    /\ HandoffEnabled /\ ~bytes[c]
    /\ \E d \in Correct \ {c} : gate[d]
    /\ bytes' = [bytes EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<clockVars, storeVars, head, activeRoot, gate, gateLive,
                   boundary, crashed, execVars>>

----------------------------------------------------------------------------
\* Executor operation: fresh context, push to every configured member.
NewOp(root, dom, slot, value, pred, rid) ==
    [root |-> root, dom |-> dom, slot |-> slot, value |-> value, pred |-> pred,
     start |-> now, rid |-> rid, replies |-> [c \in Correct |-> NoReply]]
Begin(e, dom, slot, value, pred, rid) ==
    /\ ~crashed[e] /\ ~Active(e) /\ ~HasGrant(e) /\ ~HasInflight(e)
    /\ now + Delta < MaxTime
    /\ IF dom = Handoff
       THEN value = Successor /\ slot = 1 /\ pred = Init0
            /\ activeRoot[e] = OldRoot /\ ~gate[e]
       ELSE value \in Candidates /\ slot <= Len(head[e][dom]) + 1
    /\ op' = [op EXCEPT ![e] = NewOp(activeRoot[e], dom, slot, value, pred, rid)]
    /\ UNCHANGED <<clockVars, memberVars, grant, accepted, claims, inflight,
                   calls, register, lateClaim>>

\* Decide: after the rooted cutoff, every retained reply must be a valid
\* snapshot (any typed refusal aborts) and the authority rule must hold.
Decide(e) ==
    /\ ~crashed[e] /\ Active(e)
    /\ LET o == op[e]
           replied == {c \in Correct : o.replies[c].kind # "none"}
           valid == {c \in replied : o.replies[c].kind = "snapshot"}
           accept == /\ valid # {} /\ valid = replied
                     /\ \A c \in valid :
                          IF AuthorityMode = "owned"
                          THEN o.replies[c].cands = {o.value}
                          ELSE o.replies[c].first = o.value
           g == [root |-> o.root, dom |-> o.dom, slot |-> o.slot,
                 value |-> o.value, pred |-> o.pred, rid |-> o.rid,
                 expires |-> now + Lifetime, height |-> height]
           a == [root |-> o.root, dom |-> o.dom, slot |-> o.slot,
                 value |-> o.value, pred |-> o.pred]
       IN /\ LateReplyAdmitted \/ now > Deadline(o)
          /\ replied # {}
          /\ grant' = [grant EXCEPT ![e] = IF accept THEN g ELSE NoGrant]
          /\ accepted' = [accepted EXCEPT ![e] = IF accept THEN @ \cup {a} ELSE @]
          /\ op' = [op EXCEPT ![e] = Idle]
    /\ UNCHANGED <<clockVars, memberVars, claims, inflight, calls, register, lateClaim>>

\* Own accepted-history advancement.  A different hash at an occupied offset
\* is the ConflictingAcceptedHistory refusal: no write, the grant is unusable.
Advance(e) ==
    /\ ~crashed[e] /\ HasGrant(e) /\ grant[e].dom # Handoff
    /\ LET g == grant[e] IN
       /\ g.slot = Len(head[e][g.dom]) + 1
       /\ head' = [head EXCEPT ![e][g.dom] = Append(@, g.value)]
    /\ UNCHANGED <<clockVars, storeVars, activeRoot, gate, gateLive, boundary,
                   bytes, crashed, execVars>>
HeadHolds(e, g) ==
    g.slot <= Len(head[e][g.dom]) /\ head[e][g.dom][g.slot] = g.value

\* Claim fence: unexpired continuation, unchanged execution height, durable
\* own head, and exact admitted-manifest binding.
Fresh(g) == now <= g.expires /\ height = g.height
FenceOK(g) == ClaimAfterExpiry \/ Fresh(g)
BindingOK(e, g) ==
    /\ g.dom # Handoff
    /\ HeadHolds(e, g)
    /\ g.root = activeRoot[e]
    /\ Admitted(g.dom, g.slot) = g.value
    /\ AdmittedPred(g.dom, g.slot) = g.pred
ClaimKey(g) == [rid |-> IF ResourceIdSplitsKey THEN g.rid ELSE Stable,
                dom |-> g.dom, slot |-> g.slot]
SKey(g) == [dom |-> g.dom, slot |-> g.slot]
Bump(n) == IF n < 2 THEN n + 1 ELSE n

Claim(e) ==
    /\ ~CallBeforeClaim
    /\ ~crashed[e] /\ HasGrant(e) /\ ~HasInflight(e)
    /\ LET g == grant[e] IN
       /\ FenceOK(g) /\ BindingOK(e, g)
       /\ ClaimKey(g) \notin claims[e]
       /\ claims' = [claims EXCEPT ![e] = @ \cup {ClaimKey(g)}]
       /\ inflight' = [inflight EXCEPT ![e] =
            [rid |-> g.rid, dom |-> g.dom, slot |-> g.slot, claimed |-> TRUE]]
       /\ lateClaim' = [lateClaim EXCEPT ![e] = @ \/ ~Fresh(g)]
    /\ grant' = [grant EXCEPT ![e] = NoGrant]
    /\ UNCHANGED <<clockVars, memberVars, op, accepted, calls, register>>

\* Register call: put-if-absent on the idempotency key carried by the call.
Call(e) ==
    /\ ~crashed[e] /\ HasInflight(e) /\ inflight[e].claimed
    /\ register' = register \cup {ClaimKey(inflight[e])}
    /\ calls' = [calls EXCEPT ![e][SKey(inflight[e])] = Bump(@)]
    /\ inflight' = [inflight EXCEPT ![e] = NoInflight]
    /\ UNCHANGED <<clockVars, memberVars, op, grant, accepted, claims, lateClaim>>

\* CallBeforeClaim mutation: the call is issued first; the claim is a later,
\* separately crashable step.
CallFirst(e) ==
    /\ CallBeforeClaim
    /\ ~crashed[e] /\ HasGrant(e) /\ ~HasInflight(e)
    /\ LET g == grant[e] IN
       /\ FenceOK(g) /\ BindingOK(e, g)
       /\ ClaimKey(g) \notin claims[e]
       /\ register' = register \cup {ClaimKey(g)}
       /\ calls' = [calls EXCEPT ![e][SKey(g)] = Bump(@)]
       /\ inflight' = [inflight EXCEPT ![e] =
            [rid |-> g.rid, dom |-> g.dom, slot |-> g.slot, claimed |-> FALSE]]
       /\ lateClaim' = [lateClaim EXCEPT ![e] = @ \/ ~Fresh(g)]
    /\ grant' = [grant EXCEPT ![e] = NoGrant]
    /\ UNCHANGED <<clockVars, memberVars, op, accepted, claims>>
ClaimLate(e) ==
    /\ ~crashed[e] /\ HasInflight(e) /\ ~inflight[e].claimed
    /\ claims' = [claims EXCEPT ![e] = @ \cup {ClaimKey(inflight[e])}]
    /\ inflight' = [inflight EXCEPT ![e] = NoInflight]
    /\ UNCHANGED <<clockVars, memberVars, op, grant, accepted, calls, register, lateClaim>>

\* Lookup-only reconciliation: a durable claim without a live call handle
\* never issues a second call; the grant is consumed without externalizing.
Reconcile(e) ==
    /\ ~crashed[e] /\ HasGrant(e) /\ grant[e].dom # Handoff
    /\ ClaimKey(grant[e]) \in claims[e]
    /\ grant' = [grant EXCEPT ![e] = NoGrant]
    /\ UNCHANGED <<clockVars, memberVars, op, accepted, claims, inflight,
                   calls, register, lateClaim>>

\* A process-local continuation may be dropped at any time.
DiscardGrant(e) ==
    /\ HasGrant(e)
    /\ grant' = [grant EXCEPT ![e] = NoGrant]
    /\ UNCHANGED <<clockVars, memberVars, op, accepted, claims, inflight,
                   calls, register, lateClaim>>

\* SkipExecutorQuv mutation: claim from another executor's cached transcript.
ClaimFromTranscript(e) ==
    /\ SkipExecutorQuv
    /\ ~crashed[e] /\ ~HasInflight(e)
    /\ \E d \in Correct : \E a \in accepted[d] :
         /\ a.dom # Handoff
         /\ LET g == [root |-> a.root, dom |-> a.dom, slot |-> a.slot,
                      value |-> a.value, pred |-> a.pred, rid |-> "ra",
                      expires |-> now, height |-> height]
            IN /\ ClaimKey(g) \notin claims[e]
               /\ claims' = [claims EXCEPT ![e] = @ \cup {ClaimKey(g)}]
               /\ inflight' = [inflight EXCEPT ![e] =
                    [rid |-> "ra", dom |-> g.dom, slot |-> g.slot, claimed |-> TRUE]]
    /\ UNCHANGED <<clockVars, memberVars, op, grant, accepted, calls, register, lateClaim>>

----------------------------------------------------------------------------
\* Handoff: the successor gate is installed only by consuming this member's
\* own live handoff grant; activation requires the installed gate.
InstallGate(e) ==
    /\ ~crashed[e] /\ HasGrant(e) /\ grant[e].dom = Handoff
    /\ ~gate[e] /\ FenceOK(grant[e])
    /\ gate' = [gate EXCEPT ![e] = TRUE]
    /\ gateLive' = [gateLive EXCEPT ![e] = TRUE]
    /\ grant' = [grant EXCEPT ![e] = NoGrant]
    /\ UNCHANGED <<clockVars, storeVars, head, activeRoot, boundary, bytes,
                   crashed, op, accepted, claims, inflight, calls, register, lateClaim>>
SynthesizeGate(e) ==
    /\ ActivateFromBytes
    /\ ~crashed[e] /\ bytes[e] /\ ~gate[e]
    /\ gate' = [gate EXCEPT ![e] = TRUE]
    /\ UNCHANGED <<clockVars, storeVars, head, activeRoot, gateLive, boundary,
                   bytes, crashed, execVars>>
Activate(e) ==
    /\ ~crashed[e] /\ gate[e] /\ activeRoot[e] = OldRoot
    /\ activeRoot' = [activeRoot EXCEPT ![e] = Successor]
    /\ UNCHANGED <<clockVars, storeVars, head, gate, gateLive, boundary,
                   bytes, crashed, execVars>>

----------------------------------------------------------------------------
Next ==
    \/ Tick \/ AdvanceHeight
    \/ \E c \in Correct :
         \/ (\E e \in Correct : Record(c, e))
         \/ Commit(c) \/ Crash(c) \/ Recover(c) \/ ReachBoundary(c) \/ ReceiveBytes(c)
    \/ \E e \in Correct :
         \/ (\E dom \in AllDoms, slot \in Slots, value \in Values :
               \E pred \in BeginPreds(e, dom, slot), rid \in BeginRids :
                 Begin(e, dom, slot, value, pred, rid))
         \/ Decide(e) \/ Advance(e) \/ Claim(e) \/ Call(e) \/ CallFirst(e)
         \/ ClaimLate(e) \/ Reconcile(e) \/ DiscardGrant(e)
         \/ ClaimFromTranscript(e) \/ InstallGate(e) \/ SynthesizeGate(e)
         \/ Activate(e)
Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
TypeOK ==
    /\ now \in 0..MaxTime /\ height \in 0..MaxHeight
    /\ anchor \in [Correct -> [Keys -> Entries]]
    /\ \A c \in Correct : anchorGen[c] \in 0..MaxGen /\ authGen[c] \in 0..MaxGen
                          /\ anchorGen[c] <= authGen[c] + 1
    /\ \A c \in Correct : ~IsStaged(c) \/
         (staged[c].gen = anchorGen[c] + 1 /\ staged[c].auth \in BOOLEAN
          /\ staged[c].content \in [Keys -> Entries] /\ staged[c].exec \in Correct
          /\ staged[c].key \in Keys /\ staged[c].req \in Requests)
    /\ \A c \in Correct, d \in Domains :
         head[c][d] \in Seq(Candidates) /\ Len(head[c][d]) <= MaxSlot
    /\ activeRoot \in [Correct -> Roots]
    /\ gate \in [Correct -> BOOLEAN] /\ gateLive \in [Correct -> BOOLEAN]
    /\ boundary \in [Correct -> BOOLEAN] /\ bytes \in [Correct -> BOOLEAN]
    /\ crashed \in [Correct -> BOOLEAN]
    /\ \A e \in Correct : ~Active(e) \/
         (Request(op[e]) \in Requests /\ op[e].rid \in Rids
          /\ op[e].replies \in [Correct -> Replies])
    /\ \A e \in Correct : ~HasGrant(e) \/
         (grant[e].root \in Roots /\ grant[e].dom \in AllDoms /\ grant[e].slot \in Slots
          /\ grant[e].value \in Values /\ grant[e].pred \in Preds /\ grant[e].rid \in Rids
          /\ grant[e].expires \in 0..(MaxTime + Lifetime) /\ grant[e].height \in 0..MaxHeight)
    /\ \A e \in Correct : claims[e] \subseteq ClaimKeys
    /\ \A e \in Correct : ~HasInflight(e) \/
         (inflight[e].rid \in Rids /\ inflight[e].dom \in Domains
          /\ inflight[e].slot \in Slots /\ inflight[e].claimed \in BOOLEAN)
    /\ calls \in [Correct -> [StableKeys -> 0..2]]
    /\ register \subseteq ClaimKeys
    /\ lateClaim \in [Correct -> BOOLEAN]

\* Q-E1/Q-E2 witness: no two live accepts differ for one (root, domain, slot).
NoConflictingAccepts ==
    \A e1, e2 \in Correct : \A a \in accepted[e1], b \in accepted[e2] :
      (a.root = b.root /\ a.dom = b.dom /\ a.slot = b.slot) => a.value = b.value

\* One conflict store per (root, domain, slot) at every member.
OneCanonicalConflictIdentity ==
    \A c \in Correct : \A k1, k2 \in Keys :
      (k1.root = k2.root /\ k1.dom = k2.dom /\ k1.slot = k2.slot
       /\ anchor[c][k1].cands # {} /\ anchor[c][k2].cands # {}) => k1 = k2

\* Every accept is retained as conflict knowledge at every correct member.
AcceptedKnowledgeRetained ==
    \A e, c \in Correct : \A a \in accepted[e] :
      a.value \in anchor[c][KeyOf(a.root, a.dom, a.slot, a.pred)].cands

\* An executor's own head never contradicts its own accepts
\* (ConflictingAcceptedHistory is a refusal, never a rewrite).
NoConflictingOwnHead ==
    \A e \in Correct : \A a \in accepted[e] :
      (a.dom # Handoff /\ a.slot <= Len(head[e][a.dom])) => head[e][a.dom][a.slot] = a.value

\* Q-EA4: a claim exists only after this executor's own live accept.
NoClaimWithoutOwnLiveAccept ==
    \A e \in Correct : \A k \in claims[e] :
      \E a \in accepted[e] : a.dom = k.dom /\ a.slot = k.slot

\* Every claim was fenced by continuation expiry and execution height.
NoClaimAfterExpiryOrFence == \A e \in Correct : ~lateClaim[e]

\* Q-E3 / T10: one physical mutation per stable (domain, slot) key.
AtMostOneExternalMutationPerStableKey ==
    \A k \in StableKeys :
      Cardinality({r \in register : r.dom = k.dom /\ r.slot = k.slot}) <= 1

\* T10 NoBlindReplayAfterAmbiguity lifted to the executor: at most one call
\* per executor and stable key, across crashes.
NoBlindReplayAfterCrash == \A e \in Correct, k \in StableKeys : calls[e][k] <= 1

\* Recovery installs only generations that an authenticated write produced.
RecoveryNeverAdvancesBeyondAuthenticatedRecords ==
    \A c \in Correct : anchorGen[c] <= authGen[c]

\* Q-E4 / Q-EA7: successor authority only through an own live-installed gate.
NoSuccessorAuthorityFromBytes ==
    \A c \in Correct : activeRoot[c] = Successor => gate[c] /\ gateLive[c]

\* Reachability probe, NOT a theorem: its required violation exhibits a trace
\* in which one executor accepts, advances, claims and externalizes slot 1
\* and then slot 2 (a sole correct member suffices).
NoExecutedSecondSlot ==
    ~ \E e \in Correct, d \in Domains : calls[e][[dom |-> d, slot |-> 2]] >= 1

GenBound == \A c \in Correct : anchorGen[c] <= MaxGen
\* Correct members are interchangeable model values (documented symmetry).
Symm == Permutations(Correct)
=============================================================================
