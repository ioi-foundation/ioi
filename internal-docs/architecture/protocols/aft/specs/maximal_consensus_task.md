# AFT maximal-consensus task and adversary model

Status: normative research task for M11; **not an admitted protocol claim**.

Date: 2026-09-03.

This document fixes the task that the maximal-consensus program must solve. A
construction does not pass by satisfying a weaker interpretation. In
particular, agreement among a singleton correct set and termination by
unconditionally deciding `Abort` are insufficient for the target headline.

## 1. Participants, identities, and configurations

For one consensus instance:

- `P = {p_1, ..., p_n}` is a rooted configuration with `n >= 2`.
- Every member has an independently rooted signing identity and persistent
  local state.
- `B` is the Byzantine set and `H = P ∖ B` is the correct set.
- The maximal case is `|B| = f = n - 1` and `|H| = 1`.
- Which member is correct is not known to the protocol, clients, or offline
  verifier. Every singleton `{p_i}` is an admissible correct set.
- Byzantine members may deviate arbitrarily, equivocate, clone or retain their
  own keys and state, omit messages, and remain permanently silent.
- A correct member follows the protocol, maintains its required journal, and
  does not sign conflicting authority for one typed instance.

The configuration root, network, epoch, domain, instance, predecessor, and
policy are part of every authoritative transcript. Reconfiguration is a new
typed instance and may not retroactively change which proofs an existing
instance accepts.

## 2. Values and inputs

`V` contains typed application values and a distinguished `Abort` value.
`ExternalValid(v, context)` is deterministic and independently executable.
Two non-`Abort` values conflict when they prescribe different canonical state
or incompatible effects for the same typed instance.

The task is nontrivial: at least one fixed, independently rooted context admits
two conflicting externally valid values. A protocol theorem may restrict a
value domain by policy, but it may not make agreement tautological by defining
at most one value as externally valid for every instance. The paired executions
below hold the roots, context, and all non-member public inputs fixed while
varying which valid proposal reaches the sole correct member.

An input is *correctly submitted* when its complete bytes reach at least one
correct member through an authenticated client path and remain available in
that member's durable storage. The model does not demand inclusion for an
input that reaches only Byzantine members.

## 3. Required properties

The following coordinates are separate. Satisfying one does not imply another.

### 3.1 Internal agreement

No two correct members decide conflicting non-`Abort` values for the same
instance in one execution.

This property is vacuous when `|H| = 1`; it cannot carry the maximal headline
alone.

### 3.2 Transferable non-conflict

Let `Verify(root, instance, proof)` be the deterministic offline verification
algorithm. Under every admissible execution with at least one correct member,
there do not exist byte strings `proof_x`, `proof_y` such that the same rooted
verifier accepts both, their decisions are non-`Abort`, and their decisions
conflict.

The verifier receives only rooted public parameters and proof bytes. It does
not receive an oracle naming the correct member or live history. Trust roots
are provisioned independently of the proof.

This is the non-vacuous external meaning required before a decision may
authorize an irreversible effect.

### 3.3 External validity

Every accepted non-`Abort` proof binds a value satisfying
`ExternalValid(v, context)`. Self-nominated context, policy, membership, or
trust roots are invalid.

### 3.4 All-correct-input validity

If every member is correct and proposes the same externally valid value `v`,
every decision is `v`.

### 3.5 Correct-input inclusion

If a valid input is correctly submitted and remains available, the canonical
ordered state eventually includes it unless a separately identified,
externally valid conflict or policy rule rejects it. Permanent silence by the
other `n - 1` members is not such a rule.

This is stronger than commander validity and prevents a fixed Byzantine
leader from turning every slot into `Abort`.

### 3.6 Decision termination

Every correct member eventually decides a typed value in every admissible
execution. A probabilistic construction must provide almost-sure termination
against its named adversary and identify the source and availability of every
random bit.

`Abort` counts only for this coordinate.

### 3.7 Authorization and effect liveness

For every correctly submitted effect whose value and policy are valid and
that is not rejected by a separately identified, externally valid conflict or
policy rule, some non-`Abort` decision eventually produces an
offline-verifiable authorization. Such a rule must be fixed by the rooted
context and may not derive authority from local arrival order, silence, or
unmodeled external state. In particular, when exactly one valid non-`Abort`
effect is correctly submitted for an instance, permanent silence by the other
`n - 1` members is not a rejection rule and the authorization must eventually
be produced. Given the already modeled downstream atomic idempotency-register
resource and a reachable honest executor, that authorization is eventually
offered to the resource.

The protocol does not claim that arbitrary physical actors must comply.
`Abort`, a timeout record, an accountability proof, or a receipt below policy
does not satisfy effect liveness.

### 3.8 Durable ordering and recovery

Accepted decisions form one prefix-compatible ordered history under the same
root. A correct member that restarts from its durable state neither signs nor
executes conflicting authority. A newcomer additionally needs the exact named
freshness mechanism; self-consistent history bytes alone do not establish
freshness.

### 3.9 Availability

Bytes correctly submitted to a correct member remain retrievable from that
member under its storage-liveness and client-reachability assumptions. The
task does not infer global replication from a single correct holder.

## 4. Communication and scheduling profiles

The M12 viability result must say which of these profiles it addresses:

1. **Fully asynchronous:** no message-delay bound; messages between correct
   endpoints are eventually delivered. With one correct member, this condition
   imposes no delivery duty on a Byzantine endpoint.
2. **Eventual synchrony:** after unknown GST, correct-to-correct messages arrive
   within an unknown bound. Again, it imposes no duty on Byzantine endpoints.
3. **Known synchrony:** rounds have a known delivery bound between correct
   endpoints. Authenticated round structure may enable Dolev-Strong-style
   internal Byzantine agreement, but does not by itself make a transferable
   non-`Abort` proof available when `n - 1` signers are silent.

The target may select a profile, but it may not describe a synchronous result
as asynchronous. Timeouts can schedule actions; they cannot attest that a
silent identity will never issue conflicting authority.

## 5. Setup, cryptography, and storage

Permitted baseline setup:

- rooted public identities and algorithm profiles;
- local secret keys generated without a private threshold setup or DKG;
- collision-resistant hashes, PQ signatures, authenticated encryption, and
  local randomness;
- crash-consistent local storage for correct members; and
- independently provisioned verifier policy and trust roots.

Not present unless separately named and charged as a stronger assumption:

- a trusted publisher, sequencer, relay, notary, or availability committee;
- an oracle naming the correct member or current live history;
- a linearizable shared close/first-writer object;
- a trusted global clock, TEE, trusted erasure for Byzantine members, or
  honest-majority storage service;
- bounded Byzantine computation, stake, hash power, or network ownership; or
- a third-party chain whose consensus result selects AFT's result.

Correct members may erase evolved keys as required. Byzantine members can copy
their own keys before any requested erasure, so key evolution does not bind
them to future inaction.

## 6. Adversary timing and randomness

The baseline adversary is static for the identity set but chooses any
`n - 1` members. The viability campaign must also state whether a proposed
primitive survives adaptive corruption; no static proof implies that result.

The scheduler observes protocol-visible actions and may delay traffic subject
only to the chosen profile. Byzantine members know their own keys and coins and
may coordinate. For a randomized protocol, safety is unconditional over coin
outcomes; termination is almost sure or has an explicitly weaker probability
statement. A positive-probability terminating finite prefix can be fixed when
constructing a safety counterexecution.

## 7. Client and external-verifier semantics

- A client can reach at least one correct member for a correctly submitted
  input.
- An offline verifier may later receive arbitrary proofs from arbitrary
  parties in arbitrary order.
- The verifier cannot query hidden local state or distinguish an honest use of
  a member key from Byzantine use of that same key in another admissible fault
  assignment.
- A proof remains valid or invalid by bytes, roots, and explicit freshness
  inputs; network arrival order at the verifier is not authority.
- Every freshness input is either fixed in the independently provisioned root
  or explicitly included in `Verify` and held common in paired executions. A
  non-reproducible freshness output is an external authority.
- No non-member service supplies an output used by `Verify` or by proof
  construction to select, close, order, or make one authorization canonical.
- The modeled atomic idempotency resource is permitted only downstream, after
  authorization acceptance, and its receipt is not an input to `Verify`. A
  protocol using that resource's linearization or receipt to distinguish `X`
  from `Y` is outside this premise and must name the resource as its selector.
- “First seen” is local observation, not canonical first publication.
- If verifiers share a mutable service that makes their acceptance order
  consistent, that service and its safety/liveness assumptions are part of the
  protocol rather than an implementation detail.

## 8. Required smallest cases

Every construction must instantiate:

- `n = 2, f = 1`, values `X` and `Y`, with `X` submitted only to `p_0`
  and `Y` submitted only to `p_1` in their respective sole-honest executions;
- both Byzantine-silent executions;
- both conflicting values submitted together, where the rooted conflict rule
  does not require authorization of both;
- each conflicting value submitted alone, where silence by every other member
  still requires its authorization;
- the role-switched execution in which one proof-producing identity is
  Byzantine and replays the proof bytes it could produce when honest;
- replayable client bytes held common across paired executions, contrasted
  with a non-reproducible external selecting output; and
- a mutation that feeds an idempotency-register receipt into `Verify` and is
  therefore classified as an external selector;
- arbitrary `n >= 2, f = n - 1`;
- all Byzantine equivocation as well as all Byzantine silence;
- restart before and after publication/close/decision; and
- two external verifiers receiving conflicting proof orders.

## 9. Admission criteria

M11 closes when all terms above are represented in the theorem statement,
model constants, verifier API, and test plan. M12 can return
`PASS_CONSTRUCTION` only if a concrete primitive satisfies the task without an
excluded authority.

A proposal that provides only internal singleton agreement, default/`Abort`
termination, scheduled lease safety, or a bulletin that assumes canonical
closure does not solve this task. If the role-switching lower bound is upheld
under independent theorem review, the conjunction is impossible under the
non-negotiable constraints and the owner must explicitly change at least one
required property or assumption before implementation work begins.
