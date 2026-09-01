# IOI Authority Protocol Conformance And Release Gates

Status: active internal conformance-design candidate; non-canonical.
Authority: the canonical IOI Authority Protocol, Machine Authority, governance,
contract-registry, receipt, and implementation-status owners win on drift.
Supports: design of future public profile artifacts; this file releases none.
Last alignment pass: 2026-08-30.

## Outcome

A conformance result must answer one narrow question reproducibly:

> Does this named implementation, using these exact artifacts and declared
> trust inputs, satisfy this exact frozen profile and entitlement?

It must not imply product safety, effect correctness, legal compliance,
certification neutrality, settlement finality, adoption, or a broader profile.

## Frozen Surface Closure

Every released profile requires a content-addressed
`ProtocolSurfaceManifest`. The future manifest must close over, at minimum:

- profile id, semantic version, status, and compatibility/deprecation window;
- every schema/contract id, version, and content hash;
- canonicalization rule and signature-domain registry;
- cryptographic algorithms and parameter profiles;
- lifecycle/state-transition table and wire-stable refusal classes;
- trust-input types, acquisition modes, freshness horizons, and offline bundle
  rules;
- positive, boundary, negative, concurrency, crash/recovery, and replay vector
  roots;
- verifier and runner source/archive hashes plus reproducible-build inputs;
- reference-role declaration and known implementation limits;
- licensing path, change-record locator, and designation record; and
- explicit entitlements unlocked and claims not unlocked.

An unlisted field, schema, endpoint, hidden database fact, hosted lookup, or
first-party-source behavior cannot be required for conformance.

Every case receives explicit deterministic state, time, key, revocation,
allocation, policy, effect-adapter, and failure-injection inputs. A test may not
pass because it inherited the runner host's clock, cache, network, database, or
environment. When a live interoperability test necessarily uses such a source,
the result binds its measured evidence and freshness horizon rather than
pretending the run was offline.

## Verdict Shape

The future runner should emit a deterministic canonical verdict body with:

```text
profile_id
surface_manifest_hash
implementation_identity
implementation_artifact_set_hash
runner_identity_and_hash
test_bundle_hash
trust_input_bundle_hash
verdict: pass | fail | indeterminate
passed_entitlements[]
failed_case_ids[]
refusal_class_mismatches[]
excluded_claims[]
verdict_root
```

`indeterminate` is mandatory when required evidence or trust input is absent.
It must never be coerced to `pass`. `verdict_root` is derived from the canonical
body excluding `verdict_root`. `implementation_artifact_set_hash` closes over
the exact executable/library/adapter bytes under test rather than trusting a
mutable implementation name; identical frozen inputs and implementation bytes
must yield the same body and root.

A separate run-evidence envelope binds `verdict_root`, `started_at`,
`completed_at`, execution environment, and signatures. Those measured fields
are not part of the deterministic verdict body. A signature covers the complete
domain-separated run-evidence envelope, not only an embedded test root.

## Conformance Layers

| Layer | Required evidence | What it proves |
| --- | --- | --- |
| C0 artifact integrity | manifest closure, hashes, reproducible fetch/build | the tested bytes are the declared surface |
| C1 syntax and canonical bytes | schemas, canonicalization, cross-language byte fixtures | parsers agree on accepted shapes and signed bytes |
| C2 cryptographic validity | domain-separated positive/negative signatures and key rotation cases | signatures and content roots are verified as declared |
| C3 semantic authority | review binding, delegation, attenuation, currentness, audience/holder, allocation | accepted uses stay inside the selected authority contract |
| C4 consumption and concurrency | calls/budget races, replay, idempotency substitution, restart | bounded power cannot be spent more than declared |
| C5 final-PEP exact effect | domain-derived effect, batch/standing constraints, finalizer coverage | admission protects the effect which can actually leave the host |
| C6 outcome and reconciliation | invocation, failure/unknown, dead-claim, reconciliation lineage | effect ambiguity remains explicit and independently inspectable |
| C7 implementation independence | isolated twin, separate codegen/transport, outside implementation | the public specification is sufficient beyond first-party code |
| C8 governance and release | public proposal/objection record, designation, license, role disclosure | the named surface and release process are externally inspectable |

Passing a higher-numbered layer requires every lower layer selected by the
profile. C7 and C8 do not turn functional parity into neutral certification;
that designation has its own structural-independence requirements.

## Profile Gate Matrix

| Target profile | Required layers | Minimum served evidence | Entitlement ceiling |
| --- | --- | --- | --- |
| `ioi_authority_core_v1` | C0–C3 for proposal/review/decision subset, plus C7–C8 release evidence | production request, review, edit/deny/step-up/approve path and offline decision verification | action authorization |
| `ioi_delegated_authority_v1` | Core + delegation portions of C3 + C4 + C7–C8 | signed portable grant/allocation closure, currentness, attenuation, atomic calls/budgets | portable delegated authority |
| `ioi_governed_effect_v1` | C0–C2, the selected admission/authority subset of C3, C4–C6, and C7–C8; Delegated is composed separately | at least one consequential served domain-derived effect with finalizer fence and outcome/reconciliation evidence | governed exact effect for declared effect surfaces only |
| `ioi_machine_authority_complete_v1` | all C0–C8 plus MAC-1–MAC-12 and external operation/exit | independently operated consequential effect, replaceable roles, portable offline verifier and exit | complete Machine Authority |

The current qualified SCM path is candidate served evidence for C4–C6. It does
not release a profile, cover every effect surface, supply the missing portable
outer signatures, or satisfy C7–C8 by itself.

## Mandatory Vector Families

Every selected object or lifecycle transition needs:

- minimal accept and maximal-boundary accept;
- malformed type, length, encoding, enum, and unknown-field behavior;
- canonicalization equivalence and non-equivalence across at least two
  implementations;
- wrong domain, object version, profile, key, signature, and content root;
- every load-bearing reference substituted independently;
- stale/future/overflowed time and key/revocation rotation;
- review edit, denial, step-up, continuation, and ceremony replay;
- parent/child splice, holder/audience substitution, attenuation widening,
  depth/re-delegation excess, hidden descendant allocation, and revoked ancestry;
- exact-effect mismatch, non-member batch, standing-envelope excess, and
  alternate-finalizer bypass;
- concurrent final unit, duplicate idempotency, same key/different content,
  crash at every durable boundary, and restart/replay;
- no-invocation, known failure, unknown invocation/outcome, reconciliation, and
  receipt-lineage substitution; and
- profile downgrade, undeclared extension, missing offline input, and hosted-
  dependency refusal.

Negative vectors assert state deltas: invocation count, remaining calls/budget,
durable receipts, allocation tree, and outcome state. Matching an error label
while mutating protected state is a failure.

Vector expectations are derived from the frozen specification and threat
model. A first-party exporter may produce candidate bytes, but it is not the
oracle for their meaning: candidate vectors require an independent derivation
or review, and any first-party/specification disagreement is adjudicated
against the published specification. Wire-stable refusal classes are manifest members;
implementation diagnostics may refine them but cannot replace or contradict
them.

The concurrency/crash harness must control interleavings and inject failure
before and after every durable write, consumption decision, invoker claim,
effect call, and terminal receipt. It compares the complete durable next state
after recovery, not only the immediate response.

## Canonical Stable-Gate Mapping

This table maps directly to the nine gates in the canonical
[`IOI Authority Protocol`](../../../../docs/architecture/foundations/ioi-authority-protocol.md#stable-release-gates).
It does not redefine them.

| Canonical Gate | Required Release Evidence In This Design |
| --- | --- |
| 1 — immutable public surface | C0 closure; manifest, contract, invariant, fixture, and signature-profile hashes |
| 2 — separate codegen/transport | ADR 0032 evidence with generator and transport provenance distinct from the first-party path |
| 3 — clone-and-run verifier | deterministic offline runner, pinned build, result wrapper, and missing-input behavior |
| 4 — public adversarial cases | manifest-rooted positive, boundary, substitution, replay, expiry, revocation, crash, concurrency, and ambiguity bundles |
| 5 — clean-room refusal parity | isolated twin packet/result with all disagreements and specification dispositions retained |
| 6 — organizational independence | qualifying outside implementation against the same frozen manifest; mandatory before any profile is stable |
| 7 — served first-party candidate path | end-to-end lifecycle traces and finalizer coverage for every transition/effect surface selected by the profile; formal reference designation is separate |
| 8 — operational governance | public proposal, objection/disposition, designation, breaking/deprecation, and security-response records |
| 9 — exact entitlements | machine-readable and human-readable `proves`, `does_not_prove`, claim ceiling, and exclusions |

## Candidate-To-Stable Promotion

### Candidate

A candidate profile requires:

1. registered contract closure and candidate manifest hash;
2. complete prose state machine and threat-model mapping;
3. deterministic first-party runner on a clean checkout;
4. positive and adversarial bundles with retained results;
5. exact license and change-record location;
6. known gaps and entitlement ceiling in the result; and
7. no critical or high unresolved ambiguity that changes an accept/refuse
   boundary.

Candidate means implementable for evaluation. It does not mean stable,
certified, complete, or safe for every effect.

### Stable

Stable additionally requires:

1. an in-session clean-room twin with every disagreement adjudicated in the
   specification rather than patched around in private code;
2. separate code generation and a separate transport implementation under
   [ADR 0032](../../../../docs/decisions/0032-independently-implemented-client-definition.md);
3. at least one organizationally independent implementation passing the same
   frozen bundle;
4. a public proposal, objection/disposition, designation, migration, and
   deprecation record satisfying the governance owner;
5. reproducible runner/artifact builds from documented dependencies;
6. red-team completion for every mandatory threat family;
7. no unresolved critical or high finding and a published disposition for all
   remaining findings; and
8. a declared compatibility window and emergency-change procedure.

The complete profile additionally requires an outside-operated consequential
effect and a demonstrated portable exit with no IOI-hosted dependency.

## Runner Contract (Target, Not Implemented)

The public artifact should expose transport-neutral commands equivalent to:

```text
iap manifest verify <manifest>
iap vector verify --profile <id> --bundle <path>
iap implementation test --profile <id> --adapter <path>
iap evidence verify <result-bundle>
```

The names are placeholders until registered. Required behavior is not: each
command is non-interactive, deterministic for pinned inputs, produces a
machine-readable result plus human summary, distinguishes failure from missing
evidence, and can run without an IOI service.

The public artifact must live outside the retired `docs/conformance` document
class. Its future location, manifest scope, licensing, and preservation rules
must be decided with ADR 0033 before publication.

## Independence Labels

| Label | Minimum evidence | Forbidden implication |
| --- | --- | --- |
| first-party-tested | first-party tests against current code | specification sufficiency |
| internally reproduced | procedurally isolated twin from the packet only | external review or organizational independence |
| independently implemented | outside organization or qualifying boundary builds from public surface and passes | neutral certification or adoption |
| independently operated | outside operator runs a declared effect and verifies/exports evidence | universal safety or broad adoption |
| neutrally certified | structurally independent certifier applies a public program | protocol ownership, product quality, or legal approval |

Every evidence record carries `proves` and `does_not_prove` fields in equivalent
machine-readable and human-readable form.

## Current-Status Routing

This research file does not maintain a second implementation or blocker ledger.
Current profile blockers are owned by
[`ioi-authority-protocol.md` § Present Profile Status](../../../../docs/architecture/foundations/ioi-authority-protocol.md#present-profile-status),
subject-owner implementation-status declarations, and
[`canon-to-code-delta.md`](../../../../docs/architecture/_meta/canon-to-code-delta.md).
Program sequencing and exact evidence locators live in
[`machine-authority-category-program.md`](../../machine-authority-category-program.md).

Absence of a structurally independent certifier blocks only a neutral-
certification claim. It does not block candidate or stable protocol release;
the independent-implementation and governance gates above still do.
