# Security, Privacy, and Policy Invariants

Status: canonical architecture authority.
Canonical owner: this file for public security/privacy/policy invariants;
conformance details live in
[`../../conformance/hypervisor-core/`](../../conformance/hypervisor-core/).
Supersedes: overlapping plan prose when invariants conflict.
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: canonical
Implementation status: partial (authority/receipt gates are enforced across existing owner planes; registered multi-axis information-flow and declassification schemas, invariants, fixtures, and generated projections provide contract substrate only; the shared pre-effect evaluator and production propagation/enforcement across HTTP connectors, MCP, hosted models, browsers, memory, OutcomeRoom, ContextCell, general computer use, and inbound connectors/webhooks remain planned; local-agent pairing and TEE/cTEE/L1 items follow their owners and remain planned where not exposed by live routes)
Last implementation audit: 2026-07-18

## Canonical Definition

This document defines the non-negotiable authority, security, privacy, and execution boundaries for canonical Web4.

The canonical one-sentence wording of cross-cutting invariants is owned by the
invariant registry ([`invariants.md`](./invariants.md), `INV-*`); this file is
the security-domain application set. Where a numbered item below restates a
registry invariant, the registry wording wins on conflict.

## Alignment-Security Invariants

1. IOI's safety claim is execution-boundary alignment, not proof that every
   model's private cognition or goals are safe.
2. Models, agents, and workers may reason or propose; consequential effects
   cross reality only through daemon-mediated policy, authority, receipts, and
   verification.
3. Improvement proposals must not self-grant broader authority. Policy widening
   requires an external authority path such as wallet.network, organization
   policy, domain governance, or IOI L1 governance.
4. Autonomous-system upgrades are proposal-mediated. Agents may propose changes
   to governed modules, workflows, policies, tool bindings, model routes,
   schemas, and settlement rules, but only policy-bound governance may commit
   them.
5. The protected constitution, amendment gate, authority ceilings,
   ordering/finality, oracle/evidence, continuity, shutdown, and revocation
   boundaries cannot be committed through the ordinary improvement path
   (`INV-21`).
6. Bounded does not mean benevolent. The kernel constrains declared power and
   makes it auditable; it does not prove that the purpose selected by accountable
   principals is good.

## Authority Invariants

1. Workers/agents do not directly mutate canonical truth.
2. Workers/agents propose scoped changes; the fabric validates, merges, receipts, and settles them.
3. No effectful action without a tool contract and risk class.
4. No sensitive action without a persisted policy decision.
5. No policy-required approval without exact request hash, policy hash, scope, expiry, and revocation epoch.
6. No raw root secrets to agents, apps, marketplace workers, or untrusted runtimes.
7. wallet.network is the portable delegated authority plane for secrets,
   provider credentials, external effects, spend, decryption, high-risk
   approvals, and payments; local/domain governance may own local policy
   decisions that do not cross those boundaries.
8. Agentgres records authority artifacts, policy decisions, governance owner
   refs, and receipt links, but does not issue grants or own root secrets.
9. Providers may supply cognition, compute, storage, connectors, venues, and
   managed services, but they must not become the default authority root, secret
   owner, receipt truth, settlement root, or revocation plane.

## Exact-Action Authority Invariants

1. The immutable authority request, canonical reviewed representation,
   presentation evidence, authenticator ceremony evidence, authority-review
   decision, principal-authority resolution, grant issuance, final effect
   admission, execution, and outcome are separate facts. No signature, flag,
   root, receipt, or UI claim for one fact proves any of the others.
2. A policy-required exact-action chain binds the same principal, acting
   subject, product session, origin, authority-request body, authorization
   subject, reviewed-representation hash, presentation and ceremony evidence,
   one evaluation for every required factor/guardian posture ref, and, when
   portable-principal authority is claimed, exact authority binding coordinates
   and snapshot, plus policy, risk, expiry, grant, the exact
   `TemporalVerificationProfile` and `TemporalValidityEvaluation`, revocation
   posture, and required continuity-floor evidence through final effect
   admission.
   A missing required link, undefined comparison, stale dependency, or field
   substitution fails before the consequential invoker.
3. A WebAuthn assertion may establish the enrolled credential, exact challenge,
   RP/origin context, cryptographic signature, and required UP/UV and backup
   flags. UP/UV establishes ceremony-specific presence or local verification;
   it does not prove browser pixels, application-defined transaction display,
   comprehension, natural-person identity, biometric identity, device custody,
   or effect execution. A generic passkey factor is not a trusted presentation
   surface or authority grant by implication.
4. Presentation evidence is interpreted only through a versioned profile whose
   orthogonal dimensions include presentation operator/control boundary, exact
   representation binding, request/effect linkage, enrollment and attestation
   evidence, ceremony posture, freshness/replay handling, and independence from
   the proposing client. `Same client` and `independent` are not assurance
   tiers: either posture can be stronger or weaker depending on those separately
   bound properties.
5. Request-side `requested_auth_factor_posture_refs` and
   `requested_guardian_surface_refs` are requested or eligible posture, not
   evidence of participation. Only wallet/policy-minted review and ceremony
   evidence may name satisfied factors and guardians. Every required ref has
   exactly one hash-bound `satisfied`, `unsatisfied`, or `unknown` evaluation;
   approval requires all evaluations to be satisfied.
6. One-shot authority requires equality between the daemon-computed exact
   effect hash and the committed `exact_effect`. Batch authority requires a
   typed membership proof under the exact `batch_manifest` root. Standing
   authority requires a typed proof that the actual effect remains within the
   committed resources, destinations, budgets/calls, time, risk, and other
   `standing_envelope` constraints. An unknown membership or constraint result
   fails closed.
7. Editing any request, reviewed representation, destination, amount, effect
   arguments, batch member, or standing constraint creates successor
   request/review/challenge lineage. Approval or ceremony evidence from the
   predecessor cannot authorize the successor.
8. Interaction mode and authentication posture are independent: step-up is an
   authentication posture that may strengthen an interactive ceremony, not a
   third interaction mode. Only an interactive exact-effect review may be
   described as individual human review of that effect. Batch,
   session-envelope, silent-within-policy, and after-the-fact modes must
   disclose the envelope or policy actually reviewed and must not imply
   per-effect human comprehension or approval.

These exact-action invariants are release gates for the successor ceremony,
review-receipt, context-bound grant, effect-admission receipt, and WalletReceipt
contracts. They are not a claim that current registered v1/v2 authority or
receipt schemas already implement the complete chain. Final admission requires
typed `AuthorityEffectAdmissionReceiptV1` evidence; a generic tool or execution
receipt does not substitute for it.

## Temporal Verification Invariants

The canonical cross-cutting rule is `INV-36`; the clauses below are its
security-domain application.

1. A point timestamp, signature, sequence, owner epoch, or clock-health flag
   proves only its declared boundary fact. It cannot substitute for an
   absolute interval, challenge freshness, elapsed continuity, status-as-of,
   non-regression floor, or final resource fence.
2. Every consequential temporal claim binds an immutable
   `TemporalVerificationProfile`, exact evidence, source/failure-domain
   assumptions, conservative bounds, and a recomputable
   `TemporalValidityEvaluation`.
3. `TemporalValidityEvaluation` is evidence for the existing Platform
   Operability decision. It cannot issue or revoke authority, admit an effect,
   promote a writer, select a finality head, or create a resource fence.
4. Uncertainty overlapping an activation or expiry boundary is
   `indeterminate`, never rounded toward permission. The owning PEP may
   refresh, wait, narrow, or fail closed only as its policy allows.
5. Rollback resistance is relative to a named rollback domain. A
   per-namespace floor must survive outside that domain or be freshly rebound
   by admitted independent evidence; state restored with the protected subject
   cannot attest its own non-rollback.
6. Owner epochs remain scoped ordering generations and are never a global
   clock. Historical integrity, valid-as-of posture, and current authority are
   separate conclusions.
7. Disconnected continuation requires pre-admitted elapsed/boot continuity,
   holdover and revocation-exposure bounds, operation and effect budgets,
   replay/fencing posture, and reconnect behavior. Reboot, restore, continuity
   loss, or bound exhaustion cannot mint new authority or mission scope.

## Runtime Invariants

1. No workflow-only, benchmark-only, UI-only, or dogfooding-only runtime path for consequential work.
2. All surfaces use stable runtime envelopes.
3. Runtime nodes emit typed events and receipts.
4. Untrusted DePIN nodes cannot execute final effects directly.
5. Enterprise-private plaintext requires local, customer VPC, trusted hosted, or TEE execution.
6. Long-running operations require deadline, cancellation, and progress.
7. Compute/runtime nodes run Hypervisor Daemon-compatible profiles; SDKs, ADKs, GUIs,
   and TUI clients do not replace the execution substrate.
8. TUI, GUI, SDK, ADK, and harness controls must resolve to daemon/domain APIs
   for consequential work.
9. Training, evaluation, benchmark, routing, and delivery jobs run through
   Hypervisor Daemon-compatible runtime paths; product surfaces may initiate or
   inspect them but must not create private execution semantics.

## State Invariants

1. Agentgres is per-domain and does not run on IOI L1.
2. When explicitly selected, IOI L1 stores commitments and economic state, not
   operational traces.
3. Storage backends such as Filecoin/CAS store payload bytes, not Agentgres
   state, admission, or restore/import validity.
4. Local speculative state must be labeled speculative.
5. Projection state must expose freshness and source watermark.
6. Receipts are bundled; only sparse roots selected by an enrollment and
   settlement profile may reach IOI L1.
7. Sealed state archives are cold encrypted payloads; Agentgres owns archive
   refs and restore receipts, while authority providers and local/domain policy
   own restore authority. wallet.network is mandatory for portable delegated
   authority, decryption leases, secrets, restore/apply, and high-risk restore.
8. Hypervisor Node state-transition commitment records are Agentgres/domain truth. A root
   reaches an external settlement service only under the declared profile; IOI
   L1 is valid only for explicitly enrolled, selected services.
9. OutcomeRoom state has one declared hosted admission domain or a versioned
   federated admission policy. No shared board, chat, projection, leaderboard,
   or remote Agentgres database becomes universal truth by implication
   (`INV-15`).
10. Operational admission records that a domain accepted an assertion or
    decision; it does not make the semantic proposition universally true.
    Findings and ontology assertions retain uncertainty, evidence,
    contradiction, supersession, and dispute state.
11. One logical autonomous system retains identity across admitted node changes;
    a process, machine, replica, or UI is not the system identity (`INV-22`).
12. Desired topology and observed membership are separate. No node may claim a
    role, readiness, failure independence, durability, or authority that its
    membership and current evidence do not prove.

## Autonomous-System Continuity Invariants

1. Node admission, role change, writer promotion, authority-member change,
   consensus reconfiguration, migration, succession, dissolution, and network
   enrollment are distinct governed transitions.
2. Node count, replicated bytes, quorum durability, and failover do not imply
   consensus, multi-party independence, shared security, or public finality
   (`INV-23`).
3. A standby may not admit effects before catch-up, root verification, a new
   writer epoch, and proof that the old writer is fenced; ambiguous partitions
   fail closed (`INV-24`).
4. External facts remain provenance-bearing evidence. Signatures, receipts,
   votes, and consensus prove only their scoped claims, never external-world
   truth by themselves (`INV-25`).
5. Succession rotates/reissues authority within the constitution; death,
   incapacity, abandonment, dissolution, adoption, or key loss cannot widen
   purpose or power (`INV-26`).
6. Self-preservation, replication, resource acquisition, propagation, and
   recovery remain subordinate to governed membership, external revocation,
   ceilings, and decommission (`INV-28`).
7. A system claiming the intelligent-blockchain classification binds every
   admitted operation/batch to monotonic sequence, predecessor and operation
   commitments, admission proof, state root, and receipt root (`INV-29`).
8. Every durable system declares migration, export, successor/adoption,
   residual-obligation, authority-revocation, retirement, dissolution, and
   terminal evidence semantics before production promotion.

## File and Artifact Invariants

1. No artifact trusted by URL alone.
2. Hash/signature verification is mandatory.
3. Private plaintext requires key-release policy.
4. Public ciphertext is not public plaintext.
5. Sensitive artifacts must have privacy class.

## Model/Provider Invariants

1. No hardcoded provider in production-critical routing.
2. BYOK keys live in wallet.network.
3. Private tasks must not route to disallowed external providers.
4. Fallbacks must be policy-aware.
5. Model invocation receipts should be available for consequential runs.
6. Model routing selects cognition backends; worker routing selects accountable
   actors. A model must not be treated as the protocol-visible economic actor
   when a worker manifest, policy envelope, and receipts are required.
7. Provider-trust model routes require explicit privacy/authority posture and
   receipts; they must not be mislabeled as provider-independent custody,
   no-plaintext-custody, or wallet-governed authority.
8. Provider/model routes must bind access mode, unattended-automation rights,
   downstream customer-application or reseller/OEM rights, credential
   principal, the complete provider-use-of-customer-material and
   customer-use-of-output matrices, retention/ZDR posture, region, price limits,
   supported parameters, fallback classes, and exact rights-basis refs.
9. An aggregator is a replaceable route adapter, not an authority or privacy
   boundary. Provider or model fallback is a semantic substitution and must
   satisfy the same commercial, parameter, privacy, cost, authority, and
   verifier policy or fail closed.
10. `Private` for protected plaintext requires a custody-proven local,
    customer-boundary, dedicated, or equivalent no-provider-trust route. An
    aggregator or provider ZDR declaration alone does not establish that
    stronger posture.

## Worker Training Invariants

1. Worker Training improves capability; it does not grant authority.
2. A trained worker remains inert until wallet.network or equivalent policy
   authority grants bounded execution authority.
3. Training data, traces, examples, corrections, and evaluation artifacts must
   bind to policy, privacy class, source refs, and dataset commitments.
4. Fine-tuning is optional and cannot stand in for manifest, policy, benchmark,
   receipt, and authority requirements.
5. Training lineage, benchmark results, and evaluation receipts must not be used
   to claim universal intelligence or permanent routing superiority.
6. No model architecture or training profile is canonical by default.
   Subquadratic, hybrid, mutable-context, adapter-trained, and perpetually
   post-trained workers are supported classes only when bounded by policy,
   evaluation, receipts, rollback, and marketplace neutrality.
7. Raw online weight mutation from user input is not canonical truth. A deployed
   worker may propose context, adapter, route-policy, evaluation, or package
   updates, but promotion requires authority, regression gates, and receipts.
8. Worker Training must not treat raw blobs or connector payloads as domain
   truth when an ontology, object model, or data recipe exists.

## Bounded Improvement Campaign Invariants

1. An `ImprovementCampaign` is optional multi-epoch domain state. A direct,
   one-shot `UpgradeProposal` remains valid when adaptive search, sealed
   evaluation, or campaign lineage is unnecessary.
2. Search, Judgment, and Authority are logically separable. Candidate code must
   not read or write sealed cases, evaluator internals, score aggregation,
   resource/statistical/exposure ledgers, promotion controls, or recovery
   targets. A lower-assurance profile may collapse accountable principals only
   when that limitation is disclosed.
3. Every active `EvaluationEpoch` freezes the target and incumbent roots,
   admitted pursuit/component snapshot, metrics and minimum practical effects,
   hard constraints, evaluator versions and affiliations, visible/sealed/
   transfer compartments, stopping posture, and leakage/rotation policy.
4. Exploratory selection and confirmatory admission remain distinct. Repeated
   adaptive comparisons consume an ancestor-bound statistical-risk and
   evaluation-exposure allocation; inconclusive evidence stays inconclusive.
5. A candidate, evaluator successor, and controller or agenda successor may not
   validate and activate one another at the same evidence boundary. Evaluator
   changes begin in a fresh epoch and preserve the original verdict history.
6. Candidate and target-order descendants inherit the most restrictive
   applicable resource, statistical-risk, exposure, authority, protected-target,
   and learning-rights ceilings. Concurrent siblings receive disjoint atomic
   reservations rather than copies of one remaining allowance.
7. Sealed cases, labels, evaluator internals, protected monitor logic,
   unlicensed traces, and tenant-ineligible exhaust are not campaign learning
   material. Same-boundary reuse still requires `LearningEvidenceEligibility`;
   a `LearningEgressReceipt` is additionally required only for an attempted or
   completed institutional-boundary crossing.
8. Exact target base roots and conflict sets are mandatory for promotion.
   Stale-base or concurrently conflicting candidates require governed rebase or
   composition and fresh evaluation; approval is not a clerical merge license.
9. Safety, privacy, authority, security, rights, monitorability, and certified
   local physical-safety constraints are hard gates, not scalar score terms.
   Irreversible publication, disclosure, external decision, or physical effect
   cannot be described as rolled back merely because local configuration was
   restored.
10. `ImprovementEvidenceClaim` strength is bounded by its exact target lineage,
    frozen evidence contract, budget, transfer scope, evaluator validity,
    reproduction posture, and limitations. Representation of a higher target
    order is not proof of recursive improvement.

## Data and Ontology Invariants

1. Domain Ontologies define domain meaning; raw source schemas do not.
2. Connector payloads used for training, evaluation, projection, routing, or
   service delivery must pass through ConnectorMapping and DataRecipe
   boundaries.
3. PolicyBoundDataViews must gate read, transform, train, evaluate, export,
   publish, and route use of governed data.
4. DataRecipe and TransformationRun outputs must emit receipts for
   consequential training, evaluation, projection, or service outcomes.
5. EvaluationDatasets must bind ontology refs, rubric refs, benchmark refs,
   source commitments, privacy policy, and receipt roots.
6. OntologyProjections are serving views over Agentgres truth and must expose
   freshness, recipe version, policy, and source watermarks.
7. OntologyToWorkerPlan may propose workers, tools, evals, manifests, and
   training specs, but it cannot grant authority or bypass wallet.network.
8. Ontologies are locally canonical, namespaced, and versioned. Cross-domain
   work requires explicit compatibility negotiation, mappings, adapters,
   mapping receipts, and policy-bound views rather than one global ontology.
9. Ontology assertions bind valid/transaction time, source, observation
   context, uncertainty, supporting and contradicting evidence, applicability,
   supersession, and dispute state.
10. An ontology action is executable only through an OntologyActionContract
    binding typed inputs/outputs, state transition, pre/postconditions,
    invariants, capability/runtime/tool, risk, authority, approval/revocation,
    idempotency/retry, ambiguous-effect reconciliation, compensation,
    verification, evidence, receipts, and physical-safety posture when needed.

## Collaborative-Pursuit Invariants

1. Contributor scope never widens privacy, retention, custody, context,
   connector access, capability, or authority (`INV-16`).
2. Every participant message, artifact, patch, finding, mapping, evaluator
   change, and executable result remains tainted until bounded execution,
   policy, verification, and declared room/domain admission accept it
   (`INV-17`).
3. Participant consensus is evidence, not authority. Sybil identities,
   correlated reviewers, collusion, and self-verification must not manufacture
   an admission or reputation claim.
4. Participation, context, authority, resource, budget, tool, and work claims
   are bounded leases with TTL, heartbeat, renewal/release, quarantine, and
   revocation rather than ambient room membership.
5. Multi-model, multi-worker, multi-node, and multi-party are distinct. A
   first-party fleet remains one party regardless of how many models, clouds,
   nodes, or keys it uses (`INV-18`).
6. Open rooms require identity/eligibility policy, rate limits, queue
   backpressure, fair resource allocation, context/spend/network blast-radius
   limits, reviewer independence, anti-Sybil/collusion signals, reversible
   promotion, and challengeable verifier versions.
7. Positive, negative, inconclusive, invalid, exploit-finding, and superseded
   attempts remain separately attributable. No participant input promotes
   directly into durable memory, ontology, route priors, authority, or
   production capability.
8. Local-agent pairing proves possession, not authority or competence
   (`INV-20`). Pairing uses a one-time, short-lived challenge stored only as a
   commitment/hash, binds the claimed key and origin, limits attempts, supports
   expiry and revocation, and returns only the bootstrap actions required to
   submit a worker composition or room-participation request. It never returns
   a broad organization token, room database access, private context, budget,
   tools, or authority.
9. Prompt-only bootstrap is a low-assurance proposal lane. Pairing alone cannot
   raise a contribution above `attested`; admitted work must bind typed claims,
   isolated execution where applicable, evidence, declared verifiers, and the
   normal assurance ladder. Pairing never auto-promotes a guest into a private
   worker, organization worker, marketplace listing, reputation claim, or
   payout claimant.
10. Cooperation is never ambient (`INV-30`). A sovereign system remains
    complete locally; discovery, invitation, shared-room visibility, AIIP
    compatibility, or a task offer creates no obligation or access. External
    work requires exact-root terms acceptance and the separately admitted
    participant, work-claim, context, resource, budget, and authority leases.
11. Terms negotiation may keep private valuations and outside options private.
    Counteroffers remain proposals, amendments require new acceptance, and
    revocation or exit ends future access without erasing surviving obligations
    or historical evidence.

## Connector Invariants

1. Connector refresh tokens remain in wallet.network.
2. External send/spend/publish actions require appropriate approval.
3. Commerce purchase actions require explicit human or policy approval.
4. Tool outputs validate against declared schemas.
5. Tool failures feed quality/recovery ledgers.

## Information-Flow Invariants

1. Every context value that can influence a consequential effect carries a
   versioned `InformationFlowLabel` with origin, integrity, confidentiality,
   instruction-authority, egress destination/data-class, purpose, retention,
   and transitive derivation-parent axes. Missing or `unknown` axes fail closed
   at effect admission.
2. Labels join monotonically and deterministically. Summarization, model
   substitution, memory import, connector/tool output, and compaction retain
   the most restrictive applicable axes and complete parent closure; they do
   not sanitize, declassify, or confer instruction authority by transformation.
3. A consequential effect requires authoritative instruction separately from
   trustworthy content. Schema-valid external content, connector output, tool
   output, model output, or memory cannot become authority merely because it
   appears in a prompt or proposed arguments.
4. Private-or-higher context whose derivation includes untrusted content cannot
   egress. This lethal-trifecta refusal is not overridden by ordinary approval
   or declassification.
5. Every network-capable RuntimeToolContract revision declares its accepted
   data classes and exact destination patterns. `prim:net.request` never grants
   ambient network access; missing declarations, default deny, or a destination
   mismatch fail before the external invoker.
6. Protected egress requires a `DeclassificationApproval` binding the exact
   label and tool revision, canonical effect bytes, request hash, reviewed-
   representation hash, destination, purpose, target class, grant, receipt,
   status, and expiry. Any mutation invalidates it. Declassification never
   changes origin, derivation lineage, integrity, or instruction authority.
7. A blocked-before-egress claim reaches verified assurance only when the
   pre-effect decision and enforcement seam prove that the external invoker was
   not called. An error returned after network contact is not equivalent.

### Target information-flow boundary matrix

Current master does not implement the cross-plane information-flow evaluator or
the production propagation/enforcement rows below. The registered contracts and
fixtures make these requirements machine-checkable substrate; they do not prove
that an invoker, transport, browser, or persistence path enforces them.

| Boundary | Required target behavior | Honest compatibility boundary |
|---|---|---|
| non-MCP HTTP connector invoke | exact request, destination, label, and `RuntimeToolContract` are checked before credential use and immediately around the network invoker | other connector families and inbound webhook/subscription triggers remain 3B2 |
| live MCP tool backend | `tools/call` and `tools/list` require actual parent labels plus independently admitted effect authority; the restrictive join is recomputed before `McpManager`, and results return as untrusted `tool_output` | MCP resources, prompts, elicitation, tasks, Apps, and any unsupported live method are not implied by this tool-backend vertical |
| hosted model provider | blocking and streaming HTTP invocations recompute the effective label from actual input labels, bind the exact provider request/destination/tool contract, and fail before network contact; raw provider output returns as untrusted, content-only `model_output` | local/fixture execution is not external egress, and full router/ContextCell propagation beyond the hosted-provider owner remains 3B2 |
| browser action handler | every routed browser variant requires an independently supplied `BrowserInformationFlowContext`. Navigation binds its exact URL and typed action; click, hover/pointer, synthetic click, scroll, type/select/key, copy/paste, scrolling find, wait/compound follow-up, upload, dropdown selection, history-back, tab-switch, and tab-close bind the cached active URL plus their exact typed action before any action driver call. Snapshot, canvas, screenshot, dropdown-option, tab-list, and non-scrolling find observations validate their parent set before the read and every returned result is labeled `external_untrusted`, `untrusted`, with no instruction authority and full available parent closure | the production action-execution owner does not yet attach canonical parent/authority/tool-contract context, so browser tools are intentionally fail-closed rather than falsely reported available. This seam is typed-action admission, not browser network-stack interception: redirects, response/download bytes, resolved click coordinates, history targets, target-tab URLs, and ambient page requests are not independently intercepted or destination-enforced; general computer use remains separate |
| Agentgres memory write/edit | the target `persist_record` seam requires supplied parent labels, treats a replayed prior record label as an additional parent, recomputes a memory-import or summary label, and stores the full restrictive label with the payload | legacy unlabeled write/edit requests fail closed; delete/policy/event paths and portable export admission are separate owners |

No row above means that a caller-supplied output/effect label is trusted as the
effective result. Effect authority is joined with actual data parents;
boundary-produced model, browser, MCP, and memory values cannot mint integrity
or instruction authority. Until the complete production propagation path
lands, these target seams are unavailable rather than silently treated as
covered.

In particular, the browser handler must not infer parent labels from
`AgentState`, browser content, model-authored tool arguments, or copied receipt
fields. Its availability gate remains closed until the governed execution owner
can supply canonical parents and an independently admitted authority and tool
contract. Admitting a compound browser action binds the declared follow-up
arguments as part of the typed action; it does not prove that page script,
redirect, download, or target resolution matched a lower-level network or DOM
event that this seam does not observe.

## Marketplace Invariants

1. Default harness remains neutral.
2. Marketplace worker internals cannot be silently cloned.
3. Contributions receive attribution.
4. Service redirection is opt-in unless the service is explicitly ordered.
5. Quality/reputation roots should preserve the assurance ladder: attributable
   receipts, evidence, declared verification, acceptance, adjudication, and
   settlement are distinct states.
6. MoW routing must be explainable and receipt-backed when it affects payment,
   reputation, user trust, or marketplace ranking.
7. Work Credits are non-transferable product credits and never distribute as
   labor payout. External compensation requires a separately funded budget or
   service order and the declared evidence, verification, acceptance,
   adjudication, and settlement path. A `ContributionReceipt` preserves
   attribution and lineage; it does not by itself authorize payment, and raw
   token usage, attention, popularity, or hidden platform preference never does.
8. Attribution is not allocation (`INV-31`). Reward, reputation, licensing, or
   outcome rights require the contribution policy and accepted terms in force
   when work was awarded plus the declared verification, acceptance or
   adjudication, and settlement path.

## Institutional Learning Boundary Invariants

1. An `InstitutionalLearningBoundaryProfile` is a versioned scope ceiling and
   compiled policy input, not blanket consent, an IP-right generator, an
   authority grant, a privacy proof, or a new truth store.
2. Every governed memory, evaluation, analytics, dataset, training,
   distillation, package-improvement, or export use binds the effective profile,
   an individual `LearningEvidenceEligibilityEnvelope`, and applicable source,
   participant, teacher, provider/model-output, license, consent, retention,
   destination, and route-rights evidence. Training/distillation uses its
   `training_compatibility` profile, not a second eligibility decision.
3. Constraint composition is the most restrictive intersection. Organization,
   project, system, session, worker, source, and model-route policy may narrow
   one another; no broad parent profile, majority permission, aggregation,
   transformation, mapping, or de-identification silently widens a prohibited
   use.
4. Provider permissions and customer permissions are directional. Provider
   no-training/ZDR posture does not grant customer distillation rights, and
   customer output-reuse rights do not grant the provider permission to learn
   from prompts, corrections, tool traces, evals, memory, or institutional
   context.
5. Rights, obligations, and revocation propagate transitively through views,
   memory, evals, datasets, caches, adapters, checkpoints, models, workers,
   packages, routes, releases, and exports. Historical receipts remain evidence
   but never perpetual future-use permission.
6. Recall, quarantine, source deletion, route disablement, payload deletion,
   re-evaluation, rebuild, and retraining are distinct observable actions.
   Verified model unlearning requires a declared property, method, evaluation,
   verifier, and assurance result; none of those other actions implies it.
7. No provider-native thread, vector store, hosted memory, eval store, tuning
   service, or opaque session is the sole durable copy of institution-owned
   accepted memory, corrections, evals, ontology state, or derivative lineage
   needed for provider-independent operation. This creates no right to
   provider-owned weights or hidden state.
8. Managed-worker prompts, outputs, traces, corrections, evals, accepted
   memory, instance-specific datasets, adapters, and derivatives remain
   buyer-bound by default. Seller, platform, provider, and cross-tenant reuse
   requires an explicit purpose-bound eligible export; installation, hosting,
   support, payment, benchmarking, or a marketplace receipt is not consent.
9. A receipt proves only the declared admission, policy, routing, egress,
   transformation, deletion, recall, evaluation, or verification fact it binds.
   It cannot prove hidden provider retention, internal training, deletion,
   cross-customer reuse, or unlearning by assertion.
10. Model-swap continuity freezes the system/profile/state root,
    policy-filtered memory, package/workflow/tool contracts, and eval floors;
    disables the incumbent and provider-only durable state; and reruns the
    candidate through ordinary eval, canary, rollback, promotion, and Governance
    gates. It proves only observed continuity under the declared envelope and
    grants no authority or universal model-equivalence claim.

## Mainnet Invariants

1. IOI L1 gas applies to registry/rights/settlement boundaries, not every runtime step.
2. L2s/rollups are scaling contingencies, not default first-party architecture.
3. Independent L1s may register for discovery; IOI-compatible systems need not
   connect to or settle into IOI.
4. When explicitly selected, Mainnet is the notary, not the notebook.
5. Hypervisor Nodes settle autonomous work locally. Explicitly enrolled systems
   may use IOI L1 for selected shared-trust and economic-finality services.
6. Compatibility, connection, and shared security are distinct assurance
   claims. No L0 use, AIIP message, local receipt, or node transition creates an
   ambient L1 fee (`INV-27`).

## Privacy Doctrine

> **Share permitted semantic projections and intelligence, not raw context. Share ciphertext availability, not plaintext readability. Share attributable receipts and policy-bound evidence, not secrets or universal-truth claims.**

## Execution Privacy Doctrine

> **Without TEE/MPC/FHE, do not make the host blind by hiding execution from it. Make the host unable to see enough or do enough to matter.**

## One-Line Doctrine

> **Canonical Web4 is safe only when authority, execution, state, payloads, and settlement remain separated by design.**
