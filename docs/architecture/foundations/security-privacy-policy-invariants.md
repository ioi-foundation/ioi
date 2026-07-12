# Security, Privacy, and Policy Invariants

Status: canonical architecture authority.
Canonical owner: this file for public security/privacy/policy invariants;
conformance details live in
[`../../conformance/hypervisor-core/`](../../conformance/hypervisor-core/).
Supersedes: overlapping plan prose when invariants conflict.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: partial (authority/receipt gates enforced across built planes; TEE/cTEE/L1 items follow their owners)
Last implementation audit: 2026-07-05

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
2. IOI L1 stores commitments and economic state, not operational traces.
3. Storage backends such as Filecoin/CAS store payload bytes, not Agentgres
   state, admission, or restore/import validity.
4. Local speculative state must be labeled speculative.
5. Projection state must expose freshness and source watermark.
6. Receipts are bundled; only sparse roots may reach IOI L1.
7. Sealed state archives are cold encrypted payloads; Agentgres owns archive
   refs and restore receipts, while authority providers and local/domain policy
   own restore authority. wallet.network is mandatory for portable delegated
   authority, decryption leases, secrets, restore/apply, and high-risk restore.
8. Hypervisor Node local settlement records are Agentgres/domain truth until a
   selected root is anchored to IOI L1 for public trust, dispute, reputation, or
   economic settlement.
9. OutcomeRoom state has one declared hosted admission domain or a versioned
   federated admission policy. No shared board, chat, projection, leaderboard,
   or remote Agentgres database becomes universal truth by implication
   (`INV-15`).
10. Operational admission records that a domain accepted an assertion or
    decision; it does not make the semantic proposition universally true.
    Findings and ontology assertions retain uncertainty, evidence,
    contradiction, supersession, and dispute state.

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
   principal, data-collection/retention posture, region, price limits,
   supported parameters, fallback classes, and training/distillation rights.
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

## Connector Invariants

1. Connector refresh tokens remain in wallet.network.
2. External send/spend/publish actions require appropriate approval.
3. Commerce purchase actions require explicit human or policy approval.
4. Tool outputs validate against declared schemas.
5. Tool failures feed quality/recovery ledgers.

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
7. Subscription-credit and outcome payouts should be based on verified
   ContributionReceipts, not raw token usage, attention, popularity, or hidden
   platform preference.

## Mainnet Invariants

1. IOI L1 gas applies to registry/rights/settlement boundaries, not every runtime step.
2. L2s/rollups are scaling contingencies, not default first-party architecture.
3. Independent L1s register for discovery; they need not settle into IOI.
4. Mainnet is the notary, not the notebook.
5. Hypervisor Nodes settle autonomous work locally; IOI L1 settles machine labor
   globally.

## Privacy Doctrine

> **Share permitted semantic projections and intelligence, not raw context. Share ciphertext availability, not plaintext readability. Share attributable receipts and policy-bound evidence, not secrets or universal-truth claims.**

## Execution Privacy Doctrine

> **Without TEE/MPC/FHE, do not make the host blind by hiding execution from it. Make the host unable to see enough or do enough to matter.**

## One-Line Doctrine

> **Canonical Web4 is safe only when authority, execution, state, payloads, and settlement remain separated by design.**
