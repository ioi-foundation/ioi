# Model Router, BYOK, and Run-to-Idle Specification

Status: canonical architecture authority.
Canonical owner: this file for model routing, supply-portfolio, commercial
route-rights, BYOK/BYOA, privacy/fallback, and run-to-idle doctrine; low-level
model-router API lives in [`model-router-api-byok-and-mounting.md`](./api-byok-mounting.md).
Supersedes: overlapping model/provider prose when routing or BYOK boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: partial (model-route registry and local Ollama mounting
built; sealed BYOK and multi-transport session execution are unimplemented, and
only active/available Ollama routes are currently bindable for execution;
custody and commercial-rights policy remain partial)
Last implementation audit: 2026-07-05

## Canonical Definition

**The Model Router is the IOI runtime subsystem that selects and invokes model
routes according to task, quality, privacy, custody, cost, latency, commercial
rights, primitive capability constraints, authority scopes, and policy.**

It should support foundation-model APIs, direct and dedicated provider
capacity, local model mounting, BYOK/BYOA, aggregator adapters, open-model
serving, run-to-idle infrastructure, and decentralized/hosted compute providers.

The model router belongs inside the runtime/node contract. Model weights,
provider endpoints, local model servers, and hosted cognition backends are
mounted by deployment profile. They are not part of the Hypervisor Node binary
or architecture default.

Model routing is not Worker routing. Model routing selects a cognition backend:
OpenAI, Anthropic, Gemini, local open-weights, fine-tuned models, MoE systems,
or provider-routed inference. Worker routing selects an accountable actor with
a manifest, policy envelope, tools, runtime requirements, receipt obligations,
license terms, and settlement identity. Mixture of Experts is model/provider
routing. Mixture of Workers is labor routing.

Product naming rule:

> **Expose `Models` to users; preserve `ModelRoute` as runtime truth.**

Hypervisor composer controls, Applications catalog entries, and setup flows
should usually say `Model`, `Reasoning`, and `Speed`. The implementation still
records `ModelRoute`, `ModelEndpoint`, `ModelConfiguration`,
`ReasoningEffort`, `ServiceTier`, custody posture, fallback policy, and
receipt obligations for daemon/runtime use.

Execution-policy naming rule:

> **Expose `Auto`, `Pinned`, and `Compare`; preserve every candidate, route,
> attempt, verifier, fallback, rights, and cost decision as runtime truth.**

Model serving compute follows the same runtime-node rule as worker execution:
remote, hosted, DePIN, TEE, and customer-boundary model jobs should be
represented as compute sessions behind Hypervisor Daemon runtime-node profiles or
explicit model-provider endpoints. The SDK may call the router; it does not own
model execution.

## Core Doctrine

> **Hypervisor should not care whether a model is OpenAI, local LM Studio, tenant BYOK, vLLM on a sleeping GPU, or a decentralized cloud worker. It should call a model route through policy.**

The provider-neutral abstraction must not erase the contract behind a route.
Every candidate is eligible only when automation, downstream application,
credential-principal, data-use, retention, region, training/distillation,
fallback, and customer-facing rights permit the requested work. A route that
cannot prove its required right fails closed.

Node packaging doctrine:

> **The node contains model routing and invocation boundaries. The model itself
> is a mounted cognition backend unless a deployment profile explicitly bundles
> local weights.**

Workers may internally use model routes, including fine-tuned or MoE-backed
routes, but benchmarks, authority scopes, receipts, ContributionReceipts,
disputes, royalties, reputation, and MoW routing eligibility attach to the
worker identity and manifest rather than merely to the model that powered one
reasoning step.

Foundation-model subscriptions are not production inference inventory. Do not
pool, share, browser-automate, or resell named-user chat/workspace seats as
machine capacity. Provider-approved named-user harness access may be mounted as
user-scoped BYOA for that user's interactive Goal Space, but it is not IOI
worker-market inventory. Managed unattended work uses API, dedicated endpoint,
expressly negotiated inference, self-hosted, or explicitly authorized OEM/
reseller capacity.

The model router may record model architecture and training-profile metadata,
but that metadata is descriptive. It does not make a model the protocol actor.
Dense transformers, MoE systems, subquadratic or nonquadratic backends, hybrid
attention/state models, mutable-context systems, retrieval-augmented systems,
adapters, and deterministic verifier models are cognition choices mounted
behind workers or workflows.

## Model Surfaces

Model availability is profile-dependent. Supported deployment shapes include:

- bundled local model weights for small, offline, demo, or sovereign profiles;
- mounted local files such as GGUF, MLX, ONNX, SafeTensors, or equivalent
  model artifacts;
- local servers such as LM Studio, Ollama, vLLM, llama.cpp, or
  OpenAI-compatible endpoints;
- BYOK provider APIs brokered through wallet.network;
- user-scoped, provider-approved BYOA interactive harnesses;
- direct provider APIs, managed endpoints, dedicated capacity, and negotiated
  enterprise inference agreements;
- policy-qualified aggregator adapters such as OpenRouter for breadth,
  overflow, discovery, and fallback;
- hosted IOI or provider model pools;
- TEE, customer VPC, or DePIN compute sessions;
- specialized verifier, embedding, reranker, vision, code, or speech endpoints.

Bundling model weights is a deployment profile, not the architecture default.

## Model-Weight Custody

cTEE/private workspace guarantees protect workspace state, prompts, private
files, strategy heads, credentials, and declassification paths. They do not
magically protect proprietary model weights after those weights are mounted as
normal plaintext files or tensors inside a root-owned remote GPU node.

Every route that uses non-public model weights must declare a
`ModelWeightCustodyProfile` separately from its `ExecutionPrivacyPosture`.

```yaml
ModelWeightCustodyProfile:
  profile_id: model_weight_custody://...
  weight_class:
    public_open_weight |
    user_local_private_weight |
    remote_api_private_weight |
    provider_trust_remote_mount |
    tee_or_customer_cloud_mount |
    forbidden_plaintext_mount
  weight_owner: user | org | provider | public | marketplace_package
  mount_target:
    local_device | user_owned_node | rented_gpu |
    customer_cloud | provider_api | tee_session | none
  remote_provider_can_read_weights: true | false
  required_controls:
    - none
    - wallet_authorized_api_capability
    - local_only
    - customer_account_boundary
    - tee_attestation
    - no_remote_plaintext_mount
    - explicit_provider_trust_acceptance
  user_disclosure: string
```

Canonical lanes:

| Lane | Weight custody claim | Valid use |
| --- | --- | --- |
| `public_open_weight` | The weights are public or intentionally shareable. | Rented GPUs, DePIN nodes, local machines, hosted pools. |
| `user_local_private_weight` | The weights remain on a user-owned or customer-controlled machine. | Local/private model serving, user-owned GPU, enterprise cluster. |
| `remote_api_private_weight` | The provider keeps its own proprietary weights behind an API; the user does not receive or mount them. | Foundation-model APIs and managed private model services. |
| `provider_trust_remote_mount` | Proprietary user/org weights are mounted on a provider-visible node under contract or accepted trust. | Explicit provider-trust deployments only. |
| `tee_or_customer_cloud_mount` | Proprietary weights are mounted only inside an accepted TEE/customer-cloud/control boundary. | Confidential GPU lanes, customer VPCs, enterprise controlled accounts. |
| `forbidden_plaintext_mount` | The requested mount would expose proprietary weights to an untrusted root provider. | Must be blocked unless the user changes route or accepts provider-trust. |

Required product disclosure:

```text
Protecting a private workspace is not the same as protecting proprietary model
weights. A rented GPU can safely run public/open weights under cTEE workspace
rules, but proprietary weights need local custody, provider API custody,
customer-controlled infrastructure, accepted confidential compute, or explicit
provider-trust approval.
```

Admission rule:

```text
If `remote_provider_can_read_weights=true` and the weight class is not public,
the route cannot be presented as private-native. It is provider-trust or
forbidden until policy, wallet approval, and user disclosure accept that lane.
```

Managed execution mode rule:

```text
Standard:
  cTEE/private-native operating substrate by default for IOI-managed execution;
  provider-trust model routes may be used with disclosure and receipts.

Private:
  Standard substrate plus no-provider-trust model routing for protected data;
  use open-weight or user-controlled models inside local, BYO private node,
  customer-boundary/customer-cloud, cTEE, TEE, or another custody-proven route.
```

`Private` is not satisfied by a hosted foundation-model API receiving protected
plaintext, even when the workspace runtime is cTEE-shaped. `Standard` may accept
that provider-trust route with disclosure; `Private` must route protected
plaintext away from provider-readable model context or block/downgrade before
execution.

Supported surfaces should include:

- OpenAI-compatible APIs;
- Anthropic;
- Gemini;
- local OpenAI-compatible servers;
- LM Studio;
- Ollama;
- vLLM;
- llama.cpp;
- embeddings;
- rerankers;
- vision models;
- code models;
- verifier models;
- local/private enterprise models;
- subquadratic or nonquadratic long-context models;
- hybrid attention/state models;
- retrieval-augmented or context-graph models;
- adapter-backed or distillation-trained models;
- mutable-context and perpetually post-trained model packages.

## Model Registry

Model records should include:

```yaml
ModelEndpoint:
  id: local_lmstudio_qwen
  provider: lmstudio
  base_url: http://localhost:1234/v1
  api_format: openai_compatible
  models:
    - qwen-coder
  privacy: local
  supported_model_roles:
    - code
    - chat
  context_length: 128000
  architecture_profile: dense_transformer | moe | subquadratic | hybrid_attention_state | retrieval_augmented | mutable_context | deterministic_verifier | custom
  active_context_strategy: full_attention | local_window | state_scan | sparse_attention | retrieval_packets | external_context_graph | hybrid
  context_mutability: none | external_context_only | adapter_promoted | package_revision
  post_training_support:
    - context_update
    - adapter_training
    - route_policy_training
    - eval_generation
  tool_calling: false
  cost_profile: local
  latency_profile: interactive
```

## BYOK

BYOK keys and BYOA credential bindings belong in wallet.network, not node
config files. A customer-owned credential remains customer-owned; IOI brokers
bounded use and charges explicitly for conductor/runtime/governance value
rather than hiding a provider-spend markup.

Flow:

```text
workflow/model node declares prim:model.invoke and any required scope:model.* authority scope
→ runtime asks wallet.network
→ wallet.network checks policy and grants operation-scoped authority
→ model router invokes provider
→ receipt emitted
```

BYOA is narrower than BYOK. It may connect a provider-approved named-user
harness subscription for the named user and approved interactive automation
mode. It must preserve credential principal, access mode, automation right,
downstream right, and provider terms; it must never become pooled capacity.

## Supply Portfolio And Route Rights

Model supply is a portfolio rather than one provider or aggregator boundary:

| Supply | Preferred role | Required posture |
| --- | --- | --- |
| Direct provider API, managed endpoint, dedicated capacity, or negotiated inference agreement | high-volume, high-assurance, feature-fidelity, regional/SLA, or committed routes | first-class adapter and versioned direct contract |
| Aggregator such as OpenRouter | bootstrap breadth, long-tail models, price/availability discovery, policy-qualified fallback, overflow, and experimentation | replaceable procurement/routing adapter behind Hypervisor; never sole inference authority |
| Customer BYOK/BYOA | customer cost ownership, existing commitments, user-selected eligible harnesses | customer-owned credential binding; no key transfer or hidden provider markup |
| Open/self-hosted weights | sovereignty, Private/no-provider-trust execution, customization, training rights, and concentration/COGS hedge | explicit license, custody, runtime, and attestation posture |

OpenRouter or any equivalent aggregator is an adapter, not IOI's business model
or trust boundary. Its own terms and every underlying provider/model term still
apply. IOI must obtain explicit enterprise/OEM authorization when the intended
customer-facing behavior could resemble raw API resale or a competing routing
service. An aggregator route must remain disableable without changing the
Worker or GoalRun contract.

A provider/model term, commercial authorization, endpoint posture, or data
policy change invalidates the cached eligibility decision. The route is killed
or quarantined until a reviewed contract version is admitted; availability
alone never re-enables it.

Provider or aggregator prompt-logging, data-retention, secondary-use, and
training opt-ins are off for protected Goal Space payloads. Enabling any such
use requires an explicit eligible data class, policy/consent ref, disclosed
license effect, and route receipt; it can never be inherited from an
aggregator's broad account default.

Every candidate resolves a versioned route-rights contract before admission:

```yaml
ModelRouteRightsContract:
  contract_id: model-route-contract://...
  contract_version: semver_or_hash
  contract_hash: sha256:...
  admitted_policy_hash: sha256:...
  valid_from: timestamp
  valid_until: timestamp | null
  commercial_posture:
    direct | aggregator | customer_byok | customer_byoa | self_hosted
  access_mode:
    named_human_seat | api | dedicated_endpoint | self_hosted
  customer_facing_allowed: boolean
  reseller_oem_authorized: true | false | not_required
  automation_right:
    interactive_only | unattended_allowed | negotiated
  downstream_right:
    internal_only | customer_application | reseller_oem
  credential_principal:
    named_human | service_account | customer_owned
  provider_terms_version_ref: terms://...
  model_terms_version_ref: terms://...
  endpoint_ref: endpoint://...
  model_version_ref: model://...
  provider_allowlist: [provider://...]
  data_collection: allow | deny
  zdr_required: boolean
  retention_policy_ref: policy://... | null
  region_ref: region://... | null
  fallback_classes: [string]
  max_price_ref: price-schedule://... | null
  required_parameters: [string]
  output_training_right:
    prohibited | noncompeting_only | expressly_licensed | open_license
  status: active | quarantined | expired | superseded | revoked
```

Inference permission does not imply training or distillation permission.
Foundry must use open licenses or expressly licensed teacher/output rights for
reusable training and distillation.

## Model Profiles

Model routing should support profiles:

```text
fast
reasoning
local_private
code
vision
verifier
summarizer
redaction_safety
embedding
rerank
intake_routing
long_context_memory
adapter_candidate
```

## Routing Inputs

The router should consider:

- task class;
- risk class;
- privacy class;
- tool needs;
- context size;
- active-context strategy;
- context mutability;
- declared training profile;
- modality;
- cost budget;
- latency budget;
- local/remote policy;
- quality history;
- fallback policy;
- route-rights and applicable-terms versions;
- access/automation/downstream/customer-facing rights;
- data collection, retention/ZDR, region, provider allowlist, and required
  parameter support;
- user/org preferences.

## Auto, Pinned, And Compare Policies

```text
Auto / 1-of-N
  choose the cheapest eligible route expected to satisfy quality, privacy,
  authority, latency, context, custody, and route-rights requirements;
  optionally use a declared cheap-first verifier cascade and escalate only
  after acceptance fails

Pinned
  invoke the selected eligible route; fail closed on ineligibility or
  unavailability unless a policy-approved fallback was explicitly authorized

Compare / N-of-N
  invoke several declared routes, preserve each admitted attempt, and apply a
  named verifier/comparison/synthesis rule
```

`1-of-N` is a routing policy, not a subscription SKU. A fallback that changes
the underlying model, provider, privacy posture, commercial rights, or material
capability is a semantic substitution. It must remain inside the route
contract, emit model-route/model-invocation receipt evidence, and re-run the
applicable acceptance or verifier path. MoW `RoutingDecisionReceipt` remains
the accountable Worker-routing object, not the model/provider fallback object.
Aggregator defaults must not silently widen provider choice,
data collection, or fallback eligibility; governed sensitive routes pin or
allowlist providers, deny data collection, require declared parameters, cap
price, and fail closed.

## Run-to-Idle Lifecycle

Model/runtime resources should support:

```text
unavailable
cold
warming
ready
busy
draining
idle
sleeping
failed
```

This enables:

- local model mounting;
- server model pools;
- GPU lifecycle management;
- decentralized compute allocation;
- zero-to-idle costs.

## Compute Provider Interface

For open/decentralized model serving:

```text
ComputeProvider.quote(model, hardware, duration, privacy, region)
ComputeProvider.provision(job_spec)
ComputeProvider.health()
ComputeProvider.stop()
ComputeProvider.receipt()
```

Possible providers:

- local machine;
- hosted IOI pool;
- enterprise VPC;
- DePIN compute;
- TEE compute;
- third-party model API.

Privacy posture rule:

```text
third-party model API over sensitive plaintext
  -> provider-trust posture

third-party model API over public/redacted/declassified inputs
  -> redacted-API posture

local/rented/customer-controlled open model with no sensitive plaintext sent to
third-party APIs
  -> private-native posture when cTEE custody checks pass
```

An aggregator ZDR or no-logging control may satisfy a declared `Standard`
route when contract and policy permit it. It does not by itself satisfy strict
`Private` / no-provider-trust posture because the aggregator and selected
upstream provider still participate in request routing. `Private` resolves to a
custody-proven local, self-hosted, customer-boundary, direct confidential, or
equivalent no-provider-trust path, or it blocks.

The model router MUST NOT label a route as cTEE no-plaintext-custody when
sensitive plaintext is sent to a third-party model API without a separately
verifiable private-compute guarantee.

Weight custody rule:

```text
rented GPU + public/open weights
  -> valid cTEE workspace lane when private workspace state stays sealed/redacted

rented GPU + proprietary user/org weights mounted as plaintext
  -> forbidden_plaintext_mount unless the user explicitly accepts
     provider-trust or supplies an accepted TEE/customer-cloud boundary

foundation/provider API with provider-owned proprietary weights
  -> remote_api_private_weight for weights; input/output privacy still depends
     on ExecutionPrivacyPosture
```

## Model Invocation Receipt

The sole field-level schema is
[`ModelInvocationReceipt`](../daemon-runtime/events-receipts-delivery-bundles.md#model-invocation-and-invoice-reconciled-usage-receipts).
It is mandatory for managed, billed, fallback, `Compare`, consequential, or
customer-visible invocations. A strictly local, unmetered, non-consequential
developer invocation may omit a durable receipt only when policy explicitly
allows ephemeral execution and no result is promoted, shared, billed, accepted,
or used as evidence.

The receipt must preserve each attempted route, failure class, fallback or
escalation, and supplier-billed status when the supplier exposes it. Raw tokens
are cost telemetry, not the universal product unit; Work Credits may normalize
heterogeneous model, accelerator, tool, storage, verifier, and runtime cost
while receipts retain the accountable breakdown.

## Invariants

1. No hardcoded model provider in product-critical runtime paths.
2. Private tasks must not route to disallowed external providers.
3. BYOK keys live in wallet.network.
4. Provider fallback must be policy-aware.
5. Runtime nodes should emit model routing explanations for audits.
6. Run-to-idle serving must not break workflow determinism or receipt generation.
7. The Hypervisor Node binary must not assume embedded model weights. Embedded or
   bundled weights are allowed only when declared by a deployment profile.
8. Service modules and workers invoke models through routes, not direct
   assumptions about local files, provider names, or bundled binaries.
9. cTEE/private workspace custody does not protect proprietary model weights
   mounted as plaintext on a root-owned remote node.
10. Proprietary weights require local/customer custody, provider API custody,
    accepted TEE/customer-cloud custody, or explicit provider-trust approval.
11. Named-user chat/workspace subscriptions are not pooled managed-worker
    capacity. User-scoped BYOA remains bound to the named principal and
    provider-approved automation mode.
12. Every unattended or customer-facing route must have an admitted versioned
    commercial-rights contract. Missing required rights fail closed.
13. Aggregators remain replaceable adapters. Provider/model terms, privacy,
    retention, region, data-use, and commercial rights are not erased by one
    API format.
14. `Auto`, `Pinned`, and `Compare` preserve actual attempt, fallback,
    verifier, route-rights, provider/model, and cost lineage.
15. A model/provider substitution is a semantic routing decision, not a silent
    availability detail.
16. Inference permission and output training/distillation permission are
    separate rights.

## One-Line Doctrine

> **Use the best eligible model route, preserve its rights, custody, cost, and
> fallback truth, run it where policy permits, and let the runtime sleep when it
> is not needed.**
