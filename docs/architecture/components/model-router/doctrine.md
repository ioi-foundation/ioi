# Model Router, BYOK, and Run-to-Idle Specification

Status: canonical architecture authority.
Canonical owner: this file for model routing doctrine; low-level model-router API lives in [`model-router-api-byok-and-mounting.md`](./api-byok-mounting.md).
Supersedes: overlapping model/provider prose when routing or BYOK boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-05-24.
Doctrine status: canonical
Implementation status: partial (model-route registry, BYOK, and local mounting built; custody-lane taxonomy partially exercised)
Last implementation audit: 2026-07-05

## Canonical Definition

**The Model Router is the IOI runtime subsystem that selects and invokes model routes according to task, privacy, cost, latency, quality, primitive capability constraints, authority scopes, and policy.**

It should support foundational model APIs, local model mounting, BYOK, open-model serving, run-to-idle infrastructure, and decentralized/hosted compute providers.

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

Model serving compute follows the same runtime-node rule as worker execution:
remote, hosted, DePIN, TEE, and customer-boundary model jobs should be
represented as compute sessions behind Hypervisor Daemon runtime-node profiles or
explicit model-provider endpoints. The SDK may call the router; it does not own
model execution.

## Core Doctrine

> **Hypervisor should not care whether a model is OpenAI, local LM Studio, tenant BYOK, vLLM on a sleeping GPU, or a decentralized cloud worker. It should call a model route through policy.**

Node packaging doctrine:

> **The node contains model routing and invocation boundaries. The model itself
> is a mounted cognition backend unless a deployment profile explicitly bundles
> local weights.**

Workers may internally use model routes, including fine-tuned or MoE-backed
routes, but benchmarks, authority scopes, receipts, ContributionReceipts,
disputes, royalties, reputation, and MoW routing eligibility attach to the
worker identity and manifest rather than merely to the model that powered one
reasoning step.

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

BYOK keys belong in wallet.network, not node config files.

Flow:

```text
workflow/model node declares prim:model.invoke and any required scope:model.* authority scope
→ runtime asks wallet.network
→ wallet.network checks policy and grants operation-scoped authority
→ model router invokes provider
→ receipt emitted
```

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
- user/org preferences.

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

Every significant model invocation should optionally emit:

```yaml
ModelInvocationReceipt:
  route_id: reasoning_high
  selected_provider: openai_byok
  model_id: ...
  input_hash: ...
  output_hash: ...
  privacy_class: internal
  policy_hash: ...
  cost_estimate: ...
  latency_ms: ...
```

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

## One-Line Doctrine

> **Use the best model available, run it where policy permits, and let the runtime sleep when it is not needed.**
