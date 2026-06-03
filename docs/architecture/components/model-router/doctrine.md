# Model Router, BYOK, and Run-to-Idle Specification

Status: canonical architecture authority.
Canonical owner: this file for model routing doctrine; low-level model-router API lives in [`model-router-api-byok-and-mounting.md`](./api-byok-mounting.md).
Supersedes: overlapping model/provider prose when routing or BYOK boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-05-24.

## Canonical Definition

**The Model Router is the IOI runtime subsystem that selects and invokes model routes according to task, privacy, cost, latency, quality, primitive capability constraints, authority scopes, and policy.**

It should support foundational model APIs, local model mounting, BYOK, open-model serving, run-to-idle infrastructure, and decentralized/hosted compute providers.

The model router belongs inside the runtime/node contract. Model weights,
provider endpoints, local model servers, and hosted cognition backends are
mounted by deployment profile. They are not part of the Autopilot node binary
or architecture default.

Model routing is not Worker routing. Model routing selects a cognition backend:
OpenAI, Anthropic, Gemini, local open-weights, fine-tuned models, MoE systems,
or provider-routed inference. Worker routing selects an accountable actor with
a manifest, policy envelope, tools, runtime requirements, receipt obligations,
license terms, and settlement identity. Mixture of Experts is model/provider
routing. Mixture of Workers is labor routing.

Model serving compute follows the same runtime-node rule as worker execution:
remote, hosted, DePIN, TEE, and customer-boundary model jobs should be
represented as compute sessions behind IOI daemon/runtime-node profiles or
explicit model-provider endpoints. The SDK may call the router; it does not own
model execution.

## Core Doctrine

> **Autopilot should not care whether a model is OpenAI, local LM Studio, tenant BYOK, vLLM on a sleeping GPU, or a decentralized cloud worker. It should call a model route through policy.**

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
7. The Autopilot node binary must not assume embedded model weights. Embedded or
   bundled weights are allowed only when declared by a deployment profile.
8. Service modules and workers invoke models through routes, not direct
   assumptions about local files, provider names, or bundled binaries.

## One-Line Doctrine

> **Use the best model available, run it where policy permits, and let the runtime sleep when it is not needed.**
