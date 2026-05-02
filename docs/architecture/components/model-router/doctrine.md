# Model Router, BYOK, and Run-to-Idle Specification

Status: canonical architecture authority.
Canonical owner: this file for model routing doctrine; low-level model-router API lives in [`model-router-api-byok-and-mounting.md`](./api-byok-mounting.md).
Supersedes: overlapping model/provider prose when routing or BYOK boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Canonical Definition

**The Model Router is the IOI runtime subsystem that selects and invokes model routes according to task, privacy, cost, latency, quality, primitive capability constraints, authority scopes, and policy.**

It should support foundational model APIs, local model mounting, BYOK, open-model serving, run-to-idle infrastructure, and decentralized/hosted compute providers.

## Core Doctrine

> **Autopilot should not care whether a model is OpenAI, local LM Studio, tenant BYOK, vLLM on a sleeping GPU, or a decentralized cloud worker. It should call a model route through policy.**

## Model Surfaces

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
- local/private enterprise models.

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
```

## Routing Inputs

The router should consider:

- task class;
- risk class;
- privacy class;
- tool needs;
- context size;
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

## One-Line Doctrine

> **Use the best model available, run it where policy permits, and let the runtime sleep when it is not needed.**
