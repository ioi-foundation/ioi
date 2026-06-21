# Model Router API, BYOK, and Mounting

Status: canonical low-level reference.
Canonical owner: this file for model provider, endpoint, route, invocation, BYOK, and run-to-idle API shapes.
Supersedes: overlapping model-router API examples in plans/specs when route or invocation fields conflict.
Superseded by: none.
Last alignment pass: 2026-05-24.

## Purpose

The model router lets workflows, workers, and agents call models through primitive runtime capabilities, wallet authority scopes, and policy, not hardcoded providers. It supports foundational APIs, BYOK, local model mounting, run-to-idle serving, and future resource marketplaces.

The router and invocation contract are part of the runtime/node API. Model
weights and model servers are deployment-profile resources. A node profile may
bundle local weights, mount local files, call a local server, broker BYOK
provider calls, or allocate hosted/TEE/DePIN compute, but no profile should
assume model weights are embedded in the node binary unless that is explicitly
declared.

## API Surface

```http
GET  /v1/models/providers
POST /v1/models/providers
GET  /v1/models/endpoints
POST /v1/models/endpoints
PATCH /v1/models/endpoints/{endpoint_id}
DELETE /v1/models/endpoints/{endpoint_id}
POST /v1/models/endpoints/{endpoint_id}/healthcheck
GET  /v1/models/routes
POST /v1/models/routes
POST /v1/models/invoke
GET  /v1/models/invocations/{invocation_id}
GET  /v1/models/receipts/{receipt_id}
```

## ModelEndpoint

```json
{
  "endpoint_id": "model_endpoint_local_qwen",
  "provider": "lmstudio | ollama | openai | anthropic | gemini | vllm | custom_http | depin_pool",
  "mount_mode": "bundled_weights | local_file | local_server | external_api | hosted_pool | tee_session | depin_session | customer_vpc",
  "deployment_profile_ref": "profile://local-private-qwen",
  "model_artifact_ref": "optional cid://... | artifact://... | file://...",
  "base_url": "http://localhost:1234/v1",
  "api_format": "openai_compatible | anthropic | custom",
  "auth_mode": "none | byok | wallet_brokered | service_account",
  "key_ref": "wallet://secret/openai_optional",
  "models": [
    {
      "model_id": "qwen-coder-local",
      "modalities": ["text"],
      "context_window": 128000,
      "architecture_profile": "dense_transformer | moe | subquadratic | hybrid_attention_state | retrieval_augmented | mutable_context | deterministic_verifier | custom",
      "active_context_strategy": "full_attention | local_window | state_scan | sparse_attention | retrieval_packets | external_context_graph | hybrid",
      "context_mutability": "none | external_context_only | adapter_promoted | package_revision",
      "post_training_support": [
        "context_update",
        "adapter_training",
        "route_policy_training",
        "eval_generation"
      ],
      "tool_calling": false,
      "structured_output": true
    }
  ],
  "privacy_class": "local | external_api | tenant_private | tee_private",
  "run_to_idle": {
    "enabled": true,
    "idle_timeout_seconds": 300,
    "cold_start_allowed": true
  }
}
```

## ModelRoute

```json
{
  "route_id": "planner_high",
  "role": "planner | executor | verifier | summarizer | code | vision | embedding",
  "selection_policy": {
    "preferred_profiles": ["reasoning_high", "local_private"],
    "allowed_architecture_profiles": ["dense_transformer", "hybrid_attention_state"],
    "required_context_mutability": "none | external_context_only | adapter_promoted | package_revision | any",
    "max_cost_usd": 2,
    "privacy_constraints": ["no_external_api_for_private_data"],
    "fallback_allowed": true
  },
  "candidates": ["model_endpoint_openai", "model_endpoint_local_qwen"]
}
```

## ModelConfiguration

`ModelConfiguration` is the user/session/agent-facing selection object. It may
point to one or more `ModelRoute` objects, but it is not itself the router.

```json
{
  "model_configuration_id": "model_config_agent_default",
  "display_model": "GPT-5.5",
  "reasoning_effort": "low | medium | high | extra_high",
  "service_tier": "standard | fast",
  "route_policy_ref": "model-route-policy://...",
  "primary_route_id": "planner_high",
  "fallback_route_ids": ["planner_medium"],
  "custody_profile_ref": "model_weight_custody://...",
  "privacy_constraints": ["no_external_api_for_private_data"],
  "authority_scope_refs": ["scope:model.invoke"],
  "receipt_policy_ref": "receipt-policy://model-invocation"
}
```

Product surfaces may call this `Model`, `Reasoning`, and `Speed`. Runtime
records should preserve route, endpoint, custody, fallback, authority, and
receipt refs.

## Model Invocation

```json
{
  "route_id": "planner_high",
  "input": {
    "messages": []
  },
  "task_context": {
    "task_id": "task_123",
    "privacy_class": "internal",
    "risk_class": "low"
  },
  "authority_grant_id": "grant_model_123",
  "primitive_capability": "prim:model.invoke",
  "authority_scope": "scope:model.invoke.external",
  "receipt_mode": "hash_only | full_redacted | full_private"
}
```

Response:

```json
{
  "invocation_id": "modelinv_123",
  "selected_endpoint": "model_endpoint_openai",
  "selected_model": "gpt-x",
  "output": {},
  "receipt_id": "receipt_model_123",
  "routing_explanation": {
    "selected_reason": "reasoning profile required; privacy allowed external BYOK",
    "rejected_candidates": []
  }
}
```

## Run-to-Idle Lifecycle

```text
cold → warming → ready → busy → draining → idle → sleeping
```

## BYOK Rule

BYOK keys are stored in wallet.network. Runtimes receive brokered authority grants or short-lived operation-scoped tokens, never raw long-lived provider keys by default.

## Non-Negotiables

1. Workflow/model nodes call model routes, not hardcoded providers.
2. Private tasks must obey routing privacy policy.
3. Every model invocation can emit a receipt.
4. Local model endpoints must be mountable through OpenAI-compatible APIs where possible.
5. Run-to-idle should be a lifecycle primitive, not a deployment afterthought.
6. Bundled model weights are a deployment profile, not the architecture
   default.
7. Node binaries own router and invocation contracts, not implicit model
   possession.
