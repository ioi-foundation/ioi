# Model Router API, BYOK, and Mounting

Status: canonical low-level reference.
Canonical owner: this file for model provider, endpoint, route-rights contract,
invocation, BYOK/BYOA, and run-to-idle API shapes.
Supersedes: overlapping model-router API examples in plans/specs when route or invocation fields conflict.
Superseded by: none.
Last alignment pass: 2026-07-13.
Doctrine status: reference
Implementation status: partial (route registry and local Ollama mount/binding
are live; the registered information-flow/declassification contracts define a
target hosted-provider bundle and untrusted-output posture, but production
enforcement remains planned; sealed BYOK and multi-transport session execution
are unimplemented; only active/available Ollama routes currently bind for
execution, and full router/ContextCell propagation remains planned)
Last implementation audit: 2026-07-18

## Purpose

The model router lets workflows, workers, and agents call models through
primitive runtime capabilities, wallet authority scopes, versioned route-rights
contracts, and policy, not hardcoded providers. It supports foundation APIs,
dedicated endpoints, BYOK/BYOA, replaceable aggregators, local model mounting,
run-to-idle serving, and future resource marketplaces.

The router and invocation contract are part of the runtime/node API. Model
weights and model servers are deployment-profile resources. A node profile may
bundle local weights, mount local files, call a local server, broker BYOK
provider calls, or allocate hosted/TEE/DePIN compute, but no profile should
assume model weights are embedded in the node binary unless that is explicitly
declared.

## API Surface

This is the committed target contract. The live implementation currently
provides route registry/probe plus local Ollama binding; route-contract, quote,
sealed-BYOK, aggregator, direct-provider, and multi-transport execution paths
remain planned unless the daemon route registry reports them live.

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
GET  /v1/models/route-contracts
POST /v1/models/route-contracts
POST /v1/models/quote
POST /v1/models/invoke
GET  /v1/models/invocations/{invocation_id}
GET  /v1/models/receipts/{receipt_id}
```

## ModelEndpoint

```json
{
  "endpoint_id": "model_endpoint_local_qwen",
  "provider": "lmstudio | ollama | openai | anthropic | gemini | openrouter | vllm | custom_http | depin_pool",
  "mount_mode": "bundled_weights | local_file | local_server | external_api | aggregator_api | dedicated_endpoint | hosted_pool | tee_session | depin_session | customer_vpc",
  "deployment_profile_ref": "profile://local-private-qwen",
  "model_artifact_ref": "optional cid://... | artifact://... | file://...",
  "base_url": "http://localhost:1234/v1",
  "api_format": "openai_compatible | anthropic | custom",
  "auth_mode": "none | byok | byoa | wallet_brokered | service_account",
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
  "execution_privacy_posture": "local | external_api | tenant_private | tee_private | regulated",
  "commercial_posture": "direct | aggregator | customer_byok | customer_byoa | self_hosted",
  "route_contract_ref": "model-route-contract://...",
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
    "goal_execution_policy": "auto | pinned | compare",
    "preferred_profiles": ["reasoning_high", "local_private"],
    "allowed_architecture_profiles": ["dense_transformer", "hybrid_attention_state"],
    "required_context_mutability": "none | external_context_only | adapter_promoted | package_revision | any",
    "max_cost_usd": 2,
    "privacy_constraints": ["no_external_api_for_private_data"],
    "fallback_allowed": true,
    "provider_allowlist": ["provider://..."],
    "provider_use_policy_ref": "policy://model-provider-use/deny-learning",
    "zdr_required": false,
    "max_price_ref": "price-schedule://...",
    "required_parameters": ["tools", "structured_output"]
  },
  "candidates": ["model_endpoint_openai", "model_endpoint_local_qwen"],
  "route_contract_refs": ["model-route-contract://..."]
}
```

Every candidate referenced by a route resolves a contract such as:

```json
{
  "contract_id": "model-route-contract://...",
  "contract_version": "semver-or-hash",
  "contract_hash": "sha256:...",
  "admitted_policy_hash": "sha256:...",
  "valid_from": "timestamp",
  "valid_until": "timestamp | null",
  "commercial_posture": "direct | aggregator | customer_byok | customer_byoa | self_hosted",
  "access_mode": "named_human_seat | api | dedicated_endpoint | self_hosted",
  "customer_facing_allowed": true,
  "reseller_oem_authorized": "true | false | not_required",
  "automation_right": "interactive_only | unattended_allowed | negotiated",
  "downstream_right": "internal_only | customer_application | reseller_oem",
  "credential_principal": "named_human | service_account | customer_owned",
  "provider_terms_version_ref": "terms://...",
  "model_terms_version_ref": "terms://...",
  "endpoint_ref": "endpoint://...",
  "model_version_ref": "model://...",
  "provider_allowlist": ["provider://..."],
  "zdr_required": false,
  "provider_use_of_customer_material": {
    "request_or_prompt_logging": "prohibited | contract_limited | explicitly_permitted | not_applicable",
    "human_review": "prohibited | security_incident_only | contract_limited | explicitly_permitted | not_applicable",
    "abuse_and_security_processing": "prohibited | transient_only | contract_limited | explicitly_permitted | not_applicable",
    "service_improvement": "prohibited | contract_limited | explicitly_permitted | not_applicable",
    "provider_model_training": "prohibited | contract_limited | explicitly_permitted | not_applicable",
    "cross_customer_aggregation": "prohibited | contract_limited | explicitly_permitted | not_applicable",
    "retention": {
      "posture": "zero_retention | transient_processing | contract_bounded | provider_default | not_applicable",
      "retention_policy_ref": "policy://... | null"
    }
  },
  "customer_use_of_outputs": {
    "retain": "prohibited | terms_limited | expressly_licensed | open_license",
    "replay": "prohibited | terms_limited | expressly_licensed | open_license",
    "evaluation": "prohibited | terms_limited | expressly_licensed | open_license",
    "rag_or_memory": "prohibited | terms_limited | expressly_licensed | open_license",
    "same_provider_tuning": "prohibited | terms_limited | expressly_licensed | open_license",
    "distillation": "prohibited | terms_limited | expressly_licensed | open_license",
    "competing_model_training": "prohibited | terms_limited | expressly_licensed | open_license",
    "internal_package_reuse": "prohibited | terms_limited | expressly_licensed | open_license",
    "publication": "prohibited | terms_limited | expressly_licensed | open_license",
    "resale": "prohibited | terms_limited | expressly_licensed | open_license"
  },
  "rights_basis_refs": ["terms://...", "license://...", "contract://...", "policy://..."],
  "region_ref": "region://...",
  "fallback_classes": ["same_model_same_posture"],
  "max_price_ref": "price-schedule://...",
  "required_parameters": ["tools"],
  "status": "active | quarantined | expired | superseded | revoked"
}
```

The matrix is bidirectional and purpose-specific. No member is inferred from
inference access, a generic enterprise plan, an account-wide opt-out, ZDR, or
another member. `data_collection`, `no_training`, and
`output_training_right` may be accepted as compatibility inputs only when the
admission compiler expands them into every required matrix member from exact
versioned terms; otherwise the requested use fails closed.

For `compare` or another multi-provider invocation, each route must satisfy the
active boundary independently. Effective customer output rights are the
intersection of every contributing output; provider-side exposure is retained
per recipient and the composite posture is the least protective one. A
restricted contribution may be excluded only with separable provenance.

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
  "goal_execution_policy": "auto | pinned | compare",
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
  "goal_execution_policy": "auto | pinned | compare",
  "route_contract_ref": "model-route-contract://...",
  "input": {
    "messages": []
  },
  "task_context": {
    "task_id": "task://123",
    "privacy_class": "internal",
    "risk_class": "external_message",
    "institutional_learning_boundary_profile_ref": "learning-boundary://org/default/v1",
    "effective_learning_policy_hash": "sha256:...",
    "learning_material_classes": ["prompts_and_completions", "memory_context_procedures_workflows_and_skills"],
    "intended_output_uses": ["retain", "evaluation", "rag_or_memory"]
  },
  "authority_grant_id": "grant_model_123",
  "primitive_capability": "prim:model.invoke",
  "authority_scope": "scope:model.invoke.external",
  "information_flow": {
    "input_labels": ["<resolved InformationFlowLabel objects>"],
    "effect_label": "<independently admitted InformationFlowLabel object>",
    "runtime_tool_contract": "<exact RuntimeToolContract revision object>",
    "reviewed_representation": null,
    "declassification_approval": null
  },
  "receipt_mode": "hash_only | full_redacted | full_private",
  "budget": {
    "max_work_credits": 10,
    "max_supplier_cost": 2,
    "fallback_requires_requote": true
  }
}
```

For conforming hosted transports the inline values above are resolved,
immutable contract objects at the kernel boundary, not model-authored refs.
Missing actual inputs, effect authority, or the exact tool contract must fail
before network contact. The target kernel binds them to the canonical provider
request and exact URL, rather than trusting the effect label's declared content
hash. Returned blocking and stream records must carry an
`information_flow_label`; raw provider output remains untrusted and
content-only even when every input was verified. Current master does not yet
implement this hosted-provider information-flow seam.

Response:

```json
{
  "invocation_id": "invocation://model-123",
  "selected_endpoint": "endpoint://openai",
  "selected_model": "model://gpt-x",
  "selected_route_contract_ref": "model-route-contract://...",
  "selected_or_compared_route_refs": ["model_route://planner_high"],
  "effective_customer_output_rights_hash": "sha256:...",
  "output": {},
  "comparison_or_synthesis_ref": "verifier_path://... | artifact://... | null",
  "verifier_refs": ["verifier_path://..."],
  "receipt_id": "receipt://model_123",
  "learning_egress_receipt_refs": ["receipt://learning_egress_123"],
  "attempts": [
    {
      "endpoint_ref": "endpoint://openai",
      "model_ref": "model://...",
      "status": "succeeded | failed | rejected | escalated",
      "supplier_billed": true,
      "cost_ref": "cost://...",
      "receipt_ref": "receipt://..."
    }
  ],
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

BYOA named-user credentials remain user-scoped, interactive-only unless the
provider contract says otherwise, and never enter IOI managed-worker inventory.
Direct, aggregator, dedicated, customer, and self-hosted routes all retain their
own commercial-rights and data-policy contracts. An aggregator such as
OpenRouter is a replaceable procurement/routing adapter, not the sole inference
authority or a reason to erase upstream provider/model terms.

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
8. Named-user chat/workspace subscriptions must not be pooled, shared,
   browser-automated, or resold as managed machine capacity.
9. Unattended and customer-facing calls fail closed unless route contracts
   permit their access, automation, downstream, data, region, and commercial
   posture.
10. `Auto`, `Pinned`, and `Compare` preserve candidate, attempt, verifier,
    fallback, provider/model, supplier-billed, and cost lineage.
11. Provider/model fallback is a semantic substitution and must remain inside
    the admitted route contract and applicable verification path.
12. Strict `Private` routes do not treat aggregator ZDR alone as
    no-provider-trust execution.
13. Provider use of customer material and customer use of outputs are separate,
    complete matrices. Missing members fail closed for the requested purpose.
14. Compare and multi-provider synthesis intersect contributing output rights;
    synthesis does not erase route-specific restrictions or provider exposure.
