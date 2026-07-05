# aiagent.xyz Integration Surface Taxonomy

Status: canonical architecture authority.
Canonical owner: this file for integration-surface classes used by aiagent vertical packs and managed worker instances.
Supersedes: plan prose that treats platform integrations as ad hoc worker categories.
Superseded by: none.
Last alignment pass: 2026-06-23.
Doctrine status: canonical
Implementation status: planned
Last implementation audit: 2026-07-05

## Canonical Definition

`IntegrationSurface` is the class of external environment a worker may observe,
act within, or expose to a user. It is a policy and evidence profile, not an
authority grant by itself.

The same worker ontology can cover a Discord moderator, a Steam game helper, a
quant research worker, a Shopify support worker, or a robot carwash prep worker
because each vertical binds to integration surfaces rather than bespoke
runtimes.

Integration surfaces are different from contact/delivery channels. An
`IntegrationSurface` is where the worker observes or acts as part of its job. A
`ContactDeliveryChannel` is how the managed instance notifies, reports to,
asks, or deep-links the user. The same external platform can be both: Slack may
be a delivery channel for a weekly digest, or it may be a work integration when
the worker reads threads, posts updates, opens incidents, or responds to
commands inside Slack. The latter requires connector posture, authority scopes,
policy, and receipts; the former may remain notification-only.

## Owns

This taxonomy owns the default mapping from integration classes to:

- allowed action classes;
- forbidden action classes;
- `prim:*` requirements;
- `scope:*` authority requirements;
- default risk classes;
- approval defaults;
- receipt obligations;
- connector requirements;
- platform policy posture;
- abuse controls;
- settlement triggers;
- safety envelope requirements;
- human supervision requirements;
- emergency-stop authority;
- sensor and actuator evidence requirements;
- liability or insurance hooks.

## Integration Classes

| Surface | Examples | Default Posture |
| --- | --- | --- |
| `chat_community` | Discord, Slack, Matrix | external messages, moderation, audit receipts |
| `contact_delivery` | email, SMS, Slack, Discord, Telegram, mobile push, webhook, MCP callback | notification/delivery only unless upgraded to a work integration |
| `game_platform` | Steam, Xbox, game server selection | platform terms, rate limits, anti-cheat care |
| `browser_saas` | CRM, helpdesk, admin dashboards | browser-use receipts and step-up for destructive actions |
| `developer_code` | GitHub, GitLab, local repos | patch receipts, tests, branch policy |
| `commerce` | Shopify, Stripe-like admin, marketplaces | funds/PII risk and transaction receipts |
| `finance_trading` | broker APIs, exchange/trade candidates | wallet authority, risk labels, max-loss policy |
| `local_computer_use` | desktop apps, file systems | local authority and workspace trust |
| `enterprise_vpc` | customer cloud, private APIs | org policy, audit export, data boundaries |
| `webhook_api` | typed HTTP/RPC integrations | schema validation and signed receipts |
| `voice_sms_access` | SMS, voice, phone links | notification/intent only unless step-up |
| `robotics_physical` | robot arms, mobile robots | physical-action safety required |
| `embodied_humanoid` | humanoids, facility assistants | supervision and e-stop required |
| `vehicles_mobility` | vehicle-adjacent or mobility systems | high-risk physical policy |
| `field_service_inspection` | site visits, inspections | sensor evidence and liability hooks |
| `education_tutoring` | learner support | safety, privacy, age/jurisdiction policy |
| `creative_media` | design, video, publishing | rights and disclosure policy |
| `support_operations` | tickets, operations consoles | escalation and audit trails |

## Minimal Implementation Object

```yaml
IntegrationSurfaceProfile:
  surface_id: integration_surface:game_platform
  allowed_action_classes:
    - observe_state
    - request_invite
    - coordinate_session
  forbidden_action_classes:
    - cheat
    - evade_platform_enforcement
  primitive_capability_requirements:
    - prim:browser.use
  authority_scope_requirements:
    - scope:platform.read
    - scope:platform.message.send
  default_risk_classes:
    - external_message
  approval_defaults:
    low_risk: session_envelope
    high_risk: step_up_review
  receipt_obligations:
    - action
    - platform_policy
  platform_policy_posture: terms_bound
  abuse_controls:
    - rate_limit
    - category_allowlist
  safety_envelope_required: false
```

Contact channel bindings live on managed worker instances:

```yaml
ContactDeliveryChannel:
  channel_ref: contact_channel://...
  owner_ref: account://... | org://... | wallet://...
  channel_kind:
    web_console | email | sms | slack | discord | telegram |
    webhook | mcp_callback | mobile_push | custom_channel
  posture:
    notification_only | summary_delivery | interactive_thread |
    approval_deeplink | workflow_callback
  connector_ref: connector://... | null
  integration_surface_ref: integration_surface:... | null
  redaction_policy_ref: policy://...
  quiet_hours_policy_ref: policy://...
  delivery_receipt_required: true
```

Notification-only channels may receive redacted summaries, delivery artifacts,
status, and approval deep links. They must not carry secrets, durable authority
grants, protected plaintext, or high-risk approvals themselves.

## Admission / Settlement Boundary

Integration surfaces submit proposed actions into the daemon and the relevant
authority-provider or local-governance boundary. They do not confer authority.
Settlement occurs only when platform contracts, marketplace payment, dispute,
reputation, or public commitments require it.

## Events And Receipts

- `IntegrationSurfaceBoundReceipt`
- `ConnectorCapabilityLeaseReceipt`
- `PlatformPolicyReviewReceipt`
- `IntegrationActionReceipt`
- `IntegrationAbuseControlReceipt`

Physical surfaces additionally require sensor and actuator receipts from
[`physical-action-safety.md`](../../foundations/physical-action-safety.md).

## Conformance Checks

- Every surface maps to risk classes and authority scopes.
- SMS/voice surfaces cannot hold durable authority or secrets.
- Notification-only contact channels cannot be treated as work integrations.
- Game/platform surfaces include platform-policy posture.
- Finance/trading surfaces bind to wallet authority, not marketplace authority.
- Physical surfaces require safety envelope, supervision, and e-stop profiles.

## Anti-Patterns

- Treating an integration as a credential.
- Treating a platform bot as safe because it is "only digital."
- Giving game, Discord, broker, or robot integrations unbounded authority.
- Hiding platform-policy violations as ordinary failures.
- Treating SMS as authentication or decryption authority by itself.
- Treating a digest destination as proof that the agent may read or mutate that
  destination's workspace.

## Related Canon

- [`digital-worker-ontology.md`](./digital-worker-ontology.md)
- [`vertical-ontology-packs.md`](./vertical-ontology-packs.md)
- [`managed-worker-instance-lifecycle.md`](./managed-worker-instance-lifecycle.md)
- [`wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
