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
| `voice_sms_access` | SMS, voice, phone links | notification/intent only unless step-up, or the conversational voice profile (below) |
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

## Conversational Voice Profile

A `voice_sms_access` work integration may run a conversational voice agent (one
that answers or places calls, books, answers billing questions and verifies
callers) under this profile instead of the notification/intent posture. The
profile confines what the agent can say and read. It does not make free speech
safe, and it says so.

- **One call, one cell.** A call is one session in one cell scoped to one
  counterparty of record. The cell reads no protected data about that subject
  until the caller is verified against the records, by a deterministic check
  the executor runs. Verification decides what the cell may read; it confers no
  authority.
- **Disclosure first.** The executor plays the disclosure that the caller is
  talking to an automated agent, and the recording notice, before anything the
  agent says. Regulated wording (the disclosure, the recording notice, the
  emergency script) is rendered from pinned templates, never generated. Text
  channels on the same surface are template-only: the agent supplies slot
  values.
- **A closed dialogue.** The call follows a closed intent machine that runs in
  the executor, not in the model. Its states and transitions are pack content,
  pinned by the governing policy, and an agent update cannot widen them.
- **Effects leave the stream.** Utterances are a receipted, hash-linked stream,
  not decided one by one. Booking, disclosure, payment and transfer are typed
  effects, decided like any other, and a commitment exists only as a typed
  effect.
- **Transfer, and emergencies.** A request outside the intent set is transferred
  to a staffed role or becomes a callback. An emergency intent runs the pinned
  emergency script and transfers at once: a deterministic keyword matcher in the
  executor or the model's advisory flag triggers it, and nothing the agent side
  controls (the model, an agent update or the advisory monitor) can suppress it.
  The script is finite and pinned (a template), and its only effect is the
  transfer, which the governing policy authorizes in advance for the deployment
  rather than for the agent, so it can never become an open channel.
- **A monitor that only narrows.** An advisory monitor may transfer a call or
  cut the agent out of it. It never widens what the call may do, never cuts a
  running emergency script, and each intervention records the evaluator that
  made it.
- **Stops are scoped.** A principal's valid stop takes effect at once, locally,
  within its scope. A stop scoped to the agent removes the agent, and a running
  emergency script, which is not the agent's, completes its transfer. A stop
  that covers the deployment ends the script too: the principal can always stop
  everything.
- **Never the principal's own identity.** The agent never proves the
  principal's identity or speaks the principal's secrets. Verifying a caller
  against records is a different act, and it is allowed.

**The residual is stated, not removed.** Free speech can still carry advice or
a commitment the intent machine did not type. The profile bounds it (typed
commitments only, closed intents, pinned regulated wording, a narrowing-only
monitor, after-the-fact audit) and measures it (the flag rate, sampled review,
complaints) against a registered bar. A deployment of the profile states that
residual in its governing policy and never claims it is zero.

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
- A conversational voice profile reads no protected data before the caller is
  verified, runs its intent machine in the executor, keeps its emergency script
  finite, pinned and transfer-only, lets nothing on the agent side suppress it,
  honours a principal's stop at once within its scope, and states its residual
  rather than claiming none.
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
