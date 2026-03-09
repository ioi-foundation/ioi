# Autopilot Interventions and Assistant Notifications Spec

**Version:** 1.0  
**Status:** Proposed  
**Audience:** Autopilot desktop runtime, Studio UI, Spotlight UI, connector background jobs, policy/runtime teams

## 1. Purpose

Autopilot is not a generic notification client. It is a private desktop assistant that must:

1. stop the user only when the user must control or authorize something,
2. surface proactive opportunities only when the likely value exceeds the interruption cost,
3. preserve privacy and user legibility,
4. remain adaptable at runtime through direct user instruction.

This spec defines two distinct but related systems:

- **Interventions**: authoritative workflow-control state such as approval gates, clarification requests, credential prompts, and reauthentication gates.
- **Assistant Notifications**: non-blocking, productivity-oriented prompts such as deadline risk, unreplied thread reminders, meeting preparation nudges, valuable completions, and digests.

These two systems may share storage, delivery infrastructure, and visual primitives, but they are **not** the same object model, state machine, or trust class.

## 2. Core Conclusion

Autopilot must not conflate policy-gating cards with productivity notifications.

- **Interventions** are control-plane state.
- **Assistant Notifications** are attention-plane state.

If they are merged into one semantic class, the user loses the ability to distinguish:

- what must be acted on,
- what may be ignored,
- what is deterministic,
- what is heuristic,
- what is required by policy,
- what is merely suggested by the assistant.

## 3. Design Principles

### 3.1 Control and assistance are separate rails

Autopilot must operate two rails:

- **Control rail** for interventions
- **Assistant rail** for productivity notifications

They may render in one operator console, but they must remain distinct in storage, policy, and lifecycle.

### 3.2 Notify only when outcome or leverage changes

Autopilot should surface an item only if one of the following is true:

- the user can change the outcome,
- delay materially increases risk,
- the result is valuable enough to deserve attention,
- the assistant has high confidence that a prompt will save meaningful time or prevent loss.

### 3.3 Privacy-first, not merely local-first

Running locally is not enough. Autopilot must also minimize observation and disclosure.

- Prefer metadata before content.
- Prefer redacted content before full content.
- Prefer workflow state before ambient host behavior.

### 3.4 Legibility over omniscience

Users should be able to understand why Autopilot knows something.

A useful assistant feels timely.  
A creepy assistant feels omniscient.

Autopilot must favor signals the user would reasonably expect it to use.

### 3.5 Query-time adaptability is mandatory

Users must be able to change notification behavior with direct instructions such as:

- "Only toast me for investor emails."
- "Put build completions in digest."
- "Do not interrupt me during calendar focus blocks."
- "Stop scanning Gmail for follow-up reminders."

These instructions must compile into typed policy, not remain as raw natural-language memory.

## 4. Non-Goals

Autopilot notifications must not become:

- a raw event log,
- a duplicate of the micro-event stream,
- a mirror of every agent/tool step,
- a generic OS notification layer,
- a covert behavioral surveillance system,
- a system that silently escalates heuristic suggestions into authoritative control prompts.

## 5. Architectural Model

Autopilot should implement a single shared substrate with separate producers.

### 5.1 Shared substrate

The shared platform should include:

- `NotificationStore`
- `DeliveryPolicyResolver`
- `EscalationScheduler`
- `ToastDispatcher`
- `BadgeCounter`
- `InboxQueryService`
- shared persistence, dedupe, archival, and snooze logic

### 5.2 Control producer

`InterventionEngine` emits deterministic workflow-control items.

Examples:

- approval gate
- clarification required
- credential required
- connector reauthentication required
- deny/approve outcome acknowledgment

### 5.3 Assistant producer

`AssistantAttentionEngine` emits non-blocking productivity prompts.

Examples:

- unreplied thread risk
- meeting preparation reminder
- stale workflow reminder
- valuable completion
- digest summary
- repeated-friction suggestion

### 5.4 Hard rule

The assistant engine must never create a blocking intervention by itself.

Only deterministic runtime or policy engines may create interventions.

## 6. Domain Split

## 6.1 Interventions

Interventions are authoritative state transitions that affect whether a workflow may proceed.

### Examples

- approve or deny an outbound send
- approve or deny use of a protected connector capability
- review sensitive-output transformation
- provide a one-time credential
- resolve a clarification needed for exact execution
- reconnect a connector required for continuation

### Characteristics

- deterministic
- policy-backed
- exact semantics
- often blocking
- receipt/evidence-linked
- non-dismissible unless policy allows

### Examples that are **not** assistant notifications

- approval card
- deny confirmation card
- clarification selection card
- credential prompt
- reauthentication continuation card

## 6.2 Assistant Notifications

Assistant Notifications are non-blocking prompts intended to improve productivity, timing, and follow-through.

### Examples

- "You have not replied to this client thread."
- "Meeting starts in 20 minutes and no prep brief is open."
- "This workflow will miss today's deadline if the approval remains unresolved."
- "The report bundle is ready."
- "You repeatedly approve the same Google Calendar write pattern."

### Characteristics

- heuristic or ranked
- suppressible
- digestable
- adaptive
- privacy-shaped
- never authoritative over workflow permission

## 7. Shared Object Envelope

All surfaced items should share a common envelope with a domain discriminator:

```json
{
  "item_id": "item_...",
  "kind": "intervention",
  "source_engine": "control",
  "thread_id": "thread_...",
  "session_id": "session_...",
  "workflow_id": "wf_...",
  "run_id": "run_...",
  "dedupe_key": "approval:0xabc...",
  "title": "Approval needed: send investor reply",
  "summary": "Outbound email send requires your approval.",
  "created_at_ms": 0,
  "updated_at_ms": 0,
  "status": "new",
  "delivery_state": {
    "toast_sent": false,
    "inbox_visible": true,
    "badge_counted": true
  },
  "privacy": {
    "preview_mode": "redacted",
    "contains_sensitive_data": true,
    "observation_tier": "workflow_state"
  },
  "source": {
    "service_name": "Autopilot",
    "workflow_name": "gmail.reply",
    "step_name": "send_draft"
  },
  "artifact_refs": [],
  "source_event_ids": [],
  "policy_refs": {
    "policy_hash": "0x...",
    "request_hash": "0x..."
  }
}
```

## 8. Intervention Model

## 8.1 Intervention types

Autopilot v1 interventions should support:

- `approval_gate`
- `pii_review_gate`
- `clarification_gate`
- `credential_gate`
- `reauth_gate`
- `decision_gate`
- `intervention_outcome`

`intervention_outcome` is used for precise acknowledgments such as:

- "Denied: outbound send was blocked."
- "Connector reconnected. Workflow may resume."

These acknowledgments are still intervention-domain records, not assistant notifications.

## 8.2 Intervention state machine

Interventions should use a stricter lifecycle than assistant notifications.

### States

- `new`
- `seen`
- `pending`
- `responded`
- `resolved`
- `expired`
- `cancelled`

### Rules

- `approval_gate`, `credential_gate`, `clarification_gate`, and `reauth_gate` must not be directly dismissible by default.
- `resolved` must be driven by workflow/runtime state or explicit response.
- `expired` must preserve auditability.
- `responded` does not necessarily mean `resolved`; the runtime may still need to commit the result.

## 8.3 Intervention schema

```json
{
  "kind": "intervention",
  "intervention_type": "approval_gate",
  "severity": "high",
  "blocking": true,
  "request_hash": "0x...",
  "policy_hash": "0x...",
  "approval_scope": "connector.google.gmail.send",
  "recommended_action": "Review and approve or deny the send.",
  "consequence_if_ignored": "The workflow remains paused.",
  "actions": [
    { "id": "approve", "label": "Approve" },
    { "id": "deny", "label": "Deny" },
    { "id": "open_details", "label": "Open Details" }
  ]
}
```

## 9. Assistant Notification Model

## 9.1 Notification classes

Assistant Notifications should support at least:

- `follow_up_risk`
- `deadline_risk`
- `meeting_prep`
- `stalled_workflow`
- `valuable_completion`
- `digest`
- `automation_opportunity`
- `habitual_friction`
- `auth_attention`

`auth_attention` is non-blocking and informational, for example:

- "Calendar watch will expire soon."
- "Gmail connector has degraded health."

If the workflow cannot continue and a user action is required, that should be a `reauth_gate` intervention instead.

## 9.2 Notification state machine

Assistant Notifications should use:

- `new`
- `seen`
- `acknowledged`
- `snoozed`
- `resolved`
- `dismissed`
- `expired`
- `archived`

### Rules

- `snoozed` must retain original class, rank, and reasoning.
- `dismissed` is allowed for assistant notifications.
- `resolved` may be driven by changed facts, not only explicit user action.
- escalation should update the existing record, not create duplicates.

## 9.3 Notification schema

```json
{
  "kind": "assistant_notification",
  "notification_class": "follow_up_risk",
  "severity": "medium",
  "priority_score": 0.82,
  "confidence_score": 0.76,
  "recommended_action": "Draft a reply now or snooze until after lunch.",
  "consequence_if_ignored": "The thread may fall outside your usual reply window.",
  "ranking_reason": [
    "external_contact",
    "reply_window_nearly_missed",
    "user_history_high_response_consistency"
  ],
  "actions": [
    { "id": "draft_reply", "label": "Draft Reply" },
    { "id": "snooze_60m", "label": "Snooze 1h" },
    { "id": "mute_similar", "label": "Mute Similar" }
  ]
}
```

## 10. Productivity Alpha Model

Assistant notifications should be ranked using the following core objective:

`expected_user_value - interruption_cost - privacy_cost`

### 10.1 Value inputs

- actionability
- urgency
- expected user utility
- confidence
- workflow criticality
- reversible vs irreversible missed opportunity

### 10.2 Cost inputs

- current interruptibility
- recent notification density
- privacy sensitivity of the observation
- user suppression history
- ambiguity of the inference

### 10.3 Hard rule

If confidence is low and interruption cost is non-trivial, Autopilot should prefer digest placement over immediate prompting.

## 11. Observation Ladder

Autopilot must use the least invasive useful observation tier.

### Tier 1: Workflow state

Examples:

- run paused
- approval pending
- task completed
- workflow missed SLA

### Tier 2: Connector metadata

Examples:

- unread thread age
- replied/unreplied state
- meeting start time
- connector degradation
- subscription renewal deadline

### Tier 3: Redacted connector content

Examples:

- thread topic class
- whether a message appears externally time-sensitive
- meeting subject category

### Tier 4: Coarse host context

Examples:

- whether Autopilot/Studio is already open
- active app family
- user active vs idle
- current focus mode

### Tier 5: Deep ambient behavior

Examples:

- detailed app-switching sequences
- inferred emotional or behavioral state
- granular local interaction profiling

### Policy

- Tiers 1 and 2 are the preferred default.
- Tier 3 must be policy-gated and minimally retained.
- Tier 4 must be coarse and clearly explainable.
- Tier 5 is disallowed by default and should not be part of v1.

## 12. Surveillance Noise vs Productivity Alpha

Autopilot becomes surveillance noise when it:

- observes more than is needed,
- exposes more than is needed,
- interrupts without clear leverage,
- uses signals the user would not expect,
- cannot explain why the prompt appeared.

Autopilot produces productivity alpha when it:

- notices high-leverage moments,
- acts on legible signals,
- prompts only when timing matters,
- respects attention cost,
- learns from user response patterns.

### Legibility rule

Every proactive assistant prompt should be able to answer:

1. Why this?
2. Why now?
3. What signal class was used?
4. What happens if I ignore it?

## 13. Background Discovery Jobs

Autopilot should use bounded discovery, not blanket autoscanning.

## 13.1 Discovery mechanisms

### Event-driven watchers

Use push or subscription sources where possible.

Examples:

- Gmail watch events
- Workspace events
- workflow completion events
- connector health changes

### Incremental sweep jobs

Use periodic, cursor-based sweeps for detectors that cannot rely only on push.

Examples:

- unreplied important threads
- upcoming meetings without prep
- stale drafts
- automations blocked for too long

### Detector passes

Convert observations into candidate opportunities.

Examples:

- `unreplied_external_thread`
- `meeting_prep_gap`
- `stale_workflow`
- `approval_deadline_risk`
- `valuable_completion`
- `repeated_manual_pattern`

## 13.2 Discovery constraints

- opt-in per connector family and detector category
- incremental and cursor-based
- bounded scan budgets
- no full mailbox rescans by default
- metadata-first
- explanation attached to every candidate

## 13.3 Example assistant alphas

- "You have not replied to `investor@firm.com` and this is nearing your usual reply window."
- "Meeting starts in 15 minutes and the prep brief for this thread is not open."
- "This approval will likely cause the quote workflow to miss today's deadline."
- "You approved the same Calendar write pattern 8 times this week; consider a trusted rule."

## 14. Adaptability and Learning

## 14.1 Query-time overrides

Autopilot must support immediate instruction-driven changes.

Examples:

- "Only notify me for external email follow-ups."
- "Do not scan Gmail for follow-up reminders after 6 PM."
- "Toast me when an investor thread is unanswered for more than 2 hours."
- "Do not show completion notifications for docs builds."

These should compile into typed rules in an `AssistantAttentionPolicy`.

## 14.2 Durable learning

Autopilot should learn from explicit and implicit feedback:

- acted
- snoozed
- dismissed
- ignored
- muted similar
- accepted recommendation
- rejected recommendation

The system should update an `AttentionProfile`, not rewrite global policy blindly.

## 14.3 Rule proposal vs rule mutation

Heuristic learning may propose policy changes, but should not silently mutate durable high-impact settings.

Examples:

- allowed: "You often mute internal meeting reminders. Always digest these?"
- not allowed silently: disable a class of reminders without confirmation

## 14.4 Attention profile

Autopilot should maintain a local-only profile including:

- preferred surfaces
- quiet hours
- focus windows
- high-value people/workflows
- tolerated scan domains
- interruption tolerance
- digest preferences
- confidence thresholds by class

## 15. Privacy and Data Handling

## 15.1 Default preview policy

OS toasts should default to `redacted` or `compact`.

Examples:

- good: "Approval needed to send final quote"
- bad: full email body in the system toast

## 15.2 Sensitive content rules

Notifications and interventions must carry:

- `contains_sensitive_data`
- `preview_mode = redacted | compact | full`
- `observation_tier`

## 15.3 Model usage rules

Hosted inference must not be used for notification copy or ranking if the relevant policy forbids exporting the necessary context.

Assistant summarization and ranking should prefer:

1. local deterministic logic,
2. local model,
3. hosted model only when explicitly allowed.

## 15.4 Data minimization

Autopilot should retain:

- detector outputs,
- evidence references,
- ranking rationale,
- user feedback,

and should avoid retaining unnecessary raw content snapshots.

## 16. Delivery Surfaces

## 16.1 Gate Window

Primary surface for blocking interventions.

Use for:

- approval gates
- PII review
- credential gates
- reauth continuation
- exact clarification flows when continuation is blocked

## 16.2 Assistant Inbox

Primary surface for assistant notifications.

This should live in Studio and eventually be accessible from Spotlight.

Suggested sections:

- Now
- Soon
- Follow-up
- Workflow Risk
- Ready
- Digest

## 16.3 Operator Console

Autopilot may expose a unified console that visually contains both domains, but it must keep separate tabs or panes:

- `Interventions`
- `Assistant`

## 16.4 Pill Surface

Use the pill for the highest-priority active item related to the current run.

- if the user is already focused on the run, prefer pill/banner over toast
- interventions may be mirrored here, but the canonical action surface is still the gate or intervention view

## 16.5 Native Toast

Use sparingly.

- interventions: yes, when the app is not focused and user action is needed
- assistant notifications: only above configured score/severity
- digest: no

## 16.6 Badge Count

Default badge behavior should count:

- unresolved interventions
- optionally, high-priority assistant notifications

Digest items should not count by default.

## 17. Dedupe and Grouping

### 17.1 Interventions

- one active intervention per unique request hash or equivalent continuation key
- escalation updates the existing intervention
- outcome acknowledgments should reference the original intervention

### 17.2 Assistant notifications

- group by detector + subject + workflow
- repeated reminders should roll up into one record with updated rank and timestamps
- nightly/periodic low-value items should collapse into digest cards

## 18. Runtime Hooks

Autopilot should emit structured source events for:

- `approval_requested`
- `pii_review_requested`
- `clarification_requested`
- `credential_requested`
- `reauth_required`
- `run_blocked`
- `run_stalled`
- `deadline_risk`
- `valuable_completion`
- `digest_candidate`
- `connector_health_changed`
- `subscription_event_observed`
- `assistant_opportunity_detected`

## 19. Policy Model

Autopilot should maintain two distinct policy domains:

### 19.1 Shield / execution policy

Determines what may execute and when approval is required.

This governs interventions.

### 19.2 Assistant attention policy

Determines what may be observed, ranked, surfaced, and how aggressively.

This governs assistant notifications.

### 19.3 Hard rule

Assistant attention policy must never widen execution authority.

## 20. Recommended Data Models

## 20.1 AssistantAttentionPolicy

```json
{
  "version": 1,
  "global": {
    "toasts_enabled": true,
    "badge_enabled": true,
    "digest_enabled": true,
    "quiet_hours": [{ "start": "22:00", "end": "08:00" }],
    "hosted_inference_allowed": false
  },
  "detectors": {
    "unreplied_external_thread": { "enabled": true, "min_age_minutes": 120 },
    "meeting_prep_gap": { "enabled": true, "lead_time_minutes": 20 },
    "valuable_completion": { "enabled": true, "toast_min_score": 0.8 }
  },
  "connectors": {
    "gmail": { "scan_mode": "metadata_only" },
    "calendar": { "scan_mode": "metadata_only" }
  }
}
```

## 20.2 AttentionProfile

```json
{
  "version": 1,
  "preferred_surfaces": ["inbox", "pill"],
  "high_value_contacts": ["investor", "customer", "manager"],
  "focus_windows": ["calendar_busy"],
  "notification_feedback": {
    "follow_up_risk": { "acted_bps": 7400, "dismissed_bps": 900 }
  }
}
```

## 21. Defaults

### 21.1 Intervention defaults

- persist until resolved
- visible in intervention queue
- toast when user is not focused in Autopilot
- badge counted
- no silent dismissal

### 21.2 Assistant defaults

- digest by default for low-confidence items
- toast only for high-value/high-confidence/time-sensitive prompts
- retain explanation and ranking rationale
- archive low-value completions after configurable retention

### 21.3 Discovery defaults

- metadata-first
- connector-specific opt-in
- local-only ranking by default
- no deep ambient behavior analysis

## 22. Anti-Goals

Autopilot v1 must not:

- read everything because it can,
- infer from fine-grained desktop behavior by default,
- emit one notification per event,
- let assistant heuristics masquerade as policy requirements,
- hide why a prompt appeared,
- silently change persistent notification policy in material ways.

## 23. Definition of Done

Autopilot notifications are complete when:

1. interventions and assistant notifications are separate domain models,
2. approvals, denials, clarification, credential entry, and reauth are modeled as interventions,
3. productivity prompts are ranked with explicit attention and privacy cost,
4. background discovery jobs are bounded, incremental, and explainable,
5. users can change notification behavior by query and persist those changes as typed policy,
6. the UI exposes distinct intervention and assistant surfaces,
7. the event stream remains observability, not the notification product,
8. every proactive prompt can explain why it appeared and what signal tier it used.

## 24. Immediate Implementation Guidance

The first implementation steps should be:

1. Add `InterventionRecord` and `AssistantNotificationRecord` types.
2. Add a shared persisted `NotificationStore`.
3. Move approval/clarification/credential/reauth UI onto `InterventionRecord` rather than hanging only off `current_task`.
4. Add an Assistant Inbox in Studio.
5. Add a detector registry for low-risk, high-legibility opportunities:
   - `unreplied_external_thread`
   - `meeting_prep_gap`
   - `stale_workflow`
   - `valuable_completion`
6. Add query-driven attention-policy compilation.
7. Add explanation fields and observation-tier labeling to every assistant notification.

This creates a private assistant attention layer without collapsing control-plane state into productivity noise.
