# Reference → IOI API integration ("working backwards")

The hypervisor app serves the **live reference** (`apps/hypervisor/scripts/serve-live-reference.mjs`):
the reference's real bundle (IOI-branded snapshot) is served from the gitignored local
mirror, so dark mode and every client-side interaction work natively (no hand-wired tail)
and it is pixel-exact by construction. An **IOI-owned `/api` adapter**
(`apps/hypervisor/scripts/ioi-api-adapter.mjs`) sits in front and replaces the reference's
mocked backend endpoint-by-endpoint; anything not yet ported is proxied to the mirror so
nothing breaks during the migration.

```
browser :4173 ─▶ serve-live-reference
                   ├─ /api/* ─▶ ioi-api-adapter ─▶ real IOI behavior
                   └─ else / unported /api ─▶ proxy ─▶ mirror :9301 (bundle + branding + mocks)
```

## The frontend's contract (Gitpod Connect-RPC, `gitpod.v1.*`)

POST `application/(json|connect+json)`; responses are JSON (or Connect length-prefixed
frames for streams — header byte `2` + uint32 length + payload, see
`connectEndStreamBuffer`).

| Service / method | Request (key fields) | Response shape |
| --- | --- | --- |
| `EventService/WatchEvents` | — | Connect stream; mirror sends an immediate end-stream frame |
| `RunnerService/CreateRunner` | — | `{ runner: { id, spec{...}, status{ phase, message }, kind } }` |
| `RunnerService/CheckAuthenticationForHost` | `{ host }` | `{ type: "Authenticated" }` |
| `UserService/GetPreference` | `{ preferenceKey }` | `{ preference: { key, value, id, createdAt, updatedAt } \| null }` |
| `UserService/SetPreference` | `{ preference: { key, value } }` | `{ preference: {...} }` |
| `EnvironmentService/GetEnvironment` | `{ environmentId }` | `{ environment: {...} }` |
| `EnvironmentService/Create[FromProject]` | `{ spec / projectId }` | `{ environment: {... phase running} }` |
| `EnvironmentService/Start\|Stop\|Delete\|Update` | `{ environmentId, spec.desiredPhase }` | `{ environment: {... phase} }` |
| `EnvironmentService/CreateEnvironment{Access,Logs}Token` | `{ environmentId }` | `{ accessToken }` |
| `EnvironmentService/MarkEnvironmentActive\|Archive\|Unarchive` | `{ environmentId }` | `{}` |
| `AgentService/CreateAgentExecution\|StartAgent` | `{ ... }` | `{ agentExecutionId }` |
| `AgentService/ListAgentExecutions` | `{ pagination }` | `{ pagination, agentExecutions: [{ id, ... }] }` |
| `AgentService/GetAgentExecution` | `{ agentExecutionId }` | `{ agentExecution: {...} }` |
| `AgentService/CreateAgentExecutionConversationToken` | `{ agentExecutionId }` | `{ token }` |
| `AgentService/SendToAgentExecution\|Stop\|Delete` | `{ agentExecutionId }` | `{}` |

(Mock fixtures: `internal-docs/reverse-engineering/ioi/public/api/gitpod.v1.*`.)

## The real IOI backend

- `crates/node/src/bin/hypervisor-daemon.rs` — built (`target/debug/hypervisor-daemon`),
  serves HTTP (axum), data dir `IOI_HYPERVISOR_DATA_DIR` (default `.ioi/hypervisor/data`).
- Speaks **IOI's own protocol** (model-mount kernel: sessions / turns / events, preview
  servers), **not** Gitpod proto — so each endpoint needs a shape-mapping adapter.

## Per-endpoint wiring status & plan

Projection layer: `scripts/ioi-projection.mjs` (verb-disciplined daemon→UI mappers).

### Backed by real IOI (daemon + provider + persistence)

- **Session** — `AgentService/{ListAgentExecutions,GetAgentExecution,CreateAgentExecution,
  StartAgent,SendToAgentExecution}` → daemon `/v1/threads` (+ `/turns`). Creating a session
  creates a real daemon thread; the projected object carries a `governance` block
  (`approvalMode`, `harnessBindingRef`, `workspaceScope`, `evidenceRefs`) — WS3.
- **Environment** (WS2) — `EnvironmentService/{Get,List,Start,Stop,Delete,Update,Create,
  CreateFromProject,*Token,MarkActive,Archive,Unarchive}` → the `EnvironmentProvider`
  (`scripts/ioi-environment-provider.mjs`). Interim **Simulated** provider: lifecycle
  `STOPPED→STARTING→RUNNING→STOPPING→STOPPED`, logs, actions, persisted to the non-
  authoritative app-local store (`.ioi/hypervisor-app-local/`, NOT the daemon data dir).
  Phase 0 swaps daemon-owned VM/microVM/devcontainer behind the same interface.
- **Preferences** — `UserService/{Get,Set}Preference` → app-local store (client config).

If the daemon is unreachable the adapter returns null and the request falls back to the
live reference, so the app never breaks.

### Boundary (WS3) — daemon-enforced, surfacing awaits native UI

The daemon **enforces** the child/operator split: threads default `approval_mode: "suggest"`
(child plane PROPOSES), and host/platform changes route through the operator-plane request
path (`/v1/threads/:id/approvals/*`, `…/workspace-change-reviews/control`,
`…-admissions`). wallet authority is invoked by the daemon only at delegated-authority
crossings. The projection carries these signals on the governed object. **Rendering the
approval/review flow needs native IOI surfaces** — the borrowed Gitpod UI is session-centric
and has no slot for it (the impedance-mismatch case for a native UI).

### Still on the live reference (documented reasons)

- **Project** (WS1) — daemon `/v1/hypervisor/projects` is **create-only** (requires
  `repository_url`); no list/projection GET. Stays proxied until the daemon exposes a
  project list (or an Agentgres projection). The borrowed UI keeps showing the demo project.
- `Account/Org/Billing` — daemon `/v1/account` is a bare `local-operator` stub; wiring it
  degrades the identity for no gain.
- `EventService/WatchEvents` — daemon emits **per-thread SSE**; the frontend wants a
  **global** Gitpod-shaped Connect stream. Stays a safe end-frame until a bridge is built +
  verified against a live conversation (blind framing risks breaking the parser).

Done for every object with a real, mappable, verifiable IOI backend; the rest are documented
above with the reason.

## Split-brain guard (the JS boundary)

The serve layer must NOT become a second runtime. Rules, enforced:
- **Projection only.** `ioi-projection.mjs` + the AgentService wiring translate/render the
  daemon's objects; the daemon owns runtime truth. Serving/proxy/identity-rewrite are
  client-surface concerns, not a runtime.
- **No JS-owned runtime truth in the daemon data dir.** `.ioi/hypervisor/data` is
  daemon-owned. JS-owned state (the simulated env provider, app preferences) lives in the
  separate, non-authoritative `.ioi/hypervisor-app-local/`.
- **The Simulated EnvironmentProvider is a deletable stand-in, not a parallel runtime.**
  The `EnvironmentProvider` interface is the seam; at Phase 0 the daemon owns the provider
  (executes env lifecycle) and the JS simulator is **deleted** — the JS layer then projects
  the daemon's environment like it projects Session. It must never coexist with a daemon
  env owner. (This is the one place that, left unchecked, would reintroduce split brain.)
