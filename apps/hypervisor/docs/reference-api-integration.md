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

### Wired to the real IOI daemon

- `UserService/GetPreference` + `SetPreference` → persisted to
  `.ioi/hypervisor/data/hypervisor-app-preferences.json` (the daemon's data dir; survives
  restart; replaces the mirror's ephemeral Map).
- `AgentService/ListAgentExecutions` → `GET /v1/threads` (mapped thread → agentExecution)
- `AgentService/GetAgentExecution` → `GET /v1/threads/:id`
- `AgentService/CreateAgentExecution` + `StartAgent` → `POST /v1/threads` (real thread)
- `AgentService/SendToAgentExecution` → `POST /v1/threads/:id/turns`

The daemon is the source of truth for the agentic surface: creating a session creates a
real daemon thread; the list reflects real daemon state (bare threads, no demo metadata).
If the daemon is unreachable the adapter returns null and the request falls back to the
live reference, so the app never breaks.

### Deliberately left on the live reference (not a TODO — a design decision)

These have **no real IOI backing that improves on the reference today**; wiring them to the
bare local daemon would *degrade* the UX, so they stay proxied until a real IOI service
exists:

- `AccountService` / `OrganizationService` / `BillingService` — daemon `/v1/account` is a
  bare `local-operator` stub (no name/email/org/billing). Wiring it replaces the polished
  identity with a stub for no real gain.
- `EnvironmentService` / `RunnerService` — daemon `/v1/runtime/nodes` are infra nodes, not
  Ona workspaces; the demo's environments are interwoven with the workspace fixtures.
- `EventService/WatchEvents` — daemon emits **per-thread SSE** (`/v1/threads/:id/events`);
  the frontend wants a **global** Connect event stream with Gitpod-shaped resource events.
  The app works via explicit fetches on navigation; a blind global-event bridge risks
  breaking the stream parser, so it stays a safe end-frame until built + verified against a
  live conversation.

Migration is complete for every endpoint with a real, mappable, verifiable IOI backend;
the rest are documented above with the reason they remain on the reference.
