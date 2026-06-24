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

- **DONE — IOI-owned:** `UserService/GetPreference` + `SetPreference` → persisted to
  `.ioi/hypervisor/data/hypervisor-app-preferences.json` (survives restart; replaces the
  mirror's ephemeral Map).
- **NEXT (proxied to mirror until wired), per endpoint:**
  1. `AgentService/ListAgentExecutions` + `GetAgentExecution` → daemon session/run list →
     map run → `agentExecution` shape. (Highest value: drives the sessions/Recent list.)
  2. `AgentService/CreateAgentExecution` / `StartAgent` / `SendToAgentExecution` → daemon
     start-session / send-turn; return `{ agentExecutionId }`.
  3. `EventService/WatchEvents` → bridge daemon event stream → Connect streaming frames
     (live updates instead of the immediate end-frame).
  4. `EnvironmentService/*` → daemon environment/preview API (start/stop/create/get);
     map phase enums (`ENVIRONMENT_PHASE_*`).
  5. `RunnerService/*` → daemon runner registration.

Each requires verifying the exact request/response shapes the (minified) frontend sends
against the running daemon — done iteratively per endpoint, not blind, to avoid silent
breakage.
