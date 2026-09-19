# @ioi-ai/orchestration

**ioi.ai application code.** This package is the ioi.ai application's composer over the
Hypervisor's thread-orchestration primitives (the daemon's `/v1/threads`, fork control and
subagents, reached through `@ioi/agent-sdk`) and the System-scoped record seam. It holds no store:
every byte it admits lives in the Hypervisor. What it holds are ioi.ai's cross-record rules — the
obligations the portable invariant language cannot express because that language is single-record
— refused here by name and proven by the hypervisor's driven verifiers.

It is NOT the primitives (those are the daemon's and the agent SDK's), and it is not a Hypervisor
plane: the owner ruled goal pursuit out of the Hypervisor on 2026-09-18 (register R-192), and the
GoalRun, OutcomeRoom and collaboration families are compositions this package makes.

Relocated from `packages/ioi-ai-orchestration` on 2026-09-19 (register R-200) because canon places
the application's vocabulary with the application (`docs/architecture/_meta/start-here.md`:
"Applications such as ioi.ai compose this platform; their own vocabulary lives under
`domains/ioi-ai/`"), and a package named `@ioi/ioi-ai-orchestration` under the platform's
`packages/` read as platform code. It remains a root npm workspace so the hypervisor verifiers and
CI build it with `npm run build --workspace=@ioi-ai/orchestration`; `apps/ioi-ai` itself stays a
standalone package and reaches this one by relative path from its web-ui plugin.

Modules: `orchestrations` (the S2 handle made durable, successor of OutcomeRoom v2),
`collaboration`, `bindings`, `work` (the v4 work objects), `goalrun` (M04.4: a run's resolution is
copied off the admitted profile-resolution receipt, never taken from the caller).

Build and test: `npm run build --workspace=@ioi-ai/orchestration && npm test --workspace=@ioi-ai/orchestration`.
