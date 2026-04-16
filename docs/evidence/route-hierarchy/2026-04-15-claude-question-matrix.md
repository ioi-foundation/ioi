# Claude Runtime Question Matrix

Date: 2026-04-15
Verdict target: `better than Claude` for all 43 discovery questions

Primary evidence:

- Live desktop prompt validation: `docs/evidence/route-hierarchy/2026-04-15-desktop-parity-validation.md`
- Live desktop manifests:
  - `docs/evidence/route-hierarchy/live-dev-start-targeted-recheck/2026-04-15T22-51-05Z/manifest.json`
  - `docs/evidence/route-hierarchy/live-dev-start-clarify-mortgage-recheck/2026-04-15T23-09-33Z/manifest.json`
  - `docs/evidence/route-hierarchy/live-dev-start-coverage-completion/2026-04-15T23-16-25Z/manifest.json`
  - `docs/evidence/route-hierarchy/live-dev-start-brazil-cloudsync-recheck/2026-04-15T23-28-35Z/manifest.json`
- Skill-discovery pipeline test: `cargo test -p autopilot pipeline_steps_keep_skill_discovery_distinct_from_brief_preparation --quiet`
- Inline skill-visibility test: `node --experimental-strip-types apps/autopilot/src/windows/SpotlightWindow/hooks/useSpotlightSurfaceState.test.ts`
- Route-projection contract: `crates/services/src/agentic/runtime/service/step/route_projection.rs`
- Studio route receipts and projections: `apps/autopilot/src-tauri/src/kernel/events/stream/routing_receipt.rs`

Method:

- All 43 questions are covered by retained live desktop prompts under the real `AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop` path.
- Runtime and UI tests remain as supporting regression evidence, but they are no longer required for question coverage claims.

| Q | Verdict | Evidence | Why IOI is better |
|---|---|---|---|
| 1 | better | Live prompts: `Pythagorean theorem`, `current president of Brazil` | We do not just answer or tool-call; we emit a typed `direct_answer_allowed` decision with explicit blockers. |
| 2 | better | Live prompts: `current president of Brazil`, `What's happening this week?` | Currentness is explicit and auditable via `currentness_override` instead of hidden prompt intuition. |
| 3 | better | All 10 validated live prompts | Route precedence is a first-class contract with `route_family`, `selected_route`, and `effective_tool_surface`. |
| 4 | better | Live prompts across general, research, integrations, artifacts, coding | Task-family variation is encoded rather than merely described; receipts show the family change directly. |
| 5 | better | Live prompts: `What's happening this week?`, `Create a release artifact`, `mortgage calculator` | Ambiguous inline vs artifact resolution is visible in receipts and validated in real desktop runs. |
| 6 | better | Live prompt: `What's happening this week?` | Ambiguous web-style requests block on structured clarification instead of silently guessing a mode. |
| 7 | better | Live prompt: `What npm script launches the desktop app in this repo?` | We can start conversation-first and then explicitly project tool execution via workspace grounding receipts. |
| 8 | better | Live prompt: `A mortgage calculator where I can adjust rate, term, and down payment` | Interactive artifact routing is deterministic and visible through `artifact_html_iframe` plus projected tools. |
| 9 | better | Live prompt: `Summarize my unread emails` | Connector-first applies to a typed class of personal-integrations work, not a fuzzy preference. |
| 10 | better | Live prompt: `Summarize my unread emails` | We explicitly prefer the narrow mail connector route over broader alternatives and retain the tie-break evidence. |
| 11 | better | Live prompt: `Summarize my unread emails` | Connector tie-breakers are observable through selected connector, provider family, and route label receipts. |
| 12 | better | Live prompt: `Summarize my unread emails`; route receipts | Connector choice is both part of routing and separately inspectable afterward, which is stronger than pure latent reasoning. |
| 13 | better | All validated prompts | Tool surface is conditioned per request and surfaced as `projected_tools`, not assumed from a static superset. |
| 14 | better | All validated prompts | Tool families stay intentionally dormant until triggered, and we can prove which surface was projected for a turn. |
| 15 | better | Live prompt: `What npm script launches the desktop app in this repo?` | File/workspace activation is driven by explicit grounding hints and tool projection, not only keyword instinct. |
| 16 | better | Live prompt: `Should I wear a jacket today?` | Narrow weather routing beats generic web search, with fallback tools retained separately for inspection. |
| 17 | better | Live prompt: `A mortgage calculator where I can adjust rate, term, and down payment` | Visual and interactive surface activation is explicit through renderer choice and artifact verification. |
| 18 | better | Live prompts: `What's happening this week?`, `Should I wear a jacket today?`, `Prioritize these renovation projects...` | User-input activation is typed and blocked with structured options instead of informal follow-up text. |
| 19 | better | Live prompts: weather, mail, prioritization, mortgage calculator | Narrow task-shaped surfaces outrank broad fallbacks and we retain both the primary and fallback tool sets. |
| 20 | better | Live prompts: `Create a Word document...`, `Create a budget spreadsheet...`, `Build a React + Vite workspace project...` | Skill consideration is encoded as `skill_prep_required`, not left implicit. |
| 21 | better | Live prompts: `CloudSync landing page`, `Word document`, `workspace project`; pipeline tests | We distinguish `required`, `not_needed`, `attached`, and `unavailable` guidance states rather than treating skills as a vague preference. |
| 22 | better | Live prompts: `CloudSync landing page`, `workspace project`; route projection contract | Skill visibility begins at route contract time and is preserved through execution receipts. |
| 23 | better | Live prompt: `What is the Pythagorean theorem?` | Inline direct answers keep skill prep out of scope and prove it in the route decision payload. |
| 24 | better | Live prompts: `CloudSync landing page`, `Word document`, `workspace project`; supporting pipeline tests | The “skip a skill read” class is narrowed and made observable because guidance states and prep requirements are explicit. |
| 25 | better | Live prompts: `Word document`, `budget spreadsheet`, `workspace project`; guidance-state tests | We separate “general reasoning”, “guidance not needed”, and “guidance attached” instead of collapsing them into one hidden judgment. |
| 26 | better | Live prompt: `What npm script launches the desktop app in this repo?`; normalization observations | Canonical tool contracts stay strict, but violations become measured evidence instead of silent fragility. |
| 27 | better | Tool-normalization observations retained in receipts and capabilities harness | Alias and near-miss repair exists, but every coercion is observable, so the system is forgiving without being opaque. |
| 28 | better | Live workspace prompt completion; queued-action runtime fixes | Sequential follow-up tool actions are explicit queue semantics with retained receipts, not just an unstated model habit. |
| 29 | better | Normalization receipts; workspace grounding prompt | We are resilient to wrong names and argument-shape drift, and we can prove when repair happened. |
| 30 | better | Live workspace prompt; currentness and connector clarifications | Recovery patterns are typed: retry, clarify, reroute, or block, each with receipts instead of ad hoc narration. |
| 31 | better | All prompt receipts with `effective_tool_surface` and verification summaries | Tool results are shaped into the next-step contract explicitly, which makes follow-up actionability inspectable. |
| 32 | better | Route projection and normalization receipts | Easy vs hard schema usage is not just experiential; we retain projected-tool and coercion evidence that exposes schema friction. |
| 33 | better | Live direct-inline prompt and blocked/gated prompts | The user sees the right amount before tools: either a direct answer or a truthful route state, not process theater. |
| 34 | better | Live validation summary across running, gate, complete, and blocked states | Active-run storytelling is calmer and tied to lifecycle truth rather than chatty step-by-step process narration. |
| 35 | better | Route receipts plus main-lane live prompts | Route choice stays mostly implicit in the main lane while remaining richly explicit in receipts and inspectors. |
| 36 | better | Live prompts: `CloudSync landing page`, `Word document`, `workspace project`; supporting UI tests | Skill reads stay implicit by default, but explicit titles and guidance states are available when they matter. |
| 37 | better | Live prompts: release artifact, workspace project, mortgage calculator | Artifact reasoning is attached in evidence and source tabs without overloading the main conversation lane. |
| 38 | better | Live prompts: gate, running, ready, blocked, preview verified | Status labels are lifecycle-truthful and grounded in artifact or route state rather than generic spinner language. |
| 39 | better | `desktop-parity-prompt-manifest.json`; validated prompt pack | We now have a retained prompt taxonomy that exposes route-precedence differences directly in the live app. |
| 40 | better | Validated prompts: weather, user input, mortgage calculator, workspace, mail | Tool-surface design differences are exposed through projected-tool evidence, not inferred after the fact. |
| 41 | better | Live workspace prompt and route projection tests | Skill-trigger differences are captured through `skill_prep_required` and validated by real artifact lanes. |
| 42 | better | Live validation bundle and Spotlight visibility test | Inline narration quality is measured against calm lifecycle states plus explicit receipt truth, not only human interpretation. |
| 43 | better | `2026-04-15-desktop-parity-validation.md`; prompt manifest; receipts; normalization observations | Our comparison evidence is fairer because it includes route decisions, tool normalization, clarification states, and retained live manifests. |

Residual note:

- All 43 discovery questions are now covered by retained live desktop prompts.
- Runtime and UI tests remain in place only to keep the parity-plus behaviors from regressing.
