# Autopilot Agent Studio Full Default Harness Parity Proof Master Guide

Owner: Autopilot Workbench / Agent Studio / Workflow Compositor / Rust Agentic Runtime / Runtime Daemon / Tool Contracts / Browser and Computer Automation

Status: active planning guide

Created: 2026-05-26

Baseline verdict:

- `docs/evidence/autopilot-agent-studio-rust-tool-catalogue-live-ide-verification/tool-catalogue-final-manifest.latest.json`
- `docs/evidence/autopilot-agent-studio-rust-tool-catalogue-live-ide-verification/campaign-2026-05-25T18-20-44-582Z/final-tool-catalogue-verdict.md`

Parent guides:

- `.internal/plans/autopilot-agent-studio-rust-tool-catalogue-live-ide-verification-12h-master-guide.md`
- `.internal/plans/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus-12h-master-guide.md`
- `.internal/plans/autopilot-electron-agent-studio-rust-agentic-runtime-parity-master-guide.md`
- `.internal/plans/autopilot-electron-workbench-workflow-compositor-parity-master-guide.md`
- `.internal/plans/isolated-computer-providers-master-guide.md`

## Executive Intent

Prove full default Workflow Compositor harness parity in Agent Studio, through
the live Autopilot IDE GUI and Rust agent harness runtime.

The previous 12-hour campaign validated the catalogue effectively, but it did
not prove full parity. It ended with:

- `live_pass`: 47
- `fixed_then_pass`: 15
- `approval_gate_pass`: 3
- `external_blocker_pass`: 12
- `concrete_failure`: 27

This guide exists to close the gap from "validated and classified" to "default
harness parity proven." It is a closure plan, not another discovery sweep.
Every current concrete failure and product UX debt must either become
`live_pass` / `fixed_then_pass` / correct `approval_gate_pass`, or be removed
from the default harness parity claim with an explicit contract decision.

## Parity Definition

Full default harness parity is proven only when the final live IDE manifest has:

- zero `concrete_failure` rows for default harness lanes
- zero product UX debt rows for default harness operation
- no unclassified runtime errors
- no silent completions
- no raw fixture, receipt, trace, or JSON-ish scaffolding in product chat
- no unmanaged browser/computer-use windows for agent automation
- all scenario cleanup receipts passing
- simple direct model turns under 30 seconds unless trace evidence explains the
  delay
- Ask kept as direct model answers
- Agent kept as governed harness execution

Provider-specific rows may remain `external_blocker_pass` only if the default
Workflow Compositor harness does not claim that provider lane as available. If a
lane is part of the default harness experience, build a hermetic adapter,
fixture provider, or local loopback implementation so it can be live-proven
without real credentials, billing, or personal accounts.

## Non-Negotiable Rules

- Run proof through the real Autopilot IDE GUI and Agent Studio chat UX.
- Do not count SDK-only, CLI-only, or static checks as parity proof.
- Do not repeatedly rerun the same broad scenario hoping it turns green. Fix the
  smallest responsible layer, add a focused proof, then climb to the next
  integrated lane.
- Kill Autopilot, runtime bridge, daemon, and spawned browser/computer-use
  processes after every scenario; record cleanup proof.
- Use disposable fixtures for filesystem, browser, screen, memory, connector,
  model registry, media, commerce, and computer-use effects.
- Keep receipts, policy verdicts, runtime traces, fixture paths, and tool
  payloads in Runs/Tracing and evidence files, not product chat.
- Main chat should show a compact work summary capsule plus a clean human answer.
- Browser/computer automation must show a managed live session artifact:
  compact preview by default, expandable observe view, explicit session label,
  and takeover/return controls.
- Hermetic `Sandbox browser` is the default for agent browsing. `Local browser`
  and `Desktop` control are opt-in, visibly labeled, and more tightly gated.
- Login, CAPTCHA, payment, file picker, credential, and other user-only actions
  must switch to `Waiting for user`; the agent pauses until control is returned.
- If files become monolithic while fixing a lane, refactor immediately.

## Evidence Root

Use a new evidence root for this closure campaign:

```text
docs/evidence/autopilot-agent-studio-full-default-harness-parity/
```

Each scenario directory must include:

- `scenario.json`
- `gui-screenshot-before.png`
- `gui-screenshot-after.png`
- `chat-transcript.json`
- `runtime-events.jsonl`
- `daemon-operations.jsonl`
- `policy-verdicts.jsonl`
- `receipts.jsonl`
- `latency.json`
- `side-effects.json`
- `cleanup-proof.json`
- `failure-analysis.md` when a scenario fails
- `fixes-applied.md` when code changed
- `parity-verdict.json`

## Current Blocking Matrix

### Agent Lifecycle

Blocking rows:

- `agent__await`

Required closure:

- Build a same-thread delegate/await fixture that creates a real child session,
  stores the returned child id, and awaits that child through the live Agent
  harness.
- Verify `agent__delegate` remains permission-gated where appropriate, then
  verify an approved or hermetic child path can be awaited successfully.
- Final proof must show parent/child linkage in Tracing and clean user-facing
  chat text.

### Retained Shell Controls

Blocking rows:

- `shell__status`
- `shell__input`
- `shell__terminate`

Known state:

- The rerun at
  `docs/evidence/autopilot-agent-studio-rust-tool-catalogue-live-ide-verification/2026-05-26T02-07-05-794Z`
  proved real `shell__start:*` ids reach the retained shell rows.
- The remaining issue is executor handling: the live Rust executor does not
  admit or dispatch the retained status/input/terminate control paths.

Required closure:

- Wire retained shell control tools through the same executor path that handles
  retained shell start/run.
- Preserve daemon-owned session authority and cleanup semantics.
- Add focused tests for status/input/terminate against a retained disposable
  process.
- Live GUI proof must start a shell, query status, send input, terminate it, and
  show no leaked process after cleanup.

### Browser Automation State

Blocking rows:

- `browser__inspect_canvas`
- `browser__list_options`
- `browser__click`
- `browser__hover`
- `browser__click_at`
- `browser__type`
- `browser__select`
- `browser__press_key`
- `browser__copy`
- `browser__paste`
- `browser__wait`
- `browser__upload`
- `browser__select_option`
- `browser__switch_tab`
- `browser__close_tab`

Known state:

- Several rows can succeed when fixture state is fresh.
- Per-row hidden setup made the broad scenario slow and brittle.
- The product/right fix is not more hidden setup turns; it is a managed
  hermetic browser session with stable fixture state and live viewport UI.

Required closure:

- Add a preloaded hermetic browser session fixture for browser catalogue rows.
- Keep fixture page, tabs, selection, clipboard content, canvas, file input, and
  dropdown state alive across the scenario without model-mediated setup per row.
- Preserve stable element ids across inspect/click/click_at/select/upload rows.
- Add a browser-session work summary that references Tracing without dumping raw
  paths or receipts into chat.
- Final proof must exercise the complete browser matrix in one bounded live GUI
  session under the latency ceiling.

### Browser Subagent

Blocking row:

- `browser__subagent`

Known state:

- Schema rejection is fixed.
- The row now reaches a deeper child-agent capability routing failure:
  `workspace_ops` was selected without admitted filesystem or connector tooling.

Required closure:

- Define the browser subagent's admitted tool bundle for the default harness.
- Ensure child task scope has the browser context and any required read-only
  workspace tools.
- Verify child output returns to the parent and final `chat__reply` explains the
  result cleanly.

### Screen And Desktop Focus

Blocking rows:

- `screen__click`
- `screen__click_at`
- `screen__scroll`

Known state:

- `screen__find` is fixed-then-pass by using the driver-captured semantic XML
  fallback.
- Click/scroll rows fail because the runtime cannot focus the target `browser`
  window reliably in the live fixture.

Required closure:

- Add deterministic window targeting for screen actions.
- Prefer managed session ids over title guesses where possible.
- Make the screen driver explain focus denial in Tracing, not product chat.
- Live proof must focus the disposable target, click a known control, click by
  coordinates, scroll, and show before/after state.

### Memory Retrieval

Blocking rows:

- `memory__search`
- `memory__read`

Known state:

- `memory__append`, `memory__replace`, and `memory__clear` pass in the allowed
  `workflow.notes` section.
- `memory__search` fails retrieval verification.
- `memory__read` requires an archival id returned by search.

Required closure:

- Create a disposable memory corpus with deterministic archival ids.
- Ensure search writes and retrieval use the same namespace, section, and
  ownership context.
- Verify `memory__read` consumes the id returned by the live search row rather
  than a hard-coded id.
- Final proof must append, search, read, replace, and clear in one bounded
  memory scenario.

### Product Browser/Computer Automation UX

Blocking UX rows:

- `browser_computer.compact_live_viewport`
- `browser_computer.sandbox_local_desktop_labeling`

Required closure:

- Agent-created browser/computer sessions render a compact live preview in the
  run view by default.
- Preview expands into an observe surface.
- Controls are explicit: `Observe`, `Take over`, `Return control to agent`.
- Session labels are explicit: `Sandbox browser`, `Local browser`, `Desktop`.
- User-only blocks render `Waiting for user`, pause the agent, and resume only
  after explicit return of control.
- Raw automation receipts stay in Runs/Tracing.
- Standalone unmanaged Chromium windows do not count as product parity.

### Provider And Optional Lanes

Current external blockers:

- `model__embeddings`
- `model__rerank`
- media extract/generate/read/transcribe/synthesize rows
- `connector__toolcat__noop`
- `computer_use.request_lease`

Required closure:

- Decide which provider rows are part of default harness parity.
- For default rows, provide hermetic local adapters or fixture providers.
- For optional rows, mark them as outside the default parity claim and verify
  they fail closed with product-safe copy and trace-side detail.
- `computer_use.request_lease` must either have an admitted hermetic provider or
  be explicitly excluded from default parity. If included, it must produce the
  managed live viewport UX described above.

## Stage Plan

### Stage 0: Baseline Lock

- Read the final manifest from the catalogue campaign.
- Generate a new parity closure manifest seeded from all concrete failures,
  product UX debt, and default-harness provider decisions.
- Freeze the list of default harness lanes for this campaign.

Exit criteria:

- `parity-baseline.json` written.
- Every row has an owner, expected proof path, and closure strategy.

### Stage 1: Product UX Guardrail

- Reconfirm Ask is direct answers and Agent is governed harness.
- Reconfirm chat renders work capsules and clean answers only.
- Add regression coverage that raw receipts, fixture markers, paths, and tool
  payloads stay in Runs/Tracing.

Exit criteria:

- Screenshots prove product chat is clean.
- Trace artifacts prove receipts are still available outside chat.

### Stage 2: Agent Lifecycle Closure

- Fix `agent__await` with real child session linkage.
- Prove delegate gate and approved/hermetic await path.

Exit criteria:

- `agent__await` becomes `fixed_then_pass` or `live_pass`.

### Stage 3: Retained Shell Closure

- Fix executor handling for status/input/terminate.
- Prove retained process lifecycle through live GUI.

Exit criteria:

- `shell__status`, `shell__input`, and `shell__terminate` become
  `fixed_then_pass` or `live_pass`.

### Stage 4: Managed Hermetic Browser Session

- Implement or wire stable preloaded browser session fixture.
- Prove DOM, pointer, upload, tab, clipboard, canvas, and wait rows without
  hidden setup turns between every action.

Exit criteria:

- All default browser rows become `live_pass` or `fixed_then_pass`.
- Scenario remains under bounded latency and cleanup is clean.

### Stage 5: Browser Subagent Closure

- Admit the correct child-agent capabilities.
- Prove parent browser context, child execution, and final parent reply.

Exit criteria:

- `browser__subagent` becomes `fixed_then_pass` or `live_pass`.

### Stage 6: Screen And Desktop Closure

- Fix deterministic focus targeting.
- Prove click, click_at, scroll, inspect, find, type, window focus, app launch,
  and clipboard in a disposable target.

Exit criteria:

- Screen focus-sensitive rows become `fixed_then_pass` or `live_pass`.

### Stage 7: Memory Retrieval Closure

- Add deterministic memory search/read fixture.
- Prove append/search/read/replace/clear as one coherent memory flow.

Exit criteria:

- `memory__search` and `memory__read` become `fixed_then_pass` or `live_pass`.

### Stage 8: Provider Decision And Hermetic Adapter Closure

- Split provider rows into default parity and optional provider catalogue.
- Add hermetic adapters for any provider row kept in default parity.
- Verify optional rows fail closed with clean product copy.

Exit criteria:

- No provider row blocks the default harness parity verdict.

### Stage 9: Browser/Computer Live Viewport UX

- Add compact live preview card for browser/computer sessions.
- Add expanded observe view and takeover/return controls.
- Add `Sandbox browser`, `Local browser`, and `Desktop` labels.
- Add `Waiting for user` state for manual-only actions.

Exit criteria:

- Product UX debt rows become `live_pass`.
- Screenshots prove compact and expanded states.

### Stage 10: Cross-Surface Default Harness Scenario

- Run a realistic Agent task that uses file, shell, browser, memory, screen,
  approval, and final reply in one bounded workflow.
- Use the same GUI path a real operator would use.

Exit criteria:

- No raw scaffolding in chat.
- All receipts and traces are present in Runs/Tracing.
- Cleanup is clean.

### Stage 11: Latency And Regressions

- Run simple Ask, simple Agent, local file read, shell echo, browser find, and
  memory read probes.
- Treat simple turns over 30 seconds as pipeline defects unless trace evidence
  explains the delay.

Exit criteria:

- Latency report written.
- No simple default harness row exceeds the ceiling without an explanation.

### Stage 12: Final Parity Soak

- Run the complete default harness parity matrix through live GUI.
- Do not use SDK-only or CLI-only proof as final evidence.
- Kill processes after every scenario and after the final manifest.

Exit criteria:

- `tool-catalogue-full-default-harness-parity-final-manifest.json` written.
- `final-default-harness-parity-verdict.md` written.
- No default harness row remains `concrete_failure`.
- Browser/computer live viewport UX rows are passing.
- Final cleanup proof reports no remaining Autopilot, runtime bridge, daemon,
  browser, or computer-use child processes.

## Final Verdict Rules

The final verdict may say `full_default_harness_parity_proven` only if:

- all default harness rows are `live_pass`, `fixed_then_pass`, or legitimate
  `approval_gate_pass`
- provider rows included in default parity have hermetic live proof
- provider rows excluded from default parity have explicit contract notes
- product UX rows pass
- cleanup passes
- final screenshots show human-readable chat output
- final traces contain receipts without leaking them into chat

Otherwise the verdict must remain one of:

- `parity_blocked_by_runtime_failures`
- `parity_blocked_by_product_ux_debt`
- `parity_blocked_by_provider_contract_decisions`
- `parity_blocked_by_cleanup_or_latency`

## First Work Items

1. Add a parity closure manifest builder seeded from the final catalogue verdict.
2. Fix retained shell executor dispatch for `shell__status`, `shell__input`,
   and `shell__terminate`.
3. Build the managed hermetic browser session fixture instead of adding hidden
   setup turns.
4. Add the browser/computer live viewport product artifact.
5. Fix `agent__await` parent/child linkage.
6. Fix deterministic memory search/read ids.
7. Rerun focused live GUI proofs after each fix before attempting the full
   parity soak.
