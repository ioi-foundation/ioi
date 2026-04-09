# Autopilot Desktop UX Visibility Scratchboard

Status: living plan
Last updated: 2026-04-06
Repo: `/home/heathledger/Documents/ioi/repos/ioi`
Primary launch command: `AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop`
Primary artifact root: `/tmp/autopilot-ux-loop/`

## Current Window Goal

Make each native Autopilot window usable at its real on-screen size. If the
native screenshot does not show a control, the user does not see it and the
surface is still failing.

## Visual Thesis

Autopilot should feel like a first-party operator shell: slate, compact,
intentional, and calm. The target blend is VS Code density, Cursor clarity,
Vercel restraint, and Antigravity polish, without copying any single product
literally.

## Design North Star

- Prefer IDE shell hierarchy over dashboard-card mosaics.
- Prefer slate / graphite neutrals over terra / sand browns.
- Prefer one cool accent family over a rainbow of secondary accents.
- Prefer compact, useful headers over oversized hero-like chrome.
- Prefer alignment, spacing, and typography rhythm over glassmorphism.

## Palette Direction

- Migrate the shell from terra primitives toward slate primitives.
- Keep blue as the primary action and focus accent.
- Reserve warm hues for semantic warning/error moments only.
- Reduce warm-tinted fills, warm borders, and brown-black base layers in the
  default shell.

## Screenshot Truth Rule

- Screenshot beats DOM.
- Screenshot beats JSX.
- Screenshot beats accessibility XML.
- Accessibility and DOM evidence can explain why a control is missing, but they
  cannot override a clipped or invisible screenshot.

## Current Focus

- Spotlight is now passing the three required native states for the empty-session
  launcher flow:
  - base
  - sidebar open
  - sidebar + artifact panel open
- Spotlight query-first execution is now the active follow-on seam:
  - the submitted prompt must stay visible
  - running state must not be replaced by planner / validation chrome
  - the main app must be reachable without hidden commands
- Next window after this pass: Studio at default size, then minimum size.
- Active Studio seam:
  - clarification blocker state at `1920x976`
  - blocker controls now own the page instead of sitting below telemetry chrome
  - remaining honest blocker: native click / key automation has not yet proven
    the `Submit Choice` control transitions the session
- Residual Spotlight risk to revisit later: the fully populated artifact hub
  with live session data still has not been re-proved after the empty-session
  drawer simplification.

## Surface Inventory

| Surface | Native trigger | States to prove | Must-see controls |
| --- | --- | --- | --- |
| Spotlight | `Ctrl+Space` or another existing app trigger | base, sidebar open, sidebar + artifact open | composer/input, primary send/submit action, panel toggles, surfaced primary actions |
| Studio | existing app trigger or routed launch path | default size, constrained/min size | main navigation, primary action bar, right-edge controls, critical footer/header actions |
| Gate | live gate state or targeted dev route for diagnosis | default live state | Approve, Deny, gate details |
| Pill | live pill state | compact, expanded | expand/open action, dismiss/close action, active task summary |

## Known Seams To Audit First

- Cross-layer Spotlight width mismatch:
  - Rust window constants in `apps/autopilot/src-tauri/src/windows.rs`
    - `BASE_WIDTH = 450`
    - `SIDEBAR_WIDTH = 260`
    - `ARTIFACT_PANEL_WIDTH = 400`
  - React window constants in `apps/autopilot/src/windows/SpotlightWindow/constants.ts`
    - `BASE_PANEL_WIDTH = 450`
    - `SIDEBAR_PANEL_WIDTH = 280`
    - `ARTIFACT_PANEL_WIDTH = 468`
- Spotlight layout is hard-sized and non-resizable in
  `apps/autopilot/src-tauri/src/windows/layout.rs`.
- Tauri window defaults and min sizes also live in
  `apps/autopilot/src-tauri/tauri.conf.json`.
- Global theme primitives in `apps/autopilot/src/styles/global.css` are still
  explicitly terra-cobalt and warm-leaning.
- Spotlight shell tokens in
  `apps/autopilot/src/windows/SpotlightWindow/styles/Layout.css` still use warm
  brown background values.
- `packages/agent-ide/src/styles/theme.css` is a cleaner slate reference for
  dark product UI.
- CSS overflow and flex ownership are likely follow-on seams in:
  - `apps/autopilot/src/windows/SpotlightWindow/styles/`
  - `apps/autopilot/src/windows/StudioWindow/StudioWindow.css`
  - `apps/autopilot/src/windows/PillWindow/PillWindow.css`
  - `apps/autopilot/src/windows/GateWindow/GateWindow.css`

## Design Acceptance Rubric

For each surface, ask:

- Does it feel closer to VS Code / Cursor / Vercel than to a warm concept UI?
- Are panels legible because of hierarchy and spacing instead of heavy effects?
- Is the base shell neutral slate rather than brown-black terra?
- Is the accent story mostly one cool blue family?
- Can the user scan the important actions in one glance?

## Command Crib Sheet

- Launch:
  - `AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop`
- Find native windows:
  - `wmctrl -lx | grep -i autopilot`
  - `xdotool search --name "Autopilot"`
- Capture geometry:
  - `xdotool getwindowgeometry --shell <window-id>`
  - `xwininfo -id <window-id>`
- Capture screenshot on X11:
  - `import -window <window-id> /tmp/autopilot-ux-loop/<name>.png`
- Browser-only diagnosis fallback:
  - `http://127.0.0.1:1420/spotlight`
  - `http://127.0.0.1:1420/studio`
  - `http://127.0.0.1:1420/gate`
  - `http://127.0.0.1:1420/pill`

## Recently Completed

- Seeded the UX visibility loop with repo-native commands and files.
- Identified an existing Spotlight width-budget mismatch between Rust window
  layout constants and React panel constants.
- Identified the active palette seam:
  - `apps/autopilot/src/styles/global.css` still brands itself as terra-cobalt.
  - Spotlight-specific shell tokens are still warm brown.
- Confirmed local X11 capture tools are available:
  - `xdotool`
  - `wmctrl`
  - `xwininfo`
  - `import`
- Reconciled Spotlight width budgeting across Rust and React.
- Added a compact dual-panel Spotlight budget that keeps the sidebar + drawer
  state within the local X11 anchor (`898x600`).
- Replaced the blank empty-session artifact hub mount with a lightweight native
  drawer state so the combined Spotlight surface stays visible in screenshot
  truth.
- Shifted the active Spotlight shell from warm terra toward slate / graphite
  neutrals.
- Added a visible Spotlight-to-Studio entry point in the composer rail.
- Converted the active Spotlight run state back to query-first by retaining the
  optimistic prompt, suppressing non-essential telemetry cards, and only
  rendering the orchestration board when delegated work actually exists.

## In Progress

- Spotlight is complete for the empty-session launcher flow.
- Spotlight submitted-query running state is now passing the native `kittens`
  check.
- Studio copilot opened from Spotlight now keeps the active clarification
  request centered instead of front-loading telemetry chrome.
- Studio clarification state now uses a compact blocker footer instead of a
  disabled full-height composer.
- Native clarification submission is now proven through keyboard submission on
  the live card.
- Studio Inbox and Runs now have fresh post-restart reruns at the default
  `1280x650` launch size.
- Next active loop: reduce the concept-like default Studio home surface and
  keep auditing default/min-size density across the remaining Studio tabs.

## Current Loop Log

### Studio clarification blocker

- Surface/state:
  - Studio, live clarification blocker after submitting `kittens`
- Screenshot path:
  - `/tmp/autopilot-ux-loop/20260406-153359/studio-current.png`
- Geometry:
  - `1920x976+0+32`
- Expected control:
  - clarification options and `Submit Choice` should be the primary visible
    controls
- Actual failure:
  - stale `Working...` / `Preparing the outcome surface` chrome was shown above
    the real blocker; the blocker itself sat too low because it rendered below
    the flexing conversation region
- Controlling seam:
  - Studio state-priority logic in `SpotlightWindow/index.tsx`
  - live-thinking fallback in `ConversationTimeline.tsx`
  - blocker docking location between chat and composer
- Patch applied:
  - suppressed live-running pills/cards whenever a gate/password/clarification
    blocker is active
  - moved Studio blocker rendering inline with the conversation lane
- Rerun result:
  - `/tmp/autopilot-ux-loop/20260406-153359/studio-clarification-priority.png`
    removed the stale status chrome
  - `/tmp/autopilot-ux-loop/20260406-153359/studio-clarification-inline.png`
    moved the blocker into the primary content lane
- Design delta vs parity target:
  - closer to Cursor / VS Code task-first flow, less like telemetry stacked on
    top of the actual work

- Surface/state:
  - Studio, same clarification blocker with blocked composer chrome
- Screenshot path:
  - `/tmp/autopilot-ux-loop/20260406-153359/studio-clarification-inline.png`
- Geometry:
  - `1920x976+0+32`
- Expected control:
  - blocker should remain primary while secondary utilities stay compact
- Actual failure:
  - disabled composer still consumed a large footer footprint and repeated
    “clarification required” copy without giving the operator a real action
- Controlling seam:
  - `SpotlightInputSection.tsx` locked-input render path
- Patch applied:
  - replaced the disabled textarea/composer stack with a compact blocker footer
    and keyboard utility copy
- Rerun result:
  - `/tmp/autopilot-ux-loop/20260406-153359/studio-clarification-compact-footer.png`
    now keeps the blocker dominant and pushes utilities into a small footer rail
- Design delta vs parity target:
  - denser, calmer, more operator-grade; less dead chrome at the bottom edge

- Surface/state:
  - Studio, clarification submission proof
- Screenshot path:
  - `/tmp/autopilot-ux-loop/20260406-153359/studio-after-clarification-submit.png`
  - `/tmp/autopilot-ux-loop/20260406-153359/studio-after-clarification-submit-nodrag.png`
  - `/tmp/autopilot-ux-loop/20260406-153359/studio-after-clarification-enter.png`
- Geometry:
  - `1920x976+0+32`
- Expected control:
  - `Submit Choice` should transition the session out of the clarification
    blocker
- Actual failure:
  - native X11 automation attempts using `xdotool` click and `Return` did not
    visibly transition the session
- Controlling seam:
  - unresolved native-input proof seam; explicit `no-drag` coverage was missing
    and has now been added, but the state still does not visibly advance under
    local automation
- Patch applied:
  - added explicit `-webkit-app-region: no-drag` coverage for blocker stacks
  - added `Enter` / `Esc` keyboard affordances on the clarification card
- Rerun result:
  - visibility/layout improved, but submission remains unproven under local
    native automation
- Design delta vs parity target:
  - blocker is visually ready, but this still needs a truthful pass/fail on
    native interaction before being called complete

- Surface/state:
  - Studio, default launch size `1280x650`, Inbox queue
- Screenshot path:
  - `/tmp/autopilot-ux-loop/20260406-iterative/studio-nav-click-1.png`
- Geometry:
  - `1280x650+192+298`
- Expected control:
  - queue, selected inbox detail, and right utility rail should share the
    window without a dead empty pane
- Actual failure:
  - a full extra black pane remained between the queue content and the right
    utility rail because the queue component mounted its own shell grid inside
    the parent Inbox shell
- Controlling seam:
  - nested `notifications-shell` ownership between
    `NotificationsView.tsx` and `OperatorInboxQueueColumns.tsx`
- Patch applied:
  - added an embedded queue mode so the queue wrapper spans the parent Inbox
    shell correctly instead of instantiating a second three-column shell
- Rerun result:
  - `/tmp/autopilot-ux-loop/20260406-iterative/inbox-fresh-after-restart.png`
    now uses the width coherently and keeps the queue, detail pane, and utility
    rail visible together
- Design delta vs parity target:
  - far closer to an IDE queue/detail layout and no longer feels like a mock
    empty stage accidentally left on screen

- Surface/state:
  - Studio, default launch size `1280x650`, Runs
- Screenshot path:
  - `/tmp/autopilot-ux-loop/20260406-iterative/runs-after-agent-ide-build.png`
- Geometry:
  - `1280x650+192+298`
- Expected control:
  - first visible runtime card should immediately populate the live detail pane
- Actual failure:
  - the surface showed a live runtime card while the footer still said `No
    container selected`, leaving the supervision pane contradictory and partly
    empty
- Controlling seam:
  - `packages/agent-ide/src/features/Fleet/FleetView.tsx` did not establish a
    stable default selection for the visible filtered container set
- Patch applied:
  - auto-select the first visible container whenever the current selection is
    empty or filtered away, and scope the live detail pane to the visible
    filtered selection
- Rerun result:
  - `/tmp/autopilot-ux-loop/20260406-iterative/studio-leftnav-grid.png`
    now selects `Ollama OpenAI Dev Runtime` by default and fills the live
    detail pane immediately
- Design delta vs parity target:
  - supervision now behaves like an operator console instead of a demo card
    floating over an uninitialized terminal

- Surface/state:
  - Studio, default launch size `1280x650`, header density on Inbox / Runs /
    Capabilities
- Screenshot path:
  - `/tmp/autopilot-ux-loop/20260406-iterative/studio-fresh-home.png`
  - `/tmp/autopilot-ux-loop/20260406-iterative/inbox-fresh-after-restart.png`
- Geometry:
  - `1280x650+192+298`
- Expected control:
  - project strip, current surface label, and inbox count should remain legible
    without overlapping
- Actual failure:
  - the header toolbar text overflowed into neighboring segments, crowding the
    project selector and current surface label at the default Tauri width
- Controlling seam:
  - `StudioIdeHeader` width budget and overflow handling in
    `StudioWindow.css`
- Patch applied:
  - tightened the header grid budget, enabled ellipsis/overflow clipping on the
    toolbar segments, and hid low-value project-label chrome at `<=1280px`
- Rerun result:
  - `/tmp/autopilot-ux-loop/20260406-iterative/studio-header-overflow-fixed.png`
    keeps the header readable at the same native size without label collision
- Design delta vs parity target:
  - calmer and denser, closer to a real IDE title strip than a crowded concept
    header

## Next 5 Tasks

1. Fix the black `Autopilot Studio` window now surfaced by the native `Studio`
   handoff from a live Spotlight run.
2. Re-run the user-reported Studio failed-query wall and confirm the new
   chat-first failure copy replaces the validation/planner receipts wall.
3. Open Studio at the default Tauri size and capture navigation/action-bar
   proof once the black-window seam is closed.
4. Audit Gate for simultaneous Approve / Deny visibility in the live native
   window.
5. Audit Pill for expand/open and dismiss visibility in the live native pill.

## Exit Criteria For The Current Window

- Spotlight base state has visible composer/input and primary action. Passed.
- Spotlight sidebar-open state preserves main actions. Passed.
- Spotlight artifact-open state preserves main actions and panel actions.
  Passed for the empty-session launcher flow with native screenshot proof.
- Screenshot proof exists for each passing state. Passed.
- Spotlight reads as a slate operator shell rather than a warm floating panel.
  Passed.

## Next Window Preview

If Spotlight passes, move to Studio at both default and minimum supported
window sizes, then Gate, then Pill.

## Risks

- Native Tauri geometry may differ from browser-only diagnosis.
- A surface may look semantically correct in code while still clipping inside a
  hard-sized native window.
- Side-panel width mismatches may create repeated regressions until the shared
  constants are unified.
- Piecemeal color overrides may create a mixed terra/slate shell unless token
  changes are done at the primitive level.
- The populated Spotlight artifact hub with live session evidence still needs a
  dedicated rerun after the empty-session drawer simplification.
- Fresh-profile Studio task starts can still fail with `Tx ... did not commit
  within 15000ms`, which limits deeper live artifact reruns until the local
  kernel settles.

## Decisions

- Native screenshot proof is the acceptance bar.
- Browser routes may be used for diagnosis, not for final signoff.
- Shared geometry seams should be fixed before local CSS band-aids.
- Slate is now the preferred shell direction.
- Terra / warm sand tones are a migration target, not the desired end state.
- Use parity with VS Code / Cursor / Vercel / Antigravity as a qualitative
  design check when choosing between comparable fixes.

## Evidence

- Prompt: `docs/autopilot-desktop-ux-visibility-prompt.md`
- Scratchboard: `docs/plans/autopilot-desktop-ux-visibility-scratchboard.md`
- Native layout seam:
  - `apps/autopilot/src-tauri/src/windows.rs`
  - `apps/autopilot/src-tauri/src/windows/layout.rs`
  - `apps/autopilot/src-tauri/tauri.conf.json`
- React width seam:
  - `apps/autopilot/src/windows/SpotlightWindow/constants.ts`
- Theme seam:
  - `apps/autopilot/src/styles/global.css`
  - `apps/autopilot/src/windows/SpotlightWindow/styles/Layout.css`
  - `packages/agent-ide/src/styles/theme.css`

## Iteration Log

| Timestamp | Surface / state | Screenshot | Geometry | Expected control | Actual failure | Controlling seam | Patch | Design delta vs parity target | Rerun result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-04-06 12:35 | Spotlight / base | `/tmp/autopilot-ux-loop/20260406-123431/spotlight-base-initial.png` | `450x600+1022+298` | composer + primary send | None in base state | baseline proof | none | warm shell, oversized breathing room | pass |
| 2026-04-06 12:36 | Spotlight / sidebar open | `/tmp/autopilot-ux-loop/20260406-123431/spotlight-sidebar-attempt1.png` | `710x600+1022+298` | main composer actions still visible | Main controls visible, but Rust/React width mismatch confirmed | cross-layer width parity (`260/400` vs `280/468`) | width audit only | warm shell, card-like feel | pass |
| 2026-04-06 12:39 | Spotlight / sidebar + artifact open | `/tmp/autopilot-ux-loop/20260406-123431/spotlight-sidebar-artifact-attempt1.png` | `1110x600+1022+298` | panel close action + main composer actions | Native screenshot turned fully dark | shared width mismatch plus heavy empty-session drawer mount | initial evidence only | unusable; no visible controls | fail |
| 2026-04-06 13:07 | Spotlight / sidebar + artifact open | `/tmp/autopilot-ux-loop/20260406-123431/spotlight-sidebar-artifact-compactbudget.png` | `898x600-0+298` | panel close action + main composer actions | Window fit on-screen, but drawer state still rendered black | empty-session artifact drawer mount / drawer animation | compact dual-panel shared width budget (`450 + 112 + 336`) | geometry solved, render still failing | fail |
| 2026-04-06 13:14 | Spotlight / sidebar + artifact open | `/tmp/autopilot-ux-loop/20260406-123431/spotlight-sidebar-artifact-slate.png` | `898x600-0+298` | panel close action + main composer actions | None | empty-session drawer simplified to static shell; drawer animation removed | lightweight empty drawer fallback + slate token pass | closer to IDE shell; calmer slate surfaces | pass |
| 2026-04-06 13:15 | Spotlight / drawer close click proof | `/tmp/autopilot-ux-loop/20260406-123431/spotlight-close-click-proof-slate.png` | `730x600+1022+298` | visible drawer close affordance is clickable | None | post-fix click verification | clicked native drawer close button | slate shell preserved after interaction | pass |
| 2026-04-06 13:40 | Spotlight / base idle | `/tmp/autopilot-ux-loop/20260406-123431/spotlight-base-queryfix-before-submit.png` | `450x600+1022+298` | visible route into the main app | No visible way to open the main app from Spotlight; shell still read slightly blue | missing primary navigation affordance + palette token drift | added `Studio` composer action and neutralized shell/input tokens toward slate grey | calmer, more neutral shell; main-app affordance is explicit | pass |
| 2026-04-06 13:43 | Spotlight / submitted query running (`kittens`) | `/tmp/autopilot-ux-loop/20260406-123431/spotlight-query-kittens-submitted-running.png` | `450x600+1022+298` | submitted prompt remains visible and useful while running | Earlier native state was replaced by validation and planner cards, and the prompt could disappear during remote-history handoff | optimistic history handoff + always-on session chrome + orchestration board rendering on weak signals | retained optimistic prompt while running, hid overlay telemetry chrome for normal runs, deferred route card while live, limited orchestration board to real delegated signals | query-first again; running state is compact and legible | pass |
| 2026-04-06 13:44 | Studio / opened from Spotlight | `/tmp/autopilot-ux-loop/20260406-123431/studio-opened-from-spotlight.png` | `1280x650+192+298` | main app is reachable from Spotlight | None after clicking the new `Studio` action | hidden navigation affordance | clicked native `Studio` button in Spotlight composer | reachability fixed; Studio shell still needs its own density pass | pass |
| 2026-04-06 13:48 | Studio / copilot after Spotlight handoff | `/tmp/autopilot-ux-loop/20260406-123431/studio-opened-from-spotlight-queryfirst.png` | `1280x650+192+298` | active request stays primary in the main app | Earlier Studio handoff still front-loaded validation and planner chrome ahead of the actual clarification task | shared copilot session chrome in `variant=\"studio\"` | removed unconditional Studio session chrome so the clarification card owns the pane | closer to an IDE copilot pane; the task is now the focal point | pass |
| 2026-04-06 16:52 | Studio / pending artifact route top-left status hotspot | before `/home/heathledger/Pictures/Screenshot_2026-04-06_16-38-28.png`; after `/tmp/autopilot-ux-loop/20260406-thinking-fix/postfix-after-hotspot-click-crop.png` | `1280x650+192+298` | a single visible thinking / run-status surface, and no blanking when the old hotspot is used | Native pre-fix state showed both a `Working...` pill and a `Preparing the outcome surface` card; clicking the top-left thinking hotspot could drive the surface into a black/blank state | shared pending-state ownership between `ConversationTimeline` and `studioStatusCard` | suppress timeline pending indicators whenever a Studio run-status card is active | calmer single-status Studio surface; no duplicate pill remains in the hotspot region | pass for duplicate/hotspot removal; deeper artifact rerun blocked by `Tx ... did not commit within 15000ms` on the fresh profile |
| 2026-04-06 17:26 | Spotlight / working-pill thinking inspector | before `/tmp/autopilot-ux-loop/20260406-inspector-fix/thinking-inspector-open.png`; after `/tmp/autopilot-ux-loop/20260406-inspector-fix/thinking-inspector-after-fixes.png` | `918x600+1022+298` | clicking the live `Working...` pill should open a usable trace drawer instead of blanking the native window | Pre-fix native rerun expanded the drawer width and rendered a full black surface | trace-only drawer still mounted the full operator hook stack, and the empty fallback had no visible escape hatch | gated non-trace operator hooks whenever the drawer opens in focused trace mode; added `Back to chat` to the empty fallback; kept the thinking drawer on a trace-only nav set | closer to a compact IDE inspector instead of a dead-end admin surface | pass |
| 2026-04-06 17:26 | Spotlight / thinking inspector secondary actions | `/tmp/autopilot-ux-loop/20260406-inspector-fix/thinking-raw-trace-tab-2.png`; `/tmp/autopilot-ux-loop/20260406-inspector-fix/thinking-back-to-chat-proof.png`; `/tmp/autopilot-ux-loop/20260406-inspector-fix/empty-drawer-back-button.png` | `918x600+1022+298` | adjacent trace tabs should render, and the drawer must expose a clear route back to chat | Earlier user flow reported black sections and no return path once inside thinking | missing trace-only affordances and no persistent return control in the drawer shell | reduced the drawer to `Thinking` + `Raw trace` for the working-pill entry path and surfaced a persistent `Back to chat` action in both live and empty states | compact, low-noise trace loop with an obvious exit | pass |
| 2026-04-06 17:29 | Studio / live handoff from Spotlight run | `/tmp/autopilot-ux-loop/20260406-inspector-fix/studio-from-live-run-waited.png` | `1280x650+192+298` | clicking the live `Studio` affordance should surface a usable main app window | Native `Autopilot Studio` window opened as a full black frame | Studio handoff/render seam still unresolved on the live-run path | evidence only; no local fix yet | blocker; main app still not trustworthy from a live handoff | fail |
| 2026-04-06 17:37 | Studio / live handoff crash surfaced | `/tmp/autopilot-ux-loop/20260406-inspector-fix/studio-crash-guard-rerun.png` | `1280x650+192+298` | live Studio handoff should render the main app rather than a dead black frame | Crash guard exposed `undefined is not an object (evaluating 'snapshot.pinned_files.length')` from `useSpotlightFileContext.ts` | file-context transport shape drift between native payload and frontend expectations | added Studio crash guard temporarily and traced the failing file-context seam | moved from black-box failure to actionable seam | fail with actionable error |
| 2026-04-06 17:45 | Studio / fresh open from Spotlight after file-context fix | `/tmp/autopilot-ux-loop/20260406-studio-handoff/studio-fresh-opened-from-spotlight.png` | `1280x650+192+298` | clicking the Spotlight `Studio` control should open a readable main app surface without inheriting stale inspector clutter | None | file-context payload normalization + Studio-local inspection layout | normalized `SessionFileContext` transport at the service boundary, guarded count math in the hook, and stopped `variant="studio"` from inheriting Spotlight's persisted drawer visibility | cleaner, calmer Studio mount with the main work surface primary instead of a stale Doctor panel | pass |
| 2026-04-06 17:46 | Studio / fresh submitted query (`search kittens`) | `/tmp/autopilot-ux-loop/20260406-studio-handoff/studio-search-kittens-submitted.png`; `/tmp/autopilot-ux-loop/20260406-studio-handoff/studio-search-kittens-after-wait.png` | `1280x650+192+298` | a simple query should remain query-first and legible while Studio routes it | None during the first routing phase; prompt remains visible and the surface stays focused on the request | Studio run-state copy + fresh local panel state | reused the chat-first Studio run-state card and verified the fresh-mount local drawer behavior under submit | compact, operator-grade routing state instead of a telemetry wall | pass |
| 2026-04-06 19:00 | Spotlight -> Studio / initial artifact request handoff | `/tmp/autopilot-ux-loop/20260406-183140/spotlight-fresh-base-postfix.png`; `/tmp/autopilot-ux-loop/20260406-183140/studio-opened-no-extra-spotlight.png`; `/tmp/autopilot-ux-loop/20260406-183140/studio-after-submit-3s.png` | Spotlight `450x600+1022+298`; Studio `1280x650+192+298` | submitting an artifact request from the launcher should leave one primary operator surface, not a second leftover Spotlight window | Earlier user flow resurfaced a second shell after the first submit and split attention across surfaces | shell-origin handoff from `start_task` into window surfacing | passed `originSurface` through `TauriRuntime`, taught the kernel to hide Pill and Spotlight directly for Studio-origin runs, and reran the native submit path from Spotlight into Studio | single-surface operator loop; no duplicate shell remains after handoff | pass |
| 2026-04-06 19:02 | Studio / local HTML artifact timeout recovery | `/tmp/autopilot-ux-loop/20260406-183140/studio-after-10s-postfix.png`; `/tmp/autopilot-ux-loop/20260406-183140/studio-after-60s-postfix.png` | `1280x650+192+298` | an artifact request should open a visible artifact surface even when the local model stalls | Earlier native state could sit in `Preparing the outcome surface` and eventually strand the operator in receipts with no opened artifact | local HTML materialization budget + timeout handling for real-local runtimes | reduced the local HTML token budget, shortened the real-local HTML timeout to 45s, enabled the local draft fast path for real-local HTML/SVG/JSX, and added a truthful scaffolded draft bundle that auto-opens when generation times out | request-specific artifact stays inspectable in a calm slate shell instead of disappearing behind a stalled generation pass | pass with truthful partial fallback |
| 2026-04-07 11:42 | Studio / full modal-first artifact completion after Enter submit | `/tmp/autopilot-ux-loop/20260407-render-fix/studio-clean-before-submit.png`; `/tmp/autopilot-ux-loop/20260407-render-fix/studio-after-listener-fix.png`; `/tmp/autopilot-ux-loop/20260407-render-fix/studio-after-enter-submit-clean.png`; `/tmp/autopilot-ux-loop/20260407-render-fix/studio-after-enter-140s-clean.png` | `1280x650+192+298` | pressing Enter on the seeded Studio intent should stay in one Studio window and eventually open a completed artifact, not a crash screen or deterministic timeout scaffold | Pre-fix Studio could crash on mount with `undefined is not an object (evaluating 'listeners[eventId].handlerId')`, blocking the run before artifact completion | native Tauri listener cleanup race plus mixed raw-output HTML recovery in the modal-first artifact path | added safe Tauri listener disposal and benign-runtime-error filtering in Studio, kept modal-first HTML repair/extraction, and removed the deterministic timeout scaffold fallback so the run waits for a real artifact outcome | artifact-first Studio flow now reads like one operator surface instead of a crash/recovery detour | pass |
| 2026-04-07 12:08 | Studio / completed artifact Source tab and return to Render | before `/tmp/autopilot-ux-loop/20260407-render-fix/studio-after-enter-140s-source-clean.png`; after `/tmp/autopilot-ux-loop/20260407-source-rerun/after-source-click.png`; `/tmp/autopilot-ux-loop/20260407-source-rerun/after-render-return.png` | `1280x650+192+298` | Source should open authored HTML inside the native artifact stage and let the operator return to Render without crashing or spawning another window | Clicking `Source` on a completed artifact crashed Studio with Monaco worker error `URL is not valid or contains user credentials.` | workspace-backed artifact source route still mounted `WorkspaceEditorPane` / Monaco even after the logical source path was simplified | replaced both logical and workspace-backed artifact Source views with the shared read-only Studio source inspector and reloaded the live crash screen into the patched code path before re-clicking `Source` | calmer single-surface artifact loop; source inspection is useful instead of a native dead end | pass |
| 2026-04-07 14:05 | Studio / shared-swarm rerun after generic execution-envelope lift | `/tmp/autopilot-ux-loop/20260407-shared-swarm-rerun/studio-after-shared-envelope-rerun.png`; `/tmp/autopilot-ux-loop/20260407-shared-swarm-rerun/studio-after-repair-wait.png`; `/tmp/autopilot-ux-loop/20260407-shared-swarm-rerun/studio-after-marker-fix.png` | `1280x650+192+298` | the same native Enter-submit path should still open a completed HTML artifact after the swarm records were lifted into a shared execution model | The new path first stalled after `interaction`, then repair was rejected as out-of-scope, then a salvaged skeleton dropped a required `section:hero` end marker, and finally the narrowed repair pass still timed out at 60s | shared-swarm HTML worker transport: repair write-scope derivation, skeleton marker normalization, and overweight local repair prompt budget | gave HTML repair the canonical `index.html` region scope, normalized salvaged skeleton marker pairs before section patching, shrank local repair context/judge focus, and raised real-local repair timeout to 90s | swarm transport is again quiet enough that the artifact path can be judged on artifact quality instead of harness breakage | fail before final rerun; each blocker was concrete and local |
| 2026-04-07 14:37 | Studio / shared-swarm HTML artifact pass with live interaction proof | `/tmp/autopilot-ux-loop/20260407-shared-swarm-rerun/studio-after-repair-prompt-fix.png`; `/tmp/autopilot-ux-loop/20260407-shared-swarm-rerun/studio-after-quantum-toggle-click.png` | `1280x650+192+298` | the native Studio query `Create an interactive HTML artifact that explains quantum computers` should open a completed artifact in place, with visible controls that respond inside the live render surface | None on the final rerun | repaired shared-swarm HTML execution lane | final rerun on the hardened swarm path; render eval passed on desktop/mobile/interaction, repair completed and reparsed successfully, final judge passed, and the artifact opened directly in Studio; clicking `Quantum Qubit` changed the live render state from `Classical Computing (Bits)` to `Quantum Computing (Qubits)` | pass |
| 2026-04-07 18:00 | Studio / fresh non-artifact conversation route validation | `/tmp/autopilot-ux-loop/20260407-174925-conversation-route/studio-after-stop-ctrl-n.png`; `/tmp/autopilot-ux-loop/20260407-174925-conversation-route/studio-conversation-suggestion-after-click.png`; `/tmp/autopilot-ux-loop/20260407-174925-conversation-route/studio-conversation-accessibility.txt` | `1280x650+240+202` | a fresh Studio session should be able to launch a shared-execution conversation path without inheriting stale artifact chrome | Continuing from an active artifact task kept the old artifact surface visible and the run stuck at `Working... Sending message...`; after stopping and resetting with `Ctrl+N`, Studio returned to the welcome state, but the explicit conversational welcome action did not trigger a visible route transition through the native shell | fresh-session launcher / welcome-action delivery for non-artifact Studio runs | no code patch yet; validated shared non-artifact envelope in tests/build, then isolated the remaining native seam to fresh-session launcher behavior rather than the shared execution transport | native shell is now truthful about the next blocker: conversation routing exists below the surface, but the welcome/composer initiation path still needs a real user-facing fix | fail with actionable native seam |
| 2026-04-07 18:06 | Studio / welcome suggestion direct-submit pass for fresh session | `/tmp/autopilot-ux-loop/20260407-174925-conversation-route/studio-conversation-suggestion-direct-submit-postfix.png`; `/tmp/autopilot-ux-loop/20260407-174925-conversation-route/studio-conversation-suggestion-send-settled.png` | `1280x650+240+202` | clicking a Studio welcome suggestion should start the real submit path directly instead of only staging hidden composer text | Welcome suggestions still did not yield native screenshot proof of a routed conversation surface under AT-SPI-driven activation; the welcome surface disappeared, but no visible `Working...` or shared-execution conversation state replaced it during the rerun window | welcome suggestion submit path in the Studio shell | changed Studio welcome suggestions to call the same submit path directly via `handleSubmitText(text)` instead of only `setIntent(text)`; frontend build passed | less dead-end welcome UX in code, but native non-artifact launch still lacks screenshot proof and needs another live pass with a more faithful click path | fail pending native proof |
| 2026-04-07 19:32 | Studio / fresh welcome density and clickable conversation suggestion | `/tmp/autopilot-ux-loop/20260407-174925-conversation-route/studio-fresh-after-pill-removal.png` | `1280x650+240+202` | the conversational welcome suggestion should be visible and clickable at the default Studio size | Earlier welcome chrome was too tall; the conversational suggestion sat below the fold and only accessibility could reach it | welcome surface density and suggestion ordering | reordered the suggestion set so conversation leads, reduced headline/panel padding, and laid suggestions out as a compact two-column grid | closer to an operator launcher instead of a concept board; the conversation path is above the fold | pass |
| 2026-04-07 19:32 | Studio / post-click conversation surface without route-status pill | `/tmp/autopilot-ux-loop/20260407-174925-conversation-route/studio-conversation-after-pill-removal.png` | `1280x650+240+202` | clicking the conversation suggestion should keep the main Studio surface focused on the prompt rather than adding decorative route chrome | The newly added non-artifact route-status card/pill cluttered the surface and competed with the actual conversation path | non-artifact `studioStatusCard` chrome in the main Studio surface | removed the non-artifact route-ready card from `studioStatusCard` so routing evidence stays in receipts while the main surface just shows the prompt and conversation state | cleaner, calmer Studio lane with less ornamental status chrome | pass |
| 2026-04-07 19:38 | Studio / conversation submit shows assistant pending turn | `/tmp/autopilot-ux-loop/20260407-174925-conversation-route/studio-conversation-pending-bubble-after-click.png` | `1280x650+240+202` | after clicking the conversation suggestion, the Studio surface should read like a live chat instead of `user bubble -> empty void` | Earlier native submit left the user prompt at top-right with the rest of the pane blank until a later answer arrived | missing assistant-side pending state in `ConversationTimeline` | added an inline assistant pending bubble for the latest unanswered turn and moved the state into the chat surface instead of foreground chrome | much closer to a real operator chat: the pane now shows a live reply state immediately after submit | pass |
| 2026-04-08 11:31 | Studio / complex mission-control artifact mid-run truthfulness | `/tmp/autopilot-ux-loop/20260408-live-mission-specialist-rerun/studio-seeded-after-45s-progressfix.png`; `/tmp/autopilot-ux-loop/20260408-live-mission-specialist-rerun/studio-seeded-receipts-expanded-80s-progressfix.png`; `/tmp/autopilot-ux-loop/20260408-live-mission-specialist-rerun/studio-seeded-final-progressfix.png` | `1280x650+240+202` | a complex HTML mission-control request should surface iterative swarm progress in the native Studio window instead of reading like a one-shot black box | Before the progress plumbing patch, the exact live run showed `0 worker receipts` and `0/0 work items` even while skeleton and section workers were already executing in the backend proof trace | missing mid-run publication of swarm execution receipts from generation into current task / session materialization state | added `StudioArtifactGenerationProgress` snapshots, threaded a generation progress observer from `prepare.rs` through `materialization.rs` into `generation.rs`, and published live execution envelope / receipt updates into the current task snapshot during dispatch, render, judge, and repair verification | the main Studio surface now truthfully reads as an iterative operator run: OCR confirms `2/10`, then `4/10`, then `8/10 completed work items`, with expanded receipts showing `4 worker receipts` and later `8 worker receipts` on the native window | pass |
| 2026-04-08 11:37 | Studio / complex mission-control artifact live decomposition proof | `/tmp/autopilot-ux-loop/20260408-live-mission-specialist-rerun/studio-seeded-receipts-expanded-80s-progressfix.png` | `1280x650+240+202` | the same complex request should break into multiple bounded work items and dispatch waves, not a single opaque generation | Earlier Studio artifact runs visually hid the work graph; a user could not tell whether the system had decomposed the request at all | shared execution envelope visibility in native receipts | verified live checkpoint + proof trace alignment after progress publication: checkpoint reached `dispatch_batches=7`, `workers=9`, `verifications=3`, while the proof log showed skeleton, section-1, section-2, section-3, style-system, interaction, render evaluation, and bounded repair start on the same canonical artifact | acceptance bar met for this step: the native Studio UI now exposes real iterative decomposition on a complex query instead of a fake one-shot status strip | pass |
| 2026-04-08 11:43 | Studio / blocked-to-repair transition honesty | `/tmp/autopilot-ux-loop/20260408-live-mission-specialist-rerun/studio-seeded-repair-edge-progressfix.png` | `1280x650+240+202` | once the acceptance judge blocks, the Studio surface should move into an active repairing state rather than freezing on a stale blocked snapshot | Native proof showed `Acceptance judge returned blocked` with `9 worker receipts` while the backend had already started `repair-pass-1`; the surface lagged behind the actual bounded repair coordinator state | missing repair-start progress emission / replan receipt publication before the repair worker completed | patched `generation.rs` so judge-blocked paths immediately emit a `repairing` progress snapshot with repair / replan receipts as soon as a repair pass is spawned and marked running; compile passed, but the rebuilt native rerun had only revalidated work-batch visibility before this log cut | repair transition plumbing is in code and compiles, but a full native screenshot proof of the new `repairing` state is still pending on the rebuilt rerun | fail pending final native proof |
| 2026-04-08 12:39 | Studio / complex mission-control artifact final native completion | `/tmp/autopilot-ux-loop/20260408-live-mission-specialist-rerun/studio-mimefix-final-proof.png` | `1280x650+240+202` | the complex mission-control request should finish as a real native Studio artifact run with the artifact rendered, the swarm complete, and no blocked/timeout/mime failure state | Earlier live reruns either stalled in repair, timed out after 900s, or failed the primary artifact contract because region-owned worker output could poison `index.html` MIME and patch shape | repair-parse latency, local HTML acceptance timeout, and region-owned `index.html` patch normalization in the shared swarm materialization path | added salvage-first repair parsing, raised split-acceptance timeout to `1200s`, and normalized coerced region-owned HTML patches so non-skeleton workers cannot emit malformed full-file `index.html` contracts | native Studio now shows `Render`, `Ready`, `Pass`, and `14/14 work items`, with the HTML mission-control artifact visibly rendered in the live window and the receipts panel no longer stuck in blocked repair | pass |
| 2026-04-08 19:06 | Studio / product-rollout charts artifact early native loading truth | `/tmp/autopilot-ux-loop/20260408-190209-product-rollout-thinking-fix/06-submit-via-a11y-1s.png`; `/tmp/autopilot-ux-loop/20260408-190209-product-rollout-thinking-fix/07-after-submit-45s.png`; `/tmp/autopilot-ux-loop/20260408-190209-product-rollout-thinking-fix/08-repair-streaming-state.png` | `1280x650+320+154` | an HTML artifact request should attach the artifact pane immediately, show real thinking processes, and stream useful coding progress instead of generic dead-air pills or dropping back to conversation | User-reported native run stayed in generic `THINKING` / `Working...` chrome and did not surface the artifact pane at all for `Create an interactive HTML artifact that explains a product rollout with charts` | early artifact surfacing + studio run-state ownership + missing live preview publication from shared execution envelope into the Studio shell | kept artifact-expected runs in the artifact lane before the first file lands, replaced generic pending ownership with the richer Studio status card, and published live worker / change previews from `generation.rs` into the current materialization snapshot consumed by `StudioConversationPanels` and `StudioArtifactLogicalSurface` | clean native rerun now exposes `Hide artifact (Artifact stage)` in AT-SPI within seconds, and the same run advances through `Render evaluation ... 8/10 work items`, then `Streaming Repair pass 1 · Integrator output`, then `Streaming Repair pass 2 ... 12/14 work items` instead of collapsing into conversation or empty status chrome | pass |
| 2026-04-08 19:19 | Studio / product-rollout charts artifact settled render with attached evidence | `/tmp/autopilot-ux-loop/20260408-190209-product-rollout-thinking-fix/09-after-complete-partial.png`; `/tmp/autopilot-ux-loop/20260408-190209-product-rollout-thinking-fix/10-final-render-open.png` | `1280x650+320+154` | the same run should settle into an attached artifact surface rather than end on `Studio kept the request in conversation` | Earlier user proof ended with no artifact surface at all | shared artifact materialization / attached renderer proof after live thinking run | verified the clean rerun all the way through completion using the desktop-localgpu profile plus AT-SPI tree inspection of the final native window | final native state keeps the artifact surface mounted with `index.html`, `Render/Source`, `Evidence`, and a rendered `Interactive HTML Interface` instead of falling back to conversation; current task ends as `Complete` with the artifact still attached | pass |
| 2026-04-08 20:24 | Studio / Source stage visual parity | `/tmp/autopilot-ux-loop/20260408-190209-product-rollout-thinking-fix/12-source-monaco-view.png` | `1280x650+320+154` | Source mode should read like a real Monaco editor, not a dressed-up code block | Earlier Source view was a rounded `pre/code` card with product copy, badges, and no editor chrome; it did not resemble the file editor the user expected | `ArtifactSourceWorkbench` used static HTML rather than Monaco, and the surrounding chrome was product-surface styling instead of editor-shell styling | replaced the inline `pre/code` renderer with a read-only Monaco editor, added Monaco theme/loader wiring, and restyled the Source workbench into tab strip + breadcrumbs + editor stage + status bar | native Source view now shows the actual Monaco surface with line numbers, minimap, tab/header chrome, and a VS Code-style status bar under `index.html` | pass |
| 2026-04-08 20:34 | Studio / artifact pane collapsed full-width conversation shell | `/tmp/autopilot-ux-loop/20260408-190209-product-rollout-thinking-fix/13-artifact-collapsed-fullwidth.png`; `/tmp/autopilot-ux-loop/20260408-190209-product-rollout-thinking-fix/15-collapsed-after-shell-width-fix.png` | `1280x650+320+154` | closing the artifact pane should restore a single full-width Studio conversation surface with no cut-off overflow seam | Pre-fix native collapse left the conversation pinned to the left half of the window with a dead vertical seam and the composer clipped; the drawer was visually gone but the shell still behaved like a split layout | `StudioConversationSurface` was passing a fragment with multiple grid siblings straight into the Studio shell, so the collapsed state still reserved broken grid space and the conversation lane did not stretch | wrapped the conversation fragment into one shell item, forced the Studio shell/conversation items to stretch to their grid track, and widened the collapsed chat/input lane template so the full-width state uses the whole window | post-fix native collapse now restores a true full-width Studio surface; the vertical seam is gone and the composer/status card span the available width instead of being cut off | pass |
