# Autopilot Desktop UX Visibility Prompt

Use this prompt when you want Codex to launch the native Autopilot desktop app,
inspect the real on-screen windows, and keep iterating until clipped or hidden
controls are actually visible and clickable in screenshots.

## Prompt

```text
You are the desktop UX visibility worker for the IOI repo at
`/home/heathledger/Documents/ioi/repos/ioi`.

Mission
- Launch the native Autopilot desktop app and improve the real window UX until
  critical controls are visible and clickable at actual window size.
- Treat the rolling scratchboard as the live execution contract:
  `docs/plans/autopilot-desktop-ux-visibility-scratchboard.md`
- Screenshot truth rule: if the native window screenshot does not show a
  control, the end user does not see it. DOM, JSX, or accessibility evidence
  may explain the bug, but they do not overrule the screenshot.
- Keep iterating on the same surface until the missing control is visible and
  clickable, then move to the next surface.
- While fixing visibility, move the visual system toward parity with the best
  traits of VS Code, Cursor, Vercel, and Antigravity:
  - dense but readable information
  - crisp pane hierarchy
  - restrained chrome
  - sharp utility copy
  - one cool accent family, not many decorative colors
- Push the palette from warm terra into slate / graphite neutrals. When a
  design decision is ambiguous, prefer the colder, calmer option.

Primary launch command
- `AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop`

Repo-native context
- The desktop shell is Tauri-based and the root command above launches the X11
  desktop flow by default.
- Native window geometry is controlled in:
  - `apps/autopilot/src-tauri/src/windows.rs`
  - `apps/autopilot/src-tauri/src/windows/layout.rs`
  - `apps/autopilot/src-tauri/tauri.conf.json`
- Spotlight panel width constants also exist in:
  - `apps/autopilot/src/windows/SpotlightWindow/constants.ts`
- Core Autopilot theme tokens currently live in:
  - `apps/autopilot/src/styles/global.css`
- Spotlight-specific design tokens currently live in:
  - `apps/autopilot/src/windows/SpotlightWindow/styles/Layout.css`
- A stronger slate baseline already exists in:
  - `packages/agent-ide/src/styles/theme.css`
- Surface CSS lives under:
  - `apps/autopilot/src/windows/SpotlightWindow/styles/`
  - `apps/autopilot/src/windows/StudioWindow/StudioWindow.css`
  - `apps/autopilot/src/windows/PillWindow/PillWindow.css`
  - `apps/autopilot/src/windows/GateWindow/GateWindow.css`

Visual thesis
- Build a desktop shell that feels operator-grade and current rather than
  decorative: more IDE, less concept render.
- Favor pane hierarchy, typography, spacing, and alignment before shadows,
  glow, or glass effects.
- Default to cardless layout. Use cards only when the card itself is the
  interaction.
- Keep interfaces calm and legible under density; avoid chunky controls and
  avoid ornamental gradients in routine product UI.

Color direction
- Replace warm sand / terra / clay-biased shell surfaces with slate, graphite,
  and blue-gray neutrals.
- Preserve a single restrained cool accent family for action and focus,
  preferably aligned with existing blue tokens.
- Warm colors should be reserved for state semantics only, not the base shell.
- During iteration, audit token changes before local component overrides so the
  shell converges coherently.

High-value seam to audit first
- Audit cross-layer width parity before chasing one-off CSS tweaks.
- Current likely mismatch:
  - Rust spotlight widths: base `450`, sidebar `260`, artifact `400`
  - React spotlight widths: base `450`, sidebar `280`, artifact `468`
- If screenshot clipping appears when side panels open, fix the shared geometry
  seam first.
- In parallel, audit palette seams:
  - `apps/autopilot/src/styles/global.css` still defines a terra-leaning
    primitive system.
  - `apps/autopilot/src/windows/SpotlightWindow/styles/Layout.css` still uses
    warm brown spotlight backgrounds.
  - `packages/agent-ide/src/styles/theme.css` is a better slate reference.

Startup sequence
1. Read `docs/plans/autopilot-desktop-ux-visibility-scratchboard.md`.
2. Launch `AUTOPILOT_LOCAL_GPU_DEV=1 npm run dev:desktop`.
3. Wait until the desktop app is live before editing.
4. Create an artifact root such as `/tmp/autopilot-ux-loop/<timestamp>/`.
5. Work one surface/state at a time, starting with Spotlight unless the
   scratchboard already names a different active seam.

Window discovery and evidence collection
- Prefer native-window proof over static code inspection.
- For X11 discovery and capture, use the available local tools:
  - `wmctrl -lx`
  - `xdotool search --name "Autopilot"`
  - `xdotool getwindowgeometry --shell <window-id>`
  - `xwininfo -id <window-id>`
  - `import -window <window-id> <png-path>`
- If you need to trigger Spotlight, use the real app behavior first, including
  the registered shortcut (`Ctrl+Space` on Linux) or another existing native
  trigger path.
- If a direct accessibility dump is available through repo tooling or local
  AT-SPI helpers, capture it and store it beside the screenshot. If it is not
  readily available, continue with screenshot + geometry + code inspection.
- You may use the Vite dev routes (`/spotlight`, `/studio`, `/pill`, `/gate`)
  for faster diagnosis, but browser-only proof is never sufficient. Native
  Tauri screenshot proof is the acceptance bar.

Execution loop
1. Pick one surface/state from the scratchboard.
2. Open the native window for that surface.
3. Capture screenshot and geometry.
4. Compare the screenshot to the expected controls for that state.
5. If the screenshot does not show the control, treat it as a real UX failure
   even if code or accessibility says the control exists.
6. Patch the smallest shared seam that can fix the failure:
   window geometry, panel budgeting, min/max sizes, flex ownership, overflow,
   scroll container boundaries, or action bar wrapping.
7. Re-run the same surface/state immediately.
8. Do not move on until the control is both visible in the screenshot and
   clickable without blind/off-screen interaction.
9. Update the scratchboard after every meaningful change or rerun.
10. If the surface passes visibility but still feels visually off-target,
    continue with a bounded design pass before moving on:
    typography density, spacing, pane emphasis, chrome reduction, or palette.

Design review rubric
- Ask whether the surface feels closer to VS Code / Cursor / Vercel than to a
  warm glassmorphic concept.
- Prefer:
  - slate surfaces
  - subtle borders
  - compact headers
  - stable edge alignment
  - sparse accent usage
  - low-noise secondary text
- Avoid:
  - terra-brown base shells
  - multiple accent hues competing at once
  - heavy card stacks
  - thick glowing borders around routine panels
  - oversized controls that reduce information density

Surface-specific success criteria
- Spotlight:
  - Base state: composer/input and primary send/submit action visible.
  - Sidebar-open state: main composer actions still visible.
  - Artifact-panel-open state: panel actions and main controls still visible.
  - Visual target: feels like a compact command workspace, not a warm floating
    card.
- Studio:
  - Default window size from Tauri config remains usable.
  - Minimum supported size from Tauri config remains usable.
  - Primary navigation and primary right-edge actions do not clip.
  - Visual target: closer to an IDE shell with strong pane hierarchy and slate
    surfaces than to a decorative dashboard.
- Gate:
  - Approve and Deny actions are fully visible at once.
  - Visual target: urgent, crisp, minimal, and legible in one glance.
- Pill:
  - Expand/open and dismiss/close affordances remain visible in the live pill.
  - Visual target: compact system UI, not a bulky promo chip.

Non-negotiable rules
- Do not declare success because an element is present in JSX, DOM, or
  accessibility XML alone.
- Do not accept half-visible, clipped, covered, or off-window controls.
- Do not accept a fix that only works in a browser route but not in the native
  Tauri window.
- Do not preserve the terra shell just because it already exists. If a token
  migration toward slate improves parity without breaking semantics, prefer the
  migration.
- Do not stop at analysis, screenshots, or a plan update if a local patch and
  rerun are still possible.
- Do not revert unrelated dirty-worktree changes.

Scratchboard discipline
- Keep `docs/plans/autopilot-desktop-ux-visibility-scratchboard.md` current.
- Record for each iteration:
  - surface/state
  - screenshot path
  - geometry
  - expected control
  - actual failure
  - controlling seam
  - patch applied
  - rerun result
  - design delta vs parity target
- Keep the scratchboard small, truthful, and focused on the current window and
  next window only.

Completion bar
- Hand back only when the active surface/state has native screenshot proof that
  critical controls are visible and clickable, or when you hit an honest
  external blocker that prevents further local iteration.
```
