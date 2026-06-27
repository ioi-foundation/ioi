# Hypervisor App — Design System

**Audience: any model (or person) touching Hypervisor UX.** This is the canonical
reference for the product's visual + interaction language. It is *descriptive of the
current UX*, not aspirational — every value here is extracted from the running app.

> **The product UI _is_ the live reference.** It is served by
> `apps/hypervisor/scripts/serve-live-reference.mjs` (the reference bundle + an IOI `/api`
> adapter), not by a hand-written React app. Treat the running app at **`:4173`** as the
> source of truth; treat this doc as the index to it.

---

## 0. Rules for models (read first)

- **Do not reinvent UI.** The design language already exists in the served bundle. Reuse
  its classes/tokens; match it exactly. If unsure how something looks/behaves, open
  `:4173` and inspect it — don't guess.
- **Never hard-code raw colors.** Use the semantic tokens (`--surface-*`, `--content-*`,
  `--border-*`). They theme automatically (light/dark). Raw hex is a bug.
- **Customize in the committed serve layer, not the snapshot.** The reference bundle lives
  in a **gitignored mirror** — it is read-only. Product changes (e.g. the identity rename
  `Levi Josman → John Doe`) go in `serve-live-reference.mjs` as response rewrites / an
  `/api` adapter handler, so they're committed and survive mirror regeneration. See
  [reference-api-integration.md](./reference-api-integration.md).
- **System-aware theming is mandatory.** The app honors `prefers-color-scheme`; both
  themes must work. Never force a single theme.
- **Verify against `:4173`** (both `colorScheme: dark` and `light`) before claiming a UX
  change is done. Screenshot-diff against the live app.

---

## 1. Theming

The app sets a theme class on `<html>` (`… light|dark`) from the system color scheme (and
`--chat-color-scheme`). The token system has two layers:

- **Primitive palette** — fixed hex, theme-independent (the bundle's `--*-gray-*`/`--*-purple-*`
  primitives). Never reference these directly in product UI.
- **Semantic tokens** — themed aliases over the primitives (`--surface-*`, `--content-*`,
  `--border-*`). **Always use these.**

Tokens are stored as space-separated RGB channels and consumed as `rgb(var(--token))` or
`rgb(var(--token) / <alpha>)`.

## 2. Color tokens (resolved, dark | light)

Semantic — use these:

| Token | Dark | Light | Use |
| --- | --- | --- | --- |
| `--surface-base` | `#1c1c1c` | `#fafafa` | app/page background base |
| `--surface-01` | `#161515` | `#ffffff` | raised panels, cards, sidebar |
| `--surface-03` | `#1f1f1f` | `#ffffff` | inputs / nested surfaces |
| `--surface-hover` | white-overlay | black-overlay | hover/active fill (low-alpha overlay, not a solid) |
| `--content-primary` | `#fafafa` | `#1f1f1f` | primary text |
| `--content-secondary` / `--content-muted` | `#a3a3a3` | `#737373` | secondary / muted text |
| `--content-strong` | `#d4d4d4` | `#525252` | emphasized text |
| `--content-accent` | near-white | `#0a0a0a` | accented/active text |
| `--content-link` | `#8babfc` | `#0048ff` | links |
| `--content-invert` | `#1f1f1f` | `#fafafa` | text on inverted surfaces |
| `--content-negative` | `#ff535a` | `#ad0002` | errors/destructive text |
| `--border-base` | subtle | `#e1e1e1` | default borders |
| `--border-strong` | — | `#d4d4d4` | stronger dividers |
| `--border-brand` | `#5e8afd` | `#2f69fd` | brand/focus borders |
| `--border-input-default` | `#525252` | `#d4d4d4` | input borders |
| `--border-error` | `#ff878d` | `#ffbcc0` | error borders |

Primitive palette (fixed, for reference only):

| Family | Values |
| --- | --- |
| gray | `100 #f5f5f5` · `200 #e1e1e1` · `300 #d4d4d4` · `500 #737373` · `700 #404040` · `900 #1f1f1f` |
| blue (brand) | `300 #5e8afd` · `500 #0048ff` |
| purple (accent) | `300 #ca6eff` · `500 #9800f0` |
| red (danger) | `300 #ff535a` · `500 #e90007` |
| orange | `300 #fe9a5b` |
| green (success) | `300 #6cff64` |
| neutral | white `#ffffff` · black `#000000` |

## 3. Typography

- **Font:** `"ABC Diatype", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
  sans-serif` (+ emoji fallbacks).
- **Type scale** (`--text-*`, utility `text-*`): `xs 10px` · `sm 12px` · **`base 14px`**
  · `lg 18px` · `xl 20px` · `2xl 24px`. Body default is `text-sm`/`text-base`.
- **Weights:** normal `400` (body), medium `500` (labels, nav, buttons, headings). Heavier
  weights are rare. Tracking is default; no letter-spacing tricks.

## 4. Spacing, radius, layout

- **Spacing** follows Tailwind's 4px rhythm (`gap-1`=4, `gap-2`=8, `p-2`=8, `px-3`=12 …).
  UI is **compact/dense** — favor `gap-1`/`gap-2`, `h-8`(32px)/`h-9`(36px) controls.
- **Radius:** `rounded-md` (6px) small controls · **`rounded-lg` (8px)** the default for
  cards / nav items / buttons · `rounded-full` pills, avatars, status dots.
- **Layout:** persistent **300px sidebar** (`data-sidebar-container`, `flex-shrink-0`) +
  a `flex-grow` content pane in a `flex flex-row` shell. Content max-width ~`1200px`.
  Settings has its own left nav in the same shell slot.

## 5. Iconography

Inline SVG, `stroke="currentColor"` (or `fill="currentColor"`), sizes **16 / 20 / 24px**,
`stroke-width: 1.5`, `stroke-linecap`/`linejoin` rounded or square per glyph,
`aria-hidden="true"` for decorative. Color comes from the surrounding `--content-*`.

## 6. Components & patterns

Class signatures below are the reference's own — reuse them verbatim.

- **Buttons.** Base: `select-none font-medium whitespace-nowrap transition-colors
  rounded-lg focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1
  focus-visible:animate-focus-pulse`. Variants: _primary_ (solid dark/`bg` + invert text),
  _clear_ (`bg-surface-button-clear hover:bg-surface-button-clear-accent
  hover:text-content-accent`), _icon_ (`h-8 w-8 aspect-square p-0`). Sizes `h-6`/`h-8`.
- **Inputs / textarea.** `rounded-lg border border-border-input-default bg-surface-03
  text-sm px-3`, placeholder `text-content-muted`, focus → `border-border-brand`.
- **Cards.** `rounded-lg border border-border-base bg-surface-01 p-4`; header `text-base
  font-medium text-content-primary`, meta `text-sm text-content-muted`.
- **Nav items.** `flex flex-row items-center rounded-lg h-8 hover:bg-surface-hover`.
  **Active** = the same `bg-surface-hover` token applied as a standalone class (the
  inactive item only has `hover:bg-surface-hover`). Exactly one active per nav group.
- **Menus / popovers** (Radix). Portal-rendered, anchored to the trigger. Trigger:
  `aria-haspopup="menu"` + `aria-expanded` + `data-state`. Content: `rounded-lg border
  border-border-base bg-surface-01 shadow-lg` with items `role="menuitem"` (`h-8`, hover
  `bg-surface-hover`). Enter/exit animation: §7.
- **Dialogs / modals.** Centered; dimmed overlay `bg-black/50`; panel `rounded-xl border
  bg-surface-01 shadow-xl` with title (`text-base font-medium`), body, and a footer
  (Cancel = clear button, primary on the right). Open via `aria-haspopup="dialog"`.
- **Accordions / collapsibles.** Trigger `aria-expanded` + chevron that rotates
  (`rotate-0 → rotate-90`, `transition-transform duration-150`); content animates §7.
- **Tabs.** `role="tablist"` / `role="tab"` (`aria-selected`, `data-state`), underline or
  filled active indicator; switching is client-side.
- **Badges / pills.** `rounded-full px-2 text-xs` (e.g. the `Core` plan badge); status
  uses semantic color (`--content-negative`, green/orange families).
- **Status dots.** `rounded-full` 6–8px, semantic fill (`data-testid="status-dot"`).
- **Toggles / switches.** `role="switch"` + `aria-checked`, `data-state="checked|
  unchecked"`; track + thumb, `transition` on toggle.
- **Composer** (home). `rounded-xl border bg-surface-01` with a textarea, a left
  `Work in a project` menu trigger, right model/agent-mode menu + submit icon button.

## 7. Motion

Subtle, fast (Radix + tailwindcss-animate). Driven by `data-state`:

- **Enter:** `data-[state=open]:animate-in fade-in-0 zoom-in-95 slide-in-from-{side}-2`
  (~150ms). **Exit:** `data-[state=closed]:animate-out fade-out-0 zoom-out-95
  slide-out-to-{side}-2`.
- **Accordions:** `data-[state=open]:animate-slideDown` /
  `data-[state=closed]:animate-slideUp` (height via `--radix-collapsible-content-height`,
  ~150ms ease-out).
- **Hover/state:** `transition-colors` (and `transition-transform` for chevrons),
  ~150–300ms.
- **Focus:** `focus-visible:animate-focus-pulse` ring; respect `motion-reduce:animate-none`.
- Keep it understated — no large/slow/bouncy motion.

## 8. Accessibility

- Interactive elements expose `aria-haspopup` / `aria-expanded` / `aria-current` /
  `aria-selected` / `aria-checked` and the right `role` (`menu`/`menuitem`/`tab`/`switch`/
  `dialog`). Match the reference's roles when adding UI.
- Visible focus via `focus-visible` rings (never remove without an equivalent). Honor
  `prefers-reduced-motion`. Maintain contrast against the active theme's `--content-*` /
  `--surface-*` pairings (don't pair muted-on-muted).

---

## 9. How to make a UX change (checklist)

1. Find it in the live app (`:4173`) and identify the tokens/classes it already uses.
2. If it's a data/content change (names, copy, fixtures) → rewrite/adapter in
   `serve-live-reference.mjs` (see the identity-rename pattern).
3. If it's genuinely new UI → build it with the tokens + component patterns above so it's
   indistinguishable from the reference; both themes; the §7 motion; §8 a11y.
4. Verify on `:4173` in **dark and light**, screenshot-diff against the reference, confirm
   no operator-name or upstream-brand leakage, and no raw-hex regressions.
