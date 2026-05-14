# IOI Editorial — Featured Image Standard

**v1.3** · For social cards, blog headers, and post embeds across the IOI ecosystem.

> **Changed in v1.3:** Anaglyph treatment is now **universal across the figure layer**, not reserved for the single brightest element. Tonal hierarchy within the figure is preserved by the *center color* of each anaglyph element. This eliminates the inconsistency in earlier versions where some marked elements got parallax and others didn't.
> **Changed in v1.2:** Anaglyph parallax added to the focal layer.
> **Changed in v1.1:** Terra accent removed. Hierarchy carried by value, not hue.

---

## 01 — Format

- **Aspect:** 2.5 : 1
- **Resolution:** 1500 × 600 px native, SVG-first, no rasterization
- **No light theme.** All assets ship dark.
- **No gradients, no glows, no drop shadows, no blur.**
- **No hue in the system field.** The mono palette is zinc. Brightness carries hierarchy.
- **Anaglyph is universal on the figure layer.** See §04 for the figure/ground rule.

## 02 — System Palette (mono)

| Token         | Hex       | Role |
|---------------|-----------|------|
| `--bg`        | `#0a0a0a` | Canvas. Never pure black at scale. |
| `--grid`      | `#171717` | Ambient grid, faintest visible structure |
| `--line`      | `#3f3f46` | Primary line work (zinc-700) |
| `--node`      | `#a1a1aa` | Marked elements, secondary tone (zinc-400) |
| `--node-hi`   | `#f4f4f5` | Marked elements, focal tone (zinc-100) |

**Hierarchy doctrine:** four tonal steps. Within the figure layer, the focal element uses `--node-hi`; all other figure elements use `--node`. There must be exactly one focal *role* per image (it may comprise multiple elements sharing that role — e.g. a boundary line and the states resolved against it).

## 03 — Anaglyph Channels

| Token        | Hex       | Role |
|--------------|-----------|------|
| `--ana-red`  | `#dc2626` | Red ghost (offset right of center) |
| `--ana-cyan` | `#06b6d4` | Cyan ghost (offset left of center) |

The muted tailwind red-600 / cyan-500 pairing preserves the parallax illusion while keeping chromatic load proportional. Pure `#ff0000` / `#00ffff` reads loud on screen.

## 04 — The Figure/Ground Rule

**Every cover has two layers.**

**FIGURE** — the marked discrete elements that carry the post's idea. These are the "things" the post is conceptually about: nodes, filled cells, marked intersections, resolved states, boundary lines that the diagram is *for*.

**GROUND** — everything else: connecting lines (tree edges, lattice grid), ambient grid, probabilistic field/noise textures, structural subdivision frames that contain the figure but aren't themselves the subject.

### The rule

> **Anaglyph is applied uniformly across the figure layer, never selectively. Ground stays mono.**

Anaglyph is not a focal marker — it is the visual treatment that identifies *what counts as a thing* in the diagram. Once you've drawn the figure/ground line for a cover, every element on the figure side gets anaglyph; every element on the ground side stays mono.

### Tonal hierarchy within the figure layer

The focal element uses `--node-hi` as its anaglyph center color. All other figure elements use `--node`. The red and cyan ghosts are constant across both. This way:

- Brightness identifies the focal element within the figure layer.
- Anaglyph identifies the figure layer relative to ground.

### Test: figure or ground?

When describing what the cover *means*, the figure is what you point to. Everything else is ground. Some heuristics:

- Filled and discrete? → figure
- Stroke-only outline of structural container? → ground
- Connects two figure elements? → ground (lines/edges)
- Field of noise or probability mass? → ground
- Faint ambient context grid? → ground
- Singular bright/load-bearing? → figure (and gets `--node-hi` center)

## 05 — Anaglyph Construction

For each figure element, three copies are drawn in Z-order:

1. Red ghost offset to the **right** by N pixels
2. Cyan ghost offset to the **left** by N pixels
3. Center fill (`--node-hi` or `--node`) on top

Red-right / cyan-left is convention. Do not invert.

**Offset by element size:**

| Element                       | Offset           |
|-------------------------------|------------------|
| Rectangular fills (≥ 30 px)   | 5 px             |
| Lines                         | 5 px perpendicular |
| Circles r ≥ 5                 | 3 px             |
| Circles r ≈ 3–4               | 2 px             |
| Circles r ≈ 2–2.5             | ~50% of radius (1–1.5 px) |

For figure elements that would be too small for readable anaglyph (radius < 2, diameter < 4), **size up the element** rather than skipping anaglyph. Inconsistent treatment within the figure layer breaks the doctrine.

## 06 — Typography (HTML pairing)

The featured image carries no embedded text. Title and series live in the surrounding layout.

```
IOI · 01                       mono · 11px · 600 · uppercase · tracked 0.18em · dim
Fractal Agency                 sans · 32px · 600 · tracked -0.02em
The Operating System for       sans · 16px · 400 · dim
the Automated Economy
```

Pair a geometric mono (Berkeley Mono / JetBrains Mono / IBM Plex Mono) with a characterful sans (Söhne / GT America / ABC Diatype / Plex Sans). Inter is forbidden — it is the font of generic SaaS.

## 07 — Composition

- The motif fills the canvas. 50 px minimum margin; bleed is permitted, decoration is not.
- One conceptual motif per post. No mixing.
- The figure layer is a single floating plane created by anaglyph parallax. The ground stays flat against the canvas.
- No perspective, no rendered 3D. Depth comes from channel parallax only.

## 08 — Motif Doctrine

Each post selects exactly one diagrammatic primitive that encodes the title:

| Primitive            | When it applies |
|----------------------|------------------|
| Binary tree → grid   | Hierarchy compiled to ground truth |
| Treemap subdivision  | Recursive containment, OS-like decomposition |
| Boundary + regimes   | Two systems meeting at a line |
| Lattice path         | Sequential progression, ordered states |
| Adjacency matrix     | Pairwise relations across a domain |
| Phase portrait       | Continuous state space, vector flow |
| Recursive subdivision (Sierpinski, quadtree) | Self-similar structure at scale |

Before drawing: **identify the figure**. Then render figure with anaglyph, ground without.

## 09 — Forbidden

- Hue or accent color anywhere in the ground layer. Red and cyan appear *only* as anaglyph channels on figure elements.
- Selective anaglyph within the figure layer. If one node gets parallax, every node gets parallax.
- 3D rendering, perspective scenes, faux-cinematic lighting
- Generated photography, stock composites, midjourney aesthetic
- Holographic interfaces, glassmorphic panels, "futuristic" UI screenshots
- Greek columns, scales of justice, brain motifs, neuron clouds
- Particles, glows, lens flares, bokeh
- Multi-color spectrums, rainbow gradients, additional chromatic channels beyond red/cyan
- Embedded title text — titles live in HTML
- Inter for any typography

## 10 — The Canonical Set

| # | Title | Primitive | Figure layer | Ground layer |
|---|-------|-----------|--------------|--------------|
| 01 | Fractal Agency | Treemap subdivision | 7 deepest filled cells (`--node-hi` center, 5 px offset) | Recursive subdivision frame (unfilled rectangles, `--line` stroke) |
| 02 | The Determinism Boundary | Boundary + regimes | Boundary line + 9 resolved states (`--node-hi` center; 5 px / 2 px offsets) | Probabilistic scatter (left, `--node` mono); lattice grid lines (right, `--line` mono) |
| 03 | The Internet of Intelligence | Binary tree → grid | 127 tree nodes (root at `--node-hi`, rest at `--node`) + 19 filled grid cells (`--node` center) | Tree edges (`--line`); ambient grid (`--grid`) |

## 11 — Why The Figure/Ground Rule

Earlier versions (v1.2) reserved anaglyph for the single brightest element. In practice this produced inconsistencies — Cover 03 had a single floating root above a flat tree, while Cover 02 had a floating boundary plus all nine resolved states. Same standard, different element counts, different visual logic. Readers noticed.

The figure/ground rule resolves this: anaglyph is a layer property, not a per-element accent. Once you decide what counts as "a thing" in the diagram, every thing gets the same depth treatment. Tonal hierarchy survives via center color. The result is consistent across covers and reproducible across new posts.

A second-order benefit: this rule is easy to follow without judgment calls. "Is this a marked element or structural context?" is a clearer question than "is this the single most important thing?" The author can answer the first one in seconds; the second one tempts them to under-mark.

---

## 12 — Production Notes

- Author SVGs by hand or via Python. Never via image-gen models.
- Stroke weights in the ground layer: 0.6–1.0 px. Diagram is delicate.
- Anaglyph weight compensation:
  - Boundary strokes at `--node-hi`: weight 1.2 (vs 1.4 with warm accent)
  - Treemap focal cells: inset 6 px from BSP stroke so structure survives around the bright core
  - Grid cells: inset 3 px
- Z-order: BG → faint grid → ground lines → ground fills → figure (red ghost, cyan ghost, center). Never invert.
- For Cover 03 specifically: render the root node LAST so it sits above the rest of the tree. With dense node populations this matters for visual hierarchy.
- Author checklist before shipping:
  1. Can you point to the figure in one sentence?
  2. Does every figure element have anaglyph?
  3. Is the focal element the only `--node-hi` center?
  4. Are all ground elements mono?
  5. Are colored fringes confined to the figure layer? (No anaglyph leakage onto lines or grid.)

---

*Future posts: select a primitive. Identify the figure. Anaglyph every element of the figure. Render the ground in mono zinc. Ship.*

