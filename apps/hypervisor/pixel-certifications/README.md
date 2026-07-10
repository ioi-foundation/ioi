# Pixel certifications — committed evidence, written by the instrument

A surface's `pixel_certified: true` in `harvest-app-parity-matrix.json` must point at a
`pixel-certifications/<slug>.json` file in THIS directory. These files are written by
`scripts/harness-reference-pixel-parity.mjs` itself — and ONLY on a genuine certification:
a **non-pinned** run over the **full default viewport set** (1440×900 + 1920×1080, plus 390×844 when the
reference supports mobile) in which **every** viewport passes the full verdict:

- the #34/#39 visual gates (theme match + reference IA landmarks + region geometry, both sides valid,
  neither side an error page),
- full-image diff ≤ 2.5% and chrome-only diff ≤ 0.75% after DATA-ONLY masks,
- canonical region bbox Δ ≤ 8px,
- zone palette drift ≤ 0.05 (a uniform tint cannot slide under the per-pixel threshold),
- the over-mask guard (masks may never cover chrome, nav, toolbar labels, or reference landmarks; area caps).

Why committed files instead of `.artifacts/` pointers: `.artifacts/` is **gitignored**, so a pointer there
can never be reviewed or machine-checked. The matrix generator PARSES the file here (schema, slug,
`pixel_certified: true`, `viewports_pinned: false`) and fails generation loudly on any mismatch; the pixel
verifier additionally deep-checks the file's recorded `thresholds` against the harness's `THRESHOLDS` of
record, so a certification made under quietly-loosened thresholds is rejected.

Do not hand-author or hand-edit files here — regenerate them by running the harness:

```
node apps/hypervisor/scripts/harness-reference-pixel-parity.mjs
```

`pixel_certified` is a STRONGER evidence layer on top of `daemon_wired`. It never replaces `daemon_wired`,
the hardened visual gate, or daemon truth.
