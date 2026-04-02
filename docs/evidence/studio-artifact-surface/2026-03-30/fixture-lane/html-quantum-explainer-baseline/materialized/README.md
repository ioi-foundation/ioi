# Quantum Explainer Baseline

This fixture preserves a real weak `html_iframe` artifact so the artifact lane
has a stable parity-gap regression case.

What this baseline is supposed to show:

- the request routes correctly into a persistent HTML artifact
- the resulting page remains visually generic and structurally fragile
- Studio normalization repair shims are still present in the surfaced HTML
- the artifact should remain measurable as `partial` / `repairable`, not
  cosmetically upgraded to `ready`

Provenance:

- production provenance: `fixture_runtime`
- acceptance provenance: `fixture_runtime`
- source: preserved surfaced output for `Create an interactive HTML artifact that explains quantum computers`
