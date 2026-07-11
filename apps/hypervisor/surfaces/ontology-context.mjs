// Shared ontology context (Ontology Application Runtime wave) — the semantic-layer primitives
// every application interpolates through. Ontology is not just a shell: Pipeline materializes
// semantic objects, Object Explorer browses them, Ontology Manager defines their types — and
// other apps deep-link into that shared context instead of inventing their own. Introduced with
// the Manager/Explorer extraction; DELIBERATELY UNWIRED there (zero behavior change) — the
// interactive Explorer/Manager PRs and the cross-app interpolation PR wire these.
//
// The URL is the context's single source of truth (kit parseSelection/selectionQuery — reused,
// never duplicated): canonical key order is the serializer's sorted order, so the same context
// always produces the same URL.
import { escHtml, parseSelection, selectionQuery, inspectorShell, disabledCommand } from "./kit.mjs";

export const ONTOLOGY_CONTEXT_KEYS = ["ontology", "objectType", "objectSet", "objectId", "pane", "section"];

// Read the ontology context carried by a URL: only known keys, only non-empty values.
export function parseOntologyContext(url) {
  return parseSelection(url, ONTOLOGY_CONTEXT_KEYS);
}

// Serialize an ontology context onto a route (stable canonical order, empties dropped).
export function ontologyContextQuery(route, ctx) {
  const known = {};
  for (const k of ONTOLOGY_CONTEXT_KEYS) if (ctx && ctx[k] !== undefined) known[k] = ctx[k];
  return selectionQuery(route, known);
}

// Surface link helpers — the owning route for each semantic act. Types and sets BROWSE in the
// Explorer; type DEFINITIONS live in the Manager.
export const managerLink = (ctx) => ontologyContextQuery("/__ioi/ontology/manager", ctx || {});
export const explorerLink = (ctx) => ontologyContextQuery("/__ioi/ontology/explorer", ctx || {});
export const objectTypeLink = (ontology, objectType, extra) => explorerLink({ ontology, objectType, ...(extra || {}) });
export const objectSetLink = (ontology, objectSet, extra) => explorerLink({ ontology, objectSet, ...(extra || {}) });

// The semantic breadcrumb: `Ontology → Object type → Object set → Source/Pipeline/Proof`.
// parts = [{ label, href? }] — linked when an owning surface exists, plain text otherwise.
export function semanticBreadcrumb(parts) {
  const seg = (p) => p.href
    ? `<a class="ioi-sem-crumb" href="${escHtml(p.href)}">${escHtml(p.label)}</a>`
    : `<span class="ioi-sem-crumb">${escHtml(p.label)}</span>`;
  return `<nav class="ioi-sem-breadcrumb" data-testid="ioi-sem-breadcrumb">${(parts || []).map(seg).join('<span class="ioi-sem-sep" aria-hidden="true"> → </span>')}</nav>`;
}

// Semantic inspector shell — the kit inspector with the semantic-layer marker the cross-app
// verifiers target (one shell contract everywhere; apps style within their own namespace).
export function semanticInspectorShell({ id, title, subtitle, body, cls }) {
  return inspectorShell({ id, title, subtitle, body, cls: `ioi-sem-inspector${cls ? " " + cls : ""}` });
}

// A semantic action with no backing authority: visibly disabled, reason named (standing rule).
export function disabledSemanticAction({ label, reason }) {
  return disabledCommand({ label, reason, cls: "ioi-sem-action" });
}

// Safe ref formatting: escaped, monospace-marked, never a link unless the CALLER owns the route.
export function formatRef(ref) {
  return `<code class="ioi-ref">${escHtml(ref == null ? "" : String(ref))}</code>`;
}

// The shared Manager/Explorer surface model — both certified ports load the same four ODK
// projections (moved verbatim from the serve's flat branches; dead daemon → honest empty lists).
export async function loadOntologyModel(daemon) {
  const J = (p) => fetch(`${daemon}${p}`).then((r) => r.json()).catch(() => ({}));
  const [ov, o, op, ms] = await Promise.all([
    J("/v1/hypervisor/odk/overview"),
    J("/v1/hypervisor/odk/domain-ontologies"),
    J("/v1/hypervisor/odk/ontology-projections"),
    J("/v1/hypervisor/odk/materialized-object-sets"),
  ]);
  return {
    overview: ov,
    lists: {
      ontologies: o.ontologies || [],
      projections: op.ontology_projections || [],
      materialized_sets: ms.materialized_object_sets || [],
    },
  };
}
