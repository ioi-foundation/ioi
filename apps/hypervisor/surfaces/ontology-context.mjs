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

// Canonical semantic context (#64 adds the typed cross-plane identity keys). Values are RECORD
// IDS for owning-record routes — full refs ONLY where the proof plane addresses by receipt ref.
// NEVER context material: endpoint URLs, credential postures beyond labels, tokens/grants, raw
// source rows, arbitrary query bodies, unvalidated caller refs — the builders below construct
// context exclusively from daemon record ids/refs already in hand, and parse bounds every value.
export const ONTOLOGY_CONTEXT_KEYS = ["ontology", "objectType", "objectSet", "objectId", "pane", "section", "definitionKind", "definitionId", "dataSource", "connectorMapping", "policyView", "ontologyProjection", "materializingRun", "receipt"];
const CONTEXT_VALUE_MAX = 256;

// The Manager's section vocabulary (operational wave #63) — an unknown section fails closed to
// the discover default with a visible explanation (the module enforces; this is the allowlist).
export const MANAGER_SECTIONS = ["discover", "object-types", "properties", "value-types", "link-types", "action-types", "functions", "health", "resources", "configuration", "create"];
// Typed resource kinds (#64) replace the ambiguous generic "resource" selector — the Manager
// resolves the exact requested FAMILY before id lookup so identical ids across families can
// never select the wrong record. "resource" stays readable as a compatibility fallback only.
export const DEFINITION_KINDS = ["object-type", "property", "value-type", "link-type", "action-type", "function", "health-gap", "connector-mapping", "policy-view", "ontology-projection", "materialized-set", "resource"];

// Read the ontology context carried by a URL: only known keys, only non-empty BOUNDED values
// (an oversized value is dropped, never truncated into a different identity).
export function parseOntologyContext(url) {
  const raw = parseSelection(url, ONTOLOGY_CONTEXT_KEYS);
  for (const k of Object.keys(raw)) if (raw[k].length > CONTEXT_VALUE_MAX) delete raw[k];
  return raw;
}

// Serialize an ontology context onto a route (stable canonical order, empties dropped).
export function ontologyContextQuery(route, ctx) {
  const known = {};
  for (const k of ONTOLOGY_CONTEXT_KEYS) if (ctx && ctx[k] !== undefined) known[k] = ctx[k];
  return selectionQuery(route, known);
}

// Surface link helpers — the owning route for each semantic act. Types and sets BROWSE in the
// Explorer; type DEFINITIONS live in the Manager. Every builder serializes ONLY known context
// (unknown keys are dropped by ontologyContextQuery), never constructs refs from display labels,
// and FAILS CLOSED (returns null) when the owning id cannot be resolved — callers render plain
// text for a null link, never a fabricated one. Embed is preserved by passing {embed: "1"} in
// extra (already-embedded callers thread it); the serve embed-rewrite covers extracted routes.
export const managerLink = (ctx) => ontologyContextQuery("/__ioi/ontology/manager", ctx || {});
export const explorerLink = (ctx) => ontologyContextQuery("/__ioi/ontology/explorer", ctx || {});
export const objectTypeLink = (ontology, objectType, extra) => explorerLink({ ontology, objectType, ...(extra || {}) });
export const objectSetLink = (ontology, objectSet, extra) => explorerLink({ ontology, objectSet, ...(extra || {}) });
export const sourcesLink = (dataSource, extra) => (dataSource ? ontologyContextQuery("/__ioi/data/sources", { dataSource, ...(extra || {}) }) : null);
export const managerResourceLink = (ontology, kind, id, extra) => (ontology && id && ["connector-mapping", "policy-view", "ontology-projection", "materialized-set"].includes(kind) ? managerLink({ ontology, section: "resources", definitionKind: kind, definitionId: id, ...(extra || {}) }) : null);
export const pipelineNodeLink = (ontology, node, extra) => (ontology ? selectionQuery("/__ioi/pipeline", { ontology, node, ...(extra || {}) }) : null);
export const lineageLink = (ontology, objectSet, extra) => (ontology ? ontologyContextQuery("/__ioi/lineage", { ontology, objectSet, ...(extra || {}) }) : null);
export const vertexLink = (ontology, objectSet, objectId, extra) => (ontology ? ontologyContextQuery("/__ioi/vertex", { ontology, objectSet, objectId, ...(extra || {}) }) : null);
export const provenanceReceiptLink = (receipt, extra) => (receipt ? ontologyContextQuery("/__ioi/work-ledger", { receipt, ...(extra || {}) }) : null);
// Set-context provenance: lands on the ledger with the odk_materialization entry for that set
// selected (the ledger resolves set → entry → receipt; callers need no extra ledger fetch).
export const provenanceSetLink = (objectSet, extra) => (objectSet ? ontologyContextQuery("/__ioi/work-ledger", { objectSet, ...(extra || {}) }) : null);

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
