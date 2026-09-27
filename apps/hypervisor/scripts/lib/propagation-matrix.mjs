// propagation-matrix — which surface WRITES a value and which surfaces must then SHOW it (R-240).
//
// Per-page checks cannot see a value that lands in one place and not another: each page is right
// about itself. This module names the cross-surface contract as data — the writes, through their
// owning surface's own form, and the reads, each judged by the written value's own name — and the
// pure rules that keep that contract honest. It reaches no browser, file, clock or network.

// The run's unique tag stands in for `{tag}`; every needle MUST carry it.
export const TAG = "{tag}";

// The writes, in order, each through the form its owning surface renders: a module action (`module` +
// `action`), a serve-rendered form named by its exact `form` action, or a `drive` — an editor whose
// script submits its own form, driven through its UI by a driver the gate names. `capture` names the
// variable the landed URL's last path segment fills (the created record's id).
export const WRITES = Object.freeze([
  { id: "ontology", module: "ontology-manager", action: "create-ontology", route: "/__ioi/ontology/manager?section=create" },
  { id: "object-type", module: "ontology-manager", action: "upsert-object-type", route: "/__ioi/ontology/manager?ontology={ontology}&section=create&newKind=object-type" },
  { id: "properties", module: "ontology-manager", action: "upsert-property", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types&definitionKind=object-type&definitionId=loan" },
  { id: "title-property", module: "ontology-manager", action: "upsert-object-type", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types&definitionKind=object-type&definitionId=loan" },
  { id: "source", module: "sources", action: "declare", route: "/__ioi/data/sources?declare=1" },
  { id: "mapping", module: "ontology-manager", action: "map-backing-datasource", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types&definitionKind=object-type&definitionId=loan" },
  // R-240: three of the four ODK create forms were refused on every submission (no owner, no
  // idempotency key, v1 member names) and every edit was refused (no expected head).
  { id: "recipe", form: "/__ioi/odk/data-recipes", route: "/__ioi/odk/data-recipes/new", capture: "recipe" },
  { id: "recipe-edit", form: "/__ioi/odk/data-recipes/{recipe}/patch", route: "/__ioi/odk/data-recipes/{recipe}/edit" },
  { id: "manifest", form: "/__ioi/odk/manifests", route: "/__ioi/odk/manifests/new", capture: "manifest" },
  // R-240: Insight read a saved set's type from the top level; the writer nests it under `selection`.
  { id: "saved-set", module: "object-explorer", action: "save-object-set", route: "/__ioi/ontology/explorer?ontology={ontology}&objectType=loan" },
  // R-240: the lanes that replaced disabled "New…" buttons — each must reach the surfaces that list it.
  { id: "model", form: "/__ioi/foundry/models/register", route: "/__ioi/foundry/models?tab=registered" },
  { id: "diagram", drive: "diagram-editor", route: "/__ioi/studio/designer/diagram" },
  { id: "graph", drive: "machinery-editor", route: "/__ioi/studio/machinery/graph" },
  // R-240: Issues' "New" was disabled while the daemon owned an authored incident plane.
  { id: "issue", form: "/__ioi/missions/incidents/new", route: "/__ioi/missions/incidents?new=1" },
]);

// The reads: every surface that must show what the writes made, by the value's OWN name.
export const READS = Object.freeze([
  { after: "object-type", consumer: "Ontology Manager lists the object type", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types", needle: "Loan {tag}" },
  { after: "object-type", consumer: "Object Explorer offers the object type", route: "/__ioi/ontology/explorer?ontology={ontology}", needle: "Loan {tag}" },
  { after: "ontology", consumer: "Solution Designer lists the ontology", route: "/__ioi/studio/designer", needle: "{tag}-lending" },
  { after: "ontology", consumer: "Open Diagram · Recent has the ontology", route: "/__ioi/studio/designer?open=recent", needle: "{tag}-lending" },
  { after: "ontology", consumer: "Pipeline's picker offers the ontology", route: "/__ioi/pipeline", needle: "{tag}-lending" },
  { after: "ontology", consumer: "ODK lists the ontology", route: "/__ioi/odk", needle: "{tag}-lending" },
  // The ADOPTED Pipeline Builder (the owner's /data/recipes) is a single-page app over the local reference mirror, so
  // it is read by the WIRE its own pages call, judged by the same tagged needle (R-240 Arm A, 2026-09-27): its output
  // ontology picker (Target ontology) and its landing's pipelines.
  { after: "ontology", consumer: "Pipeline Builder (Data recipes) offers the ontology as an output target", route: "/ontology-metadata/api/ontology/v2/load/all", wire: { method: "POST", body: {} }, needle: "{tag}-lending" },
  { after: "source", consumer: "Data sources lists the source", route: "/__ioi/data/sources", needle: "{tag}-src" },
  { after: "source", consumer: "Pipeline Builder (Data recipes) Add data offers the source", named: { what: "the builder's Add data searches its dataset index, and a declared data source is not offered there: adding data is not yet bound to the Data sources and connector mappings a recipe reads", owner: "R-241 seed depth: Pipeline Builder editor.add-data (open)" }, route: "/foundry-search/api/compass/v0/search", wire: { method: "POST", body: { query: { includeResources: ["FILE"], text: "" }, limit: 50, offset: 0 } }, needle: "{tag}-src" },
  { after: "mapping", consumer: "Ontology Manager shows the backing datasource", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types&definitionKind=object-type&definitionId=loan", needle: "Loan {tag} backing datasource" },
  { after: "mapping", consumer: "Solution Designer composes the mapping", route: "/__ioi/studio/designer?ontology={ontology}", needle: "Loan {tag} backing datasource" },
  { after: "mapping", consumer: "Pipeline's mapping node shows it", route: "/__ioi/pipeline?ontology={ontology}&node=mapping", needle: "Loan {tag} backing datasource" },
  { after: "mapping", consumer: "Pipeline's datasource node carries the source", route: "/__ioi/pipeline?ontology={ontology}&node=datasource", needle: "{tag}-src" },
  { after: "mapping", consumer: "Data sources shows the source's mapping", route: "/__ioi/data/sources?dataSource={source}", needle: "Loan {tag} backing datasource" },
  { after: "recipe", consumer: "ODK lists the data recipe", route: "/__ioi/odk?ontology={ontology}", needle: "recipe-{tag}" },
  { after: "recipe", consumer: "Pipeline Builder (Data recipes) lists the data recipe", named: { what: "two recipe families: the ODK data-recipe form authors v1 records (/v1/hypervisor/odk/data-recipes) while the Pipeline Builder lists v2 DataRecipe families (/v1/hypervisor/data-recipe-revisions); a recipe made in ODK is no pipeline until it converges into v2", owner: "R-240 / ADR 0056 P4: converge the ODK recipe form onto the v2 family (open a founding change set, as the builder's Create does)" }, route: "/graphql-gateway/api/bulk?q=PipelineLandingSearchQuery", wire: { method: "POST", body: { operations: { 0: "query PipelineLandingSearchQuery($text: String, $pageSize: Int!) { searchResourcesV2(pageSize: $pageSize, filter: {text: $text, types: [EDDIE_PIPELINE]}) { results { resource { rid name __typename } __typename } nextPageToken __typename } __typename }" }, requests: [{ hash: "0", name: "PipelineLandingSearchQuery", variables: { text: "", pageSize: 50 } }] } }, needle: "recipe-{tag}" },
  { after: "recipe-edit", consumer: "The recipe's page shows its edited name", route: "/__ioi/odk/data-recipes/{recipe}", needle: "recipe-{tag}-v2" },
  { after: "manifest", consumer: "ODK lists the manifest", route: "/__ioi/odk?ontology={ontology}", needle: "manifest-{tag}" },
  { after: "manifest", consumer: "The recipe's page names the manifest that bundles it", route: "/__ioi/odk/data-recipes/{recipe}", needle: "manifest-{tag}" },
  { after: "saved-set", consumer: "Object Explorer lists the saved set", route: "/__ioi/ontology/explorer?ontology={ontology}", needle: "saved-{tag}" },
  // ADR 0056 M6: Insight merged into Object Explorer, which names a saved set's type beside its name.
  { after: "saved-set", consumer: "Object Explorer names the saved set's type", route: "/__ioi/ontology/explorer?ontology={ontology}", needle: 'saved-{tag}</td><td class="oe-sssel">type loan' },
  { after: "model", consumer: "Model Catalog lists the registered model", route: "/__ioi/foundry/models?tab=registered", needle: "probe-{tag}:1b" },
  { after: "model", consumer: "Inference offers the registered model", route: "/__ioi/foundry/inference", needle: "probe-{tag}:1b" },
  { after: "diagram", consumer: "Designer Recents lists the saved diagram", route: "/__ioi/studio/designer", needle: "diagram-{tag}" },
  { after: "diagram", consumer: "Studio's blueprints list the saved diagram", route: "/__ioi/studio/workbench?view=blueprints", needle: "diagram-{tag}" },
  { after: "graph", consumer: "Machinery lists the saved process graph", route: "/__ioi/studio/machinery", needle: "process-{tag}" },
  { after: "issue", consumer: "Issues lists the filed issue in its open lane", route: "/__ioi/missions/incidents?lane=open", needle: "issue-{tag}" },
  // ADR 0056: Issues is Operations' tool at /operations/issues; the Missions root this consumer read retires.
  { after: "issue", consumer: "Issues at its Operations route lists the filed issue", route: "/operations/issues?lane=open", needle: "issue-{tag}" },
  // ADR 0056 M3: Work / Incidents points at the Operations-owned link — the facet carries the issue's own title.
  { after: "issue", consumer: "Work / Incidents points at the filed issue", route: "/__ioi/work-projection/incidents", needle: "issue-{tag}" },
]);

// A needle is SPECIFIC only if it carries the run's tag. "backing datasource" alone is printed by the
// very notes that say NO mapping exists — a check on it passes on the absence it is testing.
export function isSpecificNeedle(needle) {
  return typeof needle === "string" && needle.includes(TAG) && needle.replace(TAG, "").trim().length > 0;
}

export function fill(template, vars) {
  return String(template).replace(/\{(tag|ontology|source|recipe|manifest)\}/gu, (_, k) => (vars[k] == null ? `{${k}}` : String(vars[k])));
}

// The matrix's own shape: every read follows a declared write, names a consumer once, and is specific;
// every write names a module and an action. `actionsOf(module)` returns that module's declared ids.
export function matrixFindings({ writes, reads, actionsOf, drivers = [] }) {
  const f = [];
  const writeIds = new Set(writes.map((w) => w.id));
  for (const w of writes) {
    if (!w.route) f.push(`write ${w.id}: incomplete`);
    else if (w.drive !== undefined) {
      if (!drivers.includes(w.drive) || w.module || w.action || w.form) f.push(`write ${w.id}: drives '${w.drive}', which the gate has no driver for`);
    } else if (w.form !== undefined) {
      // A serve-rendered form is named by the exact action it posts to, on the product's own path.
      if (typeof w.form !== "string" || !w.form.startsWith("/__ioi/") || w.module || w.action) f.push(`write ${w.id}: a form write names one /__ioi/ form action and no module`);
    } else if (!w.module || !w.action) f.push(`write ${w.id}: incomplete`);
    else if (!(actionsOf(w.module) || []).includes(w.action)) f.push(`write ${w.id}: ${w.module} declares no action '${w.action}'`);
  }
  const seen = new Set();
  for (const r of reads) {
    if (!writeIds.has(r.after)) f.push(`read '${r.consumer}': follows no declared write '${r.after}'`);
    if (!isSpecificNeedle(r.needle)) f.push(`read '${r.consumer}': needle '${r.needle}' is not specific to the run`);
    // A read may be NAMED — a known propagation defect, with what it is and who owns its fix — never nameless.
    if (r.named !== undefined && (!r.named || typeof r.named.what !== "string" || !r.named.what.trim() || typeof r.named.owner !== "string" || !r.named.owner.trim())) f.push(`read '${r.consumer}': a named read says what the defect is and who owns its fix`);
    if (r.wire !== undefined && (!r.wire || typeof r.wire !== "object")) f.push(`read '${r.consumer}': a wire read names its method and body`);
    const key = `${r.consumer}`;
    if (seen.has(key)) f.push(`read '${r.consumer}': named twice`);
    seen.add(key);
  }
  if (!reads.length) f.push("no reads: a propagation check that reads nothing proves nothing");
  return f;
}

// What a read found, judged. A consumer that did not render is not a consumer that lacks the value.
export function readVerdict({ status, html, needle }) {
  if (!(status >= 200 && status < 400)) return { verdict: "unrendered", why: `status ${status}` };
  if (typeof html !== "string" || !html.length) return { verdict: "unrendered", why: "empty page" };
  return html.includes(needle) ? { verdict: "shown", why: "the value's own name is on the page" } : { verdict: "missing", why: `'${needle}' is not on the page` };
}
