// propagation-matrix — which surface WRITES a value and which surfaces must then SHOW it (R-240).
//
// Per-page checks cannot see a value that lands in one place and not another: each page is right
// about itself. This module names the cross-surface contract as data — the writes, through their
// owning surface's own form, and the reads, each judged by the written value's own name — and the
// pure rules that keep that contract honest. It reaches no browser, file, clock or network.

// The run's unique tag stands in for `{tag}`; every needle MUST carry it.
export const TAG = "{tag}";

// The writes, in order, each through the form its owning surface renders.
export const WRITES = Object.freeze([
  { id: "ontology", module: "ontology-manager", action: "create-ontology", route: "/__ioi/ontology/manager?section=create" },
  { id: "object-type", module: "ontology-manager", action: "upsert-object-type", route: "/__ioi/ontology/manager?ontology={ontology}&section=create&newKind=object-type" },
  { id: "properties", module: "ontology-manager", action: "upsert-property", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types&definitionKind=object-type&definitionId=loan" },
  { id: "title-property", module: "ontology-manager", action: "upsert-object-type", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types&definitionKind=object-type&definitionId=loan" },
  { id: "source", module: "sources", action: "declare", route: "/__ioi/data/sources?declare=1" },
  { id: "mapping", module: "ontology-manager", action: "map-backing-datasource", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types&definitionKind=object-type&definitionId=loan" },
]);

// The reads: every surface that must show what the writes made, by the value's OWN name.
export const READS = Object.freeze([
  { after: "object-type", consumer: "Ontology Manager lists the object type", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types", needle: "Loan {tag}" },
  { after: "object-type", consumer: "Object Explorer offers the object type", route: "/__ioi/ontology/explorer?ontology={ontology}", needle: "Loan {tag}" },
  { after: "ontology", consumer: "Solution Designer lists the ontology", route: "/__ioi/studio/designer", needle: "{tag}-lending" },
  { after: "ontology", consumer: "Open Diagram · Recent has the ontology", route: "/__ioi/studio/designer?open=recent", needle: "{tag}-lending" },
  { after: "ontology", consumer: "Pipeline's picker offers the ontology", route: "/__ioi/pipeline", needle: "{tag}-lending" },
  { after: "ontology", consumer: "ODK lists the ontology", route: "/__ioi/odk", needle: "{tag}-lending" },
  { after: "source", consumer: "Data sources lists the source", route: "/__ioi/data/sources", needle: "{tag}-src" },
  { after: "mapping", consumer: "Ontology Manager shows the backing datasource", route: "/__ioi/ontology/manager?ontology={ontology}&section=object-types&definitionKind=object-type&definitionId=loan", needle: "Loan {tag} backing datasource" },
  { after: "mapping", consumer: "Solution Designer composes the mapping", route: "/__ioi/studio/designer?ontology={ontology}", needle: "Loan {tag} backing datasource" },
  { after: "mapping", consumer: "Pipeline's mapping node shows it", route: "/__ioi/pipeline?ontology={ontology}&node=mapping", needle: "Loan {tag} backing datasource" },
  { after: "mapping", consumer: "Pipeline's datasource node carries the source", route: "/__ioi/pipeline?ontology={ontology}&node=datasource", needle: "{tag}-src" },
  { after: "mapping", consumer: "Data sources shows the source's mapping", route: "/__ioi/data/sources?dataSource={source}", needle: "Loan {tag} backing datasource" },
]);

// A needle is SPECIFIC only if it carries the run's tag. "backing datasource" alone is printed by the
// very notes that say NO mapping exists — a check on it passes on the absence it is testing.
export function isSpecificNeedle(needle) {
  return typeof needle === "string" && needle.includes(TAG) && needle.replace(TAG, "").trim().length > 0;
}

export function fill(template, vars) {
  return String(template).replace(/\{(tag|ontology|source)\}/gu, (_, k) => (vars[k] == null ? `{${k}}` : String(vars[k])));
}

// The matrix's own shape: every read follows a declared write, names a consumer once, and is specific;
// every write names a module and an action. `actionsOf(module)` returns that module's declared ids.
export function matrixFindings({ writes, reads, actionsOf }) {
  const f = [];
  const writeIds = new Set(writes.map((w) => w.id));
  for (const w of writes) {
    if (!w.module || !w.action || !w.route) f.push(`write ${w.id}: incomplete`);
    else if (!(actionsOf(w.module) || []).includes(w.action)) f.push(`write ${w.id}: ${w.module} declares no action '${w.action}'`);
  }
  const seen = new Set();
  for (const r of reads) {
    if (!writeIds.has(r.after)) f.push(`read '${r.consumer}': follows no declared write '${r.after}'`);
    if (!isSpecificNeedle(r.needle)) f.push(`read '${r.consumer}': needle '${r.needle}' is not specific to the run`);
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
