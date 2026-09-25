// Solution Designer — the DIAGRAM EDITOR (R-240).
//
// The Designer landing was a read-only map with New Diagram disabled as a "named gap". A lane-by-lane
// harvest of the reference editor (the captured seed, driven locally) showed what the lane actually
// is, and that almost none of it needs a server: typed Concept / Component / Resource nodes, text
// notes and groups on a pannable, zoomable dotted canvas; nodes joined by dragging from a handle;
// a selected node with quick-add arrows, a delete badge and "Link resource"; Diagram Information,
// Reference Diagrams, Graph Settings and Shortcuts panels; Import / Export as JSON; undo and redo.
// Only three lanes need the platform, and each is bound here to daemon truth:
//   SAVE             — a diagram is a Studio BLUEPRINT (`graph` is its authored document), owned by
//                      the caller's organization, CAS-patched against its admitted head.
//   LINK RESOURCE    — a node binds to a REAL record: an object type, data source, connector mapping
//                      or ontology from the ODK plane, or an application from the surface registry.
//   LOAD FROM LINEAGE — the reference imports a Data Lineage graph; here the lineage is the
//                      composition the daemon holds: source → mapping → object type → Object Explorer.
// The reference library's vendor diagrams are not ours to ship; the Reference Diagrams panel offers
// IOI's own architectures over IOI's applications, plus every composition the daemon holds.

import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { bpIcon } from "../../scripts/bp-icons.mjs";
import { DSG_APP_TILE_URI } from "../../scripts/designer-assets.mjs";
import { MCH_APP_TILE_URI } from "../../scripts/machinery-assets.mjs";
import { escHtml } from "../kit.mjs";

export const DIAGRAM_SCHEMA = "ioi.studio.solution-diagram.v1";
export const DIAGRAM_KINDS = Object.freeze(["concept", "component", "resource", "text", "group", "state"]);
export const STATE_KINDS = Object.freeze(["initial", "normal", "final"]);
const MAX_NODES = 400;
const MAX_EDGES = 800;

// The reference's concept palette, as harvested — generic categories of a business problem.
export const CONCEPT_TYPES = Object.freeze([
  { type: "Analytics", description: "Analyze and investigate" },
  { type: "Application Building", description: "Build applications to automate and streamline operations" },
  { type: "Data Processing", description: "Process datasets" },
  { type: "Data Sourcing", description: "Collect and ingest data" },
  { type: "Modeling", description: "Conceive, train and use models" },
]);

// Resource node types. The first four bind to a daemon record; the rest are unlinked placeholders.
export const RESOURCE_TYPES = Object.freeze([
  { type: "Object type", record: "objectTypes", icon: "cube" },
  { type: "Data source", record: "dataSources", icon: "globe-network" },
  { type: "Connector mapping", record: "mappings", icon: "join-table" },
  { type: "Ontology", record: "ontologies", icon: "cubes" },
  { type: "File", icon: "endnote" },
  { type: "Action", icon: "take-action" },
  { type: "Interface", icon: "layout-grid" },
]);

// IOI reference architectures — authored for IOI's own applications (each component links its route).
const C = (id, route, title, description, x, y) => ({ id, kind: "component", route, title, description, x, y });
const R = (id, type, title, description, x, y) => ({ id, kind: "resource", type, title, description, x, y });
const K = (id, type, title, description, x, y) => ({ id, kind: "concept", type, title, description, x, y });
const E = (source, target, label) => ({ source, target, ...(label ? { label } : {}) });
export const REFERENCE_DIAGRAMS = Object.freeze([
  {
    id: "data-integration", category: "Workflow patterns", title: "Data integration",
    description: "A source declared in Data Connection, mapped into typed objects and explored — the ODK ladder end to end.",
    nodes: [
      R("src", "Data source", "Source system", "Any system of record — an API, a database, a bucket", 0, 0),
      C("dc", "/__ioi/data/sources", "Data Connection", "Declare the source and its sync", 400, 0),
      C("pb", "/__ioi/pipeline", "Pipeline Builder", "Map source fields to typed properties", 800, 0),
      R("ot", "Object type", "Business object", "The typed object the pipeline materializes", 1200, 0),
      C("om", "/__ioi/ontology/manager", "Ontology Manager", "Define the object type, its properties and title", 1200, 200),
      C("oe", "/__ioi/ontology/explorer", "Object Explorer", "Search, filter and save explorations", 1600, 0),
    ],
    edges: [E("src", "dc"), E("dc", "pb"), E("pb", "ot", "materializes"), E("om", "ot", "defines"), E("ot", "oe")],
  },
  {
    id: "alerting-pipeline", category: "Workflow patterns", title: "Alerting pipeline",
    description: "Events land as objects; a monitor raises an alert that a person approves before anything acts.",
    nodes: [
      R("ev", "Data source", "Event feed", "Events happening in a system", 0, 0),
      C("pb", "/__ioi/pipeline", "Pipeline Builder", "Aggregate events into alert candidates", 400, 0),
      R("al", "Object type", "Alert", "One object per raised alert", 800, 0),
      C("mon", "/__ioi/automations/monitors", "Automate", "A condition → effect rule over alert objects", 1200, 0),
      C("ap", "/__ioi/governance/approvals", "Approvals", "A person approves the effect before it runs", 1600, 0),
      R("wb", "Action", "Writeback", "Update the source system once the alert is confirmed", 2000, 0),
    ],
    edges: [E("ev", "pb"), E("pb", "al"), E("al", "mon", "watched by"), E("mon", "ap", "requests"), E("ap", "wb", "authorizes")],
  },
  {
    id: "agent-workflow", category: "Workflow patterns", title: "Agent-operated workflow",
    description: "An agent works a queue of objects inside a governed session; every effect crosses an approval.",
    nodes: [
      R("q", "Object type", "Work item", "The queue the agent works", 0, 0),
      C("auto", "/__ioi/automations/monitors", "Automate", "Trigger a run when a work item appears", 400, 0),
      C("st", "/__ioi/studio/workbench", "Studio", "The agent, its model route and its tools", 800, 0),
      C("ap", "/__ioi/governance/approvals", "Approvals", "Governed crossings for every effect", 1200, 0),
      C("ms", "/__ioi/missions", "Missions", "Runs, receipts and outcomes", 1600, 0),
    ],
    edges: [E("q", "auto"), E("auto", "st", "starts"), E("st", "ap", "requests"), E("st", "ms", "records")],
  },
  {
    id: "modeling", category: "Workflow patterns", title: "Modeling",
    description: "Training data shaped in a pipeline, a model trained and cataloged, served for inference into an operational app.",
    nodes: [
      R("td", "Data source", "Training data", "Labeled history the model learns from", 0, 0),
      C("pb", "/__ioi/pipeline", "Pipeline Builder", "Shape features from the source", 400, 0),
      C("ms", "/__ioi/foundry/model-studio", "Model Studio", "Train and compare model runs", 800, 0),
      C("mc", "/__ioi/foundry/models", "Model Catalog", "The approved model route", 1200, 0),
      C("inf", "/__ioi/foundry/inference", "Inference", "Serve predictions under a lease", 1600, 0),
      C("ws", "/__ioi/studio/workshop", "Workshop", "The app people act from", 2000, 0),
    ],
    edges: [E("td", "pb"), E("pb", "ms", "features"), E("ms", "mc", "publishes"), E("mc", "inf"), E("inf", "ws", "predictions")],
  },
  {
    id: "operational-process", category: "Workflow patterns", title: "Operational process optimization",
    description: "Changelog and current-state data back process objects; a state machine runs the process and Insight measures it.",
    nodes: [
      R("cl", "Data source", "Changelog", "Every state change the source system records", 0, 0),
      R("cs", "Data source", "Current state", "The latest state of each case", 0, 200),
      C("pb", "/__ioi/pipeline", "Pipeline Builder", "Join changelog and current state", 400, 100),
      R("case", "Object type", "Case", "One object per process instance", 800, 100),
      C("mach", "/__ioi/studio/machinery", "Machinery", "The process as a state machine", 1200, 0),
      C("ins", "/__ioi/evaluations/insight", "Insight", "Cycle times and bottlenecks", 1200, 200),
    ],
    edges: [E("cl", "pb"), E("cs", "pb"), E("pb", "case"), E("case", "mach", "runs"), E("case", "ins", "measured by")],
  },
  {
    id: "evaluation-loop", category: "Technical patterns", title: "Evaluation loop",
    description: "A model is evaluated against a suite, analyzed, and improved through a governed change.",
    nodes: [
      C("mc", "/__ioi/foundry/models", "Model Catalog", "The model routes under evaluation", 0, 0),
      C("ev", "/__ioi/evaluations/evalsuites", "AIP Evals", "Suites of graded cases", 400, 0),
      C("ins", "/__ioi/evaluations/insight", "Insight", "Analyze results over saved object sets", 800, 0),
      C("ua", "/__ioi/improvement/changes", "Upgrade Assistant", "Propose and gate the improvement", 1200, 0),
    ],
    edges: [E("mc", "ev"), E("ev", "ins"), E("ins", "ua"), E("ua", "mc", "promotes")],
  },
]);

// ---- pure helpers (server) ------------------------------------------------------------------

const str = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
const num = (v) => (typeof v === "number" && Number.isFinite(v) ? Math.round(v * 10) / 10 : 0);

// A posted diagram, cleaned to the shape this editor writes — or refused by name. The daemon bounds
// the serialized document (64 KiB); this bounds its members so a hand-edited import cannot smuggle
// arbitrary structure into a blueprint.
export function normalizeDiagramGraph(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { ok: false, reason: "the diagram is not a JSON object" };
  const rawNodes = Array.isArray(raw.nodes) ? raw.nodes : [];
  const rawEdges = Array.isArray(raw.edges) ? raw.edges : [];
  if (rawNodes.length > MAX_NODES) return { ok: false, reason: `a diagram holds at most ${MAX_NODES} nodes` };
  if (rawEdges.length > MAX_EDGES) return { ok: false, reason: `a diagram holds at most ${MAX_EDGES} connections` };
  const ids = new Set();
  const nodes = [];
  for (const n of rawNodes) {
    if (!n || typeof n !== "object") continue;
    const id = str(n.id, 64);
    if (!id || ids.has(id)) return { ok: false, reason: `node ids must be present and unique ('${id}')` };
    const kind = DIAGRAM_KINDS.includes(n.kind) ? n.kind : null;
    if (!kind) return { ok: false, reason: `node '${id}' has no known kind (${DIAGRAM_KINDS.join(", ")})` };
    ids.add(id);
    const node = { id, kind, type: str(n.type, 80), title: str(n.title, 200), description: str(n.description, 2000), x: num(n.x), y: num(n.y) };
    if (kind === "group") { node.w = Math.max(200, Math.min(4000, num(n.w) || 640)); node.h = Math.max(120, Math.min(4000, num(n.h) || 360)); }
    const ref = str(n.ref, 400); if (ref) node.ref = ref;
    const href = str(n.href, 400); if (href && href.startsWith("/") && !href.startsWith("//")) node.href = href;
    const icon = str(n.icon, 40); if (icon) node.icon = icon;
    if (kind === "state") node.stateKind = STATE_KINDS.includes(n.stateKind) ? n.stateKind : "normal";
    nodes.push(node);
  }
  const edges = [];
  const eids = new Set();
  for (const e of rawEdges) {
    if (!e || typeof e !== "object") continue;
    const source = str(e.source, 64), target = str(e.target, 64);
    if (!ids.has(source) || !ids.has(target) || source === target) continue;
    let id = str(e.id, 64) || `e_${source}_${target}`;
    while (eids.has(id)) id += "_";
    eids.add(id);
    const edge = { id, source, target };
    const label = str(e.label, 120); if (label) edge.label = label;
    edges.push(edge);
  }
  const s = raw.settings && typeof raw.settings === "object" ? raw.settings : {};
  const settings = { edgeLabels: s.edgeLabels !== false, animate: s.animate !== false, iconsOnly: s.iconsOnly === true };
  return { ok: true, graph: { schema: DIAGRAM_SCHEMA, nodes, edges, settings } };
}

// The lineage the daemon holds for one ontology, laid out as a diagram: each source a mapping reads,
// each mapping, each object type, and the application that explores them. Every node links its record.
export function compositionDiagram(ontology, lists) {
  const o = ontology || {};
  const enc = encodeURIComponent;
  const types = Array.isArray(o.canonical_object_model?.object_types) ? o.canonical_object_model.object_types : [];
  const maps = (lists.connector_mappings || []).filter((m) => m.ontology_ref === o.ref);
  const sources = lists.data_sources || [];
  const nodes = []; const edges = [];
  const rowY = (i, count) => (i - (count - 1) / 2) * 180;
  const usedSources = [...new Set(maps.map((m) => m.data_source_id).filter(Boolean))];
  usedSources.forEach((sid, i) => {
    const s = sources.find((d) => d.source_id === sid) || {};
    nodes.push({ id: `ds_${sid}`, kind: "resource", type: "Data source", title: s.name || sid, description: s.kind ? `${s.kind} source` : "declared data source", x: 0, y: rowY(i, usedSources.length), ref: sid, href: `/__ioi/data/sources?dataSource=${enc(sid)}`, icon: "globe-network" });
  });
  maps.forEach((m, i) => {
    nodes.push({ id: `map_${m.id}`, kind: "resource", type: "Connector mapping", title: m.name || m.id, description: "source fields → typed properties", x: 420, y: rowY(i, maps.length), ref: m.id, href: `/__ioi/ontology/manager?ontology=${enc(o.id)}&section=object-types&definitionKind=object-type&definitionId=${enc(m.object_type_id || "")}`, icon: "join-table" });
    if (m.data_source_id) edges.push({ id: `e_ds_${m.id}`, source: `ds_${m.data_source_id}`, target: `map_${m.id}` });
  });
  types.forEach((t, i) => {
    nodes.push({ id: `ot_${t.id}`, kind: "resource", type: "Object type", title: t.name || t.id, description: `${Array.isArray(t.properties) ? t.properties.length : 0} properties${t.title_property ? ` · titled by ${t.title_property}` : ""}`, x: 840, y: rowY(i, types.length), ref: `${o.ref}#${t.id}`, href: `/__ioi/ontology/explorer?ontology=${enc(o.id)}&objectType=${enc(t.id)}`, icon: "cube" });
    for (const m of maps.filter((x) => x.object_type_id === t.id)) edges.push({ id: `e_map_${m.id}_${t.id}`, source: `map_${m.id}`, target: `ot_${t.id}`, label: "materializes" });
  });
  if (types.length) {
    nodes.push({ id: "app_explorer", kind: "component", type: "Ontology", title: "Object Explorer", description: `Explore ${o.domain || "this ontology"}`, x: 1260, y: 0, href: `/__ioi/ontology/explorer?ontology=${enc(o.id)}` });
    for (const t of types) edges.push({ id: `e_ot_${t.id}_app`, source: `ot_${t.id}`, target: "app_explorer" });
  }
  return normalizeDiagramGraph({ nodes, edges }).graph;
}

// ---- AIP Architect: plan a workflow with a model ------------------------------------------------
// The reference asks a few questions and has a model propose a workflow summary and graph. Here the
// proposal comes from a governed model call (the daemon's invoke), constrained to IOI's own
// applications, and it lands on the canvas as a SUGGESTION the person reviews — the model's JSON is
// parsed strictly and anything that is not the asked-for shape is refused, never guessed at.
export function planPrompt({ problem, data, users, applications }) {
  const fam = {}; (applications || []).forEach((a) => { (fam[a.owner] = fam[a.owner] || []).push(a.title); });
  const apps = Object.entries(fam).map(([owner, titles]) => `${owner}: ${titles.join(", ")}`).join("\n");
  return [
    "You are a solution architect for the IOI platform. Design the workflow below as a graph.",
    "Reply with ONLY one JSON object and nothing else, in this shape:",
    '{"summary": "2-3 sentences", "nodes": [{"key": "short-id", "kind": "concept|component|resource", "title": "...", "type": "...", "description": "one sentence"}], "edges": [{"from": "key", "to": "key", "label": "verb"}]}',
    "Rules: 4 to 10 nodes. kind \"component\" means an IOI application, and its title must be EXACTLY one of these:",
    apps,
    'kind "concept" types: Analytics, Application Building, Data Processing, Data Sourcing, Modeling.',
    'kind "resource" types: Data source, Object type, Action, File.',
    "Edges follow the flow of data and work, from sources to the people who act.",
    "",
    `Problem: ${String(problem || "").slice(0, 1500)}`,
    `Data available: ${String(data || "").slice(0, 1500)}`,
    `Who uses the result, and what they do: ${String(users || "").slice(0, 1500)}`,
  ].join("\n");
}

export function planToGraph(text, applications) {
  const s = String(text || "");
  const a = s.indexOf("{"), z = s.lastIndexOf("}");
  if (a < 0 || z <= a) return { ok: false, reason: "the model did not answer with a JSON object" };
  let doc;
  try { doc = JSON.parse(s.slice(a, z + 1)); } catch { return { ok: false, reason: "the model's answer was not valid JSON" }; }
  const raw = Array.isArray(doc.nodes) ? doc.nodes.slice(0, 16) : [];
  if (raw.length < 2) return { ok: false, reason: "the model proposed fewer than two nodes" };
  const byTitle = new Map((applications || []).map((x) => [String(x.title).toLowerCase(), x]));
  const keys = new Map();
  const nodes = raw.map((n, i) => {
    const key = String(n.key || n.id || n.title || `n${i}`);
    const id = `p${i}`; keys.set(key, id);
    let kind = ["concept", "component", "resource"].includes(n.kind) ? n.kind : "concept";
    let title = String(n.title || key).slice(0, 200);
    // A model often echoes the list's decoration ("Pipeline Builder (Data)"); the application is still named.
    const bare = title.replace(/\s*[(\[][^)\]]*[)\]]\s*$/u, "").trim().toLowerCase();
    const app = byTitle.get(title.toLowerCase()) || byTitle.get(bare) || null;
    if (app && kind !== "component") kind = "component";
    if (kind === "component" && !app) kind = "concept"; // an application IOI does not have is a concept, not a link
    const res = kind === "resource" ? RESOURCE_TYPES.find((r) => r.type.toLowerCase() === String(n.type || "").toLowerCase()) : null;
    if (app) title = app.title;
    return { id, kind, title, type: app ? app.owner : String(res ? res.type : n.type || (kind === "concept" ? "Concept" : "Resource")).slice(0, 80), description: String(n.description || "").slice(0, 600), ...(app ? { href: app.route } : {}), ...(res ? { icon: res.icon } : {}), x: 0, y: 0 };
  });
  const edges = (Array.isArray(doc.edges) ? doc.edges : []).map((e) => ({ source: keys.get(String(e.from)), target: keys.get(String(e.to)), label: String(e.label || "").slice(0, 60) })).filter((e) => e.source && e.target && e.source !== e.target);
  // Layered layout: depth from the nodes nothing points at.
  const depth = {}; const incoming = new Set(edges.map((e) => e.target));
  const roots = nodes.filter((n) => !incoming.has(n.id)).map((n) => n.id);
  (roots.length ? roots : [nodes[0].id]).forEach((r) => { depth[r] = 0; });
  for (let pass = 0; pass < nodes.length; pass++) edges.forEach((e) => { if (depth[e.source] !== undefined && (depth[e.target] === undefined || depth[e.target] < depth[e.source] + 1) && depth[e.source] < nodes.length) depth[e.target] = depth[e.source] + 1; });
  // A long chain wraps after four columns, so "fit" keeps the proposal legible instead of shrinking a
  // single row until the cards cannot be read.
  const rows = {}; const band = Math.max(1, ...Object.values(nodes.reduce((acc, n) => { const d = depth[n.id] ?? 0; acc[d] = (acc[d] || 0) + 1; return acc; }, {})));
  nodes.forEach((n) => { const d = depth[n.id] ?? 0; const r = (rows[d] = (rows[d] ?? -1) + 1); n.x = (d % 4) * 400; n.y = Math.floor(d / 4) * (band * 180 + 120) + r * 180; });
  const norm = normalizeDiagramGraph({ nodes, edges });
  if (!norm.ok) return { ok: false, reason: norm.reason };
  return { ok: true, summary: String(doc.summary || "").slice(0, 1200), graph: norm.graph };
}

// ---- Machinery: a process graph is a state-machine DEFINITION ---------------------------------
// The daemon's state-machine plane holds states (exactly one initial; normal; final) and transitions
// (from, to, event, guard). The editor draws the same grammar: a state node per state, a connection
// per transition whose label is its event. The plane keeps no layout, so a reopened graph is laid
// out from the definition itself — breadth-first from the initial state.
const slug = (s, fallback) => (String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || fallback);

export function stateMachineToGraph(sm) {
  const states = Array.isArray(sm?.states) ? sm.states : [];
  const transitions = Array.isArray(sm?.transitions) ? sm.transitions : [];
  const depth = {}; const start = states.find((s) => s.kind === "initial") || states[0];
  if (start) {
    depth[start.id] = 0; const queue = [start.id];
    while (queue.length) { const at = queue.shift(); for (const t of transitions.filter((x) => x.from === at)) if (depth[t.to] === undefined) { depth[t.to] = depth[at] + 1; queue.push(t.to); } }
  }
  const maxDepth = Math.max(0, ...Object.values(depth));
  states.forEach((s) => { if (depth[s.id] === undefined) depth[s.id] = maxDepth + 1; });
  const rows = {};
  const nodes = states.map((s) => {
    const col = depth[s.id]; const row = (rows[col] = (rows[col] ?? -1) + 1);
    return { id: `s_${s.id}`, kind: "state", stateKind: STATE_KINDS.includes(s.kind) ? s.kind : "normal", type: s.kind === "initial" ? "Initial state" : s.kind === "final" ? "Final state" : "State", title: s.name || s.id, description: "", ref: s.id, x: col * 420, y: row * 190 };
  });
  const edges = transitions.map((t) => ({ id: `t_${t.id}`, source: `s_${t.from}`, target: `s_${t.to}`, label: t.event || "" }));
  return normalizeDiagramGraph({ nodes, edges }).graph;
}

// The definition a drawn graph declares. A state keeps the id it was loaded with; a new state's id is
// its title as a slug, made unique. A transition's event is its connection's label.
export function graphToStateMachine(graph) {
  const nodes = (graph?.nodes || []).filter((n) => n.kind === "state");
  const used = new Set(); const idOf = {};
  const unique = (base) => { let id = base; let i = 2; while (used.has(id)) id = `${base}-${i++}`; used.add(id); return id; };
  const states = nodes.map((n) => { const id = unique(slug(n.ref, "") || slug(n.title, "state")); idOf[n.id] = id; return { id, name: String(n.title || id).slice(0, 200), kind: STATE_KINDS.includes(n.stateKind) ? n.stateKind : "normal" }; });
  const tused = new Set();
  const transitions = (graph?.edges || []).filter((e) => idOf[e.source] && idOf[e.target]).map((e) => {
    let id = slug(e.label, "") || `${idOf[e.source]}-to-${idOf[e.target]}`; let base = id; let i = 2; while (tused.has(id)) id = `${base}-${i++}`; tused.add(id);
    const tr = { id, from: idOf[e.source], to: idOf[e.target] };
    if (e.label) tr.event = String(e.label).slice(0, 200);
    return tr;
  });
  return { states, transitions };
}

const S_ = (id, stateKind, title, x, y) => ({ id, kind: "state", stateKind, type: stateKind === "initial" ? "Initial state" : stateKind === "final" ? "Final state" : "State", title, description: "", x, y });
export const MACHINERY_TEMPLATES = Object.freeze([
  { id: "approval", category: "Process patterns", title: "Approval", description: "A request is drafted, reviewed, and approved or rejected; a rejected request can be revised.",
    nodes: [S_("draft", "initial", "Draft", 0, 0), S_("review", "normal", "In review", 420, 0), S_("approved", "final", "Approved", 840, -120), S_("rejected", "normal", "Rejected", 840, 120)],
    edges: [E("draft", "review", "submit"), E("review", "approved", "approve"), E("review", "rejected", "reject"), E("rejected", "draft", "revise")] },
  { id: "incident", category: "Process patterns", title: "Incident", description: "An incident is opened, investigated, mitigated and resolved; it can be reopened.",
    nodes: [S_("open", "initial", "Open", 0, 0), S_("investigating", "normal", "Investigating", 420, 0), S_("mitigated", "normal", "Mitigated", 840, 0), S_("resolved", "final", "Resolved", 1260, 0)],
    edges: [E("open", "investigating", "triage"), E("investigating", "mitigated", "mitigate"), E("mitigated", "resolved", "resolve"), E("resolved", "open", "reopen")] },
  { id: "order", category: "Process patterns", title: "Order fulfilment", description: "An order is placed, paid, shipped and delivered, or cancelled before it ships.",
    nodes: [S_("placed", "initial", "Placed", 0, 0), S_("paid", "normal", "Paid", 420, 0), S_("shipped", "normal", "Shipped", 840, 0), S_("delivered", "final", "Delivered", 1260, 0), S_("cancelled", "final", "Cancelled", 420, 200)],
    edges: [E("placed", "paid", "pay"), E("paid", "shipped", "ship"), E("shipped", "delivered", "deliver"), E("placed", "cancelled", "cancel"), E("paid", "cancelled", "cancel")] },
]);

// ---- render ------------------------------------------------------------------------------------

export function renderDesignerEditor(model) {
  const esc = escHtml;
  const m = model || {};
  const surfaces = (m.surfaces || []).filter((s) => s && s.route && s.title);
  const ontologies = m.ontologies || [];
  const lists = { connector_mappings: m.connector_mappings || [], data_sources: m.data_sources || [] };
  const records = {
    ontologies: ontologies.map((o) => ({ ref: o.ref, title: o.domain || o.id, sub: o.ref, href: `/__ioi/ontology/manager?ontology=${encodeURIComponent(o.id)}` })),
    objectTypes: ontologies.flatMap((o) => (o.canonical_object_model?.object_types || []).map((t) => ({ ref: `${o.ref}#${t.id}`, title: t.name || t.id, sub: o.domain || o.id, href: `/__ioi/ontology/explorer?ontology=${encodeURIComponent(o.id)}&objectType=${encodeURIComponent(t.id)}` }))),
    dataSources: lists.data_sources.map((d) => ({ ref: d.source_id, title: d.name || d.source_id, sub: d.kind || "data source", href: `/__ioi/data/sources?dataSource=${encodeURIComponent(d.source_id)}` })),
    mappings: lists.connector_mappings.map((c) => ({ ref: c.id, title: c.name || c.id, sub: c.object_type_id || "", href: "" })),
  };
  const compositions = ontologies.map((o) => ({ id: o.id, title: o.domain || o.id, ref: o.ref, graph: compositionDiagram(o, lists) })).filter((c) => c.graph.nodes.length);
  const templates = REFERENCE_DIAGRAMS.map((t) => {
    const nodes = t.nodes.map((n) => {
      if (n.kind !== "component") return { ...n, icon: (RESOURCE_TYPES.find((r) => r.type === n.type) || {}).icon };
      const s = surfaces.find((x) => x.route === n.route);
      return { id: n.id, kind: "component", type: s ? s.owner : "Application", title: n.title, description: n.description, x: n.x, y: n.y, href: n.route };
    });
    return { id: t.id, category: t.category, title: t.title, description: t.description, graph: normalizeDiagramGraph({ nodes, edges: t.edges }).graph };
  });
  const machinery = m.variant === "machinery";
  const mTemplates = MACHINERY_TEMPLATES.map((tp) => ({ id: tp.id, category: tp.category, title: tp.title, description: tp.description, graph: normalizeDiagramGraph({ nodes: tp.nodes, edges: tp.edges }).graph }));
  const icons = Object.fromEntries(["lightbulb", "cube", "globe-network", "join-table", "cubes", "endnote", "take-action", "layout-grid", "new-text-box", "group-objects", "office", "cross", "arrow-left", "arrow-right", "tag", "tick", "warning-sign", "circle-arrow-right", "selection-box"].map((n) => [n, bpIcon(n, 16)]));
  const boot = {
    bp: m.blueprint ? { id: m.blueprint.id, ref: m.blueprint.ref, head: m.head || "" } : null,
    variant: machinery ? "machinery" : "designer",
    recordPath: machinery ? "/__ioi/studio/machinery/graph?sm=" : "/__ioi/studio/designer/diagram?bp=",
    name: m.name || (m.blueprint && m.blueprint.name) || (machinery ? "New process graph" : "New solution design diagram"),
    description: m.description ?? (m.blueprint && m.blueprint.description) ?? "",
    graph: m.graph || normalizeDiagramGraph({ nodes: [], edges: [] }).graph,
    dirty: !!m.dirty,
    draft: m.draft || "",
    notice: m.notice || null,
    panel: m.panel || "",
    palette: {
      concept: CONCEPT_TYPES,
      component: surfaces.map((s) => ({ type: s.owner, title: s.title, href: s.route, iconUri: s.icon || "" })),
      resource: RESOURCE_TYPES,
    },
    records,
    modelRoutes: m.modelRoutes || [],
    compositions: machinery ? [] : compositions,
    templates: machinery ? mTemplates : templates,
    icons,
    appIcons: Object.fromEntries(surfaces.map((s) => [s.route, s.icon || ""])),
  };
  const bootJson = JSON.stringify(boot).replace(/</g, "\\u003c");
  const app = machinery
    ? { label: "Machinery", home: "/__ioi/studio/machinery", tile: MCH_APP_TILE_URI, save: "/__ioi/studio/machinery/graph/save", open: "/__ioi/studio/machinery", title: "Machinery" }
    : { label: "Solution Designer", home: "/__ioi/studio/designer", tile: DSG_APP_TILE_URI, save: "/__ioi/studio/designer/diagram/save", open: "/__ioi/studio/designer?open=recent", title: "Solution Designer" };
  const rail = ioiGlobalRailHtml({ label: app.label, href: app.home, iconUri: app.tile, railVariant: "rv-pipe rv-dsg", viewAll: true, star: false, badges: true, aipGradient: true, acctMuted: true });
  const tb = (id, icon, label, extra = "") => `<button type="button" class="dg-tool" id="${id}" title="${esc(label)}"${extra}>${bpIcon(icon, 18)}<span>${esc(label)}</span></button>`;
  const railBtn = (panel, icon, label) => `<button type="button" class="dg-rbtn" data-panel="${panel}" aria-label="${esc(label)}" title="${esc(label)}">${bpIcon(icon, 16)}</button>`;
  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,"Source Sans 3",-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
    a{color:#215db0;text-decoration:none} button{font:inherit;color:inherit}
    .dsg-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .dg-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .dg-head{flex:0 0 51px;display:flex;align-items:center;gap:10px;background:#fff;box-shadow:0 1px 0 0 #d3d8de;z-index:8;padding-right:16px}
    .dg-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(63,166,218,.1) url('${app.tile}') center/24px no-repeat;box-shadow:inset -1px 0 0 0 rgba(63,166,218,.25)}
    .dg-name{font-size:16px;font-weight:600;color:#1c2127;border:1px solid transparent;border-radius:3px;padding:3px 6px;min-width:120px;max-width:48ch;background:transparent;font-family:inherit}
    .dg-name:hover{border-color:rgba(17,20,24,.15)} .dg-name:focus{outline:none;border-color:#2d72d2;box-shadow:0 0 0 1px #2d72d2}
    .dg-badge{font-size:12px;font-weight:600;padding:1px 6px;border-radius:2px}
    .dg-badge.unsaved{background:rgba(200,118,25,.15);color:#935610}.dg-badge.saved{background:rgba(35,133,81,.12);color:#1c6e42}
    .dg-hright{margin-left:auto;display:flex;align-items:center;gap:8px}
    .dg-ibtn{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border:0;background:transparent;border-radius:3px;cursor:pointer;color:#5f6b7c}
    .dg-ibtn:hover:not(:disabled){background:rgba(143,153,168,.15)} .dg-ibtn:disabled{opacity:.4;cursor:not-allowed}
    .dg-btn{display:inline-flex;align-items:center;gap:6px;height:30px;padding:0 10px;border-radius:3px;border:1px solid rgba(17,20,24,.2);background:#f6f7f9;cursor:pointer}
    .dg-btn:hover:not(:disabled){background:#edeff2} .dg-btn:disabled{opacity:.55;cursor:not-allowed}
    .dg-btn.primary{background:#2d72d2;color:#fff;border-color:rgba(17,20,24,.2)} .dg-btn.primary:hover:not(:disabled){background:#215db0}
    .dg-btn.primary:disabled{background:#8abbff;color:rgba(255,255,255,.9)}
    .dg-work{flex:1;min-height:0;display:flex;position:relative}
    .dg-rail{flex:0 0 48px;background:#f6f7f9;box-shadow:inset -1px 0 0 #d3d8de;display:flex;flex-direction:column;align-items:center;gap:6px;padding-top:10px}
    .dg-rbtn{width:34px;height:34px;border:0;background:transparent;border-radius:4px;cursor:pointer;color:#5f6b7c;display:flex;align-items:center;justify-content:center}
    .dg-rbtn:hover{background:rgba(143,153,168,.15)} .dg-rbtn.on{background:rgba(45,114,210,.15);color:#215db0}
    .dg-rbtn.bottom{margin-top:auto;margin-bottom:12px}
    .dg-panel{flex:0 0 360px;border-right:1px solid #d3d8de;background:#fff;display:none;flex-direction:column;min-height:0}
    .dg-panel.on{display:flex} .dg-phead{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid #e5e8eb;font-weight:600}
    .dg-pbody{overflow:auto;padding:12px 16px;display:flex;flex-direction:column;gap:12px}.dg-pbody>*{flex-shrink:0}
    .dg-plabel{font-size:12px;font-weight:600;color:#5f6b7c;text-transform:uppercase;letter-spacing:.02em;margin:4px 0 0}
    .dg-pbody textarea,.dg-insp textarea,.dg-insp input,.dg-insp select,.dg-pbody input[type=search]{width:100%;border:1px solid rgba(17,20,24,.2);border-radius:3px;padding:6px 8px;font:inherit;background:#fff}
    .dg-pbody textarea{min-height:90px;resize:vertical}
    .dg-tcard{border:1px solid #d3d8de;border-radius:4px;overflow:hidden;background:#fff}
    .dg-tcard svg.dg-mini{display:block;width:100%;height:120px;background:#f6f7f9;border-bottom:1px solid #e5e8eb}
    .dg-tcard .dg-tbody{padding:10px 12px}.dg-tcard b{display:block;margin-bottom:2px}.dg-tcard p{margin:0;color:#5f6b7c;font-size:13px}
    .dg-tcard .dg-add{display:block;text-align:right;margin-top:8px;color:#215db0;cursor:pointer;background:none;border:0;padding:0;width:100%;font-size:13px}
    .dg-tcard .dg-add:hover{text-decoration:underline}
    .dg-toggle{display:flex;gap:12px;align-items:flex-start;justify-content:space-between;padding:10px 0;border-bottom:1px solid #eef0f2}
    .dg-toggle b{display:block;font-size:13px;text-transform:uppercase}.dg-toggle span{color:#5f6b7c;font-size:13px}
    .dg-kbd{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px solid #eef0f2;font-size:13px}
    .dg-kbd kbd{font:12px ui-monospace,monospace;background:#f6f7f9;border:1px solid #d3d8de;border-radius:3px;padding:1px 5px;white-space:nowrap}
    .dg-canvas{flex:1;min-width:0;position:relative;overflow:hidden;background-color:#f6f7f9;background-image:radial-gradient(circle,#d3d8de 1px,transparent 1.2px);cursor:default;touch-action:none;user-select:none}
    .dg-canvas.pan{cursor:grab}.dg-canvas.panning{cursor:grabbing}
    .dg-world{position:absolute;left:0;top:0;transform-origin:0 0}
    .dg-edges{position:absolute;left:0;top:0;width:1px;height:1px;overflow:visible;pointer-events:none}
    .dg-edge{pointer-events:auto;cursor:pointer}
    .dg-ehit{fill:none;stroke:transparent;stroke-width:14}
    .dg-eline{fill:none;stroke:#8f99a8;stroke-width:1.3;stroke-dasharray:5}
    .dg-eline.anim{animation:dgdash .5s linear infinite}
    @keyframes dgdash{to{stroke-dashoffset:-10}}
    .dg-edge.sel .dg-eline{stroke:#2d72d2;stroke-width:2}
    .dg-elabel{font-size:12px;fill:#5f6b7c;paint-order:stroke;stroke:#f6f7f9;stroke-width:4px}
    .dg-node{position:absolute;width:314px}
    .dg-card{background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(0,0,0,.15),0 0 5px 0 rgba(0,0,0,.02);cursor:grab}
    .dg-node.sel .dg-card{box-shadow:0 0 0 2px #2d72d2,0 0 0 4px rgba(45,114,210,.2)}
    .dg-top{display:flex;align-items:center;gap:10px;padding:10px 15px;border-bottom:1px solid rgba(17,20,24,.15);min-height:59px}
    .dg-ico{flex:0 0 24px;width:24px;height:24px;display:flex;align-items:center;justify-content:center;color:#5f6b7c}
    .dg-ico img{width:24px;height:24px;border-radius:3px}.dg-k-concept .dg-ico{color:#c87619}.dg-k-resource .dg-ico{color:#2d72d2}
    .dg-hd{min-width:0;flex:1}
    .dg-title{font-weight:600;font-size:14px;line-height:16px;overflow-wrap:anywhere;outline:none;border-radius:2px}
    .dg-title[contenteditable=true]{box-shadow:0 0 0 1px #2d72d2;background:#fff;cursor:text;user-select:text}
    .dg-type{font-size:12px;color:#5f6b7c;text-transform:uppercase;line-height:15px;margin-top:2px}
    .dg-linked{flex:0 0 auto;display:inline-flex;align-items:center;gap:3px;font-size:11px;color:#1c6e42;background:rgba(35,133,81,.1);border-radius:2px;padding:1px 5px}
    .dg-linked svg{width:11px;height:11px}
    .dg-desc{padding:15px;overflow-wrap:anywhere;white-space:pre-wrap}
    .dg-desc:empty{display:none}.dg-iconsonly .dg-desc{display:none}.dg-iconsonly .dg-top{border-bottom:0}
    .dg-h{position:absolute;top:50%;width:18px;height:18px;margin-top:-9px;border-radius:50%;background:#fff;border:2px solid #8f99a8;box-shadow:0 2px 4px rgba(0,0,0,.2);opacity:0;cursor:crosshair;z-index:2}
    .dg-h.l{left:-9px}.dg-h.r{right:-9px}
    .dg-node:hover .dg-h,.dg-node.sel .dg-h,.dg-canvas.connecting .dg-h{opacity:1}
    .dg-node.sel .dg-h{width:24px;height:24px;margin-top:-12px}.dg-node.sel .dg-h.l{left:-12px}.dg-node.sel .dg-h.r{right:-12px}
    .dg-nbar{position:absolute;left:50%;top:-44px;transform:translateX(-50%);display:flex;gap:2px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15),0 2px 4px rgba(17,20,24,.1);padding:3px;white-space:nowrap}
    .dg-nbar button{border:0;background:transparent;border-radius:3px;padding:3px 8px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
    .dg-nbar button:hover{background:rgba(143,153,168,.15)}
    .dg-ndel{position:absolute;right:-8px;top:-8px;width:18px;height:18px;border-radius:50%;border:0;background:#5f6b7c;color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer;padding:0;z-index:3}
    .dg-ndel svg{width:10px;height:10px}
    .dg-qa{position:absolute;top:50%;margin-top:-17px;width:34px;height:34px;border-radius:4px;border:0;background:#fff;box-shadow:0 0 0 1px rgba(17,20,24,.15),0 2px 4px rgba(17,20,24,.1);color:#215db0;cursor:pointer;display:flex;align-items:center;justify-content:center;z-index:3}
    .dg-qa.l{left:-64px}.dg-qa.r{right:-64px}
    .dg-k-state .dg-card{border-left:4px solid #8f99a8}.dg-st-initial .dg-card{border-left-color:#238551}.dg-st-final .dg-card{border-left-color:#2d72d2;box-shadow:0 0 0 1px rgba(0,0,0,.15),0 0 0 4px #fff,0 0 0 5px rgba(45,114,210,.45)}
    .dg-node.sel.dg-st-final .dg-card{box-shadow:0 0 0 2px #2d72d2,0 0 0 4px rgba(45,114,210,.2)}
    .dg-k-state .dg-ico{color:#5f6b7c}.dg-st-initial .dg-ico{color:#238551}.dg-st-final .dg-ico{color:#2d72d2}
    .dg-lint{display:flex;gap:8px;align-items:flex-start;padding:8px 10px;border-radius:4px;font-size:13px}.dg-lint.err{background:#fcf1f1;color:#8e292c}.dg-lint.warn{background:#fdf6ec;color:#935610}.dg-lint.ok{background:#f3f8f5;color:#1c6e42}
    .dg-group{background:rgba(45,114,210,.04);border:1px dashed rgba(45,114,210,.45);border-radius:6px;cursor:grab}
    .dg-group.sel{border:2px solid #2d72d2}
    .dg-group .dg-title{position:absolute;left:12px;top:8px;color:#215db0}
    .dg-textn{width:auto;min-width:120px;max-width:420px}
    .dg-textn .dg-title{font-weight:400;font-size:16px;line-height:22px;padding:6px 8px;background:transparent;cursor:grab;white-space:pre-wrap}
    .dg-textn.sel .dg-title{box-shadow:0 0 0 2px #2d72d2}
    .dg-toolbar{position:absolute;left:10px;top:10px;display:flex;align-items:stretch;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(0,0,0,.1),0 4px 6px -4px rgba(0,0,0,.1),0 10px 15px -3px rgba(0,0,0,.1);z-index:6}
    .dg-tgroup{display:flex;align-items:center;gap:4px;padding:6px 8px}.dg-tgroup+.dg-tgroup{border-left:1px solid #e5e8eb}
    .dg-tool{display:flex;flex-direction:column;align-items:center;gap:3px;min-width:58px;border:0;background:transparent;border-radius:3px;padding:5px 4px;cursor:pointer;font-size:10px;font-weight:600;color:#404854;text-transform:uppercase}
    .dg-tool:hover{background:rgba(143,153,168,.15)} .dg-tool.on{background:rgba(45,114,210,.15);color:#215db0}
    .dg-tool.sq{min-width:34px}.dg-tool.sq span{display:none}
    .dg-pop{position:absolute;z-index:20;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.1),0 2px 4px rgba(17,20,24,.2),0 8px 24px rgba(17,20,24,.2);padding:6px;min-width:280px;max-height:420px;overflow:auto;display:none}
    .dg-pop.on{display:block}
    .dg-pitem{display:flex;gap:10px;align-items:flex-start;width:100%;text-align:left;border:0;background:transparent;border-radius:3px;padding:7px 8px;cursor:pointer}
    .dg-pitem:hover,.dg-pitem:focus{background:rgba(143,153,168,.15);outline:none}
    .dg-pitem .dg-ico{flex:0 0 20px;width:20px;height:20px}.dg-pitem img{width:20px;height:20px}
    .dg-pitem b{display:block;font-weight:600}.dg-pitem small{display:block;color:#5f6b7c;font-size:12px}
    .dg-psec{font-size:11px;font-weight:600;color:#5f6b7c;text-transform:uppercase;padding:8px 8px 4px}
    .dg-pempty{color:#5f6b7c;font-size:12px;padding:2px 8px 6px}
    .dg-menu .dg-pitem{padding:6px 10px;align-items:center}.dg-menu .dg-pitem:disabled{opacity:.45;cursor:not-allowed}
    .dg-menu hr{border:0;border-top:1px solid #e5e8eb;margin:4px 0}
    .dg-controls{position:absolute;left:10px;bottom:10px;display:flex;flex-direction:column;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(0,0,0,.1),0 2px 4px rgba(0,0,0,.1);z-index:6}
    .dg-controls button{width:30px;height:30px;border:0;background:transparent;cursor:pointer;color:#404854;display:flex;align-items:center;justify-content:center}
    .dg-controls button:hover{background:rgba(143,153,168,.15)}
    .dg-zoom{position:absolute;left:48px;bottom:14px;font-size:12px;color:#5f6b7c;z-index:6}
    .dg-welcome{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;pointer-events:none;z-index:4}
    .dg-welcome h2{margin:0;font-size:22px}.dg-welcome p{margin:0 0 14px;color:#5f6b7c}
    .dg-wcards{display:flex;gap:18px;pointer-events:auto}
    .dg-wcard{width:298px;min-height:172px;border:2px dashed #d3d8de;border-radius:6px;background:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;padding:18px;text-align:center;cursor:pointer}
    .dg-wcard:hover:not([aria-disabled=true]){border-color:#2d72d2}
    .dg-wcard[aria-disabled=true]{cursor:not-allowed;opacity:.6}
    .dg-wcard .dg-wico{width:48px;height:48px;border-radius:6px;background:#f6f7f9;display:flex;align-items:center;justify-content:center;color:#5f6b7c}
    .dg-wcard b{font-size:17px}.dg-wcard span{color:#5f6b7c;font-size:13px}
    .dg-insp{position:absolute;right:10px;top:10px;width:300px;max-height:calc(100% - 20px);overflow:auto;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.12),0 4px 12px rgba(17,20,24,.12);z-index:7;display:none;padding:12px 14px}
    .dg-insp.on{display:block}.dg-insp label{display:block;font-size:12px;font-weight:600;color:#5f6b7c;margin:10px 0 4px}
    .dg-insp .dg-ihead{display:flex;justify-content:space-between;align-items:center;font-weight:600}
    .dg-insp textarea{min-height:80px;resize:vertical}
    .dg-insp .dg-open{display:inline-block;margin-top:6px;font-size:13px}
    .dg-insp .dg-danger{margin-top:14px;color:#ac2f33;background:none;border:1px solid rgba(172,47,51,.4);border-radius:3px;padding:4px 10px;cursor:pointer}
    .dg-modal{position:fixed;inset:0;background:rgba(17,20,24,.35);display:none;align-items:center;justify-content:center;z-index:40}
    .dg-modal.on{display:flex}
    .dg-dialog{background:#fff;border-radius:6px;width:min(620px,calc(100vw - 32px));max-height:calc(100vh - 64px);display:flex;flex-direction:column;box-shadow:0 8px 24px rgba(17,20,24,.25)}
    .dg-dialog header{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;border-bottom:1px solid #e5e8eb;font-weight:600}
    .dg-dialog .dg-dbody{padding:14px 18px;overflow:auto;display:flex;flex-direction:column;gap:10px}
    .dg-dialog footer{display:flex;justify-content:flex-end;gap:8px;padding:12px 18px;border-top:1px solid #e5e8eb}
    .dg-dialog textarea{width:100%;min-height:200px;font:12px ui-monospace,monospace;border:1px solid rgba(17,20,24,.2);border-radius:3px;padding:8px}
    .dg-radio{display:flex;gap:8px;align-items:flex-start}.dg-radio small{display:block;color:#5f6b7c}
    .dg-comp{display:flex;justify-content:space-between;align-items:center;gap:12px;border:1px solid #d3d8de;border-radius:4px;padding:10px 12px}
    .dg-comp small{display:block;color:#5f6b7c}
    .dg-toast{position:absolute;right:14px;bottom:14px;z-index:30;max-width:380px;border-radius:4px;padding:10px 14px;box-shadow:0 2px 8px rgba(17,20,24,.2);display:flex;gap:10px;align-items:flex-start}
    .dg-toast.ok{background:#e8f4ee;color:#1c6e42}.dg-toast.err{background:#fcebeb;color:#8e292c}
    .dg-toast button{border:0;background:none;cursor:pointer;color:inherit;padding:0 0 0 6px}
    @media (max-width:900px){.dg-panel{position:absolute;left:48px;top:0;bottom:0;z-index:9;width:calc(100vw - 64px);flex-basis:auto}.dg-name{max-width:40vw}.dg-toolbar{flex-wrap:wrap;right:10px}.dg-wcards{flex-direction:column;align-items:center}.dg-wcard{min-height:0}.dg-insp{left:10px;right:10px;width:auto}.dsg-shell .og-grail{display:none}}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(app.title)}</title><style>${css}</style></head>
<body><div class="dsg-shell">${rail}<div class="dg-main">
  <header class="dg-head">
    <a class="dg-hchip" href="${app.home}" title="${esc(app.label)} home" aria-label="${esc(app.label)} home"></a>
    <input class="dg-name" id="dg-name" aria-label="Diagram name" maxlength="200">
    <span class="dg-badge" id="dg-status"></span>
    <div class="dg-hright">
      <button type="button" class="dg-ibtn" id="dg-undo" title="Undo (Ctrl+Z)" aria-label="Undo">${bpIcon("undo", 16)}</button>
      <button type="button" class="dg-ibtn" id="dg-redo" title="Redo (Ctrl+Y)" aria-label="Redo">${bpIcon("redo", 16)}</button>
      <button type="button" class="dg-btn primary" id="dg-save">${bpIcon("tick", 14)}<span>Save</span></button>
      <button type="button" class="dg-btn" id="dg-actions" aria-haspopup="menu">Actions ${bpIcon("caret-down", 12)}</button>
      <a class="dg-btn" href="${app.open}">${bpIcon("folder-open", 14)}<span>${machinery ? "Open graph" : "Open diagram"}</span></a>
    </div>
  </header>
  <div class="dg-work">
    <nav class="dg-rail" aria-label="Diagram panels">
      ${railBtn("info", "properties", machinery ? "Graph Information" : "Diagram Information")}
      ${machinery ? "" : railBtn("architect", "aip-logo", "AIP Architect")}
      ${machinery ? railBtn("linter", "warning-sign", "Linter") : ""}
      ${railBtn("reference", "manual", machinery ? "Process templates" : "Reference Diagrams")}
      ${railBtn("settings", "cog", "Graph Settings")}
      <button type="button" class="dg-rbtn bottom" data-panel="shortcuts" aria-label="Shortcuts" title="Shortcuts">⌘</button>
    </nav>
    <aside class="dg-panel" id="dg-panel" aria-live="polite"></aside>
    <div class="dg-canvas" id="dg-canvas" tabindex="0" aria-label="Diagram canvas">
      <div class="dg-world" id="dg-world"><svg class="dg-edges" id="dg-edges"><defs><marker id="dg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#8f99a8"></path></marker><marker id="dg-arrow-sel" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#2d72d2"></path></marker></defs><g id="dg-edge-g"></g><path id="dg-temp" class="dg-eline" d="" style="display:none"></path></svg><div id="dg-nodes"></div></div>
      <div class="dg-toolbar" role="toolbar" aria-label="Add to the diagram">
        ${machinery
          // No Text tool: the state-machine plane keeps states and transitions only, so a note would be
          // dropped on save without a word.
          ? `<div class="dg-tgroup">${tb("dg-t-state", "selection-box", "State")}</div>`
          : `<div class="dg-tgroup">${tb("dg-t-concept", "lightbulb", "Concept")}${tb("dg-t-component", "office", "Component")}${tb("dg-t-resource", "cube", "Resource")}</div>
        <div class="dg-tgroup">${tb("dg-t-group", "group-objects", "Group", ' data-sq="1"')}${tb("dg-t-text", "new-text-box", "Text", ' data-sq="1"')}</div>`}
        <div class="dg-tgroup">${tb("dg-t-pan", "move", "Pan view", ' data-sq="1"')}${tb("dg-t-move", "select", "Move nodes", ' data-sq="1"')}</div>
      </div>
      <div class="dg-controls" aria-label="View">
        <button type="button" id="dg-zin" title="Zoom in" aria-label="Zoom in">${bpIcon("zoom-in", 14)}</button>
        <button type="button" id="dg-zout" title="Zoom out" aria-label="Zoom out">${bpIcon("zoom-out", 14)}</button>
        <button type="button" id="dg-fit" title="Fit view" aria-label="Fit view">${bpIcon("zoom-to-fit", 14)}</button>
      </div>
      <span class="dg-zoom" id="dg-zoomlbl"></span>
      <div class="dg-welcome" id="dg-welcome"></div>
      <aside class="dg-insp" id="dg-insp" aria-label="Selected node"></aside>
      <div class="dg-pop" id="dg-pop" role="menu"></div>
      <div id="dg-toasts"></div>
    </div>
  </div>
</div></div>
<div class="dg-modal" id="dg-modal" role="dialog" aria-modal="true"><div class="dg-dialog" id="dg-dialog"></div></div>
<form id="dg-saveform" method="post" action="${app.save}" hidden>
  <input type="hidden" name="bp"><input type="hidden" name="head"><input type="hidden" name="draft"><input type="hidden" name="name"><input type="hidden" name="description"><input type="hidden" name="graph_json">
</form>
<script type="application/json" id="dg-boot">${bootJson}</script>
<script>(${designerClient.toString()})();</script>
</body></html>`;
}

// ---- client ------------------------------------------------------------------------------------
// Serialized into the page as-is: it may reference nothing outside itself.
function designerClient() {
  const BOOT = JSON.parse(document.getElementById("dg-boot").textContent);
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.prototype.slice.call((r || document).querySelectorAll(s));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const uid = (p) => `${p}_${Math.random().toString(36).slice(2, 9)}`;
  const NODE_W = 314;
  const canvas = $("#dg-canvas"), world = $("#dg-world"), nodesEl = $("#dg-nodes"), edgeG = $("#dg-edge-g"), temp = $("#dg-temp");
  const clone = (x) => JSON.parse(JSON.stringify(x));
  const S = {
    g: clone(BOOT.graph), name: BOOT.name, description: BOOT.description || "", bp: BOOT.bp,
    draft: BOOT.draft || uid("draft"), sel: new Set(), edgeSel: null, view: { x: 90, y: 150, k: 1 }, mode: "move",
    dirty: !!BOOT.dirty, undo: [], redo: [], clip: null, panel: "", saving: false,
  };
  S.g.nodes = S.g.nodes || []; S.g.edges = S.g.edges || []; S.g.settings = S.g.settings || { edgeLabels: true, animate: true, iconsOnly: false };
  const byId = (id) => S.g.nodes.find((n) => n.id === id);
  const snap = () => JSON.stringify(S.g);
  function commit(before) {
    S.undo.push(before); if (S.undo.length > 150) S.undo.shift();
    S.redo = []; S.dirty = true; render();
  }
  function mutate(fn) { const before = snap(); fn(); commit(before); }

  // ---- icons
  const RES_ICON = {}; (BOOT.palette.resource || []).forEach((r) => { RES_ICON[r.type] = r.icon; });
  function iconFor(n) {
    if (n.kind === "component") { const uri = BOOT.appIcons[n.href] || ""; return uri ? `<img src="${esc(uri)}" alt="">` : BOOT.icons.office; }
    if (n.kind === "concept") return BOOT.icons.lightbulb;
    if (n.kind === "state") return BOOT.icons[n.stateKind === "initial" ? "circle-arrow-right" : n.stateKind === "final" ? "tick" : "selection-box"];
    if (n.kind === "resource") return BOOT.icons[n.icon || RES_ICON[n.type] || "cube"] || BOOT.icons.cube;
    return "";
  }

  // ---- render
  function nodeHtml(n) {
    const sel = S.sel.has(n.id) ? " sel" : "";
    const pos = `left:${n.x}px;top:${n.y}px`;
    const single = S.sel.size === 1 && S.sel.has(n.id);
    const extras = single ? `<button type="button" class="dg-ndel" data-act="delete" title="Delete (Backspace)" aria-label="Delete node">${BOOT.icons.cross}</button>` : "";
    if (n.kind === "group") return `<div class="dg-node dg-group${sel}" data-id="${esc(n.id)}" style="${pos};width:${n.w || 640}px;height:${n.h || 360}px"><div class="dg-title" data-edit="title">${esc(n.title || "Group")}</div>${extras}</div>`;
    if (n.kind === "text") return `<div class="dg-node dg-textn${sel}" data-id="${esc(n.id)}" style="${pos}"><div class="dg-title" data-edit="title">${esc(n.title || "Text")}</div><span class="dg-h l" data-h="in"></span><span class="dg-h r" data-h="out"></span>${extras}</div>`;
    const linked = n.kind !== "state" && (n.ref || (n.kind === "component" && n.href)) ? `<span class="dg-linked" title="Linked to ${esc(n.ref || n.href)}">${BOOT.icons.tag}linked</span>` : "";
    const bar = single ? `${n.kind === "state" ? "" : `<div class="dg-nbar"><button type="button" data-act="link">${BOOT.icons.tag}<span>${n.ref || n.href ? "Linked resource" : "Link resource"}</span></button></div>`}<button type="button" class="dg-qa l" data-act="qa-left" title="Add a node before this one" aria-label="Add a node before">${BOOT.icons["arrow-left"]}</button><button type="button" class="dg-qa r" data-act="qa-right" title="Add a node after this one" aria-label="Add a node after">${BOOT.icons["arrow-right"]}</button>` : "";
    return `<div class="dg-node dg-k-${esc(n.kind)}${n.kind === "state" ? ` dg-st-${esc(n.stateKind || "normal")}` : ""}${sel}${S.g.settings.iconsOnly ? " dg-iconsonly" : ""}" data-id="${esc(n.id)}" style="${pos}">
      <div class="dg-card"><div class="dg-top"><span class="dg-ico">${iconFor(n)}</span><div class="dg-hd"><div class="dg-title" data-edit="title">${esc(n.title || "Untitled")}</div><div class="dg-type">${esc(n.type || n.kind)}</div></div>${linked}</div><div class="dg-desc">${esc(n.description || "")}</div></div>
      <span class="dg-h l" data-h="in" title="Drop a connection here"></span><span class="dg-h r" data-h="out" title="Drag to connect"></span>${bar}${extras}</div>`;
  }
  function renderNodes() {
    const groups = S.g.nodes.filter((n) => n.kind === "group"), rest = S.g.nodes.filter((n) => n.kind !== "group");
    nodesEl.innerHTML = groups.concat(rest).map(nodeHtml).join("");
  }
  const nodeEl = (id) => nodesEl.querySelector(`.dg-node[data-id="${CSS.escape(id)}"]`);
  function anchor(id, side) {
    const n = byId(id); const el = nodeEl(id);
    const w = el ? el.offsetWidth : NODE_W, h = el ? el.offsetHeight : 120;
    return side === "out" ? [n.x + w, n.y + h / 2] : [n.x, n.y + h / 2];
  }
  const curve = (a, b) => { const dx = Math.max(40, Math.abs(b[0] - a[0]) / 2); return `M${a[0]},${a[1]} C${a[0] + dx},${a[1]} ${b[0] - dx},${b[1]} ${b[0]},${b[1]}`; };
  function renderEdges() {
    const st = S.g.settings;
    edgeG.innerHTML = S.g.edges.filter((e) => byId(e.source) && byId(e.target)).map((e) => {
      const a = anchor(e.source, "out"), b = anchor(e.target, "in"), d = curve(a, b), sel = S.edgeSel === e.id;
      const label = st.edgeLabels && e.label ? `<text class="dg-elabel" x="${(a[0] + b[0]) / 2}" y="${(a[1] + b[1]) / 2 - 6}" text-anchor="middle">${esc(e.label)}</text>` : "";
      return `<g class="dg-edge${sel ? " sel" : ""}" data-eid="${esc(e.id)}"><path class="dg-ehit" d="${d}"></path><path class="dg-eline${st.animate ? " anim" : ""}" d="${d}" marker-end="url(#${sel ? "dg-arrow-sel" : "dg-arrow"})"></path>${label}</g>`;
    }).join("");
  }
  function applyView() {
    const v = S.view;
    world.style.transform = `translate(${v.x}px,${v.y}px) scale(${v.k})`;
    canvas.style.backgroundSize = `${16 * v.k}px ${16 * v.k}px`;
    canvas.style.backgroundPosition = `${v.x}px ${v.y}px`;
    $("#dg-zoomlbl").textContent = `${Math.round(v.k * 100)}%`;
  }
  function renderChrome() {
    const name = $("#dg-name"); if (document.activeElement !== name) name.value = S.name;
    name.style.width = `${Math.min(48, Math.max(14, (name.value || "").length + 2))}ch`;
    const st = $("#dg-status");
    st.className = `dg-badge ${S.dirty || !S.bp ? "unsaved" : "saved"}`;
    st.textContent = S.saving ? "Saving…" : S.dirty || !S.bp ? "Unsaved" : "Saved";
    $("#dg-undo").disabled = !S.undo.length; $("#dg-redo").disabled = !S.redo.length;
    const save = $("#dg-save"); save.disabled = S.saving || (!S.dirty && !!S.bp) || (!S.bp && !S.g.nodes.length);
    save.title = save.disabled ? (S.bp ? "Everything is saved" : "Add a node to save this diagram") : "Save (Ctrl+S) — as a Studio blueprint owned by your organization";
    $("#dg-t-pan").classList.toggle("on", S.mode === "pan"); $("#dg-t-move").classList.toggle("on", S.mode === "move");
    canvas.classList.toggle("pan", S.mode === "pan");
    renderWelcome(); renderInspector();
    if (S.panel === "info" || S.panel === "linter") renderPanel();
  }
  function render() { renderNodes(); renderEdges(); applyView(); renderChrome(); }

  // ---- welcome
  function renderWelcome() {
    const w = $("#dg-welcome");
    if (S.g.nodes.length) { w.innerHTML = ""; w.style.display = "none"; return; }
    w.style.display = "flex";
    if (BOOT.variant === "machinery") {
      w.innerHTML = `<h2>Build a process graph</h2><p>Add a state to get started — connect states with transitions, and the linter checks the process as you draw</p>
        <div class="dg-wcards">
          <div class="dg-wcard" role="button" tabindex="0" data-welcome="initial"><span class="dg-wico">${BOOT.icons["circle-arrow-right"]}</span><b>Add the initial state</b><span>Where every instance of the process starts</span></div>
          <div class="dg-wcard" role="button" tabindex="0" data-welcome="reference"><span class="dg-wico">${BOOT.icons["layout-grid"]}</span><b>Start from a template</b><span>Approval, incident or order fulfilment</span></div>
        </div>`;
      return;
    }
    w.innerHTML = `<h2>Welcome to Solution Designer</h2><p>Get started by adding nodes, loading a graph from your composition, or exploring reference examples</p>
      <div class="dg-wcards">
        ${BOOT.modelRoutes.some((r) => r.runnable !== false)
          ? `<div class="dg-wcard" role="button" tabindex="0" data-welcome="architect"><span class="dg-wico">${BOOT.icons.lightbulb}</span><b>Start planning</b><span>Answer a few questions and a model proposes a workflow graph</span></div>`
          : `<div class="dg-wcard" aria-disabled="true" title="${BOOT.modelRoutes.length ? "No registered model route can run right now — enable one in Agent Studio or register one in the Model Catalog" : "No model route is registered in this deployment — register one in the Model Catalog to plan with a model"}" data-ioi-disabled-reason="${BOOT.modelRoutes.length ? "No registered model route can run right now — enable one in Agent Studio or register one in the Model Catalog" : "No model route is registered in this deployment — register one in the Model Catalog to plan with a model"}"><span class="dg-wico">${BOOT.icons.lightbulb}</span><b>Start planning</b><span>No model route is registered — add one in the Model Catalog</span></div>`}
        <div class="dg-wcard" role="button" tabindex="0" data-welcome="reference"><span class="dg-wico">${BOOT.icons["layout-grid"]}</span><b>Start with a reference example</b><span>Choose from IOI's reference architectures</span></div>
        <div class="dg-wcard" role="button" tabindex="0" data-welcome="lineage"><span class="dg-wico">${BOOT.icons["join-table"]}</span><b>Load from Data Lineage</b><span>Import the composition an ontology already has — sources, mappings, object types</span></div>
      </div>`;
  }

  // ---- inspector
  function renderInspector() {
    const box = $("#dg-insp");
    const n = S.sel.size === 1 ? byId([...S.sel][0]) : null;
    const edge = !n && S.edgeSel ? S.g.edges.find((x) => x.id === S.edgeSel) : null;
    if (edge) {
      if (box.dataset.for === edge.id && box.contains(document.activeElement)) return;
      box.dataset.for = edge.id; box.classList.add("on");
      const a = byId(edge.source), z = byId(edge.target);
      const isT = BOOT.variant === "machinery";
      box.innerHTML = `<div class="dg-ihead"><span>${isT ? "Transition" : "Connection"}</span><button type="button" class="dg-ibtn" data-act="deselect" aria-label="Close">${BOOT.icons.cross}</button></div>
        <div style="color:#5f6b7c;font-size:13px;margin-top:6px">${esc(a ? a.title : "?")} → ${esc(z ? z.title : "?")}</div>
        <label for="dg-i-elabel">${isT ? "Event — what moves the process along this transition" : "Label"}</label><input id="dg-i-elabel" value="${esc(edge.label || "")}" maxlength="120" placeholder="${isT ? "e.g. approve" : "e.g. feeds"}">
        <div><button type="button" class="dg-danger" data-act="delete-edge">Delete ${isT ? "transition" : "connection"}</button></div>`;
      const inp = $("#dg-i-elabel", box); let before = null;
      inp.addEventListener("focus", () => { before = snap(); });
      inp.addEventListener("input", () => { edge.label = inp.value; S.dirty = true; renderEdges(); renderChrome(); });
      inp.addEventListener("change", () => { if (before !== null && before !== snap()) { S.undo.push(before); S.redo = []; } before = snap(); renderChrome(); });
      return;
    }
    if (!n) { box.classList.remove("on"); box.innerHTML = ""; box.dataset.for = ""; return; }
    if (box.dataset.for === n.id && box.contains(document.activeElement)) return; // do not steal the caret
    box.dataset.for = n.id; box.classList.add("on");
    let link = "";
    if (n.kind === "resource") {
      const rt = (BOOT.palette.resource || []).find((r) => r.type === n.type);
      const recs = rt && rt.record ? BOOT.records[rt.record] || [] : null;
      link = recs ? `<label for="dg-i-link">Linked record</label><select id="dg-i-link"><option value="">— not linked —</option>${recs.map((r, i) => `<option value="${i}"${r.ref === n.ref ? " selected" : ""}>${esc(r.title)} · ${esc(r.sub)}</option>`).join("")}</select>${recs.length ? "" : `<div style="color:#5f6b7c;font-size:12px;margin-top:4px">No ${esc(n.type.toLowerCase())} records exist in this deployment yet.</div>`}` : `<div style="color:#5f6b7c;font-size:12px;margin-top:10px">A ${esc(n.type || "resource")} node is a placeholder — it has no record family to link.</div>`;
    } else if (n.kind === "component") {
      link = `<label for="dg-i-app">Application</label><select id="dg-i-app"><option value="">— none —</option>${BOOT.palette.component.map((c, i) => `<option value="${i}"${c.href === n.href ? " selected" : ""}>${esc(c.title)} · ${esc(c.type)}</option>`).join("")}</select>`;
    }
    const open = n.href ? `<a class="dg-open" href="${esc(n.href)}" target="_top">Open ${esc(n.kind === "component" ? n.title : "the linked record")} →</a>` : "";
    box.innerHTML = `<div class="dg-ihead"><span>${esc(n.kind === "text" ? "Text" : n.kind === "group" ? "Group" : n.type || n.kind)}</span><button type="button" class="dg-ibtn" data-act="deselect" aria-label="Close">${BOOT.icons.cross}</button></div>
      <label for="dg-i-title">${n.kind === "text" ? "Text" : "Title"}</label>${n.kind === "text" ? `<textarea id="dg-i-title">${esc(n.title)}</textarea>` : `<input id="dg-i-title" value="${esc(n.title)}" maxlength="200">`}
      ${n.kind === "state" ? `<label for="dg-i-skind">Kind</label><select id="dg-i-skind">${[["initial", "Initial — where the process starts"], ["normal", "State"], ["final", "Final — where it ends"]].map(([k, l]) => `<option value="${k}"${(n.stateKind || "normal") === k ? " selected" : ""}>${l}</option>`).join("")}</select>` : ""}
      ${n.kind === "concept" || n.kind === "component" || n.kind === "resource" ? `<label for="dg-i-type">Type</label><input id="dg-i-type" value="${esc(n.type)}" maxlength="80"><label for="dg-i-desc">Description</label><textarea id="dg-i-desc" maxlength="2000">${esc(n.description)}</textarea>` : ""}
      ${link}${open}
      <div><button type="button" class="dg-danger" data-act="delete">Delete</button></div>`;
    const bindField = (sel, key) => {
      const el = $(sel, box); if (!el) return;
      let before = null;
      el.addEventListener("focus", () => { before = snap(); });
      el.addEventListener("input", () => { n[key] = el.value; S.dirty = true; renderNodes(); renderEdges(); renderChrome(); });
      el.addEventListener("change", () => { if (before !== null && before !== snap()) { S.undo.push(before); S.redo = []; } before = snap(); renderChrome(); });
    };
    bindField("#dg-i-title", "title"); bindField("#dg-i-type", "type"); bindField("#dg-i-desc", "description");
    const sk = $("#dg-i-skind", box);
    if (sk) sk.addEventListener("change", () => mutate(() => { n.stateKind = sk.value; n.type = sk.value === "initial" ? "Initial state" : sk.value === "final" ? "Final state" : "State"; box.dataset.for = ""; }));
    const ls = $("#dg-i-link", box);
    if (ls) ls.addEventListener("change", () => mutate(() => {
      const rt = BOOT.palette.resource.find((r) => r.type === n.type); const r = (BOOT.records[rt.record] || [])[+ls.value];
      if (!r) { delete n.ref; delete n.href; return; }
      n.ref = r.ref; if (r.href) n.href = r.href; else delete n.href;
      if (!n.title || /^New |^Unlinked /.test(n.title)) n.title = r.title;
      box.dataset.for = "";
    }));
    const as = $("#dg-i-app", box);
    if (as) as.addEventListener("change", () => mutate(() => {
      const c = BOOT.palette.component[+as.value];
      if (!c) { delete n.href; return; }
      n.href = c.href; n.type = c.type; if (!n.title || n.title === "New component") n.title = c.title;
      box.dataset.for = "";
    }));
  }

  // ---- adding
  function viewCenter() { const r = canvas.getBoundingClientRect(); return [(r.width / 2 - S.view.x) / S.view.k, (r.height / 2 - S.view.y) / S.view.k]; }
  // A new node lands in free space near the middle of the view — never on top of another card.
  function freeSpot(x, y, w, h) {
    const taken = S.g.nodes.filter((n) => n.kind !== "group").map((n) => { const el = nodeEl(n.id); return [n.x, n.y, n.x + (el ? el.offsetWidth : NODE_W), n.y + (el ? el.offsetHeight : 130)]; });
    const hits = (cx, cy) => taken.some(([x1, y1, x2, y2]) => cx < x2 + 40 && cx + w + 40 > x1 && cy < y2 + 40 && cy + h + 40 > y1);
    for (let row = 0; row < 12; row++) for (let col = 0; col < 6; col++) {
      const cx = x + col * (w + 80), cy = y + row * (h + 60);
      if (!hits(cx, cy)) return [cx, cy];
    }
    return [x, y];
  }
  function addNode(spec, at) {
    const [cx, cy] = at || viewCenter();
    const w = spec.kind === "group" ? 640 : NODE_W, h = spec.kind === "group" ? 360 : 130;
    const [x, y] = spec.kind === "group" ? [cx - w / 2, cy - h / 2] : freeSpot(Math.round(cx - w / 2), Math.round(cy - h / 2), w, h);
    const n = Object.assign({ id: uid("n"), title: "", type: "", description: "" }, spec, { x: Math.round(x), y: Math.round(y) });
    if (n.kind === "group") { n.w = n.w || 640; n.h = n.h || 360; }
    mutate(() => { S.g.nodes.push(n); S.sel = new Set([n.id]); S.edgeSel = null; });
    return n;
  }
  function addGraph(graph, replace) {
    const g = clone(graph);
    mutate(() => {
      if (replace) { S.g.nodes = []; S.g.edges = []; }
      // Added content goes BELOW what is there, left-aligned — a diagram grows down the page, so
      // "fit" keeps it legible instead of shrinking one ever-longer row.
      const b = bounds(S.g.nodes); const gb = bounds(g.nodes);
      const dx = S.g.nodes.length ? b.x1 - gb.x1 : 0, dy = S.g.nodes.length ? b.y2 + 180 - gb.y1 : 0;
      const map = {};
      g.nodes.forEach((n) => { const id = uid("n"); map[n.id] = id; S.g.nodes.push(Object.assign({}, n, { id, x: n.x + dx, y: n.y + dy })); });
      g.edges.forEach((e) => { if (map[e.source] && map[e.target]) S.g.edges.push(Object.assign({}, e, { id: uid("e"), source: map[e.source], target: map[e.target] })); });
      S.sel = new Set(Object.values(map)); S.edgeSel = null;
    });
    requestAnimationFrame(fit);
  }
  function connect(source, target) {
    if (!source || !target || source === target) return;
    if (S.g.edges.some((e) => e.source === source && e.target === target)) return;
    mutate(() => { S.g.edges.push({ id: uid("e"), source, target }); });
  }
  function deleteSelection() {
    if (!S.sel.size && !S.edgeSel) return;
    mutate(() => {
      S.g.nodes = S.g.nodes.filter((n) => !S.sel.has(n.id));
      S.g.edges = S.g.edges.filter((e) => e.id !== S.edgeSel && !S.sel.has(e.source) && !S.sel.has(e.target));
      S.sel = new Set(); S.edgeSel = null;
    });
  }
  function quickAdd(id, side) {
    const n = byId(id); if (!n) return;
    const el = nodeEl(id); const w = el ? el.offsetWidth : NODE_W;
    const spec = n.kind === "state"
      ? { kind: "state", stateKind: "normal", type: "State", title: "New state", description: "" }
      : { kind: n.kind === "text" ? "concept" : n.kind, type: n.kind === "component" ? "" : n.type, title: n.kind === "component" ? "New component" : `New ${String(n.type || n.kind).toLowerCase()}`, description: "", icon: n.icon };
    const before = snap();
    const m = Object.assign({ id: uid("n") }, spec, { x: side === "right" ? n.x + w + 120 : n.x - w - 120, y: n.y });
    S.g.nodes.push(m);
    S.g.edges.push(side === "right" ? { id: uid("e"), source: n.id, target: m.id } : { id: uid("e"), source: m.id, target: n.id });
    S.sel = new Set([m.id]);
    commit(before);
  }

  // ---- geometry
  function bounds(nodes) {
    if (!nodes.length) return { x1: 0, y1: 0, x2: 0, y2: 0 };
    let x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
    nodes.forEach((n) => { const el = nodeEl(n.id); const w = n.w || (el ? el.offsetWidth : NODE_W), h = n.h || (el ? el.offsetHeight : 120); x1 = Math.min(x1, n.x); y1 = Math.min(y1, n.y); x2 = Math.max(x2, n.x + w); y2 = Math.max(y2, n.y + h); });
    return { x1, y1, x2, y2 };
  }
  function fit() {
    if (!S.g.nodes.length) { S.view = { x: 90, y: 150, k: 1 }; applyView(); return; }
    const r = canvas.getBoundingClientRect(), b = bounds(S.g.nodes);
    const k = Math.max(0.2, Math.min(1, (r.width - 160) / Math.max(1, b.x2 - b.x1), (r.height - 200) / Math.max(1, b.y2 - b.y1)));
    S.view = { k, x: (r.width - (b.x2 - b.x1) * k) / 2 - b.x1 * k, y: (r.height - (b.y2 - b.y1) * k) / 2 - b.y1 * k + 30 };
    applyView();
  }
  function zoomAt(factor, px, py) {
    const v = S.view, k = Math.max(0.15, Math.min(2.5, v.k * factor));
    S.view = { k, x: px - (px - v.x) * (k / v.k), y: py - (py - v.y) * (k / v.k) };
    applyView();
  }
  const toWorld = (e) => { const r = canvas.getBoundingClientRect(); return [(e.clientX - r.left - S.view.x) / S.view.k, (e.clientY - r.top - S.view.y) / S.view.k]; };

  // ---- pointer
  canvas.addEventListener("pointerdown", (e) => {
    const t = e.target;
    if (t.closest(".dg-toolbar,.dg-controls,.dg-insp,.dg-pop,.dg-welcome .dg-wcard,.dg-toast,[data-act]")) return;
    if (t.isContentEditable) return;
    closePop();
    const h = t.closest(".dg-h"), ne = t.closest(".dg-node"), ee = t.closest(".dg-edge");
    if (h && ne && S.mode === "move") return startConnect(e, ne.dataset.id, h.dataset.h);
    // A second press on a title within the double-click window renames the node. Detected here, not
    // by `dblclick`: the first press re-renders the node as selected, and a browser fires no
    // dblclick across two different elements.
    if (ne && S.mode === "move" && e.button === 0 && t.closest("[data-edit]")) {
      const now = Date.now();
      if (lastPress.id === ne.dataset.id && now - lastPress.t < 450) { e.preventDefault(); lastPress = {}; return startEdit(ne.dataset.id); }
      lastPress = { id: ne.dataset.id, t: now };
    }
    if (ne && S.mode === "move" && e.button === 0) return startDrag(e, ne.dataset.id);
    if (ee && e.button === 0) { S.sel = new Set(); S.edgeSel = ee.dataset.eid; renderNodes(); renderEdges(); renderChrome(); return; }
    startPan(e);
  });
  function startDrag(e, id) {
    if (e.shiftKey) { S.sel.has(id) ? S.sel.delete(id) : S.sel.add(id); S.edgeSel = null; renderNodes(); renderEdges(); renderChrome(); return; }
    if (!S.sel.has(id)) { S.sel = new Set([id]); S.edgeSel = null; renderNodes(); renderEdges(); renderChrome(); }
    const before = snap(), start = toWorld(e);
    const moving = S.g.nodes.filter((n) => S.sel.has(n.id));
    // A group carries the nodes that sit inside it.
    moving.filter((g) => g.kind === "group").forEach((g) => S.g.nodes.forEach((n) => { if (n.kind !== "group" && !S.sel.has(n.id) && n.x >= g.x && n.y >= g.y && n.x <= g.x + g.w && n.y <= g.y + g.h && !moving.includes(n)) moving.push(n); }));
    const origin = moving.map((n) => [n, n.x, n.y]);
    let moved = false;
    canvas.setPointerCapture(e.pointerId);
    const move = (ev) => {
      const p = toWorld(ev), dx = p[0] - start[0], dy = p[1] - start[1];
      if (!moved && Math.abs(dx) + Math.abs(dy) < 3) return;
      moved = true;
      origin.forEach(([n, x, y]) => { n.x = Math.round(x + dx); n.y = Math.round(y + dy); const el = nodeEl(n.id); if (el) { el.style.left = `${n.x}px`; el.style.top = `${n.y}px`; } });
      renderEdges();
    };
    const up = () => { canvas.removeEventListener("pointermove", move); canvas.removeEventListener("pointerup", up); if (moved) commit(before); };
    canvas.addEventListener("pointermove", move); canvas.addEventListener("pointerup", up);
  }
  function startConnect(e, id, side) {
    e.preventDefault();
    canvas.classList.add("connecting"); temp.style.display = "";
    const from = anchor(id, side);
    canvas.setPointerCapture(e.pointerId);
    const move = (ev) => { const p = toWorld(ev); temp.setAttribute("d", side === "out" ? curve(from, p) : curve(p, from)); };
    const up = (ev) => {
      canvas.removeEventListener("pointermove", move); canvas.removeEventListener("pointerup", up);
      canvas.classList.remove("connecting"); temp.style.display = "none"; temp.setAttribute("d", "");
      const under = document.elementFromPoint(ev.clientX, ev.clientY);
      const target = under && under.closest && under.closest(".dg-node");
      if (target && target.dataset.id !== id) side === "out" ? connect(id, target.dataset.id) : connect(target.dataset.id, id);
    };
    canvas.addEventListener("pointermove", move); canvas.addEventListener("pointerup", up);
  }
  function startPan(e) {
    const sx = e.clientX, sy = e.clientY, v0 = Object.assign({}, S.view);
    let moved = false;
    canvas.setPointerCapture(e.pointerId); canvas.classList.add("panning");
    const move = (ev) => { const dx = ev.clientX - sx, dy = ev.clientY - sy; if (!moved && Math.abs(dx) + Math.abs(dy) < 3) return; moved = true; S.view.x = v0.x + dx; S.view.y = v0.y + dy; applyView(); };
    const up = () => {
      canvas.removeEventListener("pointermove", move); canvas.removeEventListener("pointerup", up); canvas.classList.remove("panning");
      if (!moved && (S.sel.size || S.edgeSel)) { S.sel = new Set(); S.edgeSel = null; renderNodes(); renderEdges(); renderChrome(); }
    };
    canvas.addEventListener("pointermove", move); canvas.addEventListener("pointerup", up);
  }
  canvas.addEventListener("wheel", (e) => {
    if (e.target.closest(".dg-insp,.dg-pop,.dg-panel")) return;
    e.preventDefault();
    const r = canvas.getBoundingClientRect();
    if (e.ctrlKey || e.metaKey || Math.abs(e.deltaY) >= Math.abs(e.deltaX)) zoomAt(Math.exp(-e.deltaY * 0.0015), e.clientX - r.left, e.clientY - r.top);
    else { S.view.x -= e.deltaX; applyView(); }
  }, { passive: false });
  let lastPress = {};
  function startEdit(id) {
    const n = byId(id); const ne = nodeEl(id); const t = ne && ne.querySelector("[data-edit]");
    if (!n || !t) return;
    const before = snap();
    t.contentEditable = "true"; t.focus();
    const range = document.createRange(); range.selectNodeContents(t); const s = window.getSelection(); s.removeAllRanges(); s.addRange(range);
    const done = (keep) => { t.contentEditable = "false"; t.removeEventListener("blur", onBlur); t.removeEventListener("keydown", onKey); if (keep) { const v = t.innerText.trim(); if (v && v !== n.title) { n.title = v.slice(0, 200); commit(before); return; } } render(); };
    const onBlur = () => done(true);
    const onKey = (k) => { if (k.key === "Enter" && !(n.kind === "text" && k.shiftKey)) { k.preventDefault(); t.blur(); } if (k.key === "Escape") { k.preventDefault(); t.removeEventListener("blur", onBlur); done(false); } k.stopPropagation(); };
    t.addEventListener("blur", onBlur); t.addEventListener("keydown", onKey);
  }
  // Node-level buttons (delete badge, quick-add arrows, Link resource).
  canvas.addEventListener("click", (e) => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    const ne = b.closest(".dg-node"); const id = ne ? ne.dataset.id : [...S.sel][0];
    const act = b.dataset.act;
    if (act === "delete") { if (id) { S.sel = new Set([id]); S.edgeSel = null; } deleteSelection(); }
    else if (act === "qa-left" || act === "qa-right") quickAdd(id, act === "qa-left" ? "left" : "right");
    else if (act === "link") { renderInspector(); const f = $("#dg-i-link") || $("#dg-i-app"); if (f) f.focus(); }
    else if (act === "deselect") { S.sel = new Set(); S.edgeSel = null; render(); }
    else if (act === "delete-edge") { if (S.edgeSel) deleteSelection(); }
  });
  $("#dg-welcome").addEventListener("click", (e) => {
    const c = e.target.closest("[data-welcome]"); if (!c) return;
    if (c.dataset.welcome === "reference") openPanel("reference");
    else if (c.dataset.welcome === "architect") openPanel("architect");
    else if (c.dataset.welcome === "initial") addNode({ kind: "state", stateKind: "initial", type: "Initial state", title: "Start" });
    else openLineage();
  });
  $("#dg-welcome").addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && e.target.dataset.welcome) { e.preventDefault(); e.target.click(); } });

  // ---- keyboard
  document.addEventListener("keydown", (e) => {
    const t = e.target, typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === "s") { e.preventDefault(); save(); return; }
    if (typing) return;
    if (e.key === "Escape") { closePop(); closeModal(); S.sel = new Set(); S.edgeSel = null; render(); return; }
    if (e.key === "Delete" || e.key === "Backspace") { e.preventDefault(); deleteSelection(); return; }
    if (mod && e.key.toLowerCase() === "z" && !e.shiftKey) { e.preventDefault(); undo(); return; }
    if (mod && (e.key.toLowerCase() === "y" || (e.key.toLowerCase() === "z" && e.shiftKey))) { e.preventDefault(); redo(); return; }
    if (mod && e.key.toLowerCase() === "a") { e.preventDefault(); S.sel = new Set(S.g.nodes.map((n) => n.id)); render(); return; }
    if (mod && e.key.toLowerCase() === "c" && S.sel.size) { const ids = S.sel; S.clip = { nodes: S.g.nodes.filter((n) => ids.has(n.id)), edges: S.g.edges.filter((x) => ids.has(x.source) && ids.has(x.target)) }; return; }
    if (mod && e.key.toLowerCase() === "v" && S.clip) {
      e.preventDefault(); const clip = clone(S.clip);
      mutate(() => { const map = {}; clip.nodes.forEach((n) => { const id = uid("n"); map[n.id] = id; S.g.nodes.push(Object.assign(n, { id, x: n.x + 40, y: n.y + 40 })); }); clip.edges.forEach((x) => S.g.edges.push(Object.assign(x, { id: uid("e"), source: map[x.source], target: map[x.target] }))); S.sel = new Set(Object.values(map)); });
    }
  });
  function undo() { if (!S.undo.length) return; S.redo.push(snap()); S.g = JSON.parse(S.undo.pop()); S.sel = new Set(); S.edgeSel = null; S.dirty = true; render(); }
  function redo() { if (!S.redo.length) return; S.undo.push(snap()); S.g = JSON.parse(S.redo.pop()); S.sel = new Set(); S.edgeSel = null; S.dirty = true; render(); }
  $("#dg-undo").addEventListener("click", undo); $("#dg-redo").addEventListener("click", redo);
  $("#dg-zin").addEventListener("click", () => { const r = canvas.getBoundingClientRect(); zoomAt(1.2, r.width / 2, r.height / 2); });
  $("#dg-zout").addEventListener("click", () => { const r = canvas.getBoundingClientRect(); zoomAt(1 / 1.2, r.width / 2, r.height / 2); });
  $("#dg-fit").addEventListener("click", fit);
  $("#dg-name").addEventListener("input", (e) => { S.name = e.target.value; S.dirty = true; renderChrome(); });
  $("#dg-name").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); e.target.blur(); } });
  $("#dg-t-pan").addEventListener("click", () => { S.mode = "pan"; renderChrome(); });
  $("#dg-t-move").addEventListener("click", () => { S.mode = "move"; renderChrome(); });
  const onTool = (sel, fn) => { const el = $(sel); if (el) el.addEventListener("click", fn); };
  onTool("#dg-t-group", () => addNode({ kind: "group", title: "Group" }));
  onTool("#dg-t-text", () => addNode({ kind: "text", title: "Text" }));
  // Machinery: a state is initial, normal or final — exactly one initial, which the linter and the
  // daemon both hold the graph to.
  onTool("#dg-t-state", (e) => {
    const hasInitial = S.g.nodes.some((n) => n.kind === "state" && n.stateKind === "initial");
    const kinds = [["initial", "Initial state", "Where the process starts — exactly one"], ["normal", "State", "A step the process can be in"], ["final", "Final state", "Where the process ends"]];
    openPop(e.currentTarget, `<div class="dg-psec">States</div>${kinds.map(([k, label, sub]) => item(k, BOOT.icons[k === "initial" ? "circle-arrow-right" : k === "final" ? "tick" : "selection-box"], label, k === "initial" && hasInitial ? "the graph already has one — a second is a lint error" : sub)).join("")}`,
      (k) => addNode({ kind: "state", stateKind: k, type: k === "initial" ? "Initial state" : k === "final" ? "Final state" : "State", title: k === "initial" ? "Start" : k === "final" ? "Done" : "New state" }));
  });

  // ---- popovers (palettes, Actions)
  const pop = $("#dg-pop");
  let popFor = null;
  function closePop() { pop.classList.remove("on"); pop.innerHTML = ""; popFor = null; $$(".dg-tool.open").forEach((b) => b.classList.remove("open")); }
  function openPop(anchorEl, html, onPick) {
    if (popFor === anchorEl) { closePop(); return; }
    closePop(); popFor = anchorEl;
    pop.innerHTML = html; pop.classList.add("on");
    const r = anchorEl.getBoundingClientRect(), c = canvas.getBoundingClientRect();
    pop.style.left = `${Math.max(8, Math.min(r.left - c.left, c.width - pop.offsetWidth - 8))}px`;
    pop.style.top = `${r.bottom - c.top + 6}px`;
    pop.onclick = (e) => { const it = e.target.closest("[data-pick]"); if (!it || it.disabled) return; onPick(it.dataset.pick); closePop(); };
    const first = pop.querySelector("[data-pick]"); if (first) first.focus();
  }
  pop.addEventListener("keydown", (e) => {
    const items = $$("[data-pick]", pop); const i = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); (items[i + 1] || items[0]).focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); (items[i - 1] || items[items.length - 1]).focus(); }
    if (e.key === "Escape") { e.preventDefault(); const a = popFor; closePop(); if (a) a.focus(); }
  });
  const item = (key, icon, title, sub, disabled) => `<button type="button" class="dg-pitem" role="menuitem" data-pick="${esc(key)}"${disabled ? ` disabled title="${esc(disabled)}"` : ""}><span class="dg-ico">${icon}</span><span><b>${esc(title)}</b>${sub ? `<small>${esc(sub)}</small>` : ""}</span></button>`;
  onTool("#dg-t-concept", (e) => openPop(e.currentTarget,
    `<div class="dg-psec">Concepts</div>${BOOT.palette.concept.map((c, i) => item(i, BOOT.icons.lightbulb, c.type, c.description)).join("")}`,
    (k) => { const c = BOOT.palette.concept[+k]; addNode({ kind: "concept", type: c.type, title: c.type, description: c.description }); }));
  onTool("#dg-t-component", (e) => openPop(e.currentTarget,
    `<div class="dg-psec">IOI applications</div>${BOOT.palette.component.map((c, i) => item(i, c.iconUri ? `<img src="${esc(c.iconUri)}" alt="">` : BOOT.icons.office, c.title, c.type)).join("")}`,
    (k) => { const c = BOOT.palette.component[+k]; addNode({ kind: "component", type: c.type, title: c.title, description: "", href: c.href }); }));
  onTool("#dg-t-resource", (e) => {
    const secs = BOOT.palette.resource.map((r, ri) => {
      if (!r.record) return item(`u:${ri}`, BOOT.icons[r.icon], `New ${r.type.toLowerCase()} node`, "not linked to a record");
      const recs = BOOT.records[r.record] || [];
      return `<div class="dg-psec">${esc(r.type)}s</div>${recs.length ? recs.slice(0, 40).map((x, i) => item(`r:${ri}:${i}`, BOOT.icons[r.icon], x.title, x.sub)).join("") : `<div class="dg-pempty">No ${esc(r.type.toLowerCase())} records yet</div>`}${item(`u:${ri}`, BOOT.icons[r.icon], `Unlinked ${r.type.toLowerCase()}`, "link a record later")}`;
    });
    openPop(e.currentTarget, secs.join(""), (k) => {
      const [kind, ri, xi] = k.split(":"); const r = BOOT.palette.resource[+ri];
      if (kind === "u") return addNode({ kind: "resource", type: r.type, title: `New ${r.type.toLowerCase()}`, description: "", icon: r.icon });
      const x = BOOT.records[r.record][+xi];
      addNode(Object.assign({ kind: "resource", type: r.type, title: x.title, description: x.sub, ref: x.ref, icon: r.icon }, x.href ? { href: x.href } : {}));
    });
  });
  $("#dg-actions").addEventListener("click", (e) => {
    const saved = !!S.bp, empty = !S.g.nodes.length;
    openPop(e.currentTarget, `<div class="dg-menu">
      <div class="dg-psec">Import</div>${item("import-json", BOOT.icons.endnote, "Import diagram from JSON")}${item("import-lineage", BOOT.icons["join-table"], "Import diagram from Data Lineage", "the composition an ontology holds")}
      <hr><div class="dg-psec">Export</div>${item("export-file", BOOT.icons.endnote, "Save as JSON file", "", empty && "The diagram is empty")}${item("export-copy", BOOT.icons.endnote, "Copy to clipboard as JSON", "", empty && "The diagram is empty")}
      <hr><div class="dg-psec">Share</div>${item("share-link", BOOT.icons.tag, "Copy link", saved ? "anyone in your organization can open it" : "", !saved && "Save the diagram first — an unsaved diagram has no address")}
      <hr>${item("clear", BOOT.icons.cross, "Clear diagram", "", empty && "The diagram is empty")}</div>`, (k) => {
      if (k === "import-json") openImport();
      else if (k === "import-lineage") openLineage();
      else if (k === "export-file") { const blob = new Blob([JSON.stringify(exportDoc(), null, 2)], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${(S.name || "diagram").replace(/[^\w.-]+/g, "-")}.json`; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); toast("ok", "Saved the diagram as a JSON file"); }
      else if (k === "export-copy") copyText(JSON.stringify(exportDoc(), null, 2), "Copied the diagram as JSON");
      else if (k === "share-link") copyText(`${location.origin}${BOOT.recordPath}${encodeURIComponent(S.bp.id)}`, "Copied the link");
      else if (k === "clear") { if (confirm("Clear every node and connection from this diagram? Undo brings them back.")) mutate(() => { S.g.nodes = []; S.g.edges = []; S.sel = new Set(); S.edgeSel = null; }); }
    });
  });
  const exportDoc = () => ({ name: S.name, description: S.description, ...S.g });
  function copyText(text, ok) {
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject(new Error("no clipboard"))).then(() => toast("ok", ok), () => { openModal("Copy", `<textarea readonly>${esc(text)}</textarea>`, ""); });
  }

  // ---- modals
  const modal = $("#dg-modal"), dialog = $("#dg-dialog");
  function openModal(title, body, footer) {
    dialog.innerHTML = `<header><span>${esc(title)}</span><button type="button" class="dg-ibtn" data-close aria-label="Close">${BOOT.icons.cross}</button></header><div class="dg-dbody">${body}</div>${footer ? `<footer>${footer}</footer>` : ""}`;
    modal.classList.add("on"); const f = dialog.querySelector("textarea,input,button:not([data-close])"); if (f) f.focus();
  }
  function closeModal() { modal.classList.remove("on"); dialog.innerHTML = ""; dialog.onclick = null; }
  modal.addEventListener("click", (e) => { if (e.target === modal || e.target.closest("[data-close]")) closeModal(); });
  function openImport() {
    openModal("Import Diagram", `<div class="dg-plabel">Import mode</div>
      <label class="dg-radio"><input type="radio" name="dg-mode" value="add" checked><span>Add to existing diagram<small>Adds the imported diagram next to the existing content</small></span></label>
      <label class="dg-radio"><input type="radio" name="dg-mode" value="replace"><span>Replace existing diagram<small>Replaces all existing content with the imported diagram</small></span></label>
      <div class="dg-plabel">Paste JSON</div><textarea id="dg-imp" placeholder='{"nodes":[…],"edges":[…]}'></textarea>
      <div class="dg-plabel">Or upload a file</div><input type="file" id="dg-impfile" accept="application/json,.json">
      <div id="dg-imperr" style="color:#ac2f33;font-size:13px"></div>`,
      `<button type="button" class="dg-btn" data-close>Cancel</button><button type="button" class="dg-btn primary" id="dg-impgo">Import</button>`);
    $("#dg-impfile").addEventListener("change", (e) => { const f = e.target.files[0]; if (f) f.text().then((t) => { $("#dg-imp").value = t; }); });
    $("#dg-impgo").addEventListener("click", () => {
      let doc; try { doc = JSON.parse($("#dg-imp").value); } catch (err) { $("#dg-imperr").textContent = `Not valid JSON: ${err.message}`; return; }
      const nodes = Array.isArray(doc.nodes) ? doc.nodes : [], edges = Array.isArray(doc.edges) ? doc.edges : [];
      const kinds = ["concept", "component", "resource", "text", "group"];
      const bad = nodes.find((n) => !n || !n.id || !kinds.includes(n.kind));
      if (!nodes.length || bad) { $("#dg-imperr").textContent = nodes.length ? `Every node needs an id and a kind (${kinds.join(", ")}).` : "The JSON has no nodes."; return; }
      nodes.forEach((n) => { n.x = Number(n.x) || 0; n.y = Number(n.y) || 0; });
      const replace = ($("input[name=dg-mode]:checked", dialog) || {}).value === "replace";
      closeModal(); addGraph({ nodes, edges }, replace);
      toast("ok", `Imported ${nodes.length} node${nodes.length === 1 ? "" : "s"}`);
    });
  }
  function openLineage() {
    const comps = BOOT.compositions;
    openModal("Load from Data Lineage", comps.length
      ? `<p style="margin:0;color:#5f6b7c">The lineage the daemon holds for an ontology — each source a mapping reads, each mapping, each object type, and the application that explores them. Every node links its record.</p>${comps.map((c, i) => `<div class="dg-comp"><span><b>${esc(c.title)}</b><small>${esc(c.ref)} · ${c.graph.nodes.length} nodes · ${c.graph.edges.length} connections</small></span><button type="button" class="dg-btn" data-load="${i}">Add to graph</button></div>`).join("")}`
      : `<p style="margin:0">No ontology in this deployment has a composition yet. Define object types in the <a href="/__ioi/ontology/manager" target="_top">Ontology Manager</a> and back them with a source; their lineage appears here.</p>`, "");
    dialog.onclick = (e) => { const b = e.target.closest("[data-load]"); if (!b) return; const c = comps[+b.dataset.load]; closeModal(); addGraph(c.graph, false); toast("ok", `Loaded the composition of ${c.title}`); };
  }

  // ---- panels
  function miniSvg(g) {
    if (!g.nodes.length) return `<svg class="dg-mini"></svg>`;
    let x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
    g.nodes.forEach((n) => { x1 = Math.min(x1, n.x); y1 = Math.min(y1, n.y); x2 = Math.max(x2, n.x + NODE_W); y2 = Math.max(y2, n.y + 120); });
    const pad = 60, W = x2 - x1 + pad * 2, H = y2 - y1 + pad * 2;
    const by = {}; g.nodes.forEach((n) => { by[n.id] = n; });
    const edges = g.edges.map((e) => { const a = by[e.source], b = by[e.target]; if (!a || !b) return ""; return `<path d="M${a.x + NODE_W},${a.y + 60} C${a.x + NODE_W + 60},${a.y + 60} ${b.x - 60},${b.y + 60} ${b.x},${b.y + 60}" fill="none" stroke="#8f99a8" stroke-width="6" stroke-dasharray="14"/>`; }).join("");
    const nodes = g.nodes.map((n) => `<rect x="${n.x}" y="${n.y}" width="${NODE_W}" height="120" rx="8" fill="#fff" stroke="#c5cbd3" stroke-width="4"/><rect x="${n.x + 20}" y="${n.y + 22}" width="${NODE_W * 0.55}" height="18" rx="6" fill="#404854"/><rect x="${n.x + 20}" y="${n.y + 70}" width="${NODE_W * 0.75}" height="12" rx="6" fill="#c5cbd3"/>`).join("");
    return `<svg class="dg-mini" viewBox="${x1 - pad} ${y1 - pad} ${W} ${H}" preserveAspectRatio="xMidYMid meet">${edges}${nodes}</svg>`;
  }
  // What the daemon's state-machine plane will refuse, and what reads as a mistake, checked as you draw.
  function lint() {
    const out = [];
    const states = S.g.nodes.filter((n) => n.kind === "state");
    if (!states.length) return [{ level: "warn", text: "Add a state — a process needs at least its initial state" }];
    const initials = states.filter((n) => n.stateKind === "initial");
    if (initials.length === 0) out.push({ level: "err", text: "No initial state — exactly one state must be where the process starts" });
    if (initials.length > 1) out.push({ level: "err", text: `${initials.length} initial states (${initials.map((n) => n.title).join(", ")}) — exactly one is allowed` });
    const names = {}; states.forEach((n) => { const k = String(n.title || "").trim().toLowerCase(); names[k] = (names[k] || 0) + 1; });
    Object.entries(names).filter(([, c]) => c > 1).forEach(([k]) => out.push({ level: "warn", text: `Two states are named "${k}" — give each state its own name` }));
    const tr = S.g.edges.filter((e) => byId(e.source)?.kind === "state" && byId(e.target)?.kind === "state");
    if (initials.length === 1) {
      const seen = new Set([initials[0].id]); const q = [initials[0].id];
      while (q.length) { const at = q.shift(); tr.filter((e) => e.source === at).forEach((e) => { if (!seen.has(e.target)) { seen.add(e.target); q.push(e.target); } }); }
      states.filter((n) => !seen.has(n.id)).forEach((n) => out.push({ level: "warn", text: `"${n.title}" can never be reached from the initial state` }));
    }
    states.filter((n) => n.stateKind === "final" && tr.some((e) => e.source === n.id)).forEach((n) => out.push({ level: "warn", text: `"${n.title}" is final but has a transition out of it` }));
    states.filter((n) => n.stateKind !== "final" && !tr.some((e) => e.source === n.id)).forEach((n) => { if (states.length > 1) out.push({ level: "warn", text: `"${n.title}" is not final and has no way out — mark it final or add a transition` }); });
    tr.filter((e) => !String(e.label || "").trim()).forEach((e) => out.push({ level: "warn", text: `The transition ${byId(e.source).title} → ${byId(e.target).title} has no event — select it to name what moves the process` }));
    return out;
  }
  function openPanel(name) { S.panel = S.panel === name ? "" : name; renderPanel(); }
  function renderPanel() {
    const p = $("#dg-panel");
    $$(".dg-rbtn").forEach((b) => b.classList.toggle("on", b.dataset.panel === S.panel));
    if (!S.panel) { p.classList.remove("on"); p.innerHTML = ""; return; }
    p.classList.add("on");
    const head = (t) => `<div class="dg-phead"><span>${esc(t)}</span><button type="button" class="dg-ibtn" data-pclose aria-label="Close panel">${BOOT.icons.cross}</button></div>`;
    if (S.panel === "info") {
      if (p.dataset.panel === "info" && p.contains(document.activeElement)) return;
      p.innerHTML = `${head("Diagram Information")}<div class="dg-pbody"><div class="dg-plabel">Diagram description</div><textarea id="dg-desc" maxlength="2000" placeholder="Enter description…">${esc(S.description)}</textarea>
        <div class="dg-plabel">Contents</div><div>${S.g.nodes.length} node${S.g.nodes.length === 1 ? "" : "s"} · ${S.g.edges.length} connection${S.g.edges.length === 1 ? "" : "s"} · ${S.g.nodes.filter((n) => n.ref || (n.kind === "component" && n.href)).length} linked to a record</div>
        <div class="dg-plabel">Where it is saved</div><div>${BOOT.variant === "machinery"
          ? (S.bp ? `State-machine definition <code>${esc(S.bp.ref || S.bp.id)}</code> — states and transitions, inert: nothing runs. <a href="/__ioi/studio/machinery?machine=${encodeURIComponent(S.bp.id)}" target="_top">Open in Machinery →</a>` : "Not saved yet. Save stores the graph as a state-machine definition — its states and transitions; the definition is inert and nothing runs.")
          : (S.bp ? `Studio blueprint <code>${esc(S.bp.ref || S.bp.id)}</code> — owned by your organization. <a href="/__ioi/studio/workbench?view=blueprints&amp;bp=${encodeURIComponent(S.bp.id)}" target="_top">Open in Studio →</a>` : "Not saved yet. Save stores the diagram as a Studio blueprint owned by your organization.")}</div></div>`;
      $("#dg-desc").addEventListener("input", (e) => { S.description = e.target.value; S.dirty = true; renderChrome(); });
    } else if (S.panel === "reference") {
      const cats = {};
      BOOT.templates.forEach((t, i) => { (cats[t.category] = cats[t.category] || []).push([t, i]); });
      const card = (title, desc, g, key) => `<div class="dg-tcard" data-title="${esc(title.toLowerCase())}">${miniSvg(g)}<div class="dg-tbody"><b>${esc(title)}</b><p>${esc(desc)}</p><button type="button" class="dg-add" data-add="${key}">Click to add to graph</button></div></div>`;
      p.innerHTML = `${head(BOOT.variant === "machinery" ? "Process templates" : "Reference Diagrams")}<div class="dg-pbody"><input type="search" id="dg-rsearch" placeholder="Search…" aria-label="Search reference diagrams">
        ${Object.keys(cats).map((c) => `<div class="dg-plabel">${esc(c)} (${cats[c].length})</div>${cats[c].map(([t, i]) => card(t.title, t.description, t.graph, `t:${i}`)).join("")}`).join("")}
        ${BOOT.variant === "machinery" ? "" : `<div class="dg-plabel">From your composition (${BOOT.compositions.length})</div>`}${BOOT.variant === "machinery" ? "" : BOOT.compositions.length ? BOOT.compositions.map((c, i) => card(c.title, `The lineage the daemon holds for ${c.title}`, c.graph, `c:${i}`)).join("") : `<div style="color:#5f6b7c;font-size:13px">No ontology has a composition yet.</div>`}</div>`;
      $("#dg-rsearch").addEventListener("input", (e) => { const q = e.target.value.trim().toLowerCase(); $$(".dg-tcard", p).forEach((c) => { c.style.display = !q || c.dataset.title.includes(q) ? "" : "none"; }); });
    } else if (S.panel === "architect") {
      if (p.dataset.panel === "architect" && p.contains(document.activeElement)) return;
      const A = S.architect || (S.architect = { problem: "", data: "", users: "", route: (BOOT.modelRoutes.find((r) => r.runnable !== false) || {}).id || "", busy: false, result: null, error: "" });
      const res = A.result ? `<div class="dg-plabel">Proposed workflow</div><div style="font-size:13px;line-height:1.5">${esc(A.result.summary || "")}</div>${miniSvg(A.result.graph)}
          <div style="color:#5f6b7c;font-size:12px">Suggested by ${esc(A.result.model)} in ${esc(String(A.result.latency_ms ?? "—"))} ms${A.result.checked ? " (the route's availability was checked first)" : ""} — a proposal to review, not a decision. ${A.result.graph.nodes.length} nodes · ${A.result.graph.edges.length} connections; IOI applications are linked.</div>
          <div style="display:flex;gap:8px"><button type="button" class="dg-btn primary" data-plan="add">Add to graph</button><button type="button" class="dg-btn" data-plan="replace">Replace graph</button></div>` : "";
      p.innerHTML = `${head("AIP Architect")}<div class="dg-pbody">
        ${BOOT.modelRoutes.some((r) => r.runnable !== false) ? "" : BOOT.modelRoutes.length ? `<div class="dg-lint warn"><span>No registered model route can run right now. <a href="/__ioi/agent-studio#model-routes" target="_top">Enable one in Agent Studio →</a></span></div>` : `<div class="dg-lint warn"><span>No model route is registered in this deployment. <a href="/__ioi/foundry/models?register=1#register" target="_top">Register one in the Model Catalog →</a></span></div>`}
        <div class="dg-plabel">What problem are you solving?</div><textarea id="dg-a-problem" maxlength="1500" placeholder="e.g. Loan officers miss applications that sit too long in review">${esc(A.problem)}</textarea>
        <div class="dg-plabel">What data do you have?</div><textarea id="dg-a-data" maxlength="1500" placeholder="e.g. A CRM export of applications, and a nightly file of credit scores">${esc(A.data)}</textarea>
        <div class="dg-plabel">Who uses the result, and what do they do?</div><textarea id="dg-a-users" maxlength="1500" placeholder="e.g. Officers get an alert and approve or escalate">${esc(A.users)}</textarea>
        <div class="dg-plabel">Model</div><select id="dg-a-route" style="width:100%;border:1px solid rgba(17,20,24,.2);border-radius:3px;padding:6px 8px">${BOOT.modelRoutes.map((r) => r.runnable === false ? `<option value="${esc(r.id)}" disabled>${esc(r.model)} · cannot run: ${esc(r.lifecycle !== "active" ? `${r.lifecycle} — enable it in Agent Studio` : r.availability === "model_not_present" ? "the provider does not have this model" : `availability is ${r.availability}`)}</option>` : `<option value="${esc(r.id)}"${r.id === A.route ? " selected" : ""}>${esc(r.model)} · ${esc(r.availability)}${r.stale ? " (stale)" : ""}</option>`).join("")}</select>
        <div><button type="button" class="dg-btn primary" data-plan="go"${A.busy || !BOOT.modelRoutes.some((r) => r.runnable !== false) ? " disabled" : ""}>${A.busy ? "Planning…" : "Generate a plan"}</button></div>
        ${A.error ? `<div class="dg-lint err"><span>${esc(A.error)}</span></div>` : ""}
        ${res}</div>`;
      ["problem", "data", "users"].forEach((k) => { const el = $(`#dg-a-${k}`, p); el.addEventListener("input", () => { A[k] = el.value; }); });
      $("#dg-a-route", p)?.addEventListener("change", (e) => { A.route = e.target.value; });
    } else if (S.panel === "linter") {
      const issues = lint();
      p.innerHTML = `${head("Linter")}<div class="dg-pbody">${issues.length ? issues.map((x) => `<div class="dg-lint ${x.level}">${BOOT.icons[x.level === "err" ? "warning-sign" : "warning-sign"]}<span>${esc(x.text)}</span></div>`).join("") : `<div class="dg-lint ok">${BOOT.icons.tick}<span>No lint issues found</span></div>`}
        <div style="color:#5f6b7c;font-size:12px">The daemon holds a saved definition to the same rules and refuses one that breaks them; the linter shows it as you draw.</div></div>`;
    } else if (S.panel === "settings") {
      const st = S.g.settings;
      const tg = (key, title, sub) => `<label class="dg-toggle"><span><b>${esc(title)}</b><span>${esc(sub)}</span></span><input type="checkbox" data-setting="${key}"${st[key] ? " checked" : ""}></label>`;
      p.innerHTML = `${head("Graph Settings")}<div class="dg-pbody">${tg("edgeLabels", "Edge labels", "Show the labels on connections")}${tg("animate", "Edge flow animation", "Animate the direction of each connection")}${tg("iconsOnly", "Show icons only", "Collapse every node to its icon and title")}</div>`;
    } else if (S.panel === "shortcuts") {
      const k = (a, b) => `<div class="dg-kbd"><span>${esc(a)}</span><kbd>${esc(b)}</kbd></div>`;
      p.innerHTML = `${head("Shortcuts")}<div class="dg-pbody">${k("Select several nodes", "Shift + click")}${k("Delete the selected node or connection", "Backspace")}${k("Copy / paste the selection", "Ctrl + C / Ctrl + V")}${k("Select everything", "Ctrl + A")}${k("Undo / redo", "Ctrl + Z / Ctrl + Y")}${k("Save", "Ctrl + S")}${k("Rename a node", "Double-click its title")}${k("Connect two nodes", "Drag from a node's right handle")}${k("Zoom", "Mouse wheel")}${k("Pan", "Drag the background")}</div>`;
    }
    p.dataset.panel = S.panel;
  }
  $$(".dg-rbtn").forEach((b) => b.addEventListener("click", () => openPanel(b.dataset.panel)));
  $("#dg-panel").addEventListener("click", (e) => {
    if (e.target.closest("[data-pclose]")) { S.panel = ""; renderPanel(); return; }
    const a = e.target.closest("[data-add]"); if (!a) return;
    const [k, i] = a.dataset.add.split(":");
    const src = k === "t" ? BOOT.templates[+i] : BOOT.compositions[+i];
    addGraph(src.graph, false); toast("ok", `Added ${src.title}`);
  });
  $("#dg-panel").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-plan]"); if (!b) return;
    const A = S.architect;
    if (b.dataset.plan === "go") {
      A.busy = true; A.error = ""; A.result = null; p_render();
      try {
        const r = await fetch("/__ioi/studio/designer/diagram/plan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ route_id: A.route, problem: A.problem, data: A.data, users: A.users }) });
        const j = await r.json().catch(() => ({}));
        if (j.ok) A.result = j; else A.error = `No plan: ${(j.error && j.error.message) || `the planner answered HTTP ${r.status}`}`;
      } catch (err) { A.error = "No plan: the planner did not answer"; }
      A.busy = false; p_render();
    } else if (A && A.result) {
      addGraph(A.result.graph, b.dataset.plan === "replace");
      toast("ok", b.dataset.plan === "replace" ? "Replaced the graph with the proposal" : "Added the proposal to the graph");
    }
  });
  const p_render = () => { const p = $("#dg-panel"); p.dataset.panel = ""; renderPanel(); };
  $("#dg-panel").addEventListener("change", (e) => {
    const s = e.target.dataset.setting; if (!s) return;
    mutate(() => { S.g.settings[s] = e.target.checked; });
  });

  // ---- toasts
  function toast(kind, text) {
    const box = $("#dg-toasts"); const t = document.createElement("div");
    t.className = `dg-toast ${kind}`; t.setAttribute("role", kind === "err" ? "alert" : "status");
    t.innerHTML = `<span>${esc(text)}</span><button type="button" aria-label="Dismiss">✕</button>`;
    t.querySelector("button").addEventListener("click", () => t.remove());
    box.appendChild(t); if (kind === "ok") setTimeout(() => t.remove(), 4000);
  }

  // ---- save
  function save() {
    if ($("#dg-save").disabled) return;
    const f = $("#dg-saveform");
    f.bp.value = S.bp ? S.bp.id : ""; f.head.value = S.bp ? S.bp.head || "" : ""; f.draft.value = S.draft;
    f.name.value = (S.name || "").trim() || "Untitled diagram"; f.description.value = S.description || ""; f.graph_json.value = JSON.stringify(S.g);
    S.saving = true; S.dirty = false; renderChrome(); f.submit();
  }
  $("#dg-save").addEventListener("click", save);
  window.addEventListener("beforeunload", (e) => { if (S.dirty && !S.saving) { e.preventDefault(); e.returnValue = ""; } });

  // ---- boot
  render();
  requestAnimationFrame(() => { renderEdges(); if (S.g.nodes.length) fit(); else applyView(); });
  if (BOOT.notice) toast(BOOT.notice.kind === "ok" ? "ok" : "err", BOOT.notice.text);
  if (BOOT.panel) openPanel(BOOT.panel);
  // A refused save answers the POST itself; the address goes back to the diagram's own, so a reload
  // cannot re-submit (the unsaved drawing is still guarded by the leave warning).
  if (history.replaceState && /\/(?:diagram|graph)\/save$/.test(location.pathname)) history.replaceState(null, "", S.bp ? `${BOOT.recordPath}${encodeURIComponent(S.bp.id)}` : BOOT.recordPath.split("?")[0]);
  if (history.replaceState && /[?&]saved=1/.test(location.search)) history.replaceState(null, "", location.pathname + location.search.replace(/([?&])saved=1(&|$)/, (m, a, b) => (b ? a : "")));
}
