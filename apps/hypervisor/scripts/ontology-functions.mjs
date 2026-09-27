// Ontology / Functions — the product lane over the functions plane (ADR 0056 Amendment 1, plane 3).
//
// A function is typed code over the semantic world: declared inputs, a declared output and the source
// it runs. Every revision is immutable and content-addressed; a change is a successor revision with a
// greater version. Releasing a revision compiles it into an exact runtime tool-contract revision —
// the only way agents, automations and ontology actions use it — and deprecating one revokes that tool
// revision. A test run executes one exact revision in an environment you own, through the governed exec
// primitive. This lane reads the plane on every request and keeps no copy; its writes are the plane's
// own, each a form post the serve re-encodes with the caller's organization as owner and a per-render
// idempotency key.
//
// What is NOT here, named on the page instead of simulated: ontology-object inputs and outputs,
// auto-upgrade to compatible versions, usage history, and package registration (Developer Console).
import crypto from "node:crypto";
import { callerOwnerRef, escHtml as esc } from "../surfaces/kit.mjs";

export const FUNCTIONS_ROUTE = "/ontology/functions";
export const FUNCTIONS_LANE = "/__ioi/ontology/functions";

const SCALARS = ["string", "integer", "double", "boolean", "date", "timestamp"];
const TYPE_CHOICES = [...SCALARS, ...SCALARS.map((s) => `list:${s}`)];
const RUNTIMES = [["python3", "Python 3"], ["node", "Node.js"], ["bash", "Bash"]];
const INPUT_ROWS = 6;
const STATUS_PILL = { draft: "muted", released: "ok", deprecated: "warn" };
const OUTCOME_PILL = { passed: "ok", failed: "warn", errored: "warn", timed_out: "warn" };
const OUTCOME_WORD = { passed: "Passed", failed: "Failed", errored: "Errored", timed_out: "Timed out" };
const STARTER = {
  python3: "import json, sys\n\nargs = json.load(sys.stdin)  # the inputs, by name\n# print exactly one JSON value of the output type on stdout; log to stderr\nprint(json.dumps(args))\n",
  node: "const args = JSON.parse(require('fs').readFileSync(0, 'utf8')); // the inputs, by name\n// print exactly one JSON value of the output type on stdout; log to stderr\nconsole.log(JSON.stringify(args));\n",
  bash: "# the inputs arrive as one JSON object on stdin\n# print exactly one JSON value of the output type on stdout; log to stderr\ncat\n",
};

const when = (iso) => { const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/u.exec(String(iso || "")); return m ? `${m[1]} ${m[2]} UTC` : String(iso || "—"); };
const FN_CSS = `<style>.fn-scroll{overflow-x:auto;max-width:100%}.fn-scroll table{width:100%;min-width:640px}.fn-scroll code,.fn-meta code{word-break:break-all}.fn-scroll .pill{white-space:nowrap}.fn-verbs{display:flex;flex-wrap:wrap;gap:6px;align-items:center}.fn-verbs form{margin:0}.fn-meta{display:grid;grid-template-columns:160px 1fr;gap:6px 14px;font-size:13px;margin:0 0 12px}.fn-meta>*{min-width:0}.fn-src{background:var(--panel-2,#f6f7f9);border:1px solid var(--line,#e3e6ea);border-radius:6px;padding:10px;overflow:auto;max-height:360px;font-size:12px;white-space:pre}.fn-versions{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 12px}form.grid[data-fn-form]>*{min-width:0}form.grid[data-fn-form] input,form.grid[data-fn-form] select,form.grid[data-fn-form] textarea{width:100%;max-width:100%;box-sizing:border-box}.fn-inputs{display:grid;grid-template-columns:1.2fr 1fr 70px 2fr;gap:6px}.fn-inputs>*{min-width:0}@media (max-width:640px){form.grid[data-fn-form]{grid-template-columns:1fr!important}.fn-meta{grid-template-columns:1fr}.fn-inputs{grid-template-columns:1fr 1fr}}</style>`;
const fnTail = (ref) => String(ref || "").replace(/^function:\/\//u, "").split("/")[0];
const typeWord = (t) => t?.type === "list" ? `list<${t.element_type}>` : String(t?.type || "—");
const typeChoice = (t) => t?.type === "list" ? `list:${t.element_type}` : String(t?.type || "string");
const hidden = (name, value) => `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`;
const opt = (value, label, selected) => `<option value="${esc(value)}"${selected ? " selected" : ""}>${esc(label)}</option>`;
const statusPill = (status, extra = "") => `<span class="pill ${STATUS_PILL[status] || "muted"}" style="margin:0" data-fn-status="${esc(status || "")}"${extra}>${esc(status || "—")}</span>`;
const outcomePill = (o) => `<span class="pill ${OUTCOME_PILL[o] || "muted"}" style="margin:0" data-fn-outcome="${esc(o || "")}">${esc(OUTCOME_WORD[o] || o || "—")}</span>`;
const typeOptions = (selected) => TYPE_CHOICES.map((c) => opt(c, c.startsWith("list:") ? `list of ${c.slice(5)}` : c, c === selected)).join("");

function functionsTable(functions) {
  if (!functions.length) return `<div class="empty" data-fn-empty="1">No functions yet. Declare one below — name it, type its inputs and output, and write the code it runs. It is a draft until you release it.</div>`;
  const rows = functions.map((f) => {
    const latest = f.latest_revision || {};
    const released = f.released_revision;
    const id = fnTail(f.function_ref);
    return `<tr data-fn-row="${esc(f.function_ref)}">
      <td><a href="${FUNCTIONS_ROUTE}?function=${encodeURIComponent(id)}#function-detail"><b>ƒ ${esc(f.display_name || id)}</b></a><div class="sub" style="margin:2px 0 0;font-size:11px"><code>${esc(f.api_name || "")}</code></div></td>
      <td>${esc(RUNTIMES.find(([k]) => k === latest.implementation?.runtime)?.[1] || latest.implementation?.runtime || "—")}</td>
      <td>${esc(latest.version || "—")} ${statusPill(latest.status)}</td>
      <td>${released ? `${esc(released.version)} <span class="pill ${released.tool_operable ? "ok" : "warn"}" style="margin:0" data-fn-tool-operable="${released.tool_operable ? "1" : "0"}">${released.tool_operable ? "tool operable" : "tool not operable"}</span>` : `<span class="sub" style="margin:0">not released</span>`}</td>
      <td>${esc(String(f.revision_count || 0))}</td>
      <td>${esc(when(f.updated_at))}</td>
    </tr>`;
  }).join("");
  return `<div class="fn-scroll"><table data-fn-list="${functions.length}"><thead><tr><th>Name</th><th>Runtime</th><th>Latest</th><th>Released</th><th>Revisions</th><th>Updated</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function testRunsTable(runs) {
  if (!runs.length) return `<div class="empty" data-fn-runs-empty="1">No test runs yet — run a revision below with inputs of its declared types.</div>`;
  const rows = runs.map((r) => `<tr data-fn-run="${esc(r.test_run_id || "")}">
    <td>${outcomePill(r.outcome)}</td>
    <td><code>${esc(String(r.revision_ref || "").split("/").pop())}</code></td>
    <td>${esc(when(r.observed_at))}</td>
    <td>${r.exit_code == null ? "—" : esc(String(r.exit_code))}</td>
    <td>${esc(r.redacted_summary || "")}${r.stderr_tail ? `<details><summary class="sub">stderr</summary><pre class="fn-src">${esc(r.stderr_tail)}</pre></details>` : ""}</td>
    <td>${r.output == null ? "—" : `<code data-fn-run-output="1">${esc(JSON.stringify(r.output).slice(0, 400))}</code>`}</td>
  </tr>`).join("");
  return `<div class="fn-scroll"><table data-fn-runs="${runs.length}"><thead><tr><th>Outcome</th><th>Revision</th><th>Observed</th><th>Exit</th><th>Summary</th><th>Output</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function inputRows(inputs, v, disabled) {
  const rows = [];
  for (let i = 0; i < INPUT_ROWS; i++) {
    const given = inputs[i] || {};
    const name = v[`input_name_${i}`] ?? given.name ?? "";
    const type = v[`input_type_${i}`] ?? typeChoice(given.data_type);
    const required = v[`input_name_${i}`] !== undefined ? v[`input_required_${i}`] === "on" : given.required !== false;
    const description = v[`input_description_${i}`] ?? given.description ?? "";
    rows.push(`<input name="input_name_${i}" value="${esc(name)}" placeholder="${i === 0 ? "amount" : "name"}" aria-label="Input ${i + 1} name" maxlength="64"${disabled}>
      <select name="input_type_${i}" aria-label="Input ${i + 1} type"${disabled}>${typeOptions(type)}</select>
      <label style="display:flex;gap:4px;align-items:center;font-size:12px"><input type="checkbox" name="input_required_${i}"${required ? " checked" : ""} style="width:auto"${disabled}>required</label>
      <input name="input_description_${i}" value="${esc(description)}" placeholder="what it means" aria-label="Input ${i + 1} description" maxlength="1000"${disabled}>`);
  }
  return `<div class="fn-inputs" data-fn-inputs="1"><span class="sub" style="margin:0">Name</span><span class="sub" style="margin:0">Type</span><span></span><span class="sub" style="margin:0">Description</span>${rows.join("")}</div>`;
}

// The declaration form: a new function, or (with `base`) a successor revision of one.
function declarationForm({ action, base = null, values = {}, canWrite, why, formId }) {
  const v = values;
  const disabled = canWrite ? "" : " disabled";
  const runtime = v.runtime || base?.implementation?.runtime || "python3";
  const source = v.source ?? base?.implementation?.source ?? STARTER[runtime] ?? STARTER.python3;
  const outputType = v.output_type || typeChoice(base?.output?.data_type || { type: "string" });
  return `<form method="post" action="${action}" id="${formId}" data-fn-form="${base ? "revise" : "new"}" class="grid" style="grid-template-columns:170px 1fr">
    ${hidden("nonce", v.nonce || crypto.randomUUID())}${base ? hidden("id", fnTail(base.function_ref)) : ""}
    <label>Name</label><input name="display_name" maxlength="160" value="${esc(v.display_name ?? base?.display_name ?? "")}" placeholder="Double an amount"${disabled}>
    ${base ? `<label>API name</label><div><code>${esc(base.api_name)}</code><div class="sub" style="margin:2px 0 0">A function keeps its API name across revisions.</div></div>` : `<label>API name</label><input name="api_name" maxlength="64" value="${esc(v.api_name || "")}" placeholder="doubleAmount"${disabled}>`}
    <label>Version</label><div><input name="version" maxlength="20" value="${esc(v.version ?? (base ? "" : "1.0.0"))}" placeholder="${base ? `greater than ${esc(base.version)}` : "1.0.0"}"${disabled}><div class="sub" style="margin:2px 0 0">MAJOR.MINOR.PATCH${base ? ` — strictly greater than every earlier revision (latest ${esc(base.version)})` : ""}.</div></div>
    <label>Documentation</label><textarea name="documentation" rows="2" maxlength="4000"${disabled}>${esc(v.documentation ?? base?.documentation ?? "")}</textarea>
    <label>Inputs</label>${inputRows(base?.inputs || [], v, disabled)}
    <label>Output type</label><div style="display:grid;grid-template-columns:200px 1fr;gap:6px"><select name="output_type"${disabled}>${typeOptions(outputType)}</select><input name="output_description" maxlength="1000" value="${esc(v.output_description ?? base?.output?.description ?? "")}" placeholder="what it returns"${disabled}></div>
    <label>Runtime</label><select name="runtime"${disabled}>${RUNTIMES.map(([k, label]) => opt(k, label, k === runtime)).join("")}</select>
    <label>Source</label><div><textarea name="source" rows="10" maxlength="49152" spellcheck="false" style="font-family:var(--mono,monospace);font-size:12px"${disabled}>${esc(source)}</textarea><div class="sub" style="margin:2px 0 0">The inputs arrive as one JSON object on stdin. Print exactly one JSON value of the output type on stdout and log to stderr. The source runs as written — the environment's exec guardrails read it.</div></div>
    <label>Timeout</label><div><input name="timeout_seconds" type="number" min="1" max="60" value="${esc(v.timeout_seconds ?? String(Math.round((base?.timeout_ms || 30000) / 1000)))}" style="max-width:120px"${disabled}> <span class="sub" style="margin:0">seconds (1–60)</span></div>
    <span></span><div><button class="act" type="submit"${disabled}>${base ? "Add revision" : "Declare function"}</button>${canWrite ? "" : ` <span class="sub" style="margin:0" data-fn-form-disabled="1">${esc(why)}</span>`}</div>
  </form>`;
}

function testRunForm(revision, environments, values, canWrite, why) {
  const v = values || {};
  const disabled = canWrite && environments.length ? "" : " disabled";
  const envs = `<select name="environment_ref" data-fn-field="environment_ref"${disabled}>${opt("", environments.length ? "Choose an environment…" : "No running environment", !v.environment_ref)}${environments.map(([ref, name, phase]) => opt(ref, `${name || ref}${phase ? ` (${phase})` : ""}`, ref === v.environment_ref)).join("")}</select>`;
  const fields = (revision.inputs || []).map((input) => {
    const t = input.data_type || {};
    const name = `in_${input.name}`;
    const hint = t.type === "list" ? `one ${t.element_type} per line` : t.type === "boolean" ? "true or false" : t.type === "date" ? "YYYY-MM-DD" : t.type === "timestamp" ? "2026-09-26T10:00:00Z" : t.type;
    const control = t.type === "list"
      ? `<textarea name="${esc(name)}" rows="2" placeholder="${esc(hint)}"${disabled}>${esc(v[name] || "")}</textarea>`
      : `<input name="${esc(name)}" value="${esc(v[name] || "")}" placeholder="${esc(hint)}"${disabled}>`;
    return `<label>${esc(input.name)} <span class="sub" style="margin:0">${esc(typeWord(t))}${input.required ? "" : " · optional"}</span></label>${control}`;
  }).join("");
  const blocked = !environments.length && canWrite ? ` <span class="sub" style="margin:0" data-fn-test-disabled="1">a test run needs a running environment — start one in <a href="/__ioi/environments">Environments</a></span>` : (!canWrite ? ` <span class="sub" style="margin:0">${esc(why)}</span>` : "");
  return `<form method="post" action="${FUNCTIONS_LANE}/test" id="test-run" data-fn-form="test" class="grid" style="grid-template-columns:170px 1fr">
    ${hidden("nonce", v.nonce || crypto.randomUUID())}${hidden("id", fnTail(revision.function_ref))}${hidden("ordinal", String(revision.ordinal))}
    <label>Environment</label><div>${envs}<div class="sub" style="margin:2px 0 0">The revision runs there, under that environment's guardrails and isolation.</div></div>
    ${fields}
    <span></span><div><button class="act" type="submit"${disabled}>Run revision ${esc(String(revision.ordinal))} (${esc(revision.version)})</button>${blocked}</div>
  </form>`;
}

// One revision's verbs. A verb the revision cannot take says why beside it.
function revisionActions(revision, revisions, canWrite, why) {
  if (!canWrite) return `<span class="sub" style="margin:0">${esc(why)}</span>`;
  const id = fnTail(revision.function_ref);
  const nonce = () => hidden("nonce", crypto.randomUUID());
  const base = `${hidden("id", id)}${hidden("ordinal", String(revision.ordinal))}${nonce()}`;
  if (revision.status === "draft") {
    const newerReleased = revisions.find((r) => r.ordinal > revision.ordinal && r.status !== "draft");
    if (newerReleased) return `<button class="act" type="button" aria-disabled="true" disabled>Release</button> <span class="sub" style="margin:0" data-fn-disabled-reason="superseded">revision ${esc(String(newerReleased.ordinal))} is already released — a superseded draft cannot be released</span>`;
    return `<form method="post" action="${FUNCTIONS_LANE}/release">${base}<button class="act" type="submit" data-fn-release="${esc(String(revision.ordinal))}">Release ${esc(revision.version)}</button></form> <span class="sub" style="margin:0">Releasing makes it a tool agents and automations can bind by exact revision.</span>`;
  }
  if (revision.status === "released") {
    return `<form method="post" action="${FUNCTIONS_LANE}/deprecate" class="fn-verbs">${base}<input name="reason" maxlength="2000" placeholder="why it is deprecated" aria-label="Deprecation reason" style="min-width:220px"><button class="act danger" type="submit" data-fn-deprecate="${esc(String(revision.ordinal))}">Deprecate</button></form>`;
  }
  return `<span class="sub" style="margin:0" data-fn-deprecated-reason="1">Deprecated: ${esc(revision.deprecation?.reason || "")}</span>`;
}

function functionDetail(detail, selectedOrdinal, environments, opts, canWrite, why) {
  const { function: fn = {}, revisions = [], test_runs: runs = [] } = detail;
  const ordered = [...revisions].sort((a, b) => a.ordinal - b.ordinal);
  const current = ordered.find((r) => String(r.ordinal) === String(selectedOrdinal)) || ordered.at(-1) || {};
  const id = fnTail(fn.function_ref);
  const versions = ordered.slice().reverse().map((r) => `<a class="pill ${String(r.ordinal) === String(current.ordinal) ? "ok" : "muted"}" style="margin:0" href="${FUNCTIONS_ROUTE}?function=${encodeURIComponent(id)}&amp;revision=${r.ordinal}#function-detail" data-fn-version="${r.ordinal}">${esc(r.version)} · ${esc(r.status)}</a>`).join("");
  const tool = current.runtime_tool_contract;
  const inputs = (current.inputs || []).length
    ? `<div class="fn-scroll"><table data-fn-detail-inputs="${current.inputs.length}"><thead><tr><th>Input</th><th>Type</th><th>Required</th><th>Description</th></tr></thead><tbody>${current.inputs.map((i) => `<tr><td><code>${esc(i.name)}</code></td><td><span class="pill muted" style="margin:0">${esc(typeWord(i.data_type))}</span></td><td>${i.required ? "yes" : "no"}</td><td>${esc(i.description || "")}</td></tr>`).join("")}</tbody></table></div>`
    : `<div class="empty">This revision takes no inputs.</div>`;
  const runsForThis = runs;
  return `<h2 id="function-detail" data-fn-detail="${esc(fn.function_ref || "")}">ƒ ${esc(current.display_name || fn.display_name || id)}</h2>
    <div class="fn-versions" data-fn-versions="${ordered.length}">${versions}</div>
    <div class="fn-meta" data-fn-revision="${esc(current.revision_ref || "")}">
      <span class="sub" style="margin:0">Status</span><div>${statusPill(current.status)}${current.released_at ? ` <span class="sub" style="margin:0">released ${esc(when(current.released_at))}</span>` : ""}</div>
      <span class="sub" style="margin:0">Documentation</span><div>${current.documentation ? esc(current.documentation) : `<i class="sub" style="margin:0">No documentation</i>`}</div>
      <span class="sub" style="margin:0">API name</span><code>${esc(current.api_name || "")}</code>
      <span class="sub" style="margin:0">Revision</span><code>${esc(current.revision_ref || "")}</code>
      <span class="sub" style="margin:0">Content hash</span><code>${esc(current.content_hash || "")}</code>
      <span class="sub" style="margin:0">Output type</span><div><span class="pill muted" style="margin:0" data-fn-output-type="${esc(typeWord(current.output?.data_type))}">${esc(typeWord(current.output?.data_type))}</span> ${esc(current.output?.description || "")}</div>
      <span class="sub" style="margin:0">Runtime</span><div>${esc(RUNTIMES.find(([k]) => k === current.implementation?.runtime)?.[1] || "")} · timeout ${esc(String(Math.round((current.timeout_ms || 0) / 1000)))}s</div>
      <span class="sub" style="margin:0">Tool revision</span><div>${tool ? `<code data-fn-tool-revision="${esc(tool.revision_ref)}">${esc(tool.revision_ref)}</code> <span class="pill ${current.tool_operable ? "ok" : "warn"}" style="margin:0">${current.tool_operable ? "operable" : current.status === "deprecated" ? "revoked" : "not operable"}</span>` : `<span class="sub" style="margin:0">none — a draft compiles into a tool revision when it is released</span>`}</div>
      <span class="sub" style="margin:0">Created</span><div>${esc(when(current.created_at))} by <code>${esc(current.created_by_principal_ref || "")}</code></div>
    </div>
    <div class="fn-verbs" style="margin:0 0 12px">${revisionActions(current, ordered, canWrite, why)}</div>
    <h3 style="font-size:13px;margin:14px 0 6px">Inputs</h3>${inputs}
    <h3 style="font-size:13px;margin:14px 0 6px">Source</h3><pre class="fn-src" data-fn-source="1">${esc(current.implementation?.source || "")}</pre>
    <h3 style="font-size:13px;margin:14px 0 6px">Test runs</h3>${testRunsTable(runsForThis)}
    <h3 style="font-size:13px;margin:14px 0 6px">Run a test</h3>${opts.testError ? `<div class="card" style="display:block" data-fn-test-error="1"><span class="pill warn" style="margin:0 8px 0 0">Not run</span>${esc(opts.testError)}</div>` : ""}${testRunForm(current, environments, opts.testValues, canWrite, why)}
    <details${opts.reviseError ? " open" : ""} data-fn-revise="1" style="margin:14px 0 0"><summary style="font-size:13px;font-weight:600;cursor:pointer">New revision — change the code, types or documentation under a greater version</summary>${opts.reviseError ? `<div class="card" style="display:block" data-fn-revise-error="1"><span class="pill warn" style="margin:0 8px 0 0">Not added</span>${esc(opts.reviseError)}</div>` : ""}${declarationForm({ action: `${FUNCTIONS_LANE}/revise`, base: ordered.at(-1), values: opts.reviseValues || {}, canWrite, why, formId: "new-revision" })}</details>`;
}

const NAMED_GAPS = [
  ["function_object_types_absent", "Ontology-object inputs and outputs", "a function takes and returns scalars and lists of scalars; object and object-set types wait for object references that resolve through an admitted ontology revision"],
  ["function_compatible_upgrade_absent", "Auto-upgrade to compatible versions", "a consumer pins one exact revision; following the newest compatible release is not offered"],
  ["function_usage_history_absent", "Usage history", "which agents, automations and actions called a revision, and how often, is not recorded yet"],
  ["function_package_registration_absent", "Package registration", "registering a function package from the developer kit belongs to Developer Console (ADR 0056 Amendment 3 §4) and is not built"],
];

// The page. `data` is the daemon's answers for this request.
export function renderOntologyFunctions(data, opts = {}) {
  const { functions = [], detail = null, owner = "", readError = null, signInHref = "", environments = [] } = data;
  const q = opts.query || new URLSearchParams();
  const canWrite = Boolean(owner) && !readError;
  const why = readError ? "the functions could not be read, so nothing can be changed" : "your sign-in belongs to no organization of this deployment, so a function would have no owner";
  const notice = q.get("note") ? `<div class="card" style="display:block" data-fn-notice="${q.get("ok") === "1" ? "ok" : "err"}"><span class="pill ${q.get("ok") === "1" ? "ok" : "warn"}" style="margin:0 8px 0 0">${q.get("ok") === "1" ? "Done" : "Not done"}</span>${esc(q.get("note"))}</div>` : "";
  const head = `${FN_CSS}<h1>Ontology / Functions</h1>
    <p class="sub">Typed code over your ontology. Each revision declares its inputs, its output and the code it runs, and never changes once added — a change is a new revision with a greater version. Releasing a revision makes it a tool that agents, automations and actions bind by exact revision; a test run executes one revision in an environment you own. <a href="/ontology">← Ontology</a> · <a href="/ontology/schema">Ontology Manager →</a></p>`;
  if (readError) {
    return head + notice + `<div class="empty" data-fn-read-error="${esc(readError.code || "")}">The functions could not be read — <code>${esc(readError.code || "unavailable")}</code>: ${esc(readError.message || "")}.${signInHref ? ` <a href="${esc(signInHref)}" target="_top">Sign in</a> to see your functions.` : ""} Nothing is shown in their place.</div>`;
  }
  const selected = q.get("function") || "";
  let detailBlock = "";
  if (selected) {
    detailBlock = detail && detail.function
      ? functionDetail(detail, q.get("revision") || "", environments, opts, canWrite, why)
      : `<div class="empty" data-fn-detail-missing="1">No function <code>${esc(selected)}</code> is visible to you.</div>`;
  }
  const newError = opts.newError ? `<div class="card" style="display:block" data-fn-new-error="1"><span class="pill warn" style="margin:0 8px 0 0">Not declared</span>${esc(opts.newError)}</div>` : "";
  const gaps = `<h2>Not built yet</h2><ul class="sub" data-fn-named-gaps="${NAMED_GAPS.length}">${NAMED_GAPS.map(([code, label, text]) => `<li data-named-gap="${esc(code)}"><b>${esc(label)}</b> — ${esc(text)}.</li>`).join("")}</ul>`;
  return head + notice + `<h2>Functions <span class="pill muted" style="margin:0">${functions.length}</span></h2>` + functionsTable(functions) + detailBlock
    + `<h2 id="new-function">New function</h2>` + newError + declarationForm({ action: `${FUNCTIONS_LANE}/new`, values: opts.newValues || {}, canWrite, why, formId: "new-function-form" }) + gaps;
}

// ---- Serving ----------------------------------------------------------------------------------
async function readJson(daemonFetch, path) {
  try {
    const r = await daemonFetch(path);
    return { status: r.status, body: await r.json().catch(() => ({})) };
  } catch (e) {
    return { status: 0, body: {}, networkError: String(e && e.message || e) };
  }
}

async function loadFunctionsData({ daemonFetch }, selected) {
  const id = /^fn_[0-9a-f]{16}$/u.test(selected || "") ? selected : "";
  const [listR, whoR, envR, detailR] = await Promise.all([
    readJson(daemonFetch, "/v1/hypervisor/functions"),
    readJson(daemonFetch, "/v1/hypervisor/auth/whoami"),
    readJson(daemonFetch, "/v1/hypervisor/environments-summary?limit=60&phase=live"),
    id ? readJson(daemonFetch, `/v1/hypervisor/functions/${id}`) : Promise.resolve(null),
  ]);
  let readError = null;
  if (listR.networkError) readError = { code: "daemon_unreachable", message: listR.networkError };
  else if (listR.status !== 200 || listR.body.ok === false) {
    const b = listR.body || {};
    readError = { code: b.code || b.error?.code || `http_${listR.status}`, message: b.message || b.error?.message || "" };
  }
  const environments = (envR.body.environments || []).map((e) => [`environment://${e.id || e.environment_id}`, e.spec?.name || e.name || "", e.status?.phase || e.phase || ""]).filter(([ref]) => ref !== "environment://undefined");
  return {
    functions: listR.body.functions || [],
    detail: detailR && detailR.status === 200 ? detailR.body : null,
    owner: whoR.body?.authenticated === false ? "" : callerOwnerRef(whoR.body || {}),
    readError,
    signInHref: readError && /principal_required/u.test(readError.code) ? `/__ioi/login?next=${encodeURIComponent(FUNCTIONS_ROUTE)}` : "",
    environments,
  };
}

async function writeJson(daemonFetch, path, payload) {
  try {
    const r = await daemonFetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    return { status: r.status, body: await r.json().catch(() => ({})) };
  } catch {
    return { status: 0, body: {} };
  }
}

const accepted = (r) => r.status >= 200 && r.status < 300 && r.body && r.body.ok === true;
const dataTypeOf = (choice) => String(choice || "").startsWith("list:") ? { type: "list", element_type: choice.slice(5) } : { type: choice || "string" };

// The declaration fields a form posted, as the plane's body (inputs from the named rows).
function declarationBody(f) {
  const inputs = [];
  for (let i = 0; i < INPUT_ROWS; i++) {
    const name = (f.get(`input_name_${i}`) || "").trim();
    if (!name) continue;
    inputs.push({ name, description: (f.get(`input_description_${i}`) || "").trim(), data_type: dataTypeOf(f.get(`input_type_${i}`)), required: f.get(`input_required_${i}`) === "on" });
  }
  const seconds = Number.parseInt(f.get("timeout_seconds") || "30", 10);
  return {
    display_name: (f.get("display_name") || "").trim(),
    ...(f.get("api_name") !== null ? { api_name: (f.get("api_name") || "").trim() } : {}),
    version: (f.get("version") || "").trim(),
    documentation: f.get("documentation") || "",
    inputs,
    output: { data_type: dataTypeOf(f.get("output_type")), description: (f.get("output_description") || "").trim() },
    implementation: { runtime: f.get("runtime") || "python3", source: (f.get("source") || "").replace(/\r\n/gu, "\n") },
    timeout_ms: Number.isFinite(seconds) ? seconds * 1000 : 30000,
  };
}

// A typed value from what a person typed; `Err` says what is wrong in their words.
export function typedValue(dataType, raw) {
  const text = String(raw ?? "").trim();
  if (text === "") return { skip: true };
  const scalar = (kind, s) => {
    if (kind === "integer") return /^-?\d+$/u.test(s) ? { value: Number.parseInt(s, 10) } : { error: `${s} is not a whole number` };
    if (kind === "double") return s !== "" && Number.isFinite(Number(s)) ? { value: Number(s) } : { error: `${s} is not a number` };
    if (kind === "boolean") return s === "true" || s === "false" ? { value: s === "true" } : { error: `${s} is not true or false` };
    return { value: s };
  };
  if (dataType?.type === "list") {
    const items = text.split("\n").map((s) => s.trim()).filter(Boolean);
    const values = [];
    for (const item of items) {
      const one = scalar(dataType.element_type, item);
      if (one.error) return one;
      values.push(one.value);
    }
    return { value: values };
  }
  return scalar(dataType?.type, text);
}

// Returns true when it answered the request.
export async function handleOntologyFunctions(req, res, pathname, body, deps) {
  const { daemonFetch, whyRefused, send } = deps;
  if (pathname === FUNCTIONS_LANE && req.method === "GET") {
    const query = new URL(req.url, "http://x").searchParams;
    send(res, 200, renderOntologyFunctions(await loadFunctionsData(deps, query.get("function")), { query }));
    return true;
  }
  if (!pathname.startsWith(`${FUNCTIONS_LANE}/`) || req.method !== "POST") return false;
  const f = new URLSearchParams(body.toString());
  const back = (ok, note, id, ordinal) => {
    const qs = new URLSearchParams({ ...(id ? { function: id } : {}), ...(ordinal ? { revision: String(ordinal) } : {}), ok: ok ? "1" : "0", note });
    res.writeHead(303, { Location: `${FUNCTIONS_ROUTE}?${qs}${id ? "#function-detail" : ""}`, "Cache-Control": "no-store" });
    res.end();
  };
  const who = await readJson(daemonFetch, "/v1/hypervisor/auth/whoami");
  // An anonymous whoami still names the local operator (authenticated:false); only a signed-in
  // answer supplies an owner.
  const signedOut = who.status === 401 || who.body?.authenticated === false || /principal_required/u.test(JSON.stringify(who.body || {}));
  const owner = signedOut ? "" : callerOwnerRef(who.body || {});
  const noOwner = signedOut ? "you are signed out — sign in and try again" : "your sign-in belongs to no organization of this deployment";
  const action = pathname.slice(FUNCTIONS_LANE.length + 1);
  const values = Object.fromEntries([...f.keys()].map((k) => [k, (f.get(k) || "").slice(0, k === "source" ? 49152 : 4000)]));
  const rerender = async (id, opts) => send(res, 200, renderOntologyFunctions(await loadFunctionsData(deps, id), { query: new URLSearchParams(id ? { function: id } : {}), ...opts }));

  if (action === "new") {
    const refuse = (error) => rerender("", { newValues: values, newError: error });
    const decl = declarationBody(f);
    if (!decl.display_name) return refuse("give the function a name."), true;
    if (!decl.api_name) return refuse("give the function an API name (for example doubleAmount)."), true;
    if (!decl.implementation.source.trim()) return refuse("write the code the function runs."), true;
    if (!owner) return refuse(`${noOwner}, so the function would have no owner.`), true;
    const r = await writeJson(daemonFetch, "/v1/hypervisor/functions", { owner_ref: owner, idempotency_key: `function-${values.nonce || crypto.randomUUID()}`, ...decl });
    if (!accepted(r)) return refuse(`${whyRefused(r.body)}.`), true;
    const rev = r.body.revision || {};
    back(true, r.body.replayed ? "This function was already declared — the same form was submitted twice, so nothing new was written." : `Declared ${rev.api_name} ${rev.version} as a draft. Run a test, then release it.`, fnTail(rev.function_ref), rev.ordinal);
    return true;
  }
  const id = fnTail((f.get("id") || "").slice(0, 200));
  if (!/^fn_[0-9a-f]{16}$/u.test(id)) return back(false, "That is not a function.", ""), true;
  if (!owner) return back(false, `Not changed: ${noOwner}.`, id), true;
  const key = `function-${action}-${f.get("nonce") || crypto.randomUUID()}`;
  const ordinal = Number.parseInt(f.get("ordinal") || "0", 10);
  if (action === "revise") {
    const decl = declarationBody(f);
    delete decl.api_name;
    if (!decl.version) return rerender(id, { reviseValues: values, reviseError: "give the revision a version greater than the latest." }), true;
    const r = await writeJson(daemonFetch, `/v1/hypervisor/functions/${id}/revisions`, { owner_ref: owner, idempotency_key: key, ...decl });
    if (!accepted(r)) return rerender(id, { reviseValues: values, reviseError: `${whyRefused(r.body)}.` }), true;
    const rev = r.body.revision || {};
    return back(true, r.body.replayed ? "This revision was already added — nothing new was written." : `Added revision ${rev.ordinal} (${rev.version}) as a draft.`, id, rev.ordinal), true;
  }
  if (action === "release") {
    const r = await writeJson(daemonFetch, `/v1/hypervisor/functions/${id}/revisions/${ordinal}/release`, { owner_ref: owner, idempotency_key: key });
    if (!accepted(r)) return back(false, `Not released: ${whyRefused(r.body)}.`, id, ordinal), true;
    const rev = r.body.revision || {};
    return back(true, r.body.replayed ? `${rev.version} was already released.` : `Released ${rev.version} — its tool revision is ${rev.runtime_tool_contract?.revision_ref || "admitted"}.`, id, ordinal), true;
  }
  if (action === "deprecate") {
    const reason = (f.get("reason") || "").trim();
    if (!reason) return back(false, "Not deprecated: say why it is deprecated.", id, ordinal), true;
    const r = await writeJson(daemonFetch, `/v1/hypervisor/functions/${id}/revisions/${ordinal}/deprecate`, { owner_ref: owner, idempotency_key: key, reason });
    if (!accepted(r)) return back(false, `Not deprecated: ${whyRefused(r.body)}.`, id, ordinal), true;
    return back(true, `Deprecated ${r.body.revision?.version || ""} — its tool revision is revoked.`, id, ordinal), true;
  }
  if (action === "test") {
    const data = await loadFunctionsData(deps, id);
    const revision = (data.detail?.revisions || []).find((r) => r.ordinal === ordinal);
    const refuse = (error) => send(res, 200, renderOntologyFunctions(data, { query: new URLSearchParams({ function: id, revision: String(ordinal) }), testValues: values, testError: error }));
    if (!revision) return refuse("that revision is not visible to you."), true;
    const environmentRef = f.get("environment_ref") || "";
    if (!environmentRef) return refuse("choose the environment the revision runs in."), true;
    const inputs = {};
    for (const input of revision.inputs || []) {
      const typed = typedValue(input.data_type, f.get(`in_${input.name}`));
      if (typed.error) return refuse(`${input.name}: ${typed.error}.`), true;
      if (!typed.skip) inputs[input.name] = typed.value;
    }
    const r = await writeJson(daemonFetch, `/v1/hypervisor/functions/${id}/test-runs`, { owner_ref: owner, idempotency_key: key, ordinal, environment_ref: environmentRef, inputs });
    if (!accepted(r)) return refuse(`${whyRefused(r.body)}.`), true;
    const run = r.body.test_run || {};
    const output = run.output == null ? "" : ` Output: ${JSON.stringify(run.output).slice(0, 200)}.`;
    return back(true, `${OUTCOME_WORD[run.outcome] || run.outcome}: ${run.redacted_summary || ""}.${output}`, id, ordinal), true;
  }
  return false;
}
