// A small GraphQL RESOLVER for adopted reference apps (R-241). An adopted app sends its own query
// documents; this answers each one by walking the query's own AST — fields, aliases, selection sets,
// named fragments and inline fragments with type conditions — against a FACT object built from daemon
// truth. The query decides the shape; the facts decide every value.
//
// Where a selected field has no fact, the RECORDED reference answer for the same operation (local
// mirror only) may supply STRUCTURE — a typename, a boolean, an ALL_CAPS enum constant, a nested
// object — never a name, a time, an id or a list item: those would be the recorded tenant's facts shown
// as ours. Lists without a fact are empty; other scalars are null.
//
// Supported subset (what the adopted apps send): queries, fields, aliases, arguments (ignored — the
// facts are already scoped), directives (ignored), fragment spreads, inline fragments. No schema is
// known, so a fragment applies when its type condition equals the value's `__typename`, is one of the
// value's declared `__implements`, or the value declares no typename.

// The few interface facts the reference's own documents state, so a fragment on the interface applies to
// every value of the type without each builder declaring it. Evidence: the resource header selects
// `ancestors { ...FolderPathAncestor }` with `fragment FolderPathAncestor on ResourceAncestor { … on
// ResourceMetadata { openUrl … } }` — a ResourceMetadata IS a ResourceAncestor, and without this the
// breadcrumb never received a folder's openUrl (a project breadcrumb that went nowhere, found by
// check:adopted-dead-controls).
// Likewise a principal chip selects `fragment PrincipalWithTooltipFragment on Principal { … on User {…} … on Group
// {…} }` — a User and a Group ARE Principals (without this the chip read "Unknown user or group").
const KNOWN_IMPLEMENTS = Object.freeze({ ResourceMetadata: ["ResourceAncestor"], User: ["Principal"], Group: ["Principal"] });

function tokenize(src) {
  const out = [];
  const re = /\s+|,|#[^\n]*|(\.\.\.)|([{}()\[\]:!$@=|&])|("(?:[^"\\]|\\.)*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([A-Za-z_][A-Za-z0-9_]*)/gy;
  let m;
  while (re.lastIndex < src.length) {
    const at = re.lastIndex;
    m = re.exec(src);
    if (!m) throw new Error(`graphql: cannot read at ${at}: ${src.slice(at, at + 20)}`);
    const t = m[1] || m[2] || m[3] || m[4] || m[5];
    if (t) out.push(t);
  }
  return out;
}

export function parseDocument(src) {
  const toks = tokenize(String(src));
  let i = 0;
  const peek = () => toks[i];
  const next = () => toks[i++];
  const expect = (t) => { const x = next(); if (x !== t) throw new Error(`graphql: expected ${t}, got ${x}`); };
  const skipValue = () => {
    const t = next();
    if (t === "[") { while (peek() !== "]") skipValue(); next(); }
    else if (t === "{") { while (peek() !== "}") { next(); expect(":"); skipValue(); } next(); }
    else if (t === "$") next();
  };
  const skipArgs = () => { if (peek() !== "(") return; next(); while (peek() !== ")") { next(); expect(":"); skipValue(); } next(); };
  const skipDirectives = () => { while (peek() === "@") { next(); next(); skipArgs(); } };
  const selectionSet = () => {
    expect("{");
    const sels = [];
    while (peek() !== "}") {
      if (peek() === "...") {
        next();
        if (peek() === "on") { next(); const type = next(); skipDirectives(); sels.push({ kind: "inline", type, selections: selectionSet() }); }
        else if (peek() === "{" || peek() === "@") { skipDirectives(); sels.push({ kind: "inline", type: null, selections: selectionSet() }); }
        else { const name = next(); skipDirectives(); sels.push({ kind: "spread", name }); }
      } else {
        let name = next();
        let alias = name;
        if (peek() === ":") { next(); name = next(); }
        skipArgs();
        skipDirectives();
        sels.push({ kind: "field", name, alias, selections: peek() === "{" ? selectionSet() : null });
      }
    }
    next();
    return sels;
  };
  const doc = { operations: [], fragments: {} };
  while (i < toks.length) {
    const t = next();
    if (t === "fragment") {
      const name = next(); expect("on"); const type = next(); skipDirectives();
      doc.fragments[name] = { type, selections: selectionSet() };
    } else if (t === "query" || t === "mutation" || t === "subscription") {
      const name = peek() !== "(" && peek() !== "{" && peek() !== "@" ? next() : "";
      if (peek() === "(") { next(); let depth = 1; while (depth) { const x = next(); if (x === "(") depth++; else if (x === ")") depth--; } }
      skipDirectives();
      doc.operations.push({ kind: t, name, selections: selectionSet() });
    } else if (t === "{") { i--; doc.operations.push({ kind: "query", name: "", selections: selectionSet() }); }
  }
  return doc;
}

const STRUCTURAL = (v) => typeof v === "boolean" || (typeof v === "string" && /^[A-Z][A-Z0-9_]*$/.test(v));

function applies(type, value) {
  if (!type) return true;
  if (!value || typeof value !== "object") return false;
  if (!value.__typename) return true;
  return type === value.__typename || (Array.isArray(value.__implements) && value.__implements.includes(type)) || (KNOWN_IMPLEMENTS[value.__typename] || []).includes(type);
}

// GraphQL merges every selection of one response key into one value: a field selected by a fragment and
// again directly answers with the UNION of both sub-selections (element-wise for lists of the same facts).
function merge(prior, next) {
  if (Array.isArray(prior) && Array.isArray(next) && prior.length === next.length) return prior.map((p, i) => merge(p, next[i]));
  if (prior && next && typeof prior === "object" && typeof next === "object" && !Array.isArray(prior) && !Array.isArray(next)) {
    const out = { ...prior };
    for (const [k, v] of Object.entries(next)) out[k] = Object.prototype.hasOwnProperty.call(out, k) ? merge(out[k], v) : v;
    return out;
  }
  return next ?? prior;
}

// Resolve `selections` against `value` (facts) with `template` (the recorded answer at the same path).
function resolve(selections, value, template, doc, out = {}) {
  for (const sel of selections) {
    if (sel.kind === "spread") {
      const frag = doc.fragments[sel.name];
      if (frag && applies(frag.type, value ?? template)) resolve(frag.selections, value, template, doc, out);
    } else if (sel.kind === "inline") {
      if (applies(sel.type, value ?? template)) resolve(sel.selections, value, template, doc, out);
    } else {
      const has = value && typeof value === "object" && Object.prototype.hasOwnProperty.call(value, sel.name);
      const fact = has ? value[sel.name] : undefined;
      const tmpl = template && typeof template === "object" ? template[sel.alias] ?? template[sel.name] : undefined;
      if (sel.name === "__typename") { out[sel.alias] = (value && value.__typename) || (template && template.__typename) || null; continue; }
      if (!sel.selections) {
        out[sel.alias] = has ? (fact ?? null) : (Array.isArray(tmpl) ? [] : STRUCTURAL(tmpl) ? tmpl : null);
        continue;
      }
      let answer;
      if (has) {
        if (fact === null || fact === undefined) answer = null;
        else if (Array.isArray(fact)) answer = fact.map((item) => resolve(sel.selections, item, Array.isArray(tmpl) ? tmpl[0] : undefined, doc, {}));
        else answer = resolve(sel.selections, fact, tmpl, doc, {});
      } else if (Array.isArray(tmpl)) answer = [];
      else if (tmpl && typeof tmpl === "object") answer = resolve(sel.selections, undefined, tmpl, doc, {});
      else answer = null;
      out[sel.alias] = Object.prototype.hasOwnProperty.call(out, sel.alias) ? merge(out[sel.alias], answer) : answer;
    }
  }
  return out;
}

// Answer one operation document against a root fact object; `template` is the recorded `data` (or null).
export function answerDocument(query, root, template = null, operationName = null) {
  const doc = parseDocument(query);
  const op = (operationName && doc.operations.find((o) => o.name === operationName)) || doc.operations[0];
  if (!op) return null;
  return resolve(op.selections, root, template, doc, {});
}
