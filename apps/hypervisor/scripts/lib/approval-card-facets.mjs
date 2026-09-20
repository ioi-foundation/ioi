// The approval card's facet grammar (M03.9, register R-212, 2026-09-20): the signing surface
// renders the daemon challenge's signed facts BYTE-DERIVED and never re-states them.
//
// The daemon publishes, on every capability-lease challenge, `approval.request_preimage` and
// `approval.policy_preimage` — the exact JSON strings its two commitment hashes are the SHA-256 of.
// This module PARSES that preimage (never `lease_request_facets`, which is a superset a route
// echoes and which omits the account, op, environment, kind and spend posture the hash covers),
// refuses a challenge whose preimage does not hash to its request hash or which carries no
// preimage at all (a pre-R-212 challenge is not signable byte-derived), refuses a challenge whose
// echoed facets re-state a hashed member differently, and renders EVERY hashed facet member as the
// exact bytes it has in the preimage — sliced from the string, never re-serialized, so `1.0` stays
// `1.0` — together with the full policy hash, request hash and grant audience.
//
// `verifyRenderedFacets(html, challenge)` is the "wallet-app diff harness": every preimage member
// present in the card exactly once and byte-equal, nothing re-stated, nothing truncated, no member
// the preimage does not carry. A paraphrased, truncated or locally reconstructed facet set is a
// defect it names by code.
import crypto from "node:crypto";

export const PROVIDER_APPROVAL_KIND = "provider_operation";
export const PROVIDER_REQUEST_DOMAIN = "hypervisor.provider.op.request.v1";
export const PROVIDER_POLICY_DOMAIN = "hypervisor.provider.op.policy.v1";
export const DEPLOYMENT_INTENT_MEMBERS = ["stage", "ceiling_amount", "ceiling_denom", "deposit_usd", "provider_selector", "sdl_hash", "teardown_policy"];
const HASH = /^sha256:[0-9a-f]{64}$/u;
const sha256 = (text) => `sha256:${crypto.createHash("sha256").update(text, "utf8").digest("hex")}`;
export const escHtml = (value) => String(value).replace(/&/gu, "&amp;").replace(/</gu, "&lt;").replace(/>/gu, "&gt;").replace(/"/gu, "&quot;");
export const unescHtml = (value) => String(value).replace(/&quot;/gu, "\"").replace(/&gt;/gu, ">").replace(/&lt;/gu, "<").replace(/&amp;/gu, "&");
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));

// ---- a position-preserving scanner over the preimage string --------------------------------------------
// Returns, for the top-level object and for its `facets` object, each member's key and the RAW text of
// its value as it appears in the string. Throws on anything that is not one JSON value spanning the
// whole string. Deliberately small: it walks strings, numbers, literals, arrays and objects.
export function scanPreimage(preimage) {
  const s = String(preimage);
  let i = 0;
  const fail = (why) => { throw new Error(`${why} at ${i}`); };
  const ws = () => { while (i < s.length && /[ \t\n\r]/u.test(s[i])) i += 1; };
  const string = () => {
    if (s[i] !== "\"") fail("string expected");
    i += 1;
    while (i < s.length) {
      if (s[i] === "\\") { i += 2; continue; }
      if (s[i] === "\"") { i += 1; return; }
      i += 1;
    }
    fail("unterminated string");
  };
  const value = () => {
    ws();
    const c = s[i];
    if (c === "{") return object();
    if (c === "[") { i += 1; ws(); if (s[i] === "]") { i += 1; return null; } for (;;) { value(); ws(); if (s[i] === ",") { i += 1; continue; } if (s[i] === "]") { i += 1; return null; } fail("array"); } }
    if (c === "\"") { string(); return null; }
    if (/[-0-9]/u.test(c)) { const m = s.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?/u); if (!m) fail("number"); i += m[0].length; return null; }
    for (const lit of ["true", "false", "null"]) if (s.startsWith(lit, i)) { i += lit.length; return null; }
    fail("value");
    return null;
  };
  const object = () => {
    if (s[i] !== "{") fail("object expected");
    i += 1;
    const members = [];
    ws();
    if (s[i] === "}") { i += 1; return members; }
    for (;;) {
      ws();
      const keyStart = i;
      string();
      const key = JSON.parse(s.slice(keyStart, i));
      ws();
      if (s[i] !== ":") fail("colon");
      i += 1;
      ws();
      const start = i;
      const nested = value();
      members.push({ key, raw: s.slice(start, i), members: Array.isArray(nested) ? nested : null });
      ws();
      if (s[i] === ",") { i += 1; continue; }
      if (s[i] === "}") { i += 1; return members; }
      fail("object member");
    }
  };
  const top = object();
  ws();
  if (i !== s.length) fail("trailing bytes");
  const member = (name) => top.find((m) => m.key === name) ?? null;
  const facets = member("facets");
  return {
    domain: member("domain")?.raw ?? null,
    allowed_tools: member("allowed_tools")?.raw ?? null,
    resource_refs: member("resource_refs")?.raw ?? null,
    scopes: member("scopes")?.raw ?? null,
    facets: (facets?.members ?? []).map((m) => ({ key: m.key, raw: m.raw })),
    top_keys: top.map((m) => m.key),
  };
}

// ---- the projection: from the challenge bytes to what the card shows ----------------------------------------
export function projectProviderChallenge(challenge) {
  const findings = [];
  const approval = challenge?.approval && typeof challenge.approval === "object" ? challenge.approval : {};
  const preimage = approval.request_preimage;
  const base = { kind: PROVIDER_APPROVAL_KIND, ok: false, findings, policy_hash: approval.policy_hash ?? null, request_hash: approval.request_hash ?? null, audience: approval.audience ?? null, target_scope: approval.target_scope ?? null, required_scopes: Array.isArray(challenge?.required_scopes) ? challenge.required_scopes : [], allowed_tools: Array.isArray(challenge?.allowed_tools) ? challenge.allowed_tools : [], resource_refs: Array.isArray(challenge?.resource_refs) ? challenge.resource_refs : [], reason: challenge?.reason ?? null, receipt_ref: challenge?.receipt_ref ?? null, account_ref: challenge?.account_ref ?? null, facets: [], domain: null, preimage_sha256: null, preimage_bytes: 0 };
  if (typeof preimage !== "string" || preimage.length === 0) { findings.push("request_preimage_missing"); return base; }
  if (!HASH.test(String(approval.request_hash ?? ""))) findings.push("request_hash_malformed");
  else if (sha256(preimage) !== approval.request_hash) findings.push("request_preimage_mismatch");
  const policyPreimage = approval.policy_preimage;
  if (typeof policyPreimage !== "string" || policyPreimage.length === 0) findings.push("policy_preimage_missing");
  else if (!HASH.test(String(approval.policy_hash ?? "")) || sha256(policyPreimage) !== approval.policy_hash) findings.push("policy_preimage_mismatch");
  let scanned = null;
  let parsed = null;
  try { scanned = scanPreimage(preimage); parsed = JSON.parse(preimage); } catch (error) { findings.push(`request_preimage_malformed:${String(error.message).slice(0, 40)}`); return base; }
  if (parsed?.domain !== PROVIDER_REQUEST_DOMAIN) findings.push(`request_domain_not_provider_op:${String(parsed?.domain ?? "")}`);
  if (!parsed?.facets || typeof parsed.facets !== "object" || Array.isArray(parsed.facets)) findings.push("request_facets_missing");
  const facets = parsed?.facets && typeof parsed.facets === "object" ? parsed.facets : {};
  const echoed = challenge?.lease_request_facets && typeof challenge.lease_request_facets === "object" ? challenge.lease_request_facets : {};
  for (const key of Object.keys(facets)) if (Object.hasOwn(echoed, key) && stable(echoed[key]) !== stable(facets[key])) findings.push(`facets_restated:${key}`);
  if (facets.stage === "deployment_intent") for (const key of DEPLOYMENT_INTENT_MEMBERS) if (!Object.hasOwn(facets, key)) findings.push(`facet_missing:${key}`);
  if (parsed?.allowed_tools !== undefined && stable(parsed.allowed_tools) !== stable(base.allowed_tools)) findings.push("allowed_tools_restated");
  if (parsed?.resource_refs !== undefined && stable(parsed.resource_refs) !== stable(base.resource_refs)) findings.push("resource_refs_restated");
  if (parsed?.scopes !== undefined && stable(parsed.scopes) !== stable(base.required_scopes)) findings.push("scopes_restated");
  if (approval.audience != null && !/^[0-9a-f]{64}$/u.test(String(approval.audience))) findings.push("audience_malformed");
  return { ...base, ok: findings.length === 0, facets: scanned.facets, domain: parsed?.domain ?? null, preimage_sha256: sha256(preimage), preimage_bytes: Buffer.byteLength(preimage, "utf8") };
}

// ---- the card ---------------------------------------------------------------------------------------------
// Every rendered facet value is the preimage's raw bytes for that member (HTML-escaped for the page,
// unescaped byte-for-byte by the oracle). A projection with findings renders a REFUSAL with no
// approve form: a challenge that cannot be shown as the bytes that will execute cannot be signed here.
export function renderProviderFacetsCard(projection, { approveUrl = null, denyUrl = null, returnTo = "" } = {}) {
  const enc = escHtml;
  if (!projection?.ok) {
    const codes = (projection?.findings ?? ["projection_missing"]).join(",");
    return `<div class="card" data-ioi-provider-approval-refused="${enc(codes)}"><div class="main"><div class="name">This operation cannot be signed here<span class="pill warn">not byte-derived</span></div><div class="meta">The challenge could not be shown as the exact bytes that would execute: <code>${enc(codes)}</code>. Nothing to approve.</div></div></div>`;
  }
  const rows = projection.facets.map((f) => `<dt>${enc(f.key)}</dt><dd data-ioi-facet="${enc(f.key)}"><code style="font-size:11px;white-space:pre-wrap;word-break:break-all">${enc(f.raw)}</code></dd>`).join("");
  const forms = approveUrl ? `<div style="margin-top:10px;display:flex;gap:8px"><form method="post" action="${enc(approveUrl)}"><input type="hidden" name="return_to" value="${enc(returnTo)}"><button class="act" type="submit">Approve exactly this</button></form>${denyUrl ? `<form method="post" action="${enc(denyUrl)}"><input type="hidden" name="return_to" value="${enc(returnTo)}"><button class="act ghost" type="submit">Deny</button></form>` : ""}</div>` : "";
  return `<div class="card" data-ioi-provider-approval="${enc(projection.request_hash)}"><div class="main">
      <div class="name">Approve this provider operation?<span class="pill warn">awaiting your approval</span></div>
      <div class="meta"><b>What will execute</b> — every signed fact, as the daemon hashed it (${projection.preimage_bytes} bytes, <code data-ioi-request-preimage-sha256>${enc(projection.preimage_sha256)}</code>):</div>
      <dl data-ioi-facets style="display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:6px 0">${rows}</dl>
      <div class="meta"><b>Authority it needs</b>: ${projection.required_scopes.map((s) => `<code style="font-size:11px">${enc(s)}</code>`).join(" ") || "—"} · tools ${projection.allowed_tools.map((s) => `<code style="font-size:11px">${enc(s)}</code>`).join(" ") || "—"} · resources ${projection.resource_refs.map((s) => `<code style="font-size:11px">${enc(s)}</code>`).join(" ") || "—"}</div>
      <div class="meta"><b>Exact commitments</b>: policy <code data-ioi-policy-hash style="font-size:10.5px">${enc(projection.policy_hash)}</code> · request <code data-ioi-request-hash style="font-size:10.5px">${enc(projection.request_hash)}</code></div>
      <div class="meta"><b>Grant audience</b>: <code data-ioi-audience style="font-size:10.5px">${enc(projection.audience ?? "not configured — no wallet client; the grant cannot be consumed")}</code>${projection.target_scope ? ` · scope <code style="font-size:10.5px">${enc(projection.target_scope)}</code>` : ""}</div>
      ${forms}</div></div>`;
}

// ---- the diff harness -------------------------------------------------------------------------------------
export function verifyRenderedFacets(html, challenge) {
  const projection = projectProviderChallenge(challenge);
  if (!projection.ok) return projection.findings.map((f) => `challenge:${f}`);
  const findings = [];
  const text = String(html ?? "");
  const rendered = new Map();
  for (const m of text.matchAll(/<dd data-ioi-facet="([^"]*)">(?:<code[^>]*>)?([\s\S]*?)(?:<\/code>)?<\/dd>/gu)) {
    const key = unescHtml(m[1]);
    const list = rendered.get(key) ?? [];
    list.push(unescHtml(m[2]));
    rendered.set(key, list);
  }
  for (const f of projection.facets) {
    const got = rendered.get(f.key);
    if (!got) { findings.push(`facet_missing_in_card:${f.key}`); continue; }
    if (got.length > 1) findings.push(`facet_duplicated:${f.key}`);
    if (got[0] !== f.raw) findings.push(`facet_not_verbatim:${f.key}`);
  }
  for (const key of rendered.keys()) if (!projection.facets.some((f) => f.key === key)) findings.push(`facet_smuggled:${key}`);
  const node = (attr) => { const m = text.match(new RegExp(`<code ${attr}[^>]*>([^<]*)</code>`, "u")); return m ? unescHtml(m[1]) : null; };
  if (node("data-ioi-policy-hash") !== projection.policy_hash) findings.push("policy_hash_not_verbatim");
  if (node("data-ioi-request-hash") !== projection.request_hash) findings.push("request_hash_not_verbatim");
  if (node("data-ioi-request-preimage-sha256") !== projection.preimage_sha256) findings.push("preimage_sha256_not_verbatim");
  const audience = node("data-ioi-audience");
  if (projection.audience != null ? audience !== projection.audience : !(typeof audience === "string" && /not configured/u.test(audience))) findings.push("audience_not_verbatim");
  if (!text.includes(`data-ioi-provider-approval="${escHtml(projection.request_hash)}"`)) findings.push("card_not_bound_to_request_hash");
  if (/data-ioi-provider-approval-refused=/u.test(text)) findings.push("card_refused_although_projection_ok");
  return findings;
}

// ---- the SPA projection (ioi-run-timeline) ------------------------------------------------------------------
// The pane shows the same bytes: every facet's raw text, the full hashes and the full audience.
export function projectProviderApprovalForTimeline(pendingApproval) {
  const projection = projectProviderChallenge(pendingApproval?.challenge);
  return {
    facets: projection.facets.map((f) => ({ key: f.key, raw: f.raw })),
    findings: projection.findings,
    byteDerived: projection.ok,
    preimageSha256: projection.preimage_sha256,
    policyHash: projection.policy_hash,
    requestHash: projection.request_hash,
    audience: projection.audience,
    targetScope: projection.target_scope,
    requiredScopes: projection.required_scopes,
  };
}
