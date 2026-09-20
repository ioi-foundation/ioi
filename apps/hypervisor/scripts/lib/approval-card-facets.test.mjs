// The approval card's facet grammar, on a synthetic challenge built the way the daemon builds it
// (M03.9, R-212): key-sorted compact JSON with the float printed as the hash saw it. The tracked
// daemon-minted fixture and a fresh challenge from an isolated daemon are the runner's subjects;
// this file proves the grammar and its diff harness on bytes it controls.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { projectProviderChallenge, renderProviderFacetsCard, verifyRenderedFacets, scanPreimage, projectProviderApprovalForTimeline, PROVIDER_APPROVAL_KIND } from "./approval-card-facets.mjs";

const sha = (t) => `sha256:${crypto.createHash("sha256").update(t, "utf8").digest("hex")}`;
const SDL_HASH = `sha256:${"a".repeat(64)}`;
const FACETS = `{"account_ref":"provider-account://pacc_t","auto_topup":false,"ceiling_amount":"1000","ceiling_denom":"uact","deposit_usd":1.0,"environment_ref":"env-t","execution_mode":"live","external_spend_posture":"external_spend","kind":"akash","op":"create","provider_selector":{"mode":"any_marketplace","selection":"lowest_qualified_bid"},"sdl_hash":"${SDL_HASH}","stage":"deployment_intent","teardown_policy":"always_teardown_required"}`;
const REQUEST_PREIMAGE = `{"allowed_tools":["provider.create"],"domain":"hypervisor.provider.op.request.v1","facets":${FACETS},"resource_refs":["provider-account://pacc_t","env-t"],"scopes":["provider.provision"]}`;
const POLICY_PREIMAGE = `{"allowed_tools":["provider.create"],"authority_provider_ref":"wallet.network","backing_provider":"provider:account:pacc_t","domain":"hypervisor.provider.op.policy.v1","resource_refs":["provider-account://pacc_t","env-t"],"scopes":["provider.provision"]}`;
const AUDIENCE = "ab".repeat(32);
function challenge() {
  return {
    ok: false, decision: "blocked", reason: "provider_operation_authority_required",
    required_scopes: ["provider.provision"], required_authority_scope: "scope:hypervisor.live-route.hypervisor-provider-op",
    allowed_tools: ["provider.create"], resource_refs: ["provider-account://pacc_t", "env-t"],
    approval: { policy_hash: sha(POLICY_PREIMAGE), request_hash: sha(REQUEST_PREIMAGE), audience: AUDIENCE, target_scope: "scope:hypervisor.live-route.hypervisor-provider-op", policy_preimage: POLICY_PREIMAGE, request_preimage: REQUEST_PREIMAGE },
    lease_request_facets: { auto_topup: false, ceiling_amount: "1000", ceiling_denom: "uact", deposit_usd: 1, execution_mode: "live", provider_selector: { mode: "any_marketplace", selection: "lowest_qualified_bid" }, sdl_hash: SDL_HASH, sdl_yaml: "version: \"2.0\"\n", stage: "deployment_intent", teardown_policy: "always_teardown_required" },
    receipt_ref: "agentgres://provider-receipt/prc_t", account_ref: "provider-account://pacc_t", host_mutation: false,
  };
}
const render = (c) => renderProviderFacetsCard(projectProviderChallenge(c), { approveUrl: "/__ioi/runs/r1/approve", denyUrl: "/__ioi/runs/r1/deny", returnTo: "/work/sessions" });

test("the scanner returns each hashed member's RAW bytes: the float stays 1.0 and the nested selector keeps its bytes", () => {
  const scanned = scanPreimage(REQUEST_PREIMAGE);
  assert.deepEqual(scanned.top_keys, ["allowed_tools", "domain", "facets", "resource_refs", "scopes"]);
  assert.equal(scanned.facets.find((f) => f.key === "deposit_usd").raw, "1.0");
  assert.equal(scanned.facets.find((f) => f.key === "provider_selector").raw, `{"mode":"any_marketplace","selection":"lowest_qualified_bid"}`);
  assert.equal(scanned.facets.find((f) => f.key === "auto_topup").raw, "false");
  assert.equal(scanned.facets.length, 14);
  assert.throws(() => scanPreimage(`${REQUEST_PREIMAGE}x`), /trailing/u);
});

test("a daemon challenge projects byte-derived: the preimage hashes to the request hash, the echoed facets re-state nothing, every deployment_intent member is present", () => {
  const p = projectProviderChallenge(challenge());
  assert.deepEqual(p.findings, []);
  assert.equal(p.ok, true);
  assert.equal(p.kind, PROVIDER_APPROVAL_KIND);
  assert.equal(p.request_hash, sha(REQUEST_PREIMAGE));
  assert.equal(p.preimage_sha256, sha(REQUEST_PREIMAGE));
  assert.equal(p.audience, AUDIENCE);
  assert.ok(p.facets.some((f) => f.key === "external_spend_posture"), "the hashed posture the echoed facets never carried is rendered from the preimage");
  assert.ok(!p.facets.some((f) => f.key === "sdl_yaml"), "the raw SDL is not a hashed member and is not rendered");
});

test("the rendered card carries every hashed member verbatim, the full commitments, the full audience and the approve form — and the diff harness is clean on it", () => {
  const c = challenge();
  const html = render(c);
  assert.deepEqual(verifyRenderedFacets(html, c), []);
  assert.ok(html.includes(`data-ioi-facet="deposit_usd"><code style="font-size:11px;white-space:pre-wrap;word-break:break-all">1.0</code>`));
  assert.ok(html.includes(AUDIENCE));
  assert.ok(html.includes("Approve exactly this"));
  assert.ok(html.includes(`data-ioi-provider-approval="${sha(REQUEST_PREIMAGE)}"`));
});

test("a challenge WITHOUT a preimage (pre-R-212) cannot be signed here: typed refusal, a refusal card, no approve form", () => {
  const c = challenge();
  delete c.approval.request_preimage;
  const p = projectProviderChallenge(c);
  assert.deepEqual(p.findings, ["request_preimage_missing"]);
  const html = render(c);
  assert.ok(html.includes(`data-ioi-provider-approval-refused="request_preimage_missing"`));
  assert.ok(!html.includes("Approve exactly this"));
  assert.deepEqual(verifyRenderedFacets(html, c), ["challenge:request_preimage_missing"]);
});

test("a preimage that does not hash to the request hash, a re-stated echoed facet, a missing deployment_intent member, a wrong domain and a malformed audience are each refused by code", () => {
  let c = challenge(); c.approval.request_preimage = REQUEST_PREIMAGE.replace("\"deposit_usd\":1.0", "\"deposit_usd\":2.0");
  assert.ok(projectProviderChallenge(c).findings.includes("request_preimage_mismatch"));
  c = challenge(); c.lease_request_facets.deposit_usd = 2;
  assert.ok(projectProviderChallenge(c).findings.includes("facets_restated:deposit_usd"));
  c = challenge(); const pre = REQUEST_PREIMAGE.replace(`"sdl_hash":"${SDL_HASH}",`, ""); c.approval.request_preimage = pre; c.approval.request_hash = sha(pre);
  assert.ok(projectProviderChallenge(c).findings.includes("facet_missing:sdl_hash"));
  c = challenge(); const dom = REQUEST_PREIMAGE.replace("hypervisor.provider.op.request.v1", "hypervisor.session.execute.request.v1"); c.approval.request_preimage = dom; c.approval.request_hash = sha(dom);
  assert.ok(projectProviderChallenge(c).findings.some((f) => f.startsWith("request_domain_not_provider_op")));
  c = challenge(); c.approval.audience = "abc";
  assert.ok(projectProviderChallenge(c).findings.includes("audience_malformed"));
  c = challenge(); delete c.approval.policy_preimage;
  assert.ok(projectProviderChallenge(c).findings.includes("policy_preimage_missing"));
});

test("the diff harness names a paraphrased amount, a truncated hash, a truncated audience, a dropped member, a smuggled member and a duplicated member", () => {
  const c = challenge();
  const html = render(c);
  const paraphrased = html.replace(`data-ioi-facet="deposit_usd"><code style="font-size:11px;white-space:pre-wrap;word-break:break-all">1.0</code>`, `data-ioi-facet="deposit_usd"><code style="font-size:11px;white-space:pre-wrap;word-break:break-all">about $1</code>`);
  assert.deepEqual(verifyRenderedFacets(paraphrased, c), ["facet_not_verbatim:deposit_usd"]);
  const truncated = html.replace(`<code data-ioi-request-hash style="font-size:10.5px">${sha(REQUEST_PREIMAGE)}</code>`, `<code data-ioi-request-hash style="font-size:10.5px">${sha(REQUEST_PREIMAGE).slice(0, 24)}…</code>`);
  assert.deepEqual(verifyRenderedFacets(truncated, c), ["request_hash_not_verbatim"]);
  const shortAudience = html.replace(`<code data-ioi-audience style="font-size:10.5px">${AUDIENCE}</code>`, `<code data-ioi-audience style="font-size:10.5px">${AUDIENCE.slice(0, 24)}…</code>`);
  assert.deepEqual(verifyRenderedFacets(shortAudience, c), ["audience_not_verbatim"]);
  const dropped = html.replace(/<dt>teardown_policy<\/dt><dd data-ioi-facet="teardown_policy">[\s\S]*?<\/dd>/u, "");
  assert.deepEqual(verifyRenderedFacets(dropped, c), ["facet_missing_in_card:teardown_policy"]);
  const smuggled = html.replace("<dl data-ioi-facets", `<dl data-ioi-facets><dt>auto_topup_note</dt><dd data-ioi-facet="auto_topup_note"><code>never</code></dd></dl><dl`);
  assert.deepEqual(verifyRenderedFacets(smuggled, c), ["facet_smuggled:auto_topup_note"]);
  const duplicated = html.replace(`<dt>stage</dt>`, `<dt>stage</dt><dd data-ioi-facet="stage"><code>"deployment_intent"</code></dd><dt>stage</dt>`);
  assert.deepEqual(verifyRenderedFacets(duplicated, c), ["facet_duplicated:stage"]);
});

test("the SPA projection carries the same bytes: every facet raw, the full hashes and the full audience", () => {
  const t = projectProviderApprovalForTimeline({ kind: PROVIDER_APPROVAL_KIND, challenge: challenge() });
  assert.equal(t.byteDerived, true);
  assert.equal(t.audience, AUDIENCE);
  assert.equal(t.requestHash, sha(REQUEST_PREIMAGE));
  assert.equal(t.facets.find((f) => f.key === "deposit_usd").raw, "1.0");
  assert.equal(t.facets.length, 14);
  const stale = projectProviderApprovalForTimeline({ kind: PROVIDER_APPROVAL_KIND, challenge: { approval: {} } });
  assert.equal(stale.byteDerived, false);
  assert.deepEqual(stale.findings, ["request_preimage_missing"]);
});
