// R-240 Arm A — every chip on the Approvals cross-plane band links where its plane lives.
//
// The band keyed its links by plane names the daemon never publishes (`improvement_change`,
// `memory_promotion`), so the improvement and memory chips rendered as unlinked text: a dead control
// that read as "no surface yet". The plane names are the daemon's (governance_routes.rs
// handle_approvals_inbox); this test reads them from that source, so a plane added, renamed or dropped
// on either side fails here, and renders the band over every one of them.
//
//   node --test apps/hypervisor/surfaces/approvals-planes.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { APPROVAL_PLANE_SURFACES, crossPlaneBand } from "./approvals/index.mjs";
import { escHtml } from "./kit.mjs";
import { SURFACES } from "../scripts/surface-registry.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");
const GOVERNANCE_RS = path.join(ROOT, "crates", "node", "src", "bin", "hypervisor_daemon_routes", "governance_routes.rs");
const SERVE = path.join(ROOT, "apps", "hypervisor", "scripts", "serve-product-ui.mjs");

/** The planes the daemon's approvals-inbox projection publishes, read from its source: `"plane": "<name>"`. */
function daemonPlanes() {
  const src = fs.readFileSync(GOVERNANCE_RS, "utf8");
  const start = src.indexOf("pub(crate) async fn handle_approvals_inbox");
  assert.ok(start >= 0, "governance_routes.rs no longer defines handle_approvals_inbox — this test reads the plane names from it");
  const end = src.indexOf("\npub(crate) ", start + 10);
  const body = src.slice(start, end < 0 ? undefined : end);
  return [...body.matchAll(/"plane":\s*"([a-z_]+)"/gu)].map((m) => m[1]);
}

/** A route this estate serves: a registered surface's route, a v2 canonical route, or a path the serve answers itself. */
function served(href) {
  const route = href.split("#")[0];
  if (SURFACES.some((s) => s.route === route || s.canonical_route === route)) return true;
  const serve = fs.readFileSync(SERVE, "utf8");
  return serve.includes(`pathname === "${route}"`) || serve.includes(`GET ${route} `);
}

test("the band's plane map is keyed by exactly the planes the daemon publishes", () => {
  const planes = daemonPlanes();
  assert.ok(planes.length >= 7, `the daemon's inbox names ${planes.length} planes`);
  assert.deepEqual([...Object.keys(APPROVAL_PLANE_SURFACES)].sort(), [...planes].sort(),
    "every plane the daemon publishes has one entry, spelled as the daemon spells it, and no entry names a plane the daemon does not publish");
  assert.ok(planes.includes("improvement_proposal"), "the improvement plane is `improvement_proposal` on the daemon");
});

test("each plane either links to a page the estate serves or names why there is nothing to open", () => {
  for (const [plane, surface] of Object.entries(APPROVAL_PLANE_SURFACES)) {
    if (surface.href) {
      assert.ok(served(surface.href), `${plane} links to ${surface.href}, which no registered surface or serve route answers`);
    } else {
      assert.ok(typeof surface.reason === "string" && surface.reason.length > 20, `${plane} has no page and must say why`);
    }
  }
  assert.equal(APPROVAL_PLANE_SURFACES.improvement_proposal.href, "/__ioi/improvement/changes", "improvements open the improvement inbox (Upgrade Assistant)");
});

test("rendered over every daemon plane, each chip is a link to its plane's page (or states why not)", () => {
  const planes = daemonPlanes();
  const inbox = { pending_total: planes.length, planes: planes.map((plane, i) => ({ plane, pending: i + 1 })) };
  const band = crossPlaneBand(inbox, null, escHtml);
  for (const [i, plane] of planes.entries()) {
    const label = `${plane.replace(/_/g, " ")} <b>${i + 1}</b>`;
    const surface = APPROVAL_PLANE_SURFACES[plane];
    if (surface.href) {
      assert.ok(band.includes(`<a class="ap-xchip" href="${escHtml(surface.href)}">${label} →</a>`), `${plane}'s chip links to ${surface.href}`);
    } else {
      assert.ok(band.includes(`<span class="ap-xchip ap-xnolink" title="${escHtml(surface.reason)}">${label}</span>`), `${plane}'s chip names why it has nothing to open`);
    }
  }
  assert.ok(band.includes('<a class="ap-xchip" href="/__ioi/improvement/changes">improvement proposal <b>'), "the improvement chip is a link");
});

test("a plane this build does not know is named, never a silent unlinked chip", () => {
  const band = crossPlaneBand({ pending_total: 1, planes: [{ plane: "some_new_plane", pending: 1 }] }, null, escHtml);
  assert.match(band, /<span class="ap-xchip ap-xnolink" title="the daemon publishes the plane &quot;some_new_plane&quot; and this surface binds no page for it yet">some new plane <b>1<\/b><\/span>/u);
});
