#!/usr/bin/env node
// Done-bar for the native Git-authentications surface.
//
// This verifies the borrowed Settings -> Git authentications UI is backed by IOI-owned adapter
// routes, not the mirror. The token itself is never supplied here:
//   - unbound state: CheckAuthenticationForHost settles to Connect, and the native PAT modal opens;
//   - bound state: the row shows Disconnect, proving sealed daemon host credentials project back;
//   - ParseContextURL is owned so the PAT submit path can validate a GitHub repo URL after sealing.
//
// Requires serve (:4173) + daemon (:8765). Usage:
//   node scripts/verify-hypervisor-git-auth-native-functional.mjs [--json]
const JSON_OUT = process.argv.includes("--json");
const REF = (process.env.IOI_REFERENCE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const checks = [];
let failures = 0;
const ok = (cond, msg, detail) => {
  checks.push({ ok: !!cond, msg });
  if (!cond) failures++;
  if (!JSON_OUT) console.log(`    ${cond ? "OK" : "FAIL:"} ${msg}${detail ? ` (${detail})` : ""}`);
};
const blocked = (reason) => {
  console.log(JSON_OUT ? JSON.stringify({ workstream: "git-auth-native", verdict: "BLOCKED", reason }, null, 2) : `  BLOCKED: ${reason}`);
  process.exit(2);
};
const up = async (url) => {
  try { return (await fetch(url, { signal: AbortSignal.timeout(3000) })).ok; } catch { return false; }
};
const api = async (servicePath, body = {}) => {
  const res = await fetch(`${REF}/api/gitpod.v1.${servicePath}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
};

if (!JSON_OUT) console.log("Native Git authentication e2e - Settings row + PAT modal");
if (!(await up(`${REF}/__ioi/fallthrough`))) blocked("serve-live-reference (:4173) not running");
if (!(await up(`${DAEMON}/v1/hypervisor/providers`))) blocked("hypervisor-daemon (:8765) not running");

const auth = await api("RunnerService/CheckAuthenticationForHost", { runnerId: "local-microvm", host: "github.com" });
ok(auth.status === 200, "CheckAuthenticationForHost is served by the IOI adapter", `status ${auth.status}`);
ok(typeof auth.body?.authenticated === "boolean", "auth check returns an authenticated boolean");
ok(auth.body?.supportsPat && typeof auth.body.supportsPat === "object", "auth check exposes supportsPat as a PAT method object", typeof auth.body?.supportsPat);
ok(Array.isArray(auth.body?.supportsPat?.requiredScopes), "PAT method object carries requiredScopes");

const parsed = await api("RunnerService/ParseContextURL", {
  runnerId: "local-microvm",
  contextUrl: "https://github.com/teamioitest/example-repo",
});
ok(parsed.status === 200 && parsed.body?.git?.cloneUrl === "https://github.com/teamioitest/example-repo.git", "ParseContextURL parses GitHub repo URLs for the native submit path", parsed.body?.git?.cloneUrl);

let chromium;
try { ({ chromium } = await import("playwright")); } catch { blocked("playwright not installed"); }

await fetch(`${REF}/__ioi/fallthrough/reset`, { method: "POST" }).catch(() => null);
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource|WebSocket/i.test(m.text())) errors.push(m.text());
  });

  await page.goto(`${REF}/ai`, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.waitForTimeout(1500);
  await page.getByTestId("org-switcher").click();
  await page.getByLabel("Open user settings").click();
  await page.getByText("Git authentications", { exact: true }).click();

  const createButton = page.getByTestId("git-authentications-create-token-scmint-github");
  const deleteButton = page.getByTestId("git-authentications-delete-token-scmint-github");
  await Promise.race([
    createButton.waitFor({ state: "visible", timeout: 15000 }).catch(() => null),
    deleteButton.waitFor({ state: "visible", timeout: 15000 }).catch(() => null),
  ]);

  const hasDelete = await deleteButton.count();
  if (hasDelete > 0) {
    const row = await deleteButton.evaluate((b) => ({ text: b.innerText, disabled: b.disabled }));
    ok(row.text === "Disconnect" && row.disabled === false, "connected state projects a sealed host credential as Disconnect", JSON.stringify(row));
  } else {
    await createButton.waitFor({ state: "visible", timeout: 10000 });
    await page.waitForFunction(() => {
      const b = document.querySelector('[data-testid="git-authentications-create-token-scmint-github"]');
      return b && b.textContent.trim() === "Connect" && !b.disabled;
    }, null, { timeout: 15000 });
    const row = await createButton.evaluate((b) => ({ text: b.innerText, disabled: b.disabled }));
    ok(row.text === "Connect" && row.disabled === false, "unbound state settles to Connect, not Checking", JSON.stringify(row));

    await createButton.click();
    const dialog = page.getByRole("dialog", { name: "Authentication for GitHub" });
    await dialog.waitFor({ state: "visible", timeout: 10000 });
    ok((await page.getByTestId("personal-access-token-input").count()) === 1, "native PAT modal exposes the token input");
    ok((await page.getByTestId("repo-url-to-authenticate-input").count()) === 1, "native PAT modal asks for a repo URL for verification");
    const text = await dialog.innerText();
    ok(/Tokens are encrypted/.test(text), "modal copy keeps secret custody framing visible");
  }
  ok(errors.length === 0, "native Git-auth flow has zero JS/page errors", errors.slice(0, 2).join("; "));
} finally {
  await browser.close();
}

const fallthrough = await fetch(`${REF}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({ proxied: ["fallthrough-read-failed"] }));
ok(Array.isArray(fallthrough.proxied) && fallthrough.proxied.length === 0, "native Git-auth exercised zero mirror fallthrough RPCs", (fallthrough.proxied || []).join(", "));

const verdict = failures > 0 ? "FAIL" : "PASS";
if (JSON_OUT) console.log(JSON.stringify({ workstream: "git-auth-native", verdict, failures, checks: checks.length }, null, 2));
else console.log(`  VERDICT: ${verdict} (${checks.length - failures}/${checks.length} checks)`);
process.exit(verdict === "FAIL" ? 1 : 0);
