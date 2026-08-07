import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

process.env.NODE_ENV = "production";
delete process.env.CORE_SIGNING_SECRET;
delete process.env.PORTAL_IDENTITY_SECRET;
process.env.WEB_UI_PUBLIC_URL = "https://ioi.example";

const { handler } = await import("../server/index.ts");
const surface = createServer((req, res) => void handler(req, res));
await new Promise<void>((resolve) => surface.listen(0, resolve));
const base = `http://127.0.0.1:${(surface.address() as AddressInfo).port}`;

test.after(() => surface.close());

test("production handler refuses every request when either signed identity secret is absent", async () => {
  for (const path of ["/healthz", "/me", "/api/memory", "/"]) {
    const response = await fetch(`${base}${path}`);
    assert.equal(response.status, 503, path);
    assert.equal(response.headers.get("cache-control"), "no-store", path);
    assert.equal(((await response.json()) as { error?: string }).error, "identity_configuration_required", path);
  }
});

test("production executable exits before listening when signed identity configuration is absent", async () => {
  const env: NodeJS.ProcessEnv = { ...process.env, NODE_ENV: "production", WEB_UI_DEV: "0" };
  delete env.CORE_SIGNING_SECRET;
  delete env.PORTAL_IDENTITY_SECRET;
  const child = spawn(process.execPath, ["server/index.ts"], {
    cwd: new URL("..", import.meta.url),
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  assert.equal(code, 1);
  assert.match(stderr, /production identity configuration missing/);
});
