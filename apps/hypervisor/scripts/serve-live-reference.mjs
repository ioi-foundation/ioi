#!/usr/bin/env node
// Serve the LIVE reference as the hypervisor app.
//
// This is the "start with the reference, work backwards" mode: instead of re-rendering
// captured static HTML (which loses the reference's live JS — dark mode, every client
// interaction — and forces us to re-wire it by hand), we serve the reference's actual
// live bundle. The reference server applies the IOI branding + API mocks to the
// harvested snapshot, so the app IS the live reference: dark mode and all interactions
// work natively, and it's pixel-exact by definition. Working backwards from here means
// replacing the mocked /api with real IOI services and progressively swapping internals.
//
// Transitional: the harvested bundle stays in the gitignored local mirror (not committed
// to the product yet), so this serve mode requires the mirror to be present.
//
// Usage: PORT=4173 node apps/hypervisor/scripts/serve-live-reference.mjs
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const REF_SERVER = join(REPO_ROOT, "internal-docs", "reverse-engineering", "ioi", "server.js");
const PORT = process.env.PORT || "4173";

if (!existsSync(REF_SERVER)) {
  console.error(
    `Live reference not found at:\n  ${REF_SERVER}\n\n` +
      `The reference bundle is a gitignored local mirror; this serve mode needs it present.\n` +
      `(Run the captured-render build with \`vite preview\` instead if the mirror is unavailable.)`,
  );
  process.exit(1);
}

console.log(`[hypervisor] serving LIVE reference on http://localhost:${PORT}`);
const child = spawn("node", [REF_SERVER], { stdio: "inherit", env: { ...process.env, PORT } });
child.on("exit", (code) => process.exit(code ?? 0));
