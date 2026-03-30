import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../../..");
const sourceDir = path.join(repoRoot, "node_modules", "monaco-editor", "min", "vs");
const targetDir = path.join(repoRoot, "apps", "autopilot", "public", "monaco", "vs");

if (!fs.existsSync(sourceDir)) {
  throw new Error(`Monaco assets not found at ${sourceDir}`);
}

fs.rmSync(targetDir, { recursive: true, force: true });
fs.mkdirSync(path.dirname(targetDir), { recursive: true });
fs.cpSync(sourceDir, targetDir, { recursive: true });

console.log(`[sync-monaco-assets] Synced Monaco assets to ${targetDir}`);
