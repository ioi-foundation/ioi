import crypto from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";

export {
  assertCheck,
  cleanDir,
  cleanupProof,
  commandEvidence,
  ensureDir,
  maybeReadJson,
  newestDirectory,
  parseMaybeJson,
  rel,
  repoRoot,
  requestJson,
  runCommand,
  runCommandAsync,
  summarizeChecks,
  timestamp,
  writeJson,
  writeJsonl,
  writeMarkdown,
} from "../headless-runtime-unification/common.mjs";

export const CURSOR_GUIDE_PATH =
  ".internal/plans/autopilot-cursor-substrate-absorption-parity-master-guide.md";
export const CURSOR_PLAYBOOK_PATH = ".internal/playbooks/substrate-absorption-rubric-playbook.md";
export const CURSOR_REVERSE_DIR = "internal-docs/reverse-engineering/cursor";
export const CURSOR_EVIDENCE_ROOT = "docs/evidence/autopilot-cursor-substrate-absorption-parity";

export const CURSOR_INPUTS = {
  substrateMap: `${CURSOR_REVERSE_DIR}/cursor-substrate-map.md`,
  capabilityMatrix: `${CURSOR_REVERSE_DIR}/cursor-capability-matrix.json`,
  deltaAudit: `${CURSOR_REVERSE_DIR}/cursor-autopilot-delta-audit.md`,
  evidenceManifest: `${CURSOR_REVERSE_DIR}/cursor-reverse-engineering-evidence-manifest.json`,
};

export const BASELINE_VERDICTS = [
  "docs/evidence/autopilot-agent-studio-full-default-harness-parity/final-default-harness-parity-verdict.md",
  "docs/evidence/autopilot-antigravity-harness-parity-plus/final-antigravity-harness-parity-plus-verdict.md",
  "docs/evidence/autopilot-claude-code-substrate-absorption-parity/final-claude-code-substrate-absorption-verdict.md",
  "docs/evidence/autopilot-headless-runtime-unification-parity/final-headless-runtime-unification-verdict.md",
];

export const ROW_DEFINITIONS = [
  {
    id: "CURSOR-SUBSTRATE-000",
    priority: "P0",
    area: "campaign_inputs",
    owner: "Evidence runtime",
    title: "Evidence schema and source polish",
  },
  {
    id: "CURSOR-SUBSTRATE-001",
    priority: "P0",
    area: "shadow_workspace_validation",
    owner: "Runtime daemon / workspace validation",
    title: "Shadow workspace dry-run validation",
  },
  {
    id: "CURSOR-SUBSTRATE-002",
    priority: "P0",
    area: "lsp_watcher_isolation",
    owner: "Runtime daemon / IDE workspace isolation",
    title: "LSP and watcher isolation for background worktrees",
  },
  {
    id: "CURSOR-SUBSTRATE-003",
    priority: "P0",
    area: "sandbox_policy",
    owner: "Policy runtime / tool runtime",
    title: "Local sandbox policy model",
  },
  {
    id: "CURSOR-SUBSTRATE-004",
    priority: "P0",
    area: "mcp_oauth_concurrency",
    owner: "MCP runtime",
    title: "MCP OAuth refresh lease and concurrent connections",
  },
  {
    id: "CURSOR-SUBSTRATE-005",
    priority: "P1",
    area: "retrieval_indexing",
    owner: "Retrieval runtime",
    title: "Local retrieval and indexing substrate",
  },
  {
    id: "CURSOR-SUBSTRATE-006",
    priority: "P1",
    area: "commit_review_automation",
    owner: "Review runtime / product",
    title: "Commit-time and pre-push review automation",
  },
  {
    id: "CURSOR-SUBSTRATE-007",
    priority: "P1",
    area: "canvas_artifacts",
    owner: "Artifact runtime / product",
    title: "Agent-authored interactive canvas artifacts",
  },
  {
    id: "CURSOR-SUBSTRATE-008",
    priority: "P1",
    area: "browser_automation_ux",
    owner: "Browser/computer automation runtime",
    title: "Browser automation overlay versus managed viewports",
  },
  {
    id: "CURSOR-SUBSTRATE-009",
    priority: "P0",
    area: "detached_worker_lifecycle",
    owner: "Runtime daemon / shared clients",
    title: "Detached worker lifecycle and survival semantics",
  },
  {
    id: "CURSOR-SUBSTRATE-010",
    priority: "P2",
    area: "log_ingestion",
    owner: "Evidence runtime",
    title: "Local log ingestion and stream wiring",
  },
  {
    id: "CURSOR-SUBSTRATE-011",
    priority: "P2",
    area: "environment_schema",
    owner: "Environment/product runtime",
    title: "Containerized environment definition schema",
  },
  {
    id: "CURSOR-SUBSTRATE-012",
    priority: "P1",
    area: "file_service_api_boundary",
    owner: "Runtime daemon / file service",
    title: "File service and workspace API boundary",
  },
];

export function readText(path) {
  return readFileSync(path, "utf8");
}

export function readJson(path) {
  return JSON.parse(readText(path));
}

export function writeText(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, String(text));
}

export function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

export function tempWorkspace(prefix) {
  const root = join(tmpdir(), `${prefix}-${crypto.randomUUID()}`);
  mkdirSync(root, { recursive: true });
  return root;
}

export function removePath(path) {
  rmSync(path, { recursive: true, force: true });
}

export function copyDirectory(source, destination) {
  cpSync(source, destination, {
    recursive: true,
    dereference: false,
    filter: (entry) => !entry.includes(`${source}/.git`),
  });
}

export function relativeTo(path, root) {
  return relative(root, path) || ".";
}

export function fileSnapshot(root, paths) {
  return Object.fromEntries(
    paths.map((file) => {
      const absolute = resolve(root, file);
      if (!existsSync(absolute)) return [file, { exists: false }];
      const stat = statSync(absolute);
      if (!stat.isFile()) return [file, { exists: true, kind: "non_file" }];
      const text = readText(absolute);
      return [file, { exists: true, bytes: Buffer.byteLength(text), sha256: sha256(text), text }];
    }),
  );
}

export function writePackageFixture(root, { broken = true } = {}) {
  mkdirSync(join(root, "src"), { recursive: true });
  mkdirSync(join(root, "test"), { recursive: true });
  writeText(
    join(root, "package.json"),
    `${JSON.stringify(
      {
        type: "module",
        scripts: {
          test: "node --test test/calc.test.js",
          check: "node --check src/calc.js",
        },
      },
      null,
      2,
    )}\n`,
  );
  writeText(
    join(root, "src/calc.js"),
    broken
      ? "export function add(a, b) { return a - b; }\n"
      : "export function add(a, b) { return a + b; }\n",
  );
  writeText(
    join(root, "test/calc.test.js"),
    [
      "import test from 'node:test';",
      "import assert from 'node:assert/strict';",
      "import { add } from '../src/calc.js';",
      "",
      "test('adds disposable fixture values', () => {",
      "  assert.equal(add(2, 3), 5);",
      "});",
      "",
    ].join("\n"),
  );
}

export function startLocalFixtureServer(responseText = "cursor substrate fixture ok") {
  const server = createServer((request, response) => {
    response.setHeader("content-type", "text/plain; charset=utf-8");
    response.end(`${responseText}\n${request.url ?? "/"}\n`);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

export function productDecision(title, decision, rationale, evidence = []) {
  return [
    `# ${title}`,
    "",
    `Decision: ${decision}`,
    "",
    "## Rationale",
    "",
    rationale,
    "",
    "## Evidence",
    "",
    ...evidence.map((item) => `- \`${item}\``),
    "",
  ].join("\n");
}
