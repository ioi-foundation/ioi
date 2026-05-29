export {
  assertCheck,
  cleanupProof,
  commandEvidence,
  ensureDir,
  maybeReadJson,
  newestDirectory,
  readJson,
  rel,
  repoRoot,
  requestJson,
  runCommand,
  summarizeChecks,
  timestamp,
  writeJson,
  writeMarkdown,
} from "../headless-runtime-unification/common.mjs";

export const CONVERSATION_ARTIFACT_GUIDE_PATH =
  ".internal/plans/autopilot-conversation-artifact-embedded-document-canvas-master-guide.md";

export const CONVERSATION_ARTIFACT_EVIDENCE_ROOT =
  "docs/evidence/autopilot-conversation-artifact-embedded-document-canvas";

export const BASELINE_VERDICTS = [
  "docs/evidence/autopilot-agent-studio-full-default-harness-parity/final-default-harness-parity-verdict.md",
  "docs/evidence/autopilot-antigravity-harness-parity-plus/final-antigravity-harness-parity-plus-verdict.md",
  "docs/evidence/autopilot-claude-code-substrate-absorption-parity/final-claude-code-substrate-absorption-verdict.md",
  "docs/evidence/autopilot-headless-runtime-unification-parity/final-headless-runtime-unification-verdict.md",
  "docs/evidence/autopilot-cursor-substrate-absorption-parity/final-cursor-substrate-absorption-verdict.md",
];

export const ARTIFACT_CLASSES = [
  "markdown_html_report",
  "static_html_js",
  "react_vite_app",
  "imported_document",
  "pdf_preview",
  "diff_patch",
  "dataset_chart",
  "browser_observation",
];

export const ROW_DEFINITIONS = [
  {
    id: "CONV-ARTIFACT-000",
    priority: "P0",
    stage: 1,
    area: "inventory_boundary_lock",
    title: "Conversation artifact boundary is distinct from workflow compositor canvas",
  },
  {
    id: "CONV-ARTIFACT-001",
    priority: "P0",
    stage: 2,
    area: "artifact_contract_manifest",
    title: "Daemon-owned artifact records, revisions, refs, receipts, policy refs, and actions",
  },
  {
    id: "CONV-ARTIFACT-002",
    priority: "P0",
    stage: 3,
    area: "chat_embed_presentation",
    title: "Agent Studio chat renders clean artifact embeds without raw receipt/path/JSON leaks",
  },
  {
    id: "CONV-ARTIFACT-003",
    priority: "P0",
    stage: 4,
    area: "markdown_html_report",
    title: "Markdown/HTML report artifact preview",
  },
  {
    id: "CONV-ARTIFACT-004",
    priority: "P0",
    stage: 5,
    area: "static_html_js",
    title: "Static HTML/CSS/JS standalone artifact preview",
  },
  {
    id: "CONV-ARTIFACT-005",
    priority: "P0",
    stage: 6,
    area: "react_vite_app",
    title: "Generated React/Vite app artifact with rebuild after Agent edit",
  },
  {
    id: "CONV-ARTIFACT-006",
    priority: "P0",
    stage: 7,
    area: "imported_document",
    title: "Imported ODT/DOCX artifact preserves original, projection, compare, and export",
  },
  {
    id: "CONV-ARTIFACT-007",
    priority: "P0",
    stage: 8,
    area: "pdf_preview",
    title: "PDF/read-only document preview and editable summary artifact",
  },
  {
    id: "CONV-ARTIFACT-008",
    priority: "P0",
    stage: 9,
    area: "diff_patch",
    title: "Diff/patch artifact with approval and rollback",
  },
  {
    id: "CONV-ARTIFACT-009",
    priority: "P0",
    stage: 10,
    area: "dataset_chart",
    title: "Dataset/table/chart artifact",
  },
  {
    id: "CONV-ARTIFACT-010",
    priority: "P0",
    stage: 11,
    area: "browser_observation",
    title: "Browser/computer observation artifact integrated with managed live session UX",
  },
  {
    id: "CONV-ARTIFACT-011",
    priority: "P0",
    stage: 12,
    area: "artifact_actions",
    title: "Typed artifact actions and Agent iteration remain daemon-governed",
  },
  {
    id: "CONV-ARTIFACT-012",
    priority: "P0",
    stage: 13,
    area: "promotion_flow",
    title: "Artifact export and promotion flow",
  },
  {
    id: "CONV-ARTIFACT-013",
    priority: "P0",
    stage: 14,
    area: "cross_client_contract",
    title: "Cross-client SDK/headless contract consumes the same artifact lifecycle",
  },
  {
    id: "CONV-ARTIFACT-014",
    priority: "P0",
    stage: 15,
    area: "security_policy_soak",
    title: "Generated UI sandbox and typed action security soak",
  },
  {
    id: "CONV-ARTIFACT-015",
    priority: "P0",
    stage: 16,
    area: "integrated_product_soak",
    title: "Integrated product soak and cleanup proof",
  },
];

export function rowByArea(area) {
  return ROW_DEFINITIONS.find((row) => row.area === area);
}
