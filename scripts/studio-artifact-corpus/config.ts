import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import type { CorpusCase, RendererKind } from "./types";

export const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
const configuredEvidenceDate =
  process.env.STUDIO_ARTIFACT_EVIDENCE_DATE?.trim() ||
  new Date().toISOString().slice(0, 10);
export const cliBinary = path.join(repoRoot, "target", "debug", "cli");
export const studioProofBinary = path.join(
  repoRoot,
  "target",
  "debug",
  process.platform === "win32" ? "studio_artifact_proof.exe" : "studio_artifact_proof",
);
export const evidenceRoot = path.join(
  repoRoot,
  "docs",
  "evidence",
  "studio-artifact-surface",
  configuredEvidenceDate,
);
export const contractEvidenceRoot = path.join(evidenceRoot, "contract-lane");
export const liveEvidenceRoot = path.join(evidenceRoot, "live-studio-lane");
export const npmBinary = process.platform === "win32" ? "npm.cmd" : "npm";

export const corpusCases: CorpusCase[] = [
  {
    id: "html-quantum-explainer-baseline",
    prompt: "Create an interactive HTML artifact that explains quantum computers",
    expectedRenderer: "html_iframe",
    expectedKeywords: ["quantum", "qubit", "entanglement"],
  },
  {
    id: "markdown-release-checklist",
    prompt: "Create a markdown artifact that documents a release checklist",
    expectedRenderer: "markdown",
    expectedKeywords: ["release", "checklist"],
  },
  {
    id: "html-dog-shampoo",
    prompt:
      "Create an interactive HTML artifact that explains a product rollout with charts about dog shampoo",
    expectedRenderer: "html_iframe",
    expectedKeywords: ["dog shampoo", "rollout", "chart"],
  },
  {
    id: "html-instacart-mcp",
    prompt:
      "Create an interactive HTML artifact that explains a product rollout with charts for an Instacart MCP",
    expectedRenderer: "html_iframe",
    expectedKeywords: ["instacart", "mcp", "rollout"],
    useQueryAlias: true,
  },
  {
    id: "html-ai-tools-editorial",
    prompt: "Create an interactive HTML artifact for an AI tools editorial launch page",
    expectedRenderer: "html_iframe",
    expectedKeywords: ["ai tools", "editorial", "launch"],
  },
  {
    id: "html-release-workflow-onboarding",
    prompt:
      "Create an interactive HTML artifact that guides a new operator through onboarding for a release workflow",
    expectedRenderer: "html_iframe",
    expectedKeywords: ["onboarding", "release workflow", "operator"],
  },
  {
    id: "jsx-pricing-configurator",
    prompt: "Create a JSX artifact for a pricing configurator",
    expectedRenderer: "jsx_sandbox",
    expectedKeywords: ["pricing", "configurator"],
  },
  {
    id: "svg-ai-tools-hero",
    prompt: "Create an SVG hero concept for an AI tools brand",
    expectedRenderer: "svg",
    expectedKeywords: ["ai tools", "brand"],
  },
  {
    id: "mermaid-approval-pipeline",
    prompt: "Create a Mermaid diagram of an approval pipeline",
    expectedRenderer: "mermaid",
    expectedKeywords: ["approval", "pipeline"],
  },
  {
    id: "pdf-launch-brief",
    prompt: "Create a PDF artifact that summarizes a launch brief",
    expectedRenderer: "pdf_embed",
    expectedKeywords: ["launch", "brief"],
  },
  {
    id: "download-bundle",
    prompt: "Create a downloadable artifact bundle with a CSV and README",
    expectedRenderer: "download_card",
    expectedKeywords: ["csv", "readme"],
  },
  {
    id: "workspace-billing-settings",
    prompt: "Create a workspace project for a billing settings surface",
    expectedRenderer: "workspace_surface",
    expectedKeywords: ["billing settings", "workspace"],
    workspaceBuild: true,
  },
  {
    id: "html-dog-shampoo-enterprise",
    prompt: "Make it feel more enterprise",
    expectedRenderer: "html_iframe",
    expectedKeywords: ["dog shampoo", "enterprise"],
    expectedStyleTerms: ["enterprise"],
    refinementFrom: "html-dog-shampoo",
    expectedEditMode: "patch",
    styleSteering: true,
  },
  {
    id: "html-dog-shampoo-technical",
    prompt:
      "Keep the structure, but replace the hero and chart with a more technical tone",
    expectedRenderer: "html_iframe",
    expectedKeywords: ["dog shampoo", "technical", "chart"],
    refinementFrom: "html-dog-shampoo-enterprise",
    expectedEditMode: "patch",
  },
  {
    id: "html-dog-shampoo-targeted-chart",
    prompt:
      "Edit the selected chart section to show adoption by channel instead of launch-phase sequencing.",
    expectedRenderer: "html_iframe",
    expectedKeywords: ["dog shampoo", "adoption", "channel"],
    refinementFrom: "html-dog-shampoo-technical",
    expectedEditMode: "patch",
    requiresSelection: true,
    selectedTargets: [
      {
        sourceSurface: "render",
        path: "index.html",
        label: "chart section",
        snippet:
          "Hero chart section should show adoption by channel instead of launch-phase sequencing.",
      },
    ],
  },
  {
    id: "html-dog-shampoo-branch-editorial",
    prompt:
      "Branch this artifact into a more editorial launch story with sharper product language",
    expectedRenderer: "html_iframe",
    expectedKeywords: ["dog shampoo", "editorial", "launch"],
    refinementFrom: "html-dog-shampoo",
    expectedEditMode: "branch",
  },
];

export const inferenceUnavailableLiveCase: CorpusCase = {
  id: "inference-unavailable",
  prompt:
    "Create an interactive HTML artifact that explains a product rollout with charts for a productivity assistant",
  expectedRenderer: "html_iframe",
  expectedKeywords: [],
};

export const DEFAULT_OLLAMA_CHAT_ENDPOINT =
  "http://127.0.0.1:11434/v1/chat/completions";
export const DEFAULT_OLLAMA_HEALTH_ENDPOINT =
  "http://127.0.0.1:11434/api/tags";
export type OllamaSingleModelLaneOverride = {
  renderer: RendererKind;
  lane: "live" | "contract";
  modelPreferences: string[];
};
// Keep benchmark lane overrides explicit in config so runtime selection stays
// renderer/lane-driven rather than silently branching on model-family names.
export const OLLAMA_SINGLE_MODEL_LANE_OVERRIDES: OllamaSingleModelLaneOverride[] = [
  {
    renderer: "html_iframe",
    lane: "live",
    modelPreferences: ["qwen3:8b"],
  },
];
export const PREFERRED_OLLAMA_PRODUCTION_MODELS = [
  "qwen2.5:7b",
  "qwen2.5:14b",
  "llama3.2:3b",
];
export const PREFERRED_OLLAMA_ACCEPTANCE_MODELS = [
  "qwen2.5:14b",
  "qwen2.5:7b",
  "llama3.2:3b",
];
export const PREFERRED_FAST_OLLAMA_PRODUCTION_MODELS = [
  "llama3.2:3b",
  "qwen2.5:7b",
  "qwen2.5:14b",
];
export const PREFERRED_FAST_OLLAMA_ACCEPTANCE_MODELS = [
  "qwen2.5:7b",
  "qwen2.5:14b",
  "llama3.2:3b",
];
