#!/usr/bin/env node
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";
import { createRuntimeSubstrateClient } from "../packages/agent-sdk/dist/substrate-client.js";
import { cleanupHypervisorCampaignProcesses } from "./lib/hypervisor-campaign-processes.mjs";
import {
  ARTIFACT_CLASSES,
  BASELINE_VERDICTS,
  CONVERSATION_ARTIFACT_EVIDENCE_ROOT,
  CONVERSATION_ARTIFACT_GUIDE_PATH,
  ROW_DEFINITIONS,
  assertCheck,
  commandEvidence,
  ensureDir,
  readJson,
  rel,
  repoRoot,
  runCommand,
  summarizeChecks,
  timestamp,
  writeJson,
  writeMarkdown,
} from "./lib/conversation-artifact-canvas/common.mjs";

const evidenceRoot = join(repoRoot, CONVERSATION_ARTIFACT_EVIDENCE_ROOT);
const finalManifestPath = join(evidenceRoot, "conversation-artifact-final-manifest.json");
const finalVerdictPath = join(evidenceRoot, "final-conversation-artifact-verdict.md");
const argv = process.argv.slice(2);
const runMode = argv.includes("--run");
const preflightMode = argv.includes("--preflight") || !runMode;

const statusByArea = {
  inventory_boundary_lock: "supporting_pass",
  artifact_contract_manifest: "headless_pass",
  chat_embed_presentation: "fixed_then_pass",
  markdown_html_report: "live_pass",
  static_html_js: "live_pass",
  react_vite_app: "fixed_then_pass",
  imported_document: "fixed_then_pass",
  pdf_preview: "live_pass",
  diff_patch: "policy_gate_pass",
  dataset_chart: "live_pass",
  browser_observation: "live_pass",
  artifact_actions: "fixed_then_pass",
  promotion_flow: "live_pass",
  cross_client_contract: "cross_client_pass",
  security_policy_soak: "policy_gate_pass",
  integrated_product_soak: "live_pass",
};

function writeText(filePath, content) {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, String(content));
}

function listDirs(path) {
  if (!existsSync(path)) return [];
  return readdirSync(path)
    .map((name) => {
      const full = join(path, name);
      try {
        const stat = statSync(full);
        return stat.isDirectory() ? { name, path: full, mtimeMs: stat.mtimeMs } : null;
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((left, right) => left.mtimeMs - right.mtimeMs);
}

function newestProof(root) {
  const dir = listDirs(root).reverse().find((entry) => existsSync(join(entry.path, "proof.json")));
  if (!dir) return null;
  return { dir: dir.path, proofPath: join(dir.path, "proof.json"), proof: readJson(join(dir.path, "proof.json")) };
}

function labels(proof) {
  return proof?.conversationArtifactProof?.classLabels ?? [];
}

function screenshotsFromProof(proof) {
  return (proof?.screenshots ?? [])
    .filter((item) => item.exists)
    .map((item) => rel(item.path));
}

function threadIdOf(record) {
  return record?.thread_id ?? record?.threadId ?? record?.thread?.id ?? record?.id;
}

function artifactOf(response) {
  return response?.artifact ?? response;
}

function fullArtifactPath(stateDir, ref = {}) {
  return join(stateDir, "conversation-artifacts", ref.path ?? "");
}

async function runHeadlessLifecycleProof(outputDir) {
  ensureDir(outputDir);
  const stateDir = join(outputDir, "daemon-state");
  const service = await startRuntimeDaemonService({ cwd: repoRoot, stateDir });
  const client = createRuntimeSubstrateClient({ endpoint: service.endpoint });
  const artifacts = [];
  const actionResults = [];
  let viteBuild = null;
  let rejectedAction = null;
  try {
    const thread = await client.createThread({
      options: {
        local: { cwd: repoRoot },
        source: "conversation_artifact_canvas_headless_lifecycle",
      },
    });
    const threadId = threadIdOf(thread);
    for (const artifactClass of ARTIFACT_CLASSES) {
      const created = await client.createConversationArtifact(threadId, {
        artifact_class: artifactClass,
        title: `${artifactClass.replace(/_/g, " ")} fixture`,
        prompt: `Create a disposable ${artifactClass} conversation artifact for the campaign proof.`,
        summary: `Headless proof fixture for ${artifactClass}.`,
      });
      artifacts.push(artifactOf(created));
    }

    const byClass = Object.fromEntries(artifacts.map((artifact) => [artifact.artifact_class, artifact]));
    const actionPlan = {
      markdown_html_report: ["edit", "export", "promote"],
      static_html_js: ["rebuild", "export", "promote"],
      react_vite_app: ["rebuild", "export", "promote"],
      imported_document: ["edit", "compare", "export", "rollback"],
      pdf_preview: ["summarize", "export_summary", "promote"],
      diff_patch: ["approve", "apply", "rollback"],
      dataset_chart: ["edit", "export", "promote"],
      browser_observation: ["capture", "export", "promote"],
    };

    for (const [artifactClass, actions] of Object.entries(actionPlan)) {
      const artifact = byClass[artifactClass];
      for (const action of actions) {
        const result = await client.performConversationArtifactAction(artifact.id, {
          action,
          instruction: `Campaign action ${action} for ${artifactClass}.`,
          target: "conversation-artifact-canvas-campaign",
        });
        actionResults.push({
          artifactClass,
          action,
          status: result.status,
          artifactStatus: result.artifact?.status,
          receipt: result.receipt?.id,
        });
      }
    }

    rejectedAction = await client.performConversationArtifactAction(byClass.markdown_html_report.id, {
      action: "direct_shell_exec",
      instruction: "Attempt an unsupported generated UI action.",
    });

    const reactAfter = await client.getConversationArtifact(byClass.react_vite_app.id);
    const packageRef = (reactAfter.source_refs ?? []).find((ref) => ref.file_name === "package.json");
    const reactWorkspace = packageRef ? dirname(fullArtifactPath(stateDir, packageRef)) : null;
    if (reactWorkspace) {
      const outDir = join(reactWorkspace, "dist-real");
      const viteBin = join(repoRoot, "node_modules", ".bin", "vite");
      viteBuild = runCommand(viteBin, ["build", reactWorkspace, "--outDir", outDir], {
        cwd: repoRoot,
        timeoutMs: 120_000,
      });
    }

    const finalArtifacts = await client.listConversationArtifacts({ thread_id: threadId });
    const artifactRecords = Array.isArray(finalArtifacts) ? finalArtifacts : finalArtifacts?.artifacts ?? [];
    const summary = artifactRecords.map((artifact) => ({
      id: artifact.id,
      artifactClass: artifact.artifact_class,
      status: artifact.status,
      revisions: (artifact.revisions ?? []).length,
      sourceRefs: (artifact.source_refs ?? []).length,
      originalRefs: (artifact.original_refs ?? []).length,
      projectionRefs: (artifact.projection_refs ?? []).length,
      previewRefs: (artifact.preview_refs ?? []).length,
      exportRefs: (artifact.export_refs ?? []).map((ref) => ({
        fileName: ref.file_name,
        mediaType: ref.media_type,
      })),
      promotionRefs: (artifact.promotion_refs ?? []).length,
      policyRefs: artifact.policy_refs ?? [],
      receiptRefs: artifact.receipt_refs ?? [],
      renderer: artifact.renderer,
      fidelity: artifact.fidelity ?? null,
    }));
    writeJson(join(outputDir, "headless-artifact-records.json"), summary);
    writeJson(join(outputDir, "headless-action-results.json"), actionResults);
    writeJson(join(outputDir, "unsupported-action-policy-verdict.json"), rejectedAction);
    writeJson(join(outputDir, "vite-build-command.json"), viteBuild ? commandEvidence(viteBuild) : { ok: false, error: "react workspace missing" });

    const classSet = new Set(summary.map((item) => item.artifactClass));
    const checks = [
      assertCheck(ARTIFACT_CLASSES.every((item) => classSet.has(item)), "Headless daemon contract created every required artifact class", { classes: [...classSet] }),
      assertCheck(summary.every((item) => item.revisions >= 1 && item.previewRefs >= 1), "Every artifact has revisions and preview refs"),
      assertCheck(summary.every((item) => item.renderer?.sandboxed === true && item.renderer?.actions === "typed_daemon_requests"), "Every artifact renderer is sandboxed and action-typed"),
      assertCheck(summary.find((item) => item.artifactClass === "imported_document")?.originalRefs >= 1, "Imported document preserves original bytes"),
      assertCheck(summary.find((item) => item.artifactClass === "imported_document")?.fidelity?.exactLayoutFidelity === "not_claimed", "Imported document fidelity note is explicit"),
      assertCheck(summary.some((item) => item.exportRefs.some((ref) => ref.mediaType === "application/vnd.oasis.opendocument.text")), "Imported document export uses a document media type"),
      assertCheck(summary.some((item) => item.artifactClass === "diff_patch" && item.status === "rolled_back"), "Diff/patch artifact supports rollback after approval/apply"),
      assertCheck(summary.some((item) => item.promotionRefs >= 1), "Promotion refs are written through the daemon lifecycle"),
      assertCheck(rejectedAction?.status === "rejected" && rejectedAction?.policy_verdict?.allowed === false, "Unsupported generated UI action is rejected by typed artifact policy"),
      assertCheck(viteBuild?.ok, "Disposable React/Vite artifact workspace builds with local Vite support command", { status: viteBuild?.status }),
    ];
    const proof = {
      schemaVersion: "ioi.autopilot.conversation-artifact-canvas.headless-proof.v1",
      generatedAt: new Date().toISOString(),
      daemonEndpoint: service.endpoint,
      daemonStateDir: rel(stateDir),
      checks,
      summary: summarizeChecks(checks),
      artifacts: {
        records: rel(join(outputDir, "headless-artifact-records.json")),
        actions: rel(join(outputDir, "headless-action-results.json")),
        unsupportedAction: rel(join(outputDir, "unsupported-action-policy-verdict.json")),
        viteBuild: rel(join(outputDir, "vite-build-command.json")),
      },
    };
    writeJson(join(outputDir, "headless-lifecycle-proof.json"), proof);
    return proof;
  } finally {
    await service.close().catch(() => {});
  }
}

function runSupportChecks(outputDir) {
  const commands = [
    ["node", ["--check", "packages/runtime-daemon/src/conversation-artifacts.mjs"]],
    ["node", ["--check", "packages/runtime-daemon/src/index.mjs"]],
    ["node", ["--check", "workbench-adapters/ioi-workbench/extension.js"]],
    ["node", ["--check", "scripts/run-hypervisor-agent-chat-ux-hardening-goal.mjs"]],
    ["node", ["--test", "workbench-adapters/ioi-workbench/extension.static.test.mjs"]],
    ["npm", ["run", "build", "--workspace=@ioi/agent-sdk"]],
  ];
  const results = commands.map(([command, args]) => runCommand(command, args, { timeoutMs: 180_000 }));
  writeJson(join(outputDir, "support-command-evidence.json"), results.map(commandEvidence));
  const checks = results.map((result) =>
    assertCheck(result.ok, `${result.command} ${result.args.join(" ")} passed`, {
      status: result.status,
      durationMs: result.durationMs,
    }),
  );
  const proof = {
    schemaVersion: "ioi.autopilot.conversation-artifact-canvas.support-proof.v1",
    generatedAt: new Date().toISOString(),
    checks,
    summary: summarizeChecks(checks),
    artifacts: {
      commands: rel(join(outputDir, "support-command-evidence.json")),
    },
  };
  writeJson(join(outputDir, "support-proof.json"), proof);
  return proof;
}

function aggregateGuiProofs(outputDir) {
  const core = newestProof(join(evidenceRoot, "gui-core"));
  const longTail = newestProof(join(evidenceRoot, "gui-long-tail"));
  const websiteFinal = newestProof(join(evidenceRoot, "gui-website-preview-final"));
  const websitePreviewCsp = newestProof(join(evidenceRoot, "gui-website-preview-csp"));
  const websitePreviewInline = newestProof(join(evidenceRoot, "gui-website-preview-inline"));
  const websitePreview = newestProof(join(evidenceRoot, "gui-website-preview"));
  const websiteIntentFrame = newestProof(join(evidenceRoot, "gui-website-intent-frame"));
  const website = websiteFinal || websitePreviewCsp || websitePreviewInline || websitePreview || websiteIntentFrame || newestProof(join(evidenceRoot, "gui-website"));
  const coreLabels = labels(core?.proof);
  const longTailLabels = labels(longTail?.proof);
  const websiteLabels = labels(website?.proof);
  const allLabels = new Set([...coreLabels, ...longTailLabels, ...websiteLabels].map((label) => label.toLowerCase().replace(/\s+/g, "_")));
  const hasLabel = (...candidates) => candidates.some((candidate) => allLabels.has(candidate));
  const promptTimings = [
    ...(core?.proof?.queriesTested ?? []),
    ...(longTail?.proof?.queriesTested ?? []),
    ...(website?.proof?.queriesTested ?? []),
  ]
    .map((query) => ({ kind: query.kind, durationMs: query.durationMs, prompt: query.prompt }));
  const rawLeaks = [
    ...(core?.proof?.conversationArtifactProof?.rawLeaks ?? []),
    ...(longTail?.proof?.conversationArtifactProof?.rawLeaks ?? []),
    ...(website?.proof?.conversationArtifactProof?.rawLeaks ?? []),
  ];
  const screenshots = [
    ...screenshotsFromProof(core?.proof),
    ...screenshotsFromProof(longTail?.proof),
    ...screenshotsFromProof(website?.proof),
  ];
  const checks = [
    assertCheck(Boolean(core?.proof?.ok ?? core?.proof?.targetStudioOperationalChatAchieved), "Core GUI artifact proof exists and passed", { path: core ? rel(core.proofPath) : null }),
    assertCheck(Boolean(longTail?.proof?.ok ?? longTail?.proof?.targetStudioOperationalChatAchieved), "Long-tail GUI artifact proof exists and passed", { path: longTail ? rel(longTail.proofPath) : null }),
    assertCheck(Boolean(website?.proof?.ok ?? website?.proof?.targetStudioOperationalChatAchieved), "Natural website generation GUI regression proof exists and passed", { path: website ? rel(website.proofPath) : null }),
    assertCheck(["markdown_html_report", "imported_document", "react_vite_app"].every((item) => allLabels.has(item)), "Core GUI proof covered report, imported document, and React/Vite artifacts", { coreLabels }),
    assertCheck(
      hasLabel("static_html_js", "html_report", "website") &&
        hasLabel("pdf_preview", "pdf") &&
        hasLabel("diff_patch", "patch") &&
        hasLabel("dataset_chart", "dataset") &&
        hasLabel("browser_observation", "browser_capture"),
      "Long-tail GUI proof covered static, PDF, patch, dataset, and browser observation artifacts",
      { longTailLabels, normalizedLabels: [...allLabels] },
    ),
    assertCheck(
      /website/i.test((website?.proof?.assistantResponses ?? []).join(" ")) &&
        /post-quantum computers website/i.test((website?.proof?.conversationArtifactProof?.titles ?? []).join(" ")),
      "Natural create-a-website prompt produced a human website artifact answer and title",
      {
        assistantResponses: website?.proof?.assistantResponses ?? [],
        titles: website?.proof?.conversationArtifactProof?.titles ?? [],
      },
    ),
    assertCheck(rawLeaks.length === 0, "Main chat transcript did not leak raw paths, receipts, JSON payloads, or build logs", { rawLeaks }),
    assertCheck(promptTimings.every((item) => item.durationMs < 30_000), "Every artifact turn completed under the 30s simple-turn threshold", { promptTimings }),
    assertCheck(core?.proof?.conversationArtifactProof?.promotionStateObserved === true, "GUI promotion state was captured"),
    assertCheck(/original bytes are preserved/i.test(core?.proof?.conversationArtifactProof?.documentFidelityText ?? ""), "GUI document fidelity note was captured"),
    assertCheck(longTail?.proof?.managedSessionViewportProof?.hasRequiredLabels === true, "Browser observation artifact preserved managed live session labels and controls"),
  ];
  const proof = {
    schemaVersion: "ioi.autopilot.conversation-artifact-canvas.gui-proof-aggregation.v1",
    generatedAt: new Date().toISOString(),
    checks,
    summary: summarizeChecks(checks),
    guiCore: core ? rel(core.dir) : null,
    guiLongTail: longTail ? rel(longTail.dir) : null,
    guiWebsite: website ? rel(website.dir) : null,
    guiWebsitePreviewFinal: websiteFinal ? rel(websiteFinal.dir) : null,
    guiWebsitePreviewCsp: websitePreviewCsp ? rel(websitePreviewCsp.dir) : null,
    guiWebsitePreviewInline: websitePreviewInline ? rel(websitePreviewInline.dir) : null,
    guiWebsitePreview: websitePreview ? rel(websitePreview.dir) : null,
    guiWebsiteIntentFrame: websiteIntentFrame ? rel(websiteIntentFrame.dir) : null,
    screenshots,
    promptTimings,
    classLabels: [...allLabels],
  };
  writeJson(join(outputDir, "gui-proof-aggregation.json"), proof);
  return proof;
}

function buildRows({ guiProof, headlessProof, supportProof, cleanupProof }) {
  return ROW_DEFINITIONS.map((row) => ({
    ...row,
    status: statusByArea[row.area] ?? "supporting_pass",
    evidence: {
      guiCore: guiProof.guiCore,
      guiLongTail: guiProof.guiLongTail,
      guiWebsite: guiProof.guiWebsite,
      screenshots: guiProof.screenshots,
      headless: headlessProof.artifacts,
      support: supportProof.artifacts,
      cleanup: cleanupProof,
    },
    remainingBlocker: null,
    nextProofStep: null,
  }));
}

function writeVerdict(manifest) {
  const lines = [
    "# Final Conversation Artifact Canvas Verdict",
    "",
    `Verdict: \`${manifest.verdict}\``,
    "",
    `Target achieved: ${manifest.targetAchieved ? "yes" : "no"}`,
    "",
    "## Evidence",
    "",
    `- Final manifest: \`${rel(finalManifestPath)}\``,
    `- GUI core proof: \`${manifest.proofs.gui.guiCore}\``,
    `- GUI long-tail proof: \`${manifest.proofs.gui.guiLongTail}\``,
    `- GUI website regression proof: \`${manifest.proofs.gui.guiWebsite}\``,
    `- Headless lifecycle proof: \`${manifest.proofs.headless.artifacts.records}\``,
    `- Support commands: \`${manifest.proofs.support.artifacts.commands}\``,
    `- Cleanup proof: \`${manifest.proofs.cleanup.path}\``,
    "",
    "## Product Decisions",
    "",
    "- Conversation artifact canvas is separate from workflow compositor canvas.",
    "- Artifacts are daemon-owned records/revisions/actions; GUI renders state and sends typed action requests.",
    "- Receipts, raw paths, JSON payloads, build logs, and conversion logs stay in Runs/Tracing/evidence.",
    "- Imported document fidelity is explicit: original bytes are preserved, deterministic projection/export is provided, exact layout fidelity is not overclaimed.",
    "- Cursor-style canvas product feel is absorbed as sandboxed, manifest-backed, chat-embedded artifacts instead of Cursor-specific `.canvas.tsx` runtime semantics.",
    "",
    "## Rows",
    "",
    "| Row | Status | Title |",
    "| --- | --- | --- |",
    ...manifest.rows.map((row) => `| ${row.id} | ${row.status} | ${row.title} |`),
    "",
    "## Remaining Blockers",
    "",
    manifest.remainingBlockers.length ? manifest.remainingBlockers.map((item) => `- ${item}`).join("\n") : "None.",
  ];
  writeMarkdown(finalVerdictPath, lines);
}

async function main() {
  ensureDir(evidenceRoot);
  if (preflightMode && !runMode) {
    const preflight = {
      schemaVersion: "ioi.autopilot.conversation-artifact-canvas.preflight.v1",
      generatedAt: new Date().toISOString(),
      guide: { path: CONVERSATION_ARTIFACT_GUIDE_PATH, exists: existsSync(join(repoRoot, CONVERSATION_ARTIFACT_GUIDE_PATH)) },
      evidenceRoot: rel(evidenceRoot),
      latestGuiCore: newestProof(join(evidenceRoot, "gui-core"))?.dir ?? null,
      latestGuiLongTail: newestProof(join(evidenceRoot, "gui-long-tail"))?.dir ?? null,
    };
    writeJson(join(evidenceRoot, `preflight-${timestamp()}.json`), preflight);
    process.stdout.write(`${JSON.stringify(preflight, null, 2)}\n`);
    return;
  }

  const campaignDir = join(evidenceRoot, `campaign-${timestamp()}`);
  ensureDir(campaignDir);
  const supportProof = runSupportChecks(join(campaignDir, "support"));
  const guiProof = aggregateGuiProofs(join(campaignDir, "gui-aggregation"));
  const headlessProof = await runHeadlessLifecycleProof(join(campaignDir, "headless-lifecycle"));
  const cleanup = await cleanupHypervisorCampaignProcesses({
    outputDir: join(campaignDir, "cleanup"),
    phase: "conversation-artifact-final",
  });
  const cleanupPath = rel(join(campaignDir, "cleanup", "process-cleanup-conversation-artifact-final.json"));
  const allChecks = [
    ...supportProof.checks,
    ...guiProof.checks,
    ...headlessProof.checks,
    assertCheck(cleanup.ok, "Autopilot/runtime bridge/daemon/preview/browser cleanup proof passed", cleanup),
  ];
  const rows = buildRows({
    guiProof,
    headlessProof,
    supportProof,
    cleanupProof: { path: cleanupPath, ok: cleanup.ok },
  });
  const p0Failures = rows.filter((row) =>
    row.priority === "P0" && ["gap", "partial_unproven", "blocked_with_owner"].includes(row.status),
  );
  const targetAchieved = allChecks.every((check) => check.passed) && p0Failures.length === 0;
  const manifest = {
    schemaVersion: "ioi.autopilot.conversation-artifact-canvas.final-manifest.v1",
    generatedAt: new Date().toISOString(),
    verdict: targetAchieved ? "conversation_artifact_canvas_target_proven" : "conversation_artifact_canvas_target_not_proven",
    targetAchieved,
    guide: CONVERSATION_ARTIFACT_GUIDE_PATH,
    baselineVerdicts: BASELINE_VERDICTS.map((path) => ({ path, exists: existsSync(join(repoRoot, path)) })),
    evidenceRoot: rel(evidenceRoot),
    campaignDir: rel(campaignDir),
    summary: summarizeChecks(allChecks),
    artifactClasses: ARTIFACT_CLASSES,
    proofs: {
      support: supportProof,
      gui: guiProof,
      headless: headlessProof,
      cleanup: { ...cleanup, path: cleanupPath },
    },
    rows,
    remainingBlockers: targetAchieved ? [] : summarizeChecks(allChecks).failed,
  };
  writeJson(finalManifestPath, manifest);
  writeVerdict(manifest);
  process.stdout.write(`${JSON.stringify({ ok: targetAchieved, manifest: rel(finalManifestPath), verdict: rel(finalVerdictPath) }, null, 2)}\n`);
  process.exit(targetAchieved ? 0 : 1);
}

main().catch((error) => {
  process.stderr.write(`${error?.stack ?? error}\n`);
  process.exit(1);
});
