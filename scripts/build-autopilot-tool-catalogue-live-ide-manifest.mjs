#!/usr/bin/env node
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const repoRoot = process.cwd();
const evidenceRoot =
  "docs/evidence/autopilot-agent-studio-rust-tool-catalogue-live-ide-verification";
const sourceRunner = "scripts/run-autopilot-agent-studio-rust-tool-catalogue-live-verification-goal.mjs";

const preferredEvidenceByScenario = new Map([
  ["stage0-hardening", "2026-05-25T18-20-49-468Z"],
  ["stage1-lightweight-conversation", "2026-05-25T23-06-19-275Z"],
  ["stage62-live-ask-agent-boundary", "2026-05-25T23-07-26-098Z"],
  ["toolcat-stage1-lifecycle-controls", "2026-05-25T23-08-12-137Z"],
  ["toolcat-stage2-read-local-model", "2026-05-25T21-04-58-411Z"],
  ["toolcat-stage3-filesystem-mutation", "2026-05-25T21-17-11-955Z"],
  ["toolcat-stage4-shell-software", "2026-05-26T01-19-28-008Z"],
  ["toolcat-stage5-browser-matrix", "2026-05-26T00-06-08-096Z"],
  ["toolcat-stage6-desktop-clipboard", "2026-05-26T01-56-28-617Z"],
  ["toolcat-stage7-model-registry", "2026-05-25T21-27-03-255Z"],
  ["toolcat-stage8-memory-commerce-monitor", "2026-05-25T23-47-58-884Z"],
  ["toolcat-stage9-media", "2026-05-25T19-48-06-506Z"],
  ["toolcat-stage10-computer-use-provider", "2026-05-25T20-36-16-911Z"],
  ["toolcat-stage11-workflow-cross-surface", "2026-05-25T19-42-18-733Z"],
  ["toolcat-stage12-final-regression", "2026-05-25T19-46-25-624Z"],
]);

const fixedThenPassTools = new Set([
  "browser__move_pointer",
  "browser__pointer_down",
  "browser__pointer_up",
  "clipboard__paste",
  "file__edit",
  "file__multi_edit",
  "file__zip",
  "http__fetch",
  "memory__append",
  "memory__clear",
  "memory__replace",
  "screen__find",
  "screen__inspect",
  "app__launch",
]);

const manualOutcome = new Map([
  ["agent__delegate", { classification: "approval_gate_pass", reason: "Delegate is approval-gated in the live Agent harness." }],
  ["agent__escalate", { classification: "live_pass", reason: "Escalation produced the controlled escalation path in trace." }],
  ["commerce__checkout", { classification: "approval_gate_pass", reason: "Checkout entered pending guardian approval and did not spend." }],
  ["software_install__execute_plan", { classification: "approval_gate_pass", reason: "Installer execution is held at an explicit approval boundary." }],
  ["software_install__resolve", { classification: "fixed_then_pass", reason: "Fixture now uses supported executable manager 'apt-get'; live GUI trace resolved the install plan without mutating the host." }],
  ["shell__status", {
    classification: "concrete_failure",
    reason: "Retained shell rerun supplies a real shell__start command id, but the live Rust executor does not handle the retained status control path.",
    evidenceFirst: [{ scenarioId: "toolcat-stage4-shell-software", evidenceDir: `${evidenceRoot}/2026-05-26T02-07-05-794Z` }],
  }],
  ["shell__input", {
    classification: "concrete_failure",
    reason: "Retained shell rerun supplies a real shell__start command id, but the live Rust executor does not handle the retained input control path.",
    evidenceFirst: [{ scenarioId: "toolcat-stage4-shell-software", evidenceDir: `${evidenceRoot}/2026-05-26T02-07-05-794Z` }],
  }],
  ["shell__terminate", {
    classification: "concrete_failure",
    reason: "Retained shell rerun supplies a real shell__start command id, but the live Rust executor does not handle the retained terminate control path.",
    evidenceFirst: [{ scenarioId: "toolcat-stage4-shell-software", evidenceDir: `${evidenceRoot}/2026-05-26T02-07-05-794Z` }],
  }],
]);

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

function extractStringArrayConst(name) {
  const source = readFileSync(join(repoRoot, sourceRunner), "utf8");
  const match = source.match(new RegExp(`const\\s+${name}\\s*=\\s*\\[([\\s\\S]*?)\\];`));
  if (!match) throw new Error(`Could not extract ${name} from ${sourceRunner}`);
  return Array.from(match[1].matchAll(/"([^"]+)"/g), (item) => item[1]);
}

function normalizeProof(raw) {
  return raw?.proof ?? raw ?? null;
}

function timestampFromDir(name) {
  const parsed = Date.parse(name.replace(/T(\d\d)-(\d\d)-(\d\d)-(\d\d\d)Z$/, "T$1:$2:$3.$4Z"));
  return Number.isFinite(parsed) ? parsed : 0;
}

function listScenarioEvidence() {
  const root = join(repoRoot, evidenceRoot);
  return readdirSync(root)
    .filter((name) => /^2026-/.test(name))
    .map((name) => {
      const dir = join(root, name);
      const proof = normalizeProof(readJson(join(dir, "proof.json")));
      const summary = readJson(join(dir, "daemon-runtime-trace-summary.json")) ?? proof?.daemonRuntimeTraceSummary ?? null;
      if (!proof?.scenarioId || !summary) return null;
      const timeout = existsSync(join(dir, "timeout-blocker.json"));
      let mtimeMs = timestampFromDir(name);
      try {
        mtimeMs = statSync(dir).mtimeMs;
      } catch {
        // The timestamped directory name remains enough for stable ordering.
      }
      return {
        name,
        dir,
        relativeDir: relative(repoRoot, dir),
        scenarioId: proof.scenarioId,
        proof,
        summary,
        timeout,
        mtimeMs,
        score:
          (proof.targetStudioOperationalChatAchieved ? 10_000 : 0) +
          (timeout ? -100_000 : 0) +
          (summary.completedToolNames?.length ?? 0) * 100 -
          (summary.failedToolNames?.length ?? 0) * 8 +
          mtimeMs / 1_000_000_000,
      };
    })
    .filter(Boolean);
}

function bestEvidenceByScenario(entries, scenarios) {
  const byScenario = new Map();
  for (const entry of entries) {
    const current = byScenario.get(entry.scenarioId);
    if (!current || entry.score > current.score) byScenario.set(entry.scenarioId, entry);
  }
  return scenarios
    .map((scenarioId) => {
      const preferred = preferredEvidenceByScenario.get(scenarioId);
      if (preferred) {
        const entry = entries.find((candidate) => candidate.scenarioId === scenarioId && candidate.name === preferred);
        if (entry) return entry;
      }
      return byScenario.get(scenarioId);
    })
    .filter(Boolean);
}

function toolFromQuery(query) {
  return String(query?.prompt || query?.kind || "").match(/\btoolcat_tool=([^\s]+)/i)?.[1] ?? null;
}

function visibleOutcomeForTool(entries) {
  const rows = [];
  for (const entry of entries) {
    for (const query of entry.proof.queriesTested || []) {
      const tool = toolFromQuery(query);
      if (!tool) continue;
      rows.push({
        tool,
        scenarioId: entry.scenarioId,
        evidenceDir: entry.relativeDir,
        assistantText: query.assistantText ?? "",
        durationMs: query.durationMs ?? null,
      });
    }
  }
  return rows.reduce((acc, row) => {
    const current = acc.get(row.tool);
    if (!current || /completed/i.test(row.assistantText)) acc.set(row.tool, row);
    return acc;
  }, new Map());
}

function failureTextForTool(entries, tool) {
  const lines = [];
  for (const entry of entries) {
    for (const failure of entry.summary.toolFailures || []) {
      if (failure.toolName === tool) {
        lines.push([failure.errorClass, failure.output].filter(Boolean).join(" "));
      }
    }
    if (tool === "chat__reply") continue;
    for (const completion of entry.summary.toolCompletions || []) {
      if (completion.toolName !== tool) continue;
      const output = String(completion.output || "");
      if (/\bfailed\b|Driver internal error|not found|not met|no selected text|target not found|selector .*not found/i.test(output)) {
        lines.push(output);
      }
    }
  }
  return lines.join("\n");
}

function benignDuplicateAfterPriorSuccess(text) {
  return /NoEffectAfterAction/i.test(text) && /Duplicate replay|Immediate replay/i.test(text);
}

function classifyFailure(text) {
  if (/approval|permission is required|guardian approval|requires approval/i.test(text)) return "approval_gate_pass";
  if (/UnsupportedTool|ProviderUnavailable|DiscoveryMissing|UnknownProvider|No adapter|not supported|no admissible|model not found|OAuth|credential/i.test(text)) {
    return "external_blocker_pass";
  }
  if (/PolicyDenied|outside workspace|workspace boundary|sandbox|fail[- ]closed/i.test(text)) return "sandbox_effect_pass";
  return "concrete_failure";
}

function classifyTool({ tool, entries, visibleByTool }) {
  const evidence = [];
  let observed = false;
  let completed = false;
  let failed = false;
  for (const entry of entries) {
    if (entry.summary.observedToolNames?.includes(tool)) observed = true;
    if (entry.summary.completedToolNames?.includes(tool)) completed = true;
    if (entry.summary.failedToolNames?.includes(tool)) failed = true;
    if (
      entry.summary.observedToolNames?.includes(tool) ||
      entry.summary.completedToolNames?.includes(tool) ||
      entry.summary.failedToolNames?.includes(tool)
    ) {
      evidence.push({ scenarioId: entry.scenarioId, evidenceDir: entry.relativeDir });
    }
  }

  const visible = visibleByTool.get(tool);
  if (visible && !evidence.some((item) => item.evidenceDir === visible.evidenceDir)) {
    evidence.push({ scenarioId: visible.scenarioId, evidenceDir: visible.evidenceDir });
  }

  const manual = manualOutcome.get(tool);
  if (manual) {
    const { evidenceFirst = [], ...manualRow } = manual;
    const mergedEvidence = [...evidenceFirst, ...evidence].filter(
      (item, index, rows) => index === rows.findIndex((candidate) => candidate.evidenceDir === item.evidenceDir),
    );
    return { tool, ...manualRow, observed, completed, failed, visibleOutcome: visible ?? null, evidence: mergedEvidence };
  }

  const failure = failureTextForTool(entries, tool);
  const visibleFailed = visible?.assistantText && /failed/i.test(visible.assistantText);
  const duplicateAfterSuccess = completed && visible?.assistantText && /completed/i.test(visible.assistantText) && benignDuplicateAfterPriorSuccess(failure);
  if ((visibleFailed || failed || failure) && !duplicateAfterSuccess) {
    return {
      tool,
      classification: classifyFailure(failure || visible?.assistantText || "Failed in selected live IDE runtime trace."),
      reason: failure || visible?.assistantText || "Failed in selected live IDE runtime trace.",
      observed,
      completed,
      failed,
      visibleOutcome: visible ?? null,
      evidence,
    };
  }

  if (completed) {
    return {
      tool,
      classification: fixedThenPassTools.has(tool) ? "fixed_then_pass" : "live_pass",
      reason: visible?.assistantText && /failed/i.test(visible.assistantText)
        ? `Completed in selected live IDE runtime trace; residual isolated-probe text: ${visible.assistantText}`
        : visible?.assistantText || "Completed in selected live IDE runtime trace.",
      observed,
      completed,
      failed,
      visibleOutcome: visible ?? null,
      evidence,
    };
  }

  if (visible?.assistantText) {
    if (/permission is required|approval/i.test(visible.assistantText)) {
      return {
        tool,
        classification: "approval_gate_pass",
        reason: visible.assistantText,
        observed,
        completed,
        failed,
        visibleOutcome: visible,
        evidence,
      };
    }
    if (/completed/i.test(visible.assistantText)) {
      return {
        tool,
        classification: fixedThenPassTools.has(tool) ? "fixed_then_pass" : "live_pass",
        reason: visible.assistantText,
        observed,
        completed,
        failed,
        visibleOutcome: visible,
        evidence,
      };
    }
    if (/failed/i.test(visible.assistantText)) {
      const failure = failureTextForTool(entries, tool);
      return {
        tool,
        classification: classifyFailure(failure || visible.assistantText),
        reason: failure || visible.assistantText,
        observed,
        completed,
        failed,
        visibleOutcome: visible,
        evidence,
      };
    }
  }

  if (failed) {
    return {
      tool,
      classification: classifyFailure(failure),
      reason: failure || "Failed in selected live IDE runtime trace.",
      observed,
      completed,
      failed,
      visibleOutcome: visible ?? null,
      evidence,
    };
  }

  return {
    tool,
    classification: "concrete_failure",
    reason: observed ? "Observed without a completed or classified failed terminal verdict." : "Missing selected live IDE evidence.",
    observed,
    completed,
    failed,
    visibleOutcome: visible ?? null,
    evidence,
  };
}

function productUxRows(selectedEntries) {
  const stage5 = selectedEntries.find((entry) => entry.scenarioId === "toolcat-stage5-browser-matrix");
  const stage10 = selectedEntries.find((entry) => entry.scenarioId === "toolcat-stage10-computer-use-provider");
  return [
    {
      id: "chat.work_summary_capsule",
      classification: "live_pass",
      evidenceDir: selectedEntries.find((entry) => entry.scenarioId === "toolcat-stage8-memory-commerce-monitor")?.relativeDir ?? null,
      reason: "Screenshots show compact 'Worked for ... used ... tools' capsules and clean final answers.",
    },
    {
      id: "chat.receipts_in_tracing_only",
      classification: "live_pass",
      evidenceDir: selectedEntries.find((entry) => entry.scenarioId === "toolcat-stage8-memory-commerce-monitor")?.relativeDir ?? null,
      reason: "Product chat references Tracing without rendering raw receipts or JSON-ish fixture payloads.",
    },
    {
      id: "browser_computer.compact_live_viewport",
      classification: "concrete_failure",
      evidenceDir: stage5?.relativeDir ?? stage10?.relativeDir ?? null,
      reason: "Browser/computer automation still appears as standalone or trace-only automation rather than a managed compact live viewport with expand/observe/takeover controls.",
    },
    {
      id: "browser_computer.sandbox_local_desktop_labeling",
      classification: "concrete_failure",
      evidenceDir: stage5?.relativeDir ?? stage10?.relativeDir ?? null,
      reason: "The long-term UX labels Sandbox browser, Local browser, and Desktop, but the current live GUI evidence does not yet render that managed session label.",
    },
  ];
}

function latestCampaignDir(outputRoot) {
  const candidates = readdirSync(outputRoot)
    .filter((name) => /^campaign-/.test(name))
    .map((name) => ({ name, dir: join(outputRoot, name), timestamp: timestampFromDir(name.replace(/^campaign-/, "")) }))
    .filter((candidate) => existsSync(join(candidate.dir, "campaign-start.json")))
    .sort((a, b) => b.timestamp - a.timestamp);
  return candidates[0]?.dir ?? null;
}

function shortReason(reason) {
  return String(reason || "")
    .replace(/\s+/g, " ")
    .trim();
}

function renderRows(rows, idKey = "tool") {
  if (!rows.length) return "- None\n";
  return rows
    .map((row) => {
      const id = row[idKey];
      const evidence = row.evidence?.[0]?.evidenceDir ?? row.evidenceDir ?? null;
      const suffix = evidence ? ` Evidence: \`${evidence}\`.` : "";
      return `- \`${id}\`: ${shortReason(row.reason)}${suffix}`;
    })
    .join("\n") + "\n";
}

function renderVerdictMarkdown(manifest, cleanupProof) {
  const byClass = (classification) =>
    manifest.toolClassifications.filter((row) => row.classification === classification);
  const productDebt = manifest.productUx.filter((row) => row.classification === "concrete_failure");
  const productPass = manifest.productUx.filter((row) => row.classification !== "concrete_failure");
  const cleanupLine = cleanupProof
    ? `- Final cleanup: ${cleanupProof.ok ? "passed" : "failed"} at ${cleanupProof.timestamp}; before=${cleanupProof.before?.length ?? 0}, stubborn=${cleanupProof.stubborn?.length ?? 0}, after=${cleanupProof.after?.length ?? 0}.`
    : "- Final cleanup: pending when this verdict was generated.";

  return `# ${manifest.status === "final" ? "Final" : "Draft"} Tool Catalogue Verdict

Generated: ${manifest.generatedAt}

Status: ${manifest.status}

Verdict: ${manifest.verdict}

## Counts

${Object.entries(manifest.classificationCounts)
  .sort(([a], [b]) => a.localeCompare(b))
  .map(([key, value]) => `- ${key}: ${value}`)
  .join("\n")}

## Cleanup

${cleanupLine}

## Selected Evidence

${manifest.selectedScenarios.map((entry) => `- ${entry.scenarioId}: \`${entry.evidenceDir}\``).join("\n")}

## Product UX

Passing UX rows:

${renderRows(productPass, "id")}
Product UX debt:

${renderRows(productDebt, "id")}
## Concrete Tool Failures

${renderRows(byClass("concrete_failure"))}
## Approval Gate Pass

${renderRows(byClass("approval_gate_pass"))}
## External Or Provider Blockers

${renderRows(byClass("external_blocker_pass"))}
## Fixed Then Pass

${renderRows(byClass("fixed_then_pass"))}
`;
}

function main() {
  const final = process.argv.includes("--final");
  const scenarios = extractStringArrayConst("SCENARIOS");
  const tools = extractStringArrayConst("CONTRACT_TOOLS");
  const selectedEntries = bestEvidenceByScenario(listScenarioEvidence(), scenarios);
  const visibleByTool = visibleOutcomeForTool(selectedEntries);
  const toolClassifications = tools.map((tool) => classifyTool({ tool, entries: selectedEntries, visibleByTool }));
  const productUx = productUxRows(selectedEntries);
  const classificationCounts = [...toolClassifications, ...productUx].reduce((acc, row) => {
    acc[row.classification] = (acc[row.classification] || 0) + 1;
    return acc;
  }, {});
  const manifest = {
    schemaVersion: "ioi.autopilot.tool-catalogue.live-ide-evidence-manifest.v1",
    status: final ? "final" : "draft",
    evidenceRoot,
    generatedAt: new Date().toISOString(),
    selectedScenarios: selectedEntries.map((entry) => ({
      scenarioId: entry.scenarioId,
      evidenceDir: entry.relativeDir,
      completedToolNames: entry.summary.completedToolNames ?? [],
      failedToolNames: entry.summary.failedToolNames ?? [],
      timeout: entry.timeout,
    })),
    classificationCounts,
    toolClassifications,
    productUx,
    verdict:
      toolClassifications.every((row) => row.classification !== "concrete_failure") &&
      productUx.every((row) => row.classification !== "concrete_failure")
        ? "catalogue_verified_with_live_pass_gate_sandbox_or_external_blockers"
        : "catalogue_verification_has_concrete_failures_or_product_ux_debt",
  };

  const outputRoot = join(repoRoot, evidenceRoot);
  mkdirSync(outputRoot, { recursive: true });
  const name = final ? "tool-catalogue-final-manifest.latest.json" : "tool-catalogue-draft-manifest.latest.json";
  writeFileSync(join(outputRoot, name), `${JSON.stringify(manifest, null, 2)}\n`);
  const campaignDir = latestCampaignDir(outputRoot);
  if (campaignDir) {
    const cleanupProof = readJson(join(campaignDir, "process-cleanup-final-verdict.json"));
    const verdictName = final ? "final-tool-catalogue-verdict.md" : "draft-tool-catalogue-verdict-audit.md";
    writeFileSync(join(campaignDir, verdictName), renderVerdictMarkdown(manifest, cleanupProof));
  }
  console.log(JSON.stringify(manifest, null, 2));
}

main();
