#!/usr/bin/env node
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";

const repoRoot = process.cwd();
const evidenceRoot = "docs/evidence/autopilot-agent-studio-full-default-harness-parity";
const baselineManifestPath =
  "docs/evidence/autopilot-agent-studio-rust-tool-catalogue-live-ide-verification/tool-catalogue-final-manifest.latest.json";
const status = process.argv.includes("--final") ? "final" : "draft";

const defaultProviderDecision = new Map([
  ["model__embeddings", "optional_provider_external_blocker"],
  ["model__rerank", "optional_provider_external_blocker"],
  ["media__extract_transcript", "optional_provider_external_blocker"],
  ["media__extract_evidence", "optional_provider_external_blocker"],
  ["media__vision_read", "optional_provider_external_blocker"],
  ["media__transcribe_audio", "optional_provider_external_blocker"],
  ["media__generate_image", "optional_provider_external_blocker"],
  ["media__edit_image", "optional_provider_external_blocker"],
  ["media__generate_video", "optional_provider_external_blocker"],
  ["media__synthesize_speech", "optional_provider_external_blocker"],
  ["connector__toolcat__noop", "optional_provider_external_blocker"],
  ["computer_use.request_lease", "requires_default_harness_decision"],
]);

const ownerByRow = new Map([
  ["agent__await", "Rust agent lifecycle / subagent manager"],
  ["shell__status", "Rust tool executor / terminal driver"],
  ["shell__input", "Rust tool executor / terminal driver"],
  ["shell__terminate", "Rust tool executor / terminal driver"],
  ["browser__subagent", "Rust browser runtime / child agent routing"],
  ["screen__click", "Desktop UI driver / focus targeting"],
  ["screen__click_at", "Desktop UI driver / focus targeting"],
  ["screen__scroll", "Desktop UI driver / focus targeting"],
  ["memory__search", "Runtime memory service"],
  ["memory__read", "Runtime memory service"],
  ["browser_computer.compact_live_viewport", "Agent Studio run view / Tracing UX"],
  ["browser_computer.sandbox_local_desktop_labeling", "Agent Studio run view / Tracing UX"],
]);

function ownerForRow(rowId) {
  if (ownerByRow.has(rowId)) return ownerByRow.get(rowId);
  if (String(rowId).startsWith("browser__")) {
    return "Rust browser runtime / hermetic browser session fixture";
  }
  if (String(rowId).startsWith("retained_shell.")) {
    return "Agent Studio scenario driver / native fixture state / Rust decision loop";
  }
  return "Rust default harness parity owner";
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function maybeReadJson(path) {
  if (!existsSync(path)) return null;
  return readJson(path);
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function collectFiles(root, fileName) {
  const found = [];
  if (!existsSync(root)) return found;
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(path);
      } else if (entry.isFile() && entry.name === fileName) {
        found.push(path);
      }
    }
  }
  return found.sort((a, b) => statSync(a).mtimeMs - statSync(b).mtimeMs);
}

function shortReason(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text.length > 260 ? `${text.slice(0, 257)}...` : text;
}

function defaultClosureStrategy(rowId) {
  if (rowId === "agent__await") {
    return "Create a real child session, preserve the child id, await that id through live Agent Studio, and verify parent/child trace linkage.";
  }
  if (rowId.startsWith("shell__")) {
    return "Route retained shell controls through the System executor, then prove status/input/terminate against a disposable retained command.";
  }
  if (rowId.startsWith("browser__") && rowId !== "browser__subagent") {
    return "Use a managed hermetic browser session with stable fixture state instead of per-row hidden setup turns.";
  }
  if (rowId === "browser__subagent") {
    return "Admit the browser child-agent tool bundle and prove child output returns to the parent.";
  }
  if (rowId.startsWith("screen__")) {
    return "Use deterministic target window/session ids so focus-sensitive screen actions can operate on the disposable target.";
  }
  if (rowId.startsWith("memory__")) {
    return "Seed deterministic memory corpus ids and run search/read in the same namespace and ownership context.";
  }
  if (rowId.startsWith("browser_computer.")) {
    return "Render managed browser/computer session artifacts with compact preview, expanded observe view, labels, takeover controls, and Waiting for user state.";
  }
  return "Assign owner, reproduce through live GUI, fix the smallest responsible layer, and rerun focused proof.";
}

function reproductionForRow(rowId) {
  const scenarioPrefix =
    "AUTOPILOT_AGENT_STUDIO_EVIDENCE_ROOT=docs/evidence/autopilot-agent-studio-full-default-harness-parity node scripts/run-autopilot-agent-studio-chat-ux-hardening-goal.mjs --run --scenario";
  if (rowId === "agent__await") return `${scenarioPrefix} toolcat-stage1-lifecycle-controls`;
  if (rowId === "shell__terminate" || rowId === "retained_shell.live_control_sequence_latency") {
    return `${scenarioPrefix} toolcat-stage4-retained-shell-threaded-controls`;
  }
  if (rowId === "retained_shell.chain_marker_dispatch") {
    return `${scenarioPrefix} toolcat-stage4-retained-shell-controls`;
  }
  if (String(rowId).startsWith("browser__") || String(rowId).startsWith("browser_computer.")) {
    return `${scenarioPrefix} toolcat-stage5-browser-matrix`;
  }
  if (String(rowId).startsWith("screen__")) return `${scenarioPrefix} toolcat-stage6-desktop-clipboard`;
  if (String(rowId).startsWith("memory__")) return `${scenarioPrefix} toolcat-stage8-memory-commerce-monitor`;
  if (rowId === "computer_use.request_lease") return `${scenarioPrefix} toolcat-stage10-computer-use-provider`;
  return `${scenarioPrefix} toolcat-stage12-final-regression`;
}

function buildBaselineRows(baseline) {
  const concrete = baseline.toolClassifications
    .filter((row) => row.classification === "concrete_failure")
    .map((row) => ({
      rowId: row.tool,
      rowType: "tool",
      status: "open",
      baselineClassification: row.classification,
      currentClassification: row.classification,
      reason: row.reason,
      owner: ownerForRow(row.tool),
      closureStrategy: defaultClosureStrategy(row.tool),
      reproduction: reproductionForRow(row.tool),
      evidence: row.evidence || [],
      nextProofStep: "Run a focused live IDE GUI proof after the responsible fix lands.",
    }));

  const productDebt = baseline.productUx
    .filter((row) => row.classification === "concrete_failure")
    .map((row) => ({
      rowId: row.id,
      rowType: "product_ux",
      status: "open",
      baselineClassification: row.classification,
      currentClassification: row.classification,
      reason: row.reason,
      owner: ownerForRow(row.id),
      closureStrategy: defaultClosureStrategy(row.id),
      reproduction: reproductionForRow(row.id),
      evidence: row.evidenceDir ? [{ evidenceDir: row.evidenceDir }] : [],
      nextProofStep: "Capture compact and expanded live session screenshots through the real GUI.",
    }));

  const providerRows = baseline.toolClassifications
    .filter((row) => row.classification === "external_blocker_pass")
    .map((row) => {
      const decision = defaultProviderDecision.get(row.tool) || "requires_default_harness_decision";
      const optional = decision === "optional_provider_external_blocker";
      return {
        rowId: row.tool,
        rowType: "provider",
        status: optional ? "outside_default_harness_claim" : "open",
        baselineClassification: row.classification,
        currentClassification: row.classification,
        providerDecision: decision,
        reason: row.reason,
        owner: "Provider contract / harness availability",
        closureStrategy: optional
          ? "Keep outside the default harness parity claim; verify fail-closed copy and trace-side detail."
          : "Decide whether this is default harness scope; if yes, wire a hermetic adapter and live-prove it.",
        reproduction: reproductionForRow(row.tool),
        evidence: row.evidence || [],
        nextProofStep: optional
          ? "Retain as optional provider blocker in the final verdict with explicit contract note."
          : "Record default-vs-optional decision, then prove with hermetic adapter or exclude explicitly.",
      };
    });

  return [...concrete, ...productDebt, ...providerRows];
}

function applyClosureEvidence(rows) {
  const byId = new Map(rows.map((row) => [row.rowId, { ...row }]));
  for (const file of collectFiles(join(repoRoot, evidenceRoot), "parity-verdict.json")) {
    const verdict = maybeReadJson(file);
    if (!verdict) continue;
    const evidenceDir = relative(repoRoot, dirname(file));
    const rowUpdates = Array.isArray(verdict.rowUpdates)
      ? verdict.rowUpdates
      : verdict.rowId
        ? [
            {
              rowId: verdict.rowId,
              rowType: verdict.rowType || "tool",
              status:
                verdict.classification === "fixed_then_pass" ||
                verdict.verdict === "live_pass_after_fix"
                  ? "closed"
                  : "open",
              currentClassification: verdict.classification || verdict.currentClassification,
              reason: verdict.reason,
              evidence: [
                verdict.traceSummary
                  ? {
                      kind: "trace_summary",
                      path: verdict.traceSummary,
                      observedTool: verdict.rowId,
                    }
                  : null,
                verdict.cleanupProof
                  ? {
                      kind: "cleanup",
                      path: verdict.cleanupProof,
                    }
                  : null,
              ].filter(Boolean),
            },
          ]
        : [];
    for (const rawUpdate of rowUpdates) {
      const update = Object.fromEntries(
        Object.entries(rawUpdate).filter(([, value]) => value !== undefined),
      );
      const current = byId.get(update.rowId) || {
        rowId: update.rowId,
        rowType: update.rowType || "tool",
        status: "open",
        baselineClassification: "new",
        currentClassification: "not_run",
        owner: ownerForRow(update.rowId),
        closureStrategy: defaultClosureStrategy(update.rowId),
        reproduction: reproductionForRow(update.rowId),
        evidence: [],
      };
      byId.set(update.rowId, {
        ...current,
        ...update,
        evidence: [
          ...(update.evidence || []),
          ...(current.evidence || []),
          { scenarioId: verdict.scenarioId || verdict.stage || null, evidenceDir },
        ].filter(Boolean),
      });
    }
  }
  return Array.from(byId.values());
}

function countsForRows(rows) {
  return rows.reduce((acc, row) => {
    const key = row.status || row.currentClassification || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function finalVerdict(rows) {
  const blocking = rows.filter((row) =>
    !["closed", "outside_default_harness_claim", "approval_gate_pass"].includes(row.status),
  );
  if (blocking.length === 0) return "full_default_harness_parity_proven";
  const hasProductUx = blocking.some((row) => row.rowType === "product_ux");
  const hasProvider = blocking.some((row) => row.rowType === "provider");
  const hasRuntime = blocking.some((row) => !["product_ux", "provider"].includes(row.rowType));
  if (hasProductUx && hasRuntime) return "parity_blocked_by_runtime_and_product_ux_debt";
  if (hasProductUx) return "parity_blocked_by_product_ux_debt";
  if (hasProvider && hasRuntime) return "parity_blocked_by_runtime_and_provider_contract_decisions";
  if (hasProvider) return "parity_blocked_by_provider_contract_decisions";
  return "parity_blocked_by_runtime_failures";
}

function renderRows(rows) {
  if (!rows.length) return "- None\n";
  return rows
    .map((row) => {
      const evidence = row.evidence?.[0]?.evidenceDir ? ` Evidence: \`${row.evidence[0].evidenceDir}\`.` : "";
      const owner = row.owner ? ` Owner: ${row.owner}.` : "";
      const repro = row.reproduction ? ` Repro: \`${row.reproduction}\`.` : "";
      const next = row.nextProofStep ? ` Next: ${row.nextProofStep}` : "";
      return `- \`${row.rowId}\` (${row.status}): ${shortReason(row.reason)}${owner}${evidence}${repro}${next}`;
    })
    .join("\n") + "\n";
}

function renderMarkdown(manifest) {
  const openRows = manifest.rows.filter((row) => row.status === "open");
  const closedRows = manifest.rows.filter((row) => row.status === "closed");
  const outsideRows = manifest.rows.filter((row) => row.status === "outside_default_harness_claim");
  const cleanupLine = manifest.finalCleanupProof
    ? `\n## Final Cleanup\n\n- Proof: \`${manifest.finalCleanupProof.path}\`\n- OK: ${manifest.finalCleanupProof.ok}\n`
    : "";
  return `# ${manifest.status === "final" ? "Final" : "Draft"} Full Default Harness Parity Verdict

Generated: ${manifest.generatedAt}

Status: ${manifest.status}

Verdict: ${manifest.verdict}

## Counts

${Object.entries(manifest.counts)
  .sort(([a], [b]) => a.localeCompare(b))
  .map(([key, value]) => `- ${key}: ${value}`)
  .join("\n")}

## Closed Rows

${renderRows(closedRows)}
## Open Rows

${renderRows(openRows)}
## Outside Default Harness Claim

${renderRows(outsideRows)}
${cleanupLine}
`;
}

function main() {
  ensureDir(join(repoRoot, evidenceRoot));
  const baseline = readJson(join(repoRoot, baselineManifestPath));
  const rows = applyClosureEvidence(buildBaselineRows(baseline));
  const finalCleanupPath = join(evidenceRoot, "process-cleanup-final-closeout.json");
  const finalCleanupProof = maybeReadJson(join(repoRoot, finalCleanupPath));
  const manifest = {
    schemaVersion: "ioi.autopilot.full-default-harness-parity-manifest.v1",
    status,
    generatedAt: new Date().toISOString(),
    evidenceRoot,
    baselineManifest: baselineManifestPath,
    baselineVerdict: baseline.verdict,
    baselineCounts: baseline.classificationCounts,
    counts: countsForRows(rows),
    verdict: finalVerdict(rows),
    finalCleanupProof: finalCleanupProof
      ? {
          path: finalCleanupPath,
          ok: finalCleanupProof.ok === true,
          timestamp: finalCleanupProof.timestamp,
        }
      : null,
    rows,
  };

  const manifestName =
    status === "final"
      ? "tool-catalogue-full-default-harness-parity-final-manifest.json"
      : "tool-catalogue-full-default-harness-parity-draft-manifest.json";
  const markdownName =
    status === "final" ? "final-default-harness-parity-verdict.md" : "draft-default-harness-parity-verdict.md";
  writeFileSync(join(repoRoot, evidenceRoot, manifestName), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(join(repoRoot, evidenceRoot, markdownName), renderMarkdown(manifest));
  writeFileSync(join(repoRoot, evidenceRoot, "parity-baseline.json"), `${JSON.stringify({
    generatedAt: manifest.generatedAt,
    baselineManifest: baselineManifestPath,
    rows: buildBaselineRows(baseline),
  }, null, 2)}\n`);
  console.log(JSON.stringify({
    status: manifest.status,
    verdict: manifest.verdict,
    counts: manifest.counts,
    manifest: join(evidenceRoot, manifestName),
    markdown: join(evidenceRoot, markdownName),
  }, null, 2));
}

main();
