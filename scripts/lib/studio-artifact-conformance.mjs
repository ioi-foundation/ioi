import fs from "fs";
import path from "path";

const DEFAULT_EVIDENCE_ROOT = path.join(
  "docs",
  "evidence",
  "studio-artifact-surface",
);
const DEFAULT_PRODUCTION_SOURCE_PATHS = [
  path.join("crates", "api", "src", "studio", "planning.rs"),
  path.join("crates", "api", "src", "studio", "generation.rs"),
  path.join("crates", "api", "src", "studio", "validation.rs"),
  path.join("crates", "api", "src", "studio", "payload.rs"),
  path.join("crates", "api", "src", "studio", "html_registry.rs"),
  path.join("apps", "autopilot", "src-tauri", "src", "kernel", "studio", "skills.rs"),
];

function readJsonIfExists(targetPath) {
  if (!targetPath || !fs.existsSync(targetPath)) {
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(targetPath, "utf8"));
  } catch {
    return null;
  }
}

function readTextIfExists(targetPath) {
  if (!targetPath || !fs.existsSync(targetPath)) {
    return "";
  }
  return fs.readFileSync(targetPath, "utf8");
}

function unique(values) {
  return Array.from(
    new Set(values.filter((value) => typeof value === "string" && value.trim())),
  );
}

function benchmarkBindingTokens(catalog) {
  const tokens = [];
  for (const benchmark of Array.isArray(catalog?.cases) ? catalog.cases : []) {
    if (typeof benchmark.benchmarkId === "string") {
      tokens.push(benchmark.benchmarkId);
    }
    for (const binding of Array.isArray(benchmark.caseBindings) ? benchmark.caseBindings : []) {
      if (typeof binding === "string") {
        tokens.push(binding);
      }
    }
  }
  return unique(tokens);
}

function selectedSkillNameTokens(corpusSummary) {
  return unique(
    (Array.isArray(corpusSummary?.cases) ? corpusSummary.cases : []).flatMap((entry) =>
      Array.isArray(entry?.selectedSkillNames) ? entry.selectedSkillNames : [],
    ),
  );
}

function scanFilesForTokens(sourceFiles, tokens) {
  const findings = [];
  for (const sourceFile of sourceFiles) {
    let contents = readTextIfExists(sourceFile.path);
    if (sourceFile.path.endsWith(".rs") && contents.includes("#[cfg(test)]")) {
      contents = contents.split("#[cfg(test)]")[0];
    }
    if (!contents) {
      continue;
    }
    for (const token of tokens) {
      if (!contents.includes(token)) {
        continue;
      }
      findings.push({
        path: sourceFile.relativePath,
        token,
      });
    }
  }
  return findings;
}

function buildSourceFileList(repoRoot, relativePaths = DEFAULT_PRODUCTION_SOURCE_PATHS) {
  return relativePaths.map((relativePath) => ({
    relativePath,
    path: path.join(repoRoot, relativePath),
  }));
}

function collectParaphraseInstability(corpusSummary, benchmarkCatalog) {
  const cases = Array.isArray(corpusSummary?.cases) ? corpusSummary.cases : [];
  const findings = [];

  for (const benchmark of Array.isArray(benchmarkCatalog?.cases)
    ? benchmarkCatalog.cases
    : []) {
    const bindings = Array.isArray(benchmark.caseBindings)
      ? benchmark.caseBindings.filter((value) => typeof value === "string")
      : [];
    if (bindings.length < 2) {
      continue;
    }
    const matched = bindings
      .map((binding) => cases.find((entry) => entry?.id === binding))
      .filter(Boolean);
    if (matched.length < 2) {
      continue;
    }

    const scaffoldFamilies = unique(matched.map((entry) => entry?.scaffoldFamily));
    if (scaffoldFamilies.length > 1) {
      findings.push({
        benchmarkId: benchmark.benchmarkId,
        kind: "scaffold_family_divergence",
        scaffoldFamilies,
      });
    }
  }

  return findings;
}

function collectShimDependentParitySuccesses(corpusSummary) {
  return (Array.isArray(corpusSummary?.benchmarkSuite?.cases)
    ? corpusSummary.benchmarkSuite.cases
    : []
  ).filter(
    (entry) =>
      entry?.trackedParityTarget === true &&
      entry?.matchedClassification === "pass" &&
      String(entry?.matchedVerificationStatus ?? "").toLowerCase() === "ready" &&
      entry?.shimDependent === true,
  );
}

function buildCheck(id, passed, summary, details = []) {
  return {
    id,
    status: passed ? "pass" : "fail",
    summary,
    details,
  };
}

export function collectStudioArtifactConformanceReport(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ?? path.join(repoRoot, DEFAULT_EVIDENCE_ROOT);
  const corpusSummary =
    options.corpusSummary ??
    readJsonIfExists(path.join(evidenceRoot, "corpus-summary.json"));
  const benchmarkCatalog =
    options.benchmarkCatalog ??
    readJsonIfExists(path.join(evidenceRoot, "benchmark-suite.catalog.json"));
  const sourceFiles = buildSourceFileList(repoRoot, options.productionSourcePaths);

  const benchmarkLeaks = scanFilesForTokens(
    sourceFiles,
    benchmarkBindingTokens(benchmarkCatalog),
  );
  const skillNameLeaks = scanFilesForTokens(
    sourceFiles,
    selectedSkillNameTokens(corpusSummary),
  );
  const paraphraseInstability = collectParaphraseInstability(
    corpusSummary,
    benchmarkCatalog,
  );
  const shimDependentParitySuccesses =
    collectShimDependentParitySuccesses(corpusSummary);

  const checks = [
    buildCheck(
      "benchmark_specific_routing",
      benchmarkLeaks.length === 0,
      benchmarkLeaks.length === 0
        ? "Production Studio sources do not contain benchmark ids or case-binding ids."
        : "Production Studio sources contain benchmark-specific ids.",
      benchmarkLeaks.map((finding) => `${finding.path} -> ${finding.token}`),
    ),
    buildCheck(
      "skill_name_routing",
      skillNameLeaks.length === 0,
      skillNameLeaks.length === 0
        ? "Production Studio sources do not route on retained concrete skill names."
        : "Production Studio sources contain retained concrete skill names.",
      skillNameLeaks.map((finding) => `${finding.path} -> ${finding.token}`),
    ),
    buildCheck(
      "paraphrase_stability",
      paraphraseInstability.length === 0,
      paraphraseInstability.length === 0
        ? "Benchmarks with multiple retained bindings keep a stable scaffold family."
        : "At least one benchmark diverges across paraphrase-equivalent bindings.",
      paraphraseInstability.map(
        (finding) =>
          `${finding.benchmarkId} -> ${finding.scaffoldFamilies.join(", ")}`,
      ),
    ),
    buildCheck(
      "shim_free_parity_success",
      shimDependentParitySuccesses.length === 0,
      shimDependentParitySuccesses.length === 0
        ? "Tracked parity targets do not count shim-dependent ready states as conformance wins."
        : "At least one tracked parity target is still shim-dependent while marked ready.",
      shimDependentParitySuccesses.map((entry) => entry.benchmarkId),
    ),
  ];

  return {
    generatedAt: new Date().toISOString(),
    repoRoot,
    evidenceRoot,
    passing: checks.every((check) => check.status === "pass"),
    checks,
  };
}
