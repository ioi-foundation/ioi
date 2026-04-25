import fs from "fs";
import path from "path";

import { collectChatArtifactCorpusIndex } from "./chat-artifact-corpus.mjs";

export const DEFAULT_ARENA_LEDGER_PATH = path.join("arena", "ledger.json");
const DEFAULT_BENCHMARK_CATALOG_NAME = "benchmark-suite.catalog.json";
const DEFAULT_PAIRWISE_MATCHES_PATH = path.join("arena", "pairwise-matches.json");
const DEFAULT_EXTERNAL_REFERENCES_PATH = path.join(
  "arena",
  "external-references.json",
);

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

function roundMetric(value, digits = 3) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function sanitizeToken(value, fallback = "unknown") {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return normalized || fallback;
}

function humanizeToken(value, fallback = "Unknown") {
  const normalized = String(value ?? "")
    .trim()
    .replace(/[_:.-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!normalized) {
    return fallback;
  }
  return normalized.replace(/\b[a-z]/g, (char) => char.toUpperCase());
}

function sanitizeRuntimeKind(value) {
  const normalized = sanitizeToken(value, "unknown");
  switch (normalized) {
    case "fixture_runtime":
      return "fixture";
    case "real_local_runtime":
      return "local_runtime";
    case "real_remote_runtime":
      return "remote_runtime";
    default:
      return normalized;
  }
}

function runtimeLabel(value) {
  switch (sanitizeRuntimeKind(value)) {
    case "fixture":
      return "Fixture";
    case "local_runtime":
      return "Local Runtime";
    case "remote_runtime":
      return "Remote Runtime";
    case "chat_runtime":
      return "Chat Runtime";
    case "validation_runtime":
      return "Validation Runtime";
    default:
      return humanizeToken(value);
  }
}

function stripVendorWords(value) {
  return String(value ?? "")
    .replace(/\b(claude|anthropic|opus|sonnet|gemini|google|openai|chatgpt)\b/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function relativeEvidenceDisplayPath(evidenceRoot, targetPath) {
  if (!targetPath || typeof targetPath !== "string" || !fs.existsSync(targetPath)) {
    return null;
  }
  const relative = path.relative(evidenceRoot, targetPath);
  return relative && !relative.startsWith("..")
    ? relative.split(path.sep).join("/")
    : targetPath;
}

function classificationRank(classification) {
  switch (String(classification || "").trim().toLowerCase()) {
    case "pass":
    case "ready":
      return 3;
    case "repairable":
    case "partial":
      return 2;
    default:
      return 1;
  }
}

function compareExecutionsForLeader(left, right) {
  const leftClassification = classificationRank(
    left?.classification ?? left?.effectiveClassification,
  );
  const rightClassification = classificationRank(
    right?.classification ?? right?.effectiveClassification,
  );
  if (leftClassification !== rightClassification) {
    return rightClassification - leftClassification;
  }
  const leftJudge = left?.validationScore ?? -Infinity;
  const rightJudge = right?.validationScore ?? -Infinity;
  if (leftJudge !== rightJudge) {
    return rightJudge - leftJudge;
  }
  const leftRender = left?.screenshotQualityScore ?? -Infinity;
  const rightRender = right?.screenshotQualityScore ?? -Infinity;
  if (leftRender !== rightRender) {
    return rightRender - leftRender;
  }
  const leftFirstPaint = left?.firstPaintEvidenceScore ?? -Infinity;
  const rightFirstPaint = right?.firstPaintEvidenceScore ?? -Infinity;
  if (leftFirstPaint !== rightFirstPaint) {
    return rightFirstPaint - leftFirstPaint;
  }
  const leftResponsive = left?.responsivenessScore ?? -Infinity;
  const rightResponsive = right?.responsivenessScore ?? -Infinity;
  if (leftResponsive !== rightResponsive) {
    return rightResponsive - leftResponsive;
  }
  if (Boolean(left?.shimDependent) !== Boolean(right?.shimDependent)) {
    return left?.shimDependent ? 1 : -1;
  }
  const leftSkills = Number(left?.selectedSkillCount ?? 0);
  const rightSkills = Number(right?.selectedSkillCount ?? 0);
  if (leftSkills !== rightSkills) {
    return rightSkills - leftSkills;
  }
  const leftExemplars = Number(left?.retrievedExemplarCount ?? 0);
  const rightExemplars = Number(right?.retrievedExemplarCount ?? 0);
  if (leftExemplars !== rightExemplars) {
    return rightExemplars - leftExemplars;
  }
  const leftTime = Date.parse(`${left?.dateRoot ?? ""}T00:00:00.000Z`) || 0;
  const rightTime = Date.parse(`${right?.dateRoot ?? ""}T00:00:00.000Z`) || 0;
  if (leftTime !== rightTime) {
    return rightTime - leftTime;
  }
  return String(left?.executionId ?? left?.caseId ?? "").localeCompare(
    String(right?.executionId ?? right?.caseId ?? ""),
  );
}

function normalizePairwiseMatches(parsed) {
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (parsed && typeof parsed === "object" && Array.isArray(parsed.matches)) {
    return parsed.matches;
  }
  return [];
}

function normalizeExternalReferences(parsed) {
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (parsed && typeof parsed === "object" && Array.isArray(parsed.references)) {
    return parsed.references;
  }
  return [];
}

function benchmarkLookup(catalog) {
  const byBenchmarkId = new Map();
  for (const benchmark of Array.isArray(catalog?.cases) ? catalog.cases : []) {
    if (typeof benchmark?.benchmarkId === "string" && benchmark.benchmarkId.trim()) {
      byBenchmarkId.set(benchmark.benchmarkId, benchmark);
    }
  }
  return { byBenchmarkId };
}

function latestEntriesByCaseId(cases) {
  const byCaseId = new Map();
  for (const entry of Array.isArray(cases) ? cases : []) {
    if (!entry || typeof entry !== "object" || typeof entry.id !== "string") {
      continue;
    }
    const current = byCaseId.get(entry.id);
    if (!current) {
      byCaseId.set(entry.id, entry);
      continue;
    }
    const currentTime = Number(current.sortTimestampMs ?? 0);
    const nextTime = Number(entry.sortTimestampMs ?? 0);
    if (nextTime > currentTime) {
      byCaseId.set(entry.id, entry);
    }
  }
  return byCaseId;
}

function normalizeList(values) {
  return Array.from(
    new Set(
      Array.isArray(values)
        ? values.filter((value) => typeof value === "string" && value.trim())
        : [],
    ),
  ).sort();
}

function deriveInternalExecution(entry, benchmarkId) {
  const generatorRuntime = sanitizeRuntimeKind(entry?.productionProvenanceKind || "default");
  const validationRuntime = sanitizeRuntimeKind(entry?.acceptanceProvenanceKind || "default");
  const generatorStackId = `generator:${sanitizeToken(generatorRuntime || "default")}`;
  const validationStackId = `validation:${sanitizeToken(validationRuntime || "default")}`;
  const scaffoldFamilyId = `scaffold:${sanitizeToken(entry?.scaffoldFamily || "unspecified")}`;
  const componentPackFamilies = normalizeList(entry?.componentFamilies);
  const componentPackProfileId = `component_profile:${sanitizeToken(
    componentPackFamilies.length > 0 ? componentPackFamilies.join("+") : "none",
  )}`;
  const skillNames = normalizeList(entry?.selectedSkillNames);
  const skillSpineId = `skill_spine:${sanitizeToken(
    skillNames.length > 0 ? skillNames.join("+") : "none",
  )}`;
  const compositeStackId = `stack:${sanitizeToken(
    [
      generatorRuntime,
      validationRuntime !== generatorRuntime ? `validation_${validationRuntime}` : null,
      entry?.scaffoldFamily || "unspecified",
      componentPackFamilies.length > 0 ? componentPackFamilies.join("+") : null,
      skillNames.length > 0 ? skillNames.join("+") : null,
    ]
      .filter(Boolean)
      .join("__"),
  )}`;
  const executionId = `${benchmarkId}:${entry.id}:${sanitizeToken(entry?.dateRoot || "latest")}`;
  const generatorStackLabel = runtimeLabel(generatorRuntime);
  const validationStackLabel = runtimeLabel(validationRuntime);
  const scaffoldFamilyLabel = humanizeToken(entry?.scaffoldFamily || "unspecified");
  const componentPackProfileLabel =
    componentPackFamilies.length > 0
      ? componentPackFamilies.map((value) => humanizeToken(value)).join(" + ")
      : "No Shared Components";
  const skillSpineLabel =
    skillNames.length > 0
      ? skillNames.map((value) => humanizeToken(value)).join(" + ")
      : "No Promoted Skill";
  const compositeStackLabel = [
    generatorStackLabel,
    scaffoldFamilyLabel,
    skillNames.length > 0 ? skillSpineLabel : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return {
    entityType: "internal_execution",
    benchmarkId,
    executionId,
    caseId: entry?.id ?? null,
    dateRoot: entry?.dateRoot ?? null,
    summaryPath: entry?.summaryPath ?? null,
    classification: entry?.effectiveClassification ?? entry?.classification ?? "blocked",
    validationScore: entry?.validationScore ?? null,
    firstPaintEvidenceScore: entry?.firstPaintEvidenceScore ?? null,
    screenshotQualityScore: entry?.screenshotQualityScore ?? null,
    responsivenessScore: entry?.responsivenessScore ?? null,
    shimDependent: entry?.shimDependent === true,
    blueprintPresent: entry?.blueprintPresent === true,
    artifactIrPresent: entry?.artifactIrPresent === true,
    selectedSkillCount: Number(entry?.selectedSkillCount ?? 0),
    retrievedExemplarCount: Number(entry?.retrievedExemplarCount ?? 0),
    generatorStackId,
    generatorStackLabel,
    validationStackId,
    validationStackLabel,
    scaffoldFamilyId,
    scaffoldFamilyLabel,
    componentPackFamilies,
    componentPackProfileId,
    componentPackProfileLabel,
    skillSpineId,
    skillSpineLabel,
    compositeStackId,
    compositeStackLabel,
    label: entry?.id ?? executionId,
    participantAliases: normalizeList([
      compositeStackId,
      generatorStackId,
      validationStackId,
      scaffoldFamilyId,
      componentPackProfileId,
      skillSpineId,
    ]),
  };
}

function normalizeExternalReference(entry) {
  const rawParticipantId =
    typeof entry?.participant === "string" && entry.participant.trim()
      ? entry.participant
      : typeof entry?.referenceParticipant === "string" && entry.referenceParticipant.trim()
        ? entry.referenceParticipant
        : "reference:external";
  const participantId =
    rawParticipantId.startsWith("reference:")
      ? `reference:${sanitizeToken(stripVendorWords(rawParticipantId.replace(/^reference:/, "")) || "external_reference")}`
      : sanitizeToken(stripVendorWords(rawParticipantId), "external_reference");
  const componentPackFamilies = normalizeList(
    entry?.componentPackFamilies ??
      entry?.componentFamilies ??
      entry?.componentPackProfile?.families,
  );
  const componentPackProfileId =
    typeof entry?.componentPackProfileId === "string" && entry.componentPackProfileId.trim()
      ? entry.componentPackProfileId
      : componentPackFamilies.length > 0
        ? `component_profile:${sanitizeToken(componentPackFamilies.join("+"))}`
        : null;
  const skillNames = normalizeList(entry?.skillNames ?? entry?.skillSpineNames);
  const skillSpineId =
    typeof entry?.skillSpineId === "string" && entry.skillSpineId.trim()
      ? entry.skillSpineId
      : skillNames.length > 0
        ? `skill_spine:${sanitizeToken(skillNames.join("+"))}`
        : null;

  const externalLabelSource =
    typeof entry?.label === "string" && entry.label.trim()
      ? stripVendorWords(entry.label)
      : typeof entry?.title === "string" && entry.title.trim()
        ? stripVendorWords(entry.title)
        : "";
  const externalLabel =
    externalLabelSource.length > 0
      ? humanizeToken(externalLabelSource)
      : "External Reference";

  return {
    entityType: "external_reference",
    benchmarkId:
      typeof entry?.benchmarkId === "string" && entry.benchmarkId.trim()
        ? entry.benchmarkId
        : "unknown-benchmark",
    participantId,
    label: externalLabel,
    artifactPath: typeof entry?.artifactPath === "string" ? entry.artifactPath : null,
    summaryPath: typeof entry?.summaryPath === "string" ? entry.summaryPath : null,
    generatorStackId:
      typeof entry?.generatorStackId === "string" ? entry.generatorStackId : null,
    validationStackId: typeof entry?.validationStackId === "string" ? entry.validationStackId : null,
    scaffoldFamilyId:
      typeof entry?.scaffoldFamilyId === "string" ? entry.scaffoldFamilyId : null,
    componentPackFamilies,
    componentPackProfileId,
    skillSpineId,
    compositeStackId:
      typeof entry?.compositeStackId === "string" ? entry.compositeStackId : participantId,
    participantAliases: normalizeList([
      participantId,
      rawParticipantId,
      entry?.compositeStackId,
      entry?.generatorStackId,
      entry?.validationStackId,
      entry?.scaffoldFamilyId,
      componentPackProfileId,
      skillSpineId,
    ]),
  };
}

function buildExternalReferenceMaps(externalReferences) {
  const byBenchmarkId = new Map();
  const byKey = new Map();
  for (const reference of externalReferences) {
    if (!byBenchmarkId.has(reference.benchmarkId)) {
      byBenchmarkId.set(reference.benchmarkId, []);
    }
    byBenchmarkId.get(reference.benchmarkId).push(reference);
    for (const alias of reference.participantAliases) {
      const key = `${reference.benchmarkId}::${alias}`;
      if (!byKey.has(key)) {
        byKey.set(key, []);
      }
      byKey.get(key).push(reference);
    }
  }
  return { byBenchmarkId, byKey };
}

function buildInternalExecutionMaps(executions) {
  const byExecutionId = new Map();
  const byBenchmarkId = new Map();
  const byAliasKey = new Map();
  for (const execution of executions) {
    byExecutionId.set(execution.executionId, execution);
    if (!byBenchmarkId.has(execution.benchmarkId)) {
      byBenchmarkId.set(execution.benchmarkId, []);
    }
    byBenchmarkId.get(execution.benchmarkId).push(execution);
    for (const alias of execution.participantAliases) {
      const key = `${execution.benchmarkId}::${alias}`;
      if (!byAliasKey.has(key)) {
        byAliasKey.set(key, []);
      }
      byAliasKey.get(key).push(execution);
    }
  }
  return { byExecutionId, byBenchmarkId, byAliasKey };
}

function normalizeWinner(match) {
  const winner = String(match?.winner ?? "draw").trim();
  if (!winner || winner === "draw" || winner === "tie") {
    return "draw";
  }
  if (winner === "left" || winner === "right") {
    return winner;
  }
  if (winner === match?.leftParticipant) {
    return "left";
  }
  if (winner === match?.rightParticipant) {
    return "right";
  }
  return "draw";
}

function resolveArenaEntity({
  benchmarkId,
  executionId,
  participantId,
  executionMaps,
  externalMaps,
}) {
  if (typeof executionId === "string" && executionMaps.byExecutionId.has(executionId)) {
    return executionMaps.byExecutionId.get(executionId);
  }
  if (typeof participantId === "string" && participantId.trim()) {
    const internalMatches = executionMaps.byAliasKey.get(`${benchmarkId}::${participantId}`) ?? [];
    if (internalMatches.length === 1) {
      return internalMatches[0];
    }
    const externalMatches = externalMaps.byKey.get(`${benchmarkId}::${participantId}`) ?? [];
    if (externalMatches.length === 1) {
      return externalMatches[0];
    }
  }
  return null;
}

function buildResolvedPairwiseMatches({
  pairwiseMatches,
  executionMaps,
  externalMaps,
}) {
  const normalizedMatches = normalizePairwiseMatches(pairwiseMatches)
    .filter((match) => match && typeof match === "object")
    .map((match, index) => {
      const benchmarkId =
        typeof match.benchmarkId === "string" ? match.benchmarkId : "unknown-benchmark";
      const leftParticipant =
        typeof match.leftParticipant === "string" ? match.leftParticipant : null;
      const rightParticipant =
        typeof match.rightParticipant === "string" ? match.rightParticipant : null;
      const leftExecutionId =
        typeof match.leftExecutionId === "string" ? match.leftExecutionId : null;
      const rightExecutionId =
        typeof match.rightExecutionId === "string" ? match.rightExecutionId : null;
      const leftEntity = resolveArenaEntity({
        benchmarkId,
        executionId: leftExecutionId,
        participantId: leftParticipant,
        executionMaps,
        externalMaps,
      });
      const rightEntity = resolveArenaEntity({
        benchmarkId,
        executionId: rightExecutionId,
        participantId: rightParticipant,
        executionMaps,
        externalMaps,
      });
      const winner = normalizeWinner(match);

      return {
        matchId:
          typeof match.matchId === "string" && match.matchId.trim()
            ? match.matchId
            : `${benchmarkId}:match:${index + 1}`,
        benchmarkId,
        blind: match.blind !== false,
        rationale: typeof match.rationale === "string" ? match.rationale : null,
        leftParticipant,
        rightParticipant,
        leftExecutionId,
        rightExecutionId,
        leftEntity,
        rightEntity,
        winner,
        externalReferenceParticipant:
          typeof match.externalReferenceParticipant === "string"
            ? match.externalReferenceParticipant
            : null,
      };
    })
    .filter((match) => match.leftParticipant && match.rightParticipant);

  return normalizedMatches;
}

function benchmarkPairwiseKey(match) {
  const leftKey =
    typeof match.leftExecutionId === "string" && match.leftExecutionId
      ? `execution:${match.leftExecutionId}`
      : `participant:${match.leftParticipant}`;
  const rightKey =
    typeof match.rightExecutionId === "string" && match.rightExecutionId
      ? `execution:${match.rightExecutionId}`
      : `participant:${match.rightParticipant}`;
  return `${match.benchmarkId}::${[leftKey, rightKey].sort().join("::")}`;
}

function entityDimensionId(entity, dimension) {
  if (!entity || typeof entity !== "object") {
    return null;
  }
  switch (dimension) {
    case "compositeStacks":
      return entity.compositeStackId ?? entity.participantId ?? null;
    case "generatorStacks":
      return entity.generatorStackId ?? null;
    case "validationStacks":
      return entity.validationStackId ?? null;
    case "scaffoldFamilies":
      return entity.scaffoldFamilyId ?? null;
    case "componentPackProfiles":
      return entity.componentPackProfileId ?? null;
    case "skillSpines":
      return entity.skillSpineId ?? null;
    default:
      return null;
  }
}

function entityDimensionLabel(entity, dimension) {
  if (!entity || typeof entity !== "object") {
    return null;
  }
  switch (dimension) {
    case "compositeStacks":
      return entity.compositeStackLabel ?? entity.label ?? entity.compositeStackId ?? null;
    case "generatorStacks":
      return entity.generatorStackLabel ?? entity.generatorStackId ?? null;
    case "validationStacks":
      return entity.validationStackLabel ?? entity.validationStackId ?? null;
    case "scaffoldFamilies":
      return entity.scaffoldFamilyLabel ?? entity.scaffoldFamilyId ?? null;
    case "componentPackProfiles":
      return entity.componentPackProfileLabel ?? entity.componentPackProfileId ?? null;
    case "skillSpines":
      return entity.skillSpineLabel ?? entity.skillSpineId ?? null;
    default:
      return entity.label ?? null;
  }
}

function buildEloSummary(matches, dimension) {
  const projectedMatches = [];
  for (const match of Array.isArray(matches) ? matches : []) {
    const leftParticipant = entityDimensionId(match.leftEntity, dimension);
    const rightParticipant = entityDimensionId(match.rightEntity, dimension);
    if (!leftParticipant || !rightParticipant || leftParticipant === rightParticipant) {
      continue;
    }
    projectedMatches.push({
      leftParticipant,
      leftLabel: entityDimensionLabel(match.leftEntity, dimension),
      rightParticipant,
      rightLabel: entityDimensionLabel(match.rightEntity, dimension),
      winner: match.winner,
      blind: match.blind,
      benchmarkId: match.benchmarkId,
    });
  }

  if (projectedMatches.length === 0) {
    return {
      available: false,
      matchCount: 0,
      blindMatchCount: 0,
      participantCount: 0,
      ratings: [],
    };
  }

  const K_FACTOR = 24;
  const ratings = new Map();
  const records = new Map();
  const ensureParticipant = (participant, label = null) => {
    if (!ratings.has(participant)) {
      ratings.set(participant, 1500);
      records.set(participant, {
        participant,
        label: label ?? participant,
        wins: 0,
        losses: 0,
        draws: 0,
        matches: 0,
      });
    }
    if (label && records.get(participant)?.label === participant) {
      records.get(participant).label = label;
    }
    return records.get(participant);
  };

  for (const match of projectedMatches) {
    const leftRecord = ensureParticipant(match.leftParticipant, match.leftLabel);
    const rightRecord = ensureParticipant(match.rightParticipant, match.rightLabel);
    const leftRating = ratings.get(match.leftParticipant);
    const rightRating = ratings.get(match.rightParticipant);
    const expectedLeft = 1 / (1 + 10 ** ((rightRating - leftRating) / 400));
    const expectedRight = 1 - expectedLeft;
    let actualLeft = 0.5;
    let actualRight = 0.5;
    if (match.winner === "left") {
      actualLeft = 1;
      actualRight = 0;
      leftRecord.wins += 1;
      rightRecord.losses += 1;
    } else if (match.winner === "right") {
      actualLeft = 0;
      actualRight = 1;
      leftRecord.losses += 1;
      rightRecord.wins += 1;
    } else {
      leftRecord.draws += 1;
      rightRecord.draws += 1;
    }
    leftRecord.matches += 1;
    rightRecord.matches += 1;
    ratings.set(match.leftParticipant, leftRating + K_FACTOR * (actualLeft - expectedLeft));
    ratings.set(match.rightParticipant, rightRating + K_FACTOR * (actualRight - expectedRight));
  }

  return {
    available: true,
    matchCount: projectedMatches.length,
    blindMatchCount: projectedMatches.filter((match) => match.blind).length,
    participantCount: ratings.size,
    ratings: Array.from(records.values())
      .map((record) => ({
        ...record,
        rating: roundMetric(ratings.get(record.participant), 1),
      }))
      .sort(
        (left, right) =>
          right.rating - left.rating || left.participant.localeCompare(right.participant),
      ),
  };
}

function summarizeBlindWinner({ internalExecutions, externalReferences, pairwiseMatches }) {
  const scoreboard = new Map();
  const register = (entity) => {
    if (!entity) {
      return null;
    }
    const participantId = entity.compositeStackId ?? entity.participantId ?? entity.executionId;
    if (!participantId) {
      return null;
    }
    if (!scoreboard.has(participantId)) {
      scoreboard.set(participantId, {
        participant: participantId,
        label: entity.label ?? participantId,
        source:
          entity.entityType === "external_reference" ? "external_reference" : "internal_execution",
        executionId: entity.executionId ?? null,
        caseId: entity.caseId ?? null,
        wins: 0,
        losses: 0,
        draws: 0,
        matches: 0,
      });
    }
    return scoreboard.get(participantId);
  };

  for (const execution of internalExecutions) {
    register(execution);
  }
  for (const reference of externalReferences) {
    register(reference);
  }

  for (const match of pairwiseMatches) {
    const left = register(match.leftEntity);
    const right = register(match.rightEntity);
    if (!left || !right) {
      continue;
    }
    if (match.winner === "left") {
      left.wins += 1;
      right.losses += 1;
    } else if (match.winner === "right") {
      left.losses += 1;
      right.wins += 1;
    } else {
      left.draws += 1;
      right.draws += 1;
    }
    left.matches += 1;
    right.matches += 1;
  }

  const ranked = Array.from(scoreboard.values())
    .filter((entry) => entry.matches > 0)
    .sort((left, right) => {
      if (left.wins !== right.wins) {
        return right.wins - left.wins;
      }
      if (left.losses !== right.losses) {
        return left.losses - right.losses;
      }
      if (left.draws !== right.draws) {
        return right.draws - left.draws;
      }
      return left.participant.localeCompare(right.participant);
    });

  if (ranked.length === 0) {
    return null;
  }
  const top = ranked[0];
  const next = ranked[1] ?? null;
  const unique =
    !next ||
    top.wins !== next.wins ||
    top.losses !== next.losses ||
    top.draws !== next.draws;

  return {
    available: true,
    unique,
    participant: top.participant,
    label: top.label,
    source: top.source,
    caseId: top.caseId,
    executionId: top.executionId,
    pairwiseMatchCount: pairwiseMatches.length,
    blindMatchCount: pairwiseMatches.filter((match) => match.blind).length,
    scoreboard: ranked,
  };
}

function buildPendingBlindMatches({
  benchmarkId,
  internalExecutions,
  externalReferences,
  existingPairwiseMatches,
}) {
  const existingKeys = new Set(existingPairwiseMatches.map(benchmarkPairwiseKey));
  const pending = [];

  for (let index = 0; index < internalExecutions.length; index += 1) {
    for (let compareIndex = index + 1; compareIndex < internalExecutions.length; compareIndex += 1) {
      const left = internalExecutions[index];
      const right = internalExecutions[compareIndex];
      const candidate = {
        benchmarkId,
        leftParticipant: left.compositeStackId,
        rightParticipant: right.compositeStackId,
        leftExecutionId: left.executionId,
        rightExecutionId: right.executionId,
      };
      if (existingKeys.has(benchmarkPairwiseKey(candidate))) {
        continue;
      }
      pending.push({
        matchId: `${benchmarkId}:blind:${sanitizeToken(left.executionId)}:${sanitizeToken(
          right.executionId,
        )}`,
        benchmarkId,
        blind: true,
        rationale: "Compare internal stack variants on the same benchmark before promoting a winner.",
        leftParticipant: left.compositeStackId,
        rightParticipant: right.compositeStackId,
        leftExecutionId: left.executionId,
        rightExecutionId: right.executionId,
        leftLabel: left.label,
        rightLabel: right.label,
      });
    }
  }

  for (const execution of internalExecutions) {
    for (const reference of externalReferences) {
      const candidate = {
        benchmarkId,
        leftParticipant: execution.compositeStackId,
        rightParticipant: reference.participantId,
        leftExecutionId: execution.executionId,
        rightExecutionId: null,
      };
      if (existingKeys.has(benchmarkPairwiseKey(candidate))) {
        continue;
      }
      pending.push({
        matchId: `${benchmarkId}:blind:${sanitizeToken(execution.executionId)}:${sanitizeToken(
          reference.participantId,
        )}`,
        benchmarkId,
        blind: true,
        rationale:
          "Compare the strongest internal execution against the retained external reference artifact.",
        leftParticipant: execution.compositeStackId,
        rightParticipant: reference.participantId,
        leftExecutionId: execution.executionId,
        rightExecutionId: null,
        leftLabel: execution.label,
        rightLabel: reference.label,
      });
    }
  }

  return pending;
}

function buildParticipantCatalog(internalExecutions, dimension) {
  const catalog = new Map();
  for (const execution of internalExecutions) {
    const participantId = entityDimensionId(execution, dimension);
    if (!participantId) {
      continue;
    }
    const current = catalog.get(participantId) ?? {
      participant: participantId,
      label: entityDimensionLabel(execution, dimension) ?? participantId,
      executionCount: 0,
      benchmarkIds: [],
      caseIds: [],
      labels: new Set(),
    };
    current.executionCount += 1;
    if (typeof execution.benchmarkId === "string") {
      current.benchmarkIds.push(execution.benchmarkId);
    }
    if (typeof execution.caseId === "string") {
      current.caseIds.push(execution.caseId);
    }
    if (typeof execution.label === "string") {
      current.labels.add(execution.label);
    }
    catalog.set(participantId, current);
  }
  return Array.from(catalog.values())
    .map((entry) => ({
      participant: entry.participant,
      label: entry.label,
      benchmarkCount: Array.from(new Set(entry.benchmarkIds)).length,
      executionCount: entry.executionCount,
      caseIds: Array.from(new Set(entry.caseIds)).sort(),
      labels: Array.from(entry.labels).sort(),
    }))
    .sort((left, right) => right.executionCount - left.executionCount || left.participant.localeCompare(right.participant));
}

export function collectChatArtifactArenaLedger(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const summaryPath =
    options.summaryPath ?? path.join(evidenceRoot, "corpus-summary.json");
  const benchmarkCatalogPath =
    options.benchmarkCatalogPath ??
    path.join(evidenceRoot, DEFAULT_BENCHMARK_CATALOG_NAME);
  const pairwiseMatchesPath =
    options.pairwiseMatchesPath ??
    path.join(evidenceRoot, DEFAULT_PAIRWISE_MATCHES_PATH);
  const externalReferencesPath =
    options.externalReferencesPath ??
    path.join(evidenceRoot, DEFAULT_EXTERNAL_REFERENCES_PATH);

  const corpusSummary =
    options.corpusSummary ??
    (fs.existsSync(summaryPath)
      ? readJsonIfExists(summaryPath)
      : collectChatArtifactCorpusIndex({ repoRoot, evidenceRoot }));
  const benchmarkCatalog =
    options.benchmarkCatalog ?? readJsonIfExists(benchmarkCatalogPath) ?? { version: 1, cases: [] };
  const pairwiseMatches =
    options.pairwiseMatches ?? readJsonIfExists(pairwiseMatchesPath) ?? { matches: [] };
  const externalReferences = (
    options.externalReferences ??
    readJsonIfExists(externalReferencesPath) ?? { references: [] }
  );

  const latestByCaseId = latestEntriesByCaseId(corpusSummary?.cases ?? []);
  const externalReferenceEntries = normalizeExternalReferences(externalReferences).map(
    normalizeExternalReference,
  );
  const benchmarkCases = Array.isArray(benchmarkCatalog?.cases) ? benchmarkCatalog.cases : [];

  const internalExecutions = benchmarkCases.flatMap((benchmarkCase) => {
    const benchmarkId =
      typeof benchmarkCase?.benchmarkId === "string"
        ? benchmarkCase.benchmarkId
        : "unknown-benchmark";
    const bindings = Array.isArray(benchmarkCase?.caseBindings)
      ? benchmarkCase.caseBindings.filter((value) => typeof value === "string" && value.trim())
      : [];
    return bindings
      .map((caseId) => latestByCaseId.get(caseId))
      .filter(Boolean)
      .map((entry) => deriveInternalExecution(entry, benchmarkId));
  });

  const executionMaps = buildInternalExecutionMaps(internalExecutions);
  const externalMaps = buildExternalReferenceMaps(externalReferenceEntries);
  const resolvedPairwiseMatches = buildResolvedPairwiseMatches({
    pairwiseMatches,
    executionMaps,
    externalMaps,
  });
  const benchmarkMeta = benchmarkLookup(benchmarkCatalog);

  const benchmarks = benchmarkCases.map((benchmarkCase) => {
    const benchmarkId =
      typeof benchmarkCase?.benchmarkId === "string"
        ? benchmarkCase.benchmarkId
        : "unknown-benchmark";
    const internalForBenchmark = executionMaps.byBenchmarkId.get(benchmarkId) ?? [];
    const externalForBenchmark = externalMaps.byBenchmarkId.get(benchmarkId) ?? [];
    const pairwiseForBenchmark = resolvedPairwiseMatches.filter(
      (match) => match.benchmarkId === benchmarkId,
    );
    const pendingBlindMatches = buildPendingBlindMatches({
      benchmarkId,
      internalExecutions: internalForBenchmark,
      externalReferences: externalForBenchmark,
      existingPairwiseMatches: pairwiseForBenchmark,
    });
    const provisionalLeader = [...internalForBenchmark].sort(compareExecutionsForLeader)[0] ?? null;
    const blindWinner = summarizeBlindWinner({
      internalExecutions: internalForBenchmark,
      externalReferences: externalForBenchmark,
      pairwiseMatches: pairwiseForBenchmark,
    });

    return {
      benchmarkId,
      title:
        typeof benchmarkCase?.title === "string"
          ? benchmarkCase.title
          : benchmarkMeta.byBenchmarkId.get(benchmarkId)?.title ?? benchmarkId,
      prompt: typeof benchmarkCase?.prompt === "string" ? benchmarkCase.prompt : "",
      internalExecutionCount: internalForBenchmark.length,
      externalReferenceCount: externalForBenchmark.length,
      pairwiseMatchCount: pairwiseForBenchmark.length,
      blindMatchCount: pairwiseForBenchmark.filter((match) => match.blind).length,
      pendingBlindMatchCount: pendingBlindMatches.length,
      provisionalLeader:
        provisionalLeader != null
          ? {
              participant: provisionalLeader.compositeStackId,
              label: provisionalLeader.label,
              executionId: provisionalLeader.executionId,
              caseId: provisionalLeader.caseId,
              classification: provisionalLeader.classification,
              validationScore: provisionalLeader.validationScore,
              screenshotQualityScore: provisionalLeader.screenshotQualityScore,
              responsivenessScore: provisionalLeader.responsivenessScore,
              shimDependent: provisionalLeader.shimDependent,
            }
          : null,
      blindWinner,
      executions: internalForBenchmark.map((execution) => ({
        executionId: execution.executionId,
        caseId: execution.caseId,
        dateRoot: execution.dateRoot,
        label: execution.label,
        classification: execution.classification,
        validationScore: execution.validationScore,
        firstPaintEvidenceScore: execution.firstPaintEvidenceScore,
        screenshotQualityScore: execution.screenshotQualityScore,
        responsivenessScore: execution.responsivenessScore,
        shimDependent: execution.shimDependent,
        generatorStackId: execution.generatorStackId,
        validationStackId: execution.validationStackId,
        scaffoldFamilyId: execution.scaffoldFamilyId,
        componentPackFamilies: execution.componentPackFamilies,
        componentPackProfileId: execution.componentPackProfileId,
        skillSpineId: execution.skillSpineId,
        compositeStackId: execution.compositeStackId,
        summaryPath: execution.summaryPath,
      })),
      externalReferences: externalForBenchmark.map((reference) => ({
        participant: reference.participantId,
        label: reference.label,
        artifactPath: reference.artifactPath,
        summaryPath: reference.summaryPath,
      })),
      pendingBlindMatches,
    };
  });

  const dimensionRatings = {
    compositeStacks: buildEloSummary(resolvedPairwiseMatches, "compositeStacks"),
    generatorStacks: buildEloSummary(resolvedPairwiseMatches, "generatorStacks"),
    validationStacks: buildEloSummary(resolvedPairwiseMatches, "validationStacks"),
    scaffoldFamilies: buildEloSummary(resolvedPairwiseMatches, "scaffoldFamilies"),
    componentPackProfiles: buildEloSummary(
      resolvedPairwiseMatches,
      "componentPackProfiles",
    ),
    skillSpines: buildEloSummary(resolvedPairwiseMatches, "skillSpines"),
  };

  const pendingBlindMatches = benchmarks.flatMap((benchmark) =>
    benchmark.pendingBlindMatches.map((match) => ({
      ...match,
      benchmarkTitle: benchmark.title,
    })),
  );
  const internalParticipantCatalog = {
    compositeStacks: buildParticipantCatalog(internalExecutions, "compositeStacks"),
    generatorStacks: buildParticipantCatalog(internalExecutions, "generatorStacks"),
    validationStacks: buildParticipantCatalog(internalExecutions, "validationStacks"),
    scaffoldFamilies: buildParticipantCatalog(internalExecutions, "scaffoldFamilies"),
    componentPackProfiles: buildParticipantCatalog(
      internalExecutions,
      "componentPackProfiles",
    ),
    skillSpines: buildParticipantCatalog(internalExecutions, "skillSpines"),
  };

  return {
    version: 1,
    generatedAt: options.now ?? new Date().toISOString(),
    summaryPath: relativeEvidenceDisplayPath(evidenceRoot, summaryPath),
    benchmarkCatalogPath: relativeEvidenceDisplayPath(evidenceRoot, benchmarkCatalogPath),
    pairwiseMatchesPath: relativeEvidenceDisplayPath(evidenceRoot, pairwiseMatchesPath),
    externalReferencesPath: relativeEvidenceDisplayPath(evidenceRoot, externalReferencesPath),
    status:
      pendingBlindMatches.length > 0
        ? "pending_blind_comparisons"
        : resolvedPairwiseMatches.length > 0
          ? "comparative_ready"
          : "awaiting_arena_evidence",
    benchmarkCount: benchmarks.length,
    executedBenchmarkCount: benchmarks.filter((benchmark) => benchmark.internalExecutionCount > 0)
      .length,
    comparativeBenchmarkCount: benchmarks.filter(
      (benchmark) =>
        benchmark.internalExecutionCount > 1 ||
        (benchmark.internalExecutionCount > 0 && benchmark.externalReferenceCount > 0),
    ).length,
    benchmarksWithBlindWinnerCount: benchmarks.filter(
      (benchmark) => benchmark.blindWinner?.unique === true,
    ).length,
    internalExecutionCount: internalExecutions.length,
    internalParticipantCount: internalParticipantCatalog.compositeStacks.length,
    externalReferenceCount: externalReferenceEntries.length,
    pairwiseMatchCount: resolvedPairwiseMatches.length,
    blindMatchCount: resolvedPairwiseMatches.filter((match) => match.blind).length,
    pendingBlindMatchCount: pendingBlindMatches.length,
    pendingBlindMatches: pendingBlindMatches.slice(0, 24),
    internalParticipants: internalParticipantCatalog,
    dimensionRatings,
    benchmarks,
  };
}

export function writeChatArtifactArenaLedger(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const ledger = collectChatArtifactArenaLedger({
    ...options,
    repoRoot,
    evidenceRoot,
  });
  const ledgerPath =
    options.ledgerPath ?? path.join(evidenceRoot, DEFAULT_ARENA_LEDGER_PATH);
  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
  fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2));
  return { ledgerPath, ledger };
}

function loadChatArtifactArenaLedger(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const ledgerPath =
    options.ledgerPath ?? path.join(evidenceRoot, DEFAULT_ARENA_LEDGER_PATH);
  const ledger = readJsonIfExists(ledgerPath) ?? {
    version: 1,
    generatedAt: null,
    status: "awaiting_arena_evidence",
    benchmarkCount: 0,
    executedBenchmarkCount: 0,
    comparativeBenchmarkCount: 0,
    benchmarksWithBlindWinnerCount: 0,
    internalExecutionCount: 0,
    internalParticipantCount: 0,
    externalReferenceCount: 0,
    pairwiseMatchCount: 0,
    blindMatchCount: 0,
    pendingBlindMatchCount: 0,
    pendingBlindMatches: [],
    internalParticipants: {
      compositeStacks: [],
      generatorStacks: [],
      validationStacks: [],
      scaffoldFamilies: [],
      componentPackProfiles: [],
      skillSpines: [],
    },
    dimensionRatings: {
      compositeStacks: { available: false, ratings: [] },
      generatorStacks: { available: false, ratings: [] },
      validationStacks: { available: false, ratings: [] },
      scaffoldFamilies: { available: false, ratings: [] },
      componentPackProfiles: { available: false, ratings: [] },
      skillSpines: { available: false, ratings: [] },
    },
    benchmarks: [],
  };
  return { ledgerPath, ledger };
}

export function collectChatArtifactArenaView(options = {}) {
  const repoRoot = options.repoRoot ?? process.cwd();
  const evidenceRoot =
    options.evidenceRoot ??
    path.join(repoRoot, "docs", "evidence", "chat-artifact-surface");
  const { ledgerPath, ledger } = loadChatArtifactArenaLedger({
    repoRoot,
    evidenceRoot,
    ledgerPath: options.ledgerPath,
  });

  return {
    status: ledger.status ?? "awaiting_arena_evidence",
    ledgerPath,
    benchmarkCount: Number(ledger.benchmarkCount ?? 0),
    executedBenchmarkCount: Number(ledger.executedBenchmarkCount ?? 0),
    comparativeBenchmarkCount: Number(ledger.comparativeBenchmarkCount ?? 0),
    benchmarksWithBlindWinnerCount: Number(ledger.benchmarksWithBlindWinnerCount ?? 0),
    internalExecutionCount: Number(ledger.internalExecutionCount ?? 0),
    internalParticipantCount: Number(ledger.internalParticipantCount ?? 0),
    externalReferenceCount: Number(ledger.externalReferenceCount ?? 0),
    pairwiseMatchCount: Number(ledger.pairwiseMatchCount ?? 0),
    blindMatchCount: Number(ledger.blindMatchCount ?? 0),
    pendingBlindMatchCount: Number(ledger.pendingBlindMatchCount ?? 0),
    topCompositeRatings: Array.isArray(ledger?.dimensionRatings?.compositeStacks?.ratings)
      ? ledger.dimensionRatings.compositeStacks.ratings.slice(0, 5)
      : [],
    benchmarkLeaders: Array.isArray(ledger?.benchmarks)
      ? ledger.benchmarks.slice(0, 6).map((benchmark) => ({
          benchmarkId: benchmark.benchmarkId,
          title: benchmark.title,
          pairwiseMatchCount: Number(benchmark.pairwiseMatchCount ?? 0),
          pendingBlindMatchCount: Number(benchmark.pendingBlindMatchCount ?? 0),
          provisionalLeader: benchmark.provisionalLeader ?? null,
          blindWinner: benchmark.blindWinner ?? null,
        }))
      : [],
    pendingBlindMatches: Array.isArray(ledger.pendingBlindMatches)
      ? ledger.pendingBlindMatches.slice(0, 6)
      : [],
  };
}
