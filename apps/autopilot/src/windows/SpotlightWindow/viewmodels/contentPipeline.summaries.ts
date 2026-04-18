import type {
  ActivityEventRef,
  ActivityGroup,
  ActivitySummary,
  Artifact,
  ArtifactRef,
  ExecutionMoment,
  PlanSelectedSkill,
  PlanSummary,
  SourceBrowseRow,
  SourceSearchRow,
  SourceSummary,
  ThoughtAgentSummary,
  ThoughtSummary,
} from "../../../types";
import {
  asRecord,
  eventOutput,
  extractUrls,
  faviconUrlForDomain,
  firstStringValue,
  normalizedDomain,
  parseWebBundle,
  toValueString,
  WEB_READ_TOOL,
  WEB_SEARCH_TOOL,
} from "./contentPipeline.helpers";
import {
  defaultVerifierOutcome,
  defaultVerifierRole,
  explicitRouteContract,
  explicitRouteDecision,
  impliedRouteContractFromPlaybook,
  parseApprovalState,
  verifierRoleTitle,
} from "./contentPipeline.routeContracts";

const MAX_SOURCE_DOMAIN_PREVIEW = 3;
const MAX_THOUGHT_AGENTS = 8;
const MAX_THOUGHT_NOTES_PER_AGENT = 2;
const MAX_THOUGHT_NOTE_CHARS = 260;
const ACTIVE_ROUTE_PHASES = new Set([
  "started",
  "step_spawned",
  "spawned",
  "running",
  "in_progress",
]);
const TERMINAL_ROUTE_PHASES = new Set([
  "merged",
  "completed",
  "step_completed",
]);
const BLOCKED_ROUTE_MARKERS = ["blocked", "failed", "error"];

function includeSourceUrl(
  rawUrl: string,
  sourceUrls: Set<string>,
  domainCounts: Map<string, number>,
): void {
  const trimmed = rawUrl.trim();
  if (!trimmed) return;
  sourceUrls.add(trimmed);
  const domain = normalizedDomain(trimmed);
  if (!domain) return;
  const current = domainCounts.get(domain) || 0;
  domainCounts.set(domain, current + 1);
}

export function buildSourceSummary(
  events: ActivityEventRef[],
): SourceSummary | null {
  const sourceUrls = new Set<string>();
  const domainCounts = new Map<string, number>();
  const searches: SourceSearchRow[] = [];
  const browses: SourceBrowseRow[] = [];
  const seenBrowseUrls = new Set<string>();

  for (const entry of events) {
    if (entry.kind !== "workload_event" && entry.kind !== "receipt_event")
      continue;
    const normalizedTool = (entry.toolName || "").trim().toLowerCase();
    if (
      !normalizedTool.includes(WEB_SEARCH_TOOL) &&
      !normalizedTool.includes(WEB_READ_TOOL)
    ) {
      continue;
    }

    const bundle = parseWebBundle(entry.event);
    const sourceCandidateUrls =
      bundle?.sources.map((source) => source.url) ||
      extractUrls(eventOutput(entry.event));
    for (const url of sourceCandidateUrls) {
      includeSourceUrl(url, sourceUrls, domainCounts);
    }

    if (normalizedTool.includes(WEB_SEARCH_TOOL)) {
      searches.push({
        query: bundle?.query || "web search",
        resultCount: sourceCandidateUrls.length,
        stepIndex: entry.event.step_index,
      });
      continue;
    }

    if (normalizedTool.includes(WEB_READ_TOOL)) {
      const readUrl = firstStringValue(
        bundle?.url,
        bundle?.documents[0]?.url,
        bundle?.sources[0]?.url,
        sourceCandidateUrls[0],
      );
      if (!readUrl) continue;

      includeSourceUrl(readUrl, sourceUrls, domainCounts);
      if (seenBrowseUrls.has(readUrl)) continue;
      seenBrowseUrls.add(readUrl);

      browses.push({
        url: readUrl,
        domain: normalizedDomain(readUrl) || "unknown",
        title: firstStringValue(
          bundle?.documents[0]?.title,
          bundle?.sources[0]?.title,
        ),
        stepIndex: entry.event.step_index,
      });
    }
  }

  const totalSources =
    sourceUrls.size > 0
      ? sourceUrls.size
      : searches.reduce((sum, row) => sum + row.resultCount, 0);

  if (totalSources === 0 && searches.length === 0 && browses.length === 0) {
    return null;
  }

  const domains = Array.from(domainCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, MAX_SOURCE_DOMAIN_PREVIEW)
    .map(([domain, count]) => ({
      domain,
      count,
      faviconUrl: faviconUrlForDomain(domain),
    }));

  return {
    totalSources,
    sourceUrls: Array.from(sourceUrls),
    domains,
    searches,
    browses,
  };
}

function normalizeThoughtNote(raw: string): string {
  const compact = raw.replace(/\s+/g, " ").trim();
  if (!compact) return "";
  if (compact.length <= MAX_THOUGHT_NOTE_CHARS) return compact;
  return `${compact.slice(0, MAX_THOUGHT_NOTE_CHARS - 3).trim()}...`;
}

function normalizeNarrativeLine(
  raw: string | undefined,
  maxChars = 240,
): string | null {
  if (typeof raw !== "string") return null;
  const compact = raw.replace(/\s+/g, " ").trim();
  if (!compact) return null;
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 3).trim()}...`;
}

function normalizeLookupToken(value: string | null | undefined): string | null {
  const normalized = (value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return normalized || null;
}

const VERIFIER_AGENT_KEYS = new Set([
  "verifier",
  "citation_audit",
  "citation_verifier",
  "targeted_test_audit",
  "test_verifier",
  "postcondition_audit",
  "postcondition_verifier",
  "browser_postcondition_audit",
  "artifact_validation_audit",
  "artifact_validation_verifier",
]);

const PATCH_SYNTHESIZER_AGENT_KEYS = new Set([
  "patch_synthesizer",
  "patch_synthesis_handoff",
]);

const ARTIFACT_GENERATOR_AGENT_KEYS = new Set([
  "artifact_builder",
  "artifact_generator",
  "artifact_candidate_generation",
  "artifact_generate_repair",
]);

const COMPUTER_USE_OPERATOR_AGENT_KEYS = new Set([
  "perception_worker",
  "browser_operator",
  "ui_state_brief",
  "browser_postcondition_pass",
]);

export function buildThoughtSummary(
  groups: ActivityGroup[],
): ThoughtSummary | null {
  const agents: ThoughtSummary["agents"] = [];

  for (const group of groups) {
    if (agents.length >= MAX_THOUGHT_AGENTS) break;
    const notes: string[] = [];
    const seenNotes = new Set<string>();
    const identity = thoughtAgentIdentity(group, agents.length);

    for (const entry of group.events) {
      if (entry.kind === "receipt_event") continue;

      const tool = (entry.toolName || "").trim().toLowerCase();
      if (tool.includes(WEB_SEARCH_TOOL) || tool.includes(WEB_READ_TOOL)) {
        continue;
      }

      const candidate = normalizeThoughtNote(
        eventOutput(entry.event) || entry.event.title || "",
      );
      if (!candidate) continue;

      const dedup = candidate.toLowerCase();
      if (seenNotes.has(dedup)) continue;
      seenNotes.add(dedup);
      notes.push(candidate);

      if (notes.length >= MAX_THOUGHT_NOTES_PER_AGENT) {
        break;
      }
    }

    if (notes.length === 0) continue;

    agents.push({
      agentLabel: identity.agentLabel,
      agentRole: identity.agentRole,
      agentKind: thoughtAgentKind(group),
      stepIndex: group.stepIndex,
      notes,
    });
  }

  if (agents.length === 0) return null;
  return { agents };
}

function humanizeToken(value: string): string {
  const normalized = value.trim().replace(/[_-]+/g, " ").replace(/\s+/g, " ");
  if (!normalized) return "";
  return normalized.replace(/\b\w/g, (char) => char.toUpperCase());
}

function sameLabel(left: string | null, right: string | null): boolean {
  if (!left || !right) return false;
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

function firstHumanizedValue(...values: Array<unknown>): string | null {
  const value = firstStringValue(...values);
  if (!value) return null;
  const humanized = humanizeToken(value);
  return humanized || null;
}

function digestRecord(entry: ActivityEventRef): Record<string, unknown> {
  return asRecord(entry.event.digest) || {};
}

function detailsRecord(entry: ActivityEventRef): Record<string, unknown> {
  return asRecord(entry.event.details) || {};
}

function stringFromRecord(
  record: Record<string, unknown>,
  ...keys: string[]
): string | undefined {
  for (const key of keys) {
    const value = firstStringValue(record[key]);
    if (value) {
      return value;
    }
  }
  return undefined;
}

function arrayFromRecord(
  record: Record<string, unknown>,
  key: string,
): string[] {
  const raw = record[key];
  if (!Array.isArray(raw)) return [];
  return raw
    .map((value) => toValueString(value).trim())
    .filter((value) => value.length > 0);
}

function planSelectedSkillFromValue(value: unknown): PlanSelectedSkill | null {
  if (typeof value === "string") {
    const id = value.trim();
    if (!id) {
      return null;
    }
    return {
      id,
      entryId: `skill:${id}`,
      label: humanizeToken(id) || id,
    };
  }

  const record = asRecord(value);
  if (!record) {
    return null;
  }

  const id =
    firstStringValue(
      record.skill_hash,
      record.skillHash,
      record.id,
      record.skill_id,
      record.skillId,
    )?.trim() || "";
  if (!id) {
    return null;
  }

  const entryId =
    firstStringValue(record.entry_id, record.entryId)?.trim() || `skill:${id}`;
  const label =
    firstStringValue(record.label, record.name, record.title)?.trim() ||
    humanizeToken(id) ||
    id;

  return {
    id,
    entryId,
    label,
  };
}

function selectedSkillsFromRecord(
  record: Record<string, unknown>,
  key: string,
): PlanSelectedSkill[] {
  const raw = record[key];
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw
    .map((value) => planSelectedSkillFromValue(value))
    .filter((value): value is PlanSelectedSkill => value !== null);
}

function normalizedSignalText(...values: Array<string | undefined>): string {
  return values
    .filter(
      (value): value is string =>
        typeof value === "string" && value.trim().length > 0,
    )
    .join(" ")
    .trim()
    .toLowerCase();
}

function eventStageLabel(entry: ActivityEventRef): string | null {
  const digest = digestRecord(entry);
  const details = detailsRecord(entry);
  return firstHumanizedValue(
    details.step_label,
    digest.step_label,
    details.workflow_id,
    digest.workflow_id,
    details.template_id,
    digest.template_id,
    digest.phase,
  );
}

function eventNarrative(entry: ActivityEventRef): string | null {
  const digest = digestRecord(entry);
  const details = detailsRecord(entry);
  return normalizeNarrativeLine(
    firstStringValue(
      details.summary,
      digest.summary,
      entry.event.title,
      details.output,
    ),
  );
}

function eventPauseNarrative(entry: ActivityEventRef): string | null {
  const digest = digestRecord(entry);
  const details = detailsRecord(entry);
  return normalizeNarrativeLine(
    firstStringValue(
      details.output,
      details.summary,
      digest.error_class,
      entry.event.title,
    ),
  );
}

function thoughtAgentIdentity(
  group: ActivityGroup,
  index: number,
): { agentLabel: string; agentRole: string | null } {
  const entries = [...group.events].reverse();

  for (const entry of entries) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const agentLabel = firstHumanizedValue(
      digest.role,
      details.role,
      digest.template_id,
      details.template_id,
      digest.playbook_label,
      details.playbook_label,
      digest.workflow_id,
      details.workflow_id,
    );
    if (!agentLabel) continue;

    const agentRole = firstHumanizedValue(
      details.step_label,
      digest.workflow_id,
      details.workflow_id,
      digest.template_id,
      details.template_id,
    );
    return {
      agentLabel,
      agentRole: sameLabel(agentLabel, agentRole) ? null : agentRole,
    };
  }

  return {
    agentLabel: `Agent ${index + 1}`,
    agentRole: null,
  };
}

function thoughtAgentKind(
  group: ActivityGroup,
): ThoughtAgentSummary["agentKind"] {
  const entries = [...group.events].reverse();

  for (const entry of entries) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const candidateKeys = [
      firstStringValue(digest.workflow_id),
      firstStringValue(details.workflow_id),
      firstStringValue(digest.template_id),
      firstStringValue(details.template_id),
      firstStringValue(digest.role),
      firstStringValue(details.role),
    ]
      .map((value) => normalizeLookupToken(value))
      .filter((value): value is string => !!value);

    if (candidateKeys.some((value) => VERIFIER_AGENT_KEYS.has(value))) {
      return "verifier";
    }
    if (candidateKeys.some((value) => PATCH_SYNTHESIZER_AGENT_KEYS.has(value))) {
      return "patch_synthesizer";
    }
    if (candidateKeys.some((value) => ARTIFACT_GENERATOR_AGENT_KEYS.has(value))) {
      return "artifact_generator";
    }
    if (
      candidateKeys.some((value) => COMPUTER_USE_OPERATOR_AGENT_KEYS.has(value))
    ) {
      return "computer_use_operator";
    }
  }

  return "worker";
}

function inferredRouteFamily(
  events: ActivityEventRef[],
): PlanSummary["routeFamily"] {
  let sawArtifactHint = false;
  let sawComputerUseHint = false;
  let sawResearchHint = false;
  let sawCodingHint = false;

  for (const entry of events) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const toolName = (entry.toolName || "").trim().toLowerCase();
    const signal = normalizedSignalText(
      stringFromRecord(digest, "kind"),
      stringFromRecord(digest, "role"),
      stringFromRecord(digest, "phase"),
      stringFromRecord(digest, "playbook_id"),
      stringFromRecord(digest, "playbook_label"),
      stringFromRecord(digest, "template_id"),
      stringFromRecord(digest, "workflow_id"),
      stringFromRecord(digest, "selected_route"),
      stringFromRecord(digest, "route"),
      stringFromRecord(details, "step_label"),
      stringFromRecord(details, "selected_route"),
      stringFromRecord(details, "route"),
    );

    if (
      toolName.includes(WEB_SEARCH_TOOL) ||
      toolName.includes(WEB_READ_TOOL) ||
      signal.includes("research") ||
      signal.includes("citation") ||
      signal.includes("live_research_brief")
    ) {
      sawResearchHint = true;
    }

    if (
      toolName.includes("browser__") ||
      toolName.includes("screen__") ||
      toolName.includes("ui__") ||
      toolName.includes("selector__") ||
      entry.event.event_type === "BROWSER_NAVIGATE" ||
      entry.event.event_type === "BROWSER_EXTRACT" ||
      signal.includes("computer use") ||
      signal.includes("browser") ||
      signal.includes("screen") ||
      signal.includes("ui_state_brief") ||
      signal.includes("browser_postcondition_audit")
    ) {
      sawComputerUseHint = true;
    }

    if (
      toolName.includes("artifact") ||
      toolName.includes("studio") ||
      signal.includes("artifact") ||
      signal.includes("render") ||
      signal.includes("presentation")
    ) {
      sawArtifactHint = true;
    }

    if (
      signal.includes("patch") ||
      signal.includes("workspace") ||
      signal.includes("repo") ||
      signal.includes("code") ||
      signal.includes("coder") ||
      signal.includes("evidence audited patch") ||
      signal.includes("patch_build_verify") ||
      signal.includes("repo_context_brief") ||
      signal.includes("targeted_test_audit") ||
      signal.includes("patch_synthesis_handoff")
    ) {
      sawCodingHint = true;
    }
  }

  if (sawCodingHint) return "coding";
  if (sawResearchHint) return "research";
  if (sawComputerUseHint) return "computer_use";
  if (sawArtifactHint) return "artifacts";
  return "general";
}

function explicitRoutePrep(events: ActivityEventRef[]): {
  selectedSkills: PlanSelectedSkill[];
  prepSummary: string | null;
} {
  const selectedSkills: PlanSelectedSkill[] = [];
  const seenSkills = new Set<string>();
  let prepSummary: string | null = null;

  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);

    for (const skill of [
      ...selectedSkillsFromRecord(details, "selected_skills"),
      ...selectedSkillsFromRecord(digest, "selected_skills"),
    ]) {
      const dedupeKey = `${skill.entryId}::${skill.id}`.trim().toLowerCase();
      if (seenSkills.has(dedupeKey)) {
        continue;
      }
      seenSkills.add(dedupeKey);
      selectedSkills.push(skill);
    }

    if (!prepSummary) {
      prepSummary =
        stringFromRecord(details, "prep_summary") ||
        stringFromRecord(digest, "prep_summary") ||
        null;
      prepSummary = prepSummary?.trim() || null;
    }

    if (selectedSkills.length > 0 && prepSummary) {
      break;
    }
  }

  return { selectedSkills, prepSummary };
}

function explicitArtifactGeneration(
  events: ActivityEventRef[],
): PlanSummary["artifactGeneration"] {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const rawSummary =
      asRecord(details.artifact_generation) ||
      asRecord(digest.artifact_generation);
    if (!rawSummary) {
      continue;
    }

    const producedFileCount = Number(rawSummary.produced_file_count);
    return {
      status: firstStringValue(rawSummary.status) || "unknown",
      producedFileCount: Number.isFinite(producedFileCount)
        ? producedFileCount
        : 0,
      verificationSignalStatus:
        firstStringValue(rawSummary.verification_signal_status) || "unknown",
      presentationStatus:
        firstStringValue(rawSummary.presentation_status) || "unknown",
      notes: firstStringValue(rawSummary.notes) || null,
    };
  }

  return null;
}

function explicitComputerUsePerception(
  events: ActivityEventRef[],
): PlanSummary["computerUsePerception"] {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const rawSummary =
      asRecord(details.computer_use_perception) ||
      asRecord(digest.computer_use_perception);
    if (!rawSummary) {
      continue;
    }

    return {
      surfaceStatus: firstStringValue(rawSummary.surface_status) || "unknown",
      uiState:
        firstStringValue(rawSummary.ui_state) || "UI state not summarized",
      target: firstStringValue(rawSummary.target) || null,
      approvalRisk: firstStringValue(rawSummary.approval_risk) || "unknown",
      nextAction: firstStringValue(rawSummary.next_action) || null,
      notes: firstStringValue(rawSummary.notes) || null,
    };
  }

  return null;
}

function explicitResearchVerification(
  events: ActivityEventRef[],
): PlanSummary["researchVerification"] {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const rawScorecard =
      asRecord(details.research_scorecard) ||
      asRecord(digest.research_scorecard);
    if (!rawScorecard) {
      continue;
    }

    const sourceCount = Number(rawScorecard.source_count);
    const distinctDomainCount = Number(rawScorecard.distinct_domain_count);
    return {
      verdict: firstStringValue(rawScorecard.verdict) || "unknown",
      sourceCount: Number.isFinite(sourceCount) ? sourceCount : 0,
      distinctDomainCount: Number.isFinite(distinctDomainCount)
        ? distinctDomainCount
        : 0,
      sourceCountFloorMet: rawScorecard.source_count_floor_met === true,
      sourceIndependenceFloorMet:
        rawScorecard.source_independence_floor_met === true,
      freshnessStatus:
        firstStringValue(rawScorecard.freshness_status) || "unknown",
      quoteGroundingStatus:
        firstStringValue(rawScorecard.quote_grounding_status) || "unknown",
      notes: firstStringValue(rawScorecard.notes) || null,
    };
  }

  return null;
}

function explicitArtifactQuality(
  events: ActivityEventRef[],
): PlanSummary["artifactQuality"] {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const rawScorecard =
      asRecord(details.artifact_quality) || asRecord(digest.artifact_quality);
    if (!rawScorecard) {
      continue;
    }

    return {
      verdict: firstStringValue(rawScorecard.verdict) || "unknown",
      fidelityStatus:
        firstStringValue(rawScorecard.fidelity_status) || "unknown",
      presentationStatus:
        firstStringValue(rawScorecard.presentation_status) || "unknown",
      repairStatus: firstStringValue(rawScorecard.repair_status) || "unknown",
      notes: firstStringValue(rawScorecard.notes) || null,
    };
  }

  return null;
}

function explicitComputerUseVerification(
  events: ActivityEventRef[],
): PlanSummary["computerUseVerification"] {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const rawScorecard =
      asRecord(details.computer_use_verification) ||
      asRecord(digest.computer_use_verification);
    if (!rawScorecard) {
      continue;
    }

    return {
      verdict: firstStringValue(rawScorecard.verdict) || "unknown",
      postconditionStatus:
        firstStringValue(rawScorecard.postcondition_status) || "unknown",
      approvalState: firstStringValue(rawScorecard.approval_state) || "unknown",
      recoveryStatus:
        firstStringValue(rawScorecard.recovery_status) || "unknown",
      observedPostcondition:
        firstStringValue(rawScorecard.observed_postcondition) || null,
      notes: firstStringValue(rawScorecard.notes) || null,
    };
  }

  return null;
}

function explicitCodingVerification(
  events: ActivityEventRef[],
): PlanSummary["codingVerification"] {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const rawScorecard =
      asRecord(details.coding_scorecard) || asRecord(digest.coding_scorecard);
    if (!rawScorecard) {
      continue;
    }

    const targetedCommandCount = Number(rawScorecard.targeted_command_count);
    const targetedPassCount = Number(rawScorecard.targeted_pass_count);
    return {
      verdict: firstStringValue(rawScorecard.verdict) || "unknown",
      targetedCommandCount: Number.isFinite(targetedCommandCount)
        ? targetedCommandCount
        : 0,
      targetedPassCount: Number.isFinite(targetedPassCount)
        ? targetedPassCount
        : 0,
      wideningStatus:
        firstStringValue(rawScorecard.widening_status) || "unknown",
      regressionStatus:
        firstStringValue(rawScorecard.regression_status) || "unknown",
      notes: firstStringValue(rawScorecard.notes) || null,
    };
  }

  return null;
}

function explicitArtifactRepair(
  events: ActivityEventRef[],
): PlanSummary["artifactRepair"] {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const rawSummary =
      asRecord(details.artifact_repair) || asRecord(digest.artifact_repair);
    if (!rawSummary) {
      continue;
    }

    return {
      status: firstStringValue(rawSummary.status) || "unknown",
      reason: firstStringValue(rawSummary.reason) || null,
      nextStep: firstStringValue(rawSummary.next_step) || null,
    };
  }

  return null;
}

function explicitComputerUseRecovery(
  events: ActivityEventRef[],
): PlanSummary["computerUseRecovery"] {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const rawSummary =
      asRecord(details.computer_use_recovery) ||
      asRecord(digest.computer_use_recovery);
    if (!rawSummary) {
      continue;
    }

    return {
      status: firstStringValue(rawSummary.status) || "unknown",
      reason: firstStringValue(rawSummary.reason) || null,
      nextStep: firstStringValue(rawSummary.next_step) || null,
    };
  }

  return null;
}

function explicitPatchSynthesis(
  events: ActivityEventRef[],
): PlanSummary["patchSynthesis"] {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const rawSummary =
      asRecord(details.patch_synthesis) || asRecord(digest.patch_synthesis);
    if (!rawSummary) {
      continue;
    }

    const touchedFileCount = Number(rawSummary.touched_file_count);
    return {
      status: firstStringValue(rawSummary.status) || "unknown",
      touchedFileCount: Number.isFinite(touchedFileCount)
        ? touchedFileCount
        : 0,
      verificationReady: rawSummary.verification_ready === true,
      notes: firstStringValue(rawSummary.notes) || null,
    };
  }

  return null;
}

function defaultRouteLabel(
  routeFamily: PlanSummary["routeFamily"],
  topology: PlanSummary["topology"],
): string {
  if (routeFamily === "research") return "Research route";
  if (routeFamily === "coding") return "Coding route";
  if (routeFamily === "integrations") return "Connected route";
  if (routeFamily === "communication") return "Communication route";
  if (routeFamily === "user_input") return "Decision route";
  if (routeFamily === "tool_widget") return "Specialized tool route";
  if (routeFamily === "computer_use") return "Computer-use route";
  if (routeFamily === "artifacts") return "Artifact route";
  return topology === "single_agent" ? "Primary agent route" : "Planned route";
}

function explicitApprovalState(
  events: ActivityEventRef[],
  computerUseVerification: PlanSummary["computerUseVerification"],
): PlanSummary["approvalState"] | null {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const parsed =
      parseApprovalState(
        stringFromRecord(details, "approval_state", "gate_state") ||
          stringFromRecord(digest, "approval_state", "gate_state") ||
          stringFromRecord(details, "policy_decision") ||
          stringFromRecord(digest, "policy_decision"),
      ) || null;
    if (parsed) {
      return parsed;
    }
  }

  return parseApprovalState(
    computerUseVerification?.approvalState || undefined,
  );
}

function routeEventHasApprovalSignal(entry: ActivityEventRef): boolean {
  const digest = digestRecord(entry);
  const details = detailsRecord(entry);
  const title = (entry.event.title || "").toLowerCase();
  const output = eventOutput(entry.event).toLowerCase();
  return (
    parseApprovalState(
      stringFromRecord(
        digest,
        "policy_decision",
        "approval_state",
        "gate_state",
      ) ||
        stringFromRecord(
          details,
          "policy_decision",
          "approval_state",
          "gate_state",
        ),
    ) === "pending" ||
    title.includes("waiting for approval") ||
    output.includes("waiting for approval") ||
    stringFromRecord(details, "status")?.toLowerCase() === "gate"
  );
}

function workerLikeEntry(entry: ActivityEventRef): boolean {
  const digest = digestRecord(entry);
  const kind = stringFromRecord(digest, "kind")?.toLowerCase();
  return kind === "worker" || kind === "parent_playbook";
}

function isVerifierEntry(entry: ActivityEventRef): boolean {
  const digest = digestRecord(entry);
  const details = detailsRecord(entry);
  const signal = normalizedSignalText(
    stringFromRecord(digest, "role"),
    stringFromRecord(digest, "template_id"),
    stringFromRecord(digest, "workflow_id"),
    stringFromRecord(digest, "playbook_id"),
    stringFromRecord(details, "step_label"),
  );
  return (
    signal.includes("verifier") ||
    signal.includes("audit") ||
    signal.includes("validation") ||
    signal.includes("postcondition")
  );
}

function routeRequiresVerifier(events: ActivityEventRef[]): boolean {
  return events.some((entry) => {
    const digest = digestRecord(entry);
    const playbookId = stringFromRecord(digest, "playbook_id")?.toLowerCase();
    return playbookId === "evidence_audited_patch" || isVerifierEntry(entry);
  });
}

function eventSuccess(entry: ActivityEventRef): boolean | null {
  const digest = digestRecord(entry);
  if (typeof digest.success === "boolean") {
    return digest.success;
  }
  const eventStatus = (entry.event.status || "").toLowerCase();
  if (eventStatus === "success") {
    return true;
  }
  if (eventStatus === "failure" || eventStatus === "partial") {
    return false;
  }
  return null;
}

function eventLifecycleState(entry: ActivityEventRef): string {
  const digest = digestRecord(entry);
  const details = detailsRecord(entry);
  return (
    stringFromRecord(digest, "phase", "status") ||
    stringFromRecord(details, "status") ||
    entry.event.status ||
    "captured"
  )
    .trim()
    .toLowerCase();
}

function eventIsBlocked(entry: ActivityEventRef): boolean {
  const digest = digestRecord(entry);
  const state = eventLifecycleState(entry);
  const errorClass = stringFromRecord(digest, "error_class");
  return (
    !!errorClass ||
    BLOCKED_ROUTE_MARKERS.some((marker) => state.includes(marker))
  );
}

function eventIsActive(entry: ActivityEventRef): boolean {
  const state = eventLifecycleState(entry);
  return ACTIVE_ROUTE_PHASES.has(state);
}

function eventIsTerminalSuccess(entry: ActivityEventRef): boolean {
  const state = eventLifecycleState(entry);
  const success = eventSuccess(entry);
  return success === true && TERMINAL_ROUTE_PHASES.has(state);
}

export function buildPlanSummary(
  events: ActivityEventRef[],
): PlanSummary | null {
  if (events.length === 0) {
    return null;
  }

  const workerEvents = events.filter(workerLikeEntry);
  const routeSignalEvent = [...events].reverse().find((entry) => {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const title = (entry.event.title || "").toLowerCase();
    return (
      title.includes("plan") ||
      typeof digest.selected_route === "string" ||
      typeof details.selected_route === "string" ||
      typeof digest.route === "string" ||
      typeof details.route === "string" ||
      typeof digest.playbook_label === "string" ||
      typeof digest.playbook_id === "string"
    );
  });
  const explicitContract = explicitRouteContract(
    events,
    digestRecord,
    detailsRecord,
    stringFromRecord,
  );
  const routeDecision = explicitRouteDecision(
    events,
    digestRecord,
    detailsRecord,
    stringFromRecord,
  );
  const impliedPlaybookContract = impliedRouteContractFromPlaybook(
    events,
    digestRecord,
    detailsRecord,
    stringFromRecord,
  );
  const explicitPrep = explicitRoutePrep(events);
  const artifactGeneration = explicitArtifactGeneration(events);
  const computerUsePerception = explicitComputerUsePerception(events);
  const researchVerification = explicitResearchVerification(events);
  const artifactQuality = explicitArtifactQuality(events);
  const computerUseVerification = explicitComputerUseVerification(events);
  const codingVerification = explicitCodingVerification(events);
  const artifactRepair = explicitArtifactRepair(events);
  const computerUseRecovery = explicitComputerUseRecovery(events);
  const patchSynthesis = explicitPatchSynthesis(events);
  const explicitApproval = explicitApprovalState(
    events,
    computerUseVerification,
  );
  const latestApprovalEvent = [...events]
    .reverse()
    .find(routeEventHasApprovalSignal);
  const approvalPending =
    explicitApproval !== null
      ? explicitApproval === "pending"
      : events.some(routeEventHasApprovalSignal);
  const routeFamily =
    routeDecision?.routeFamily ||
    explicitContract.routeFamily ||
    impliedPlaybookContract?.routeFamily ||
    inferredRouteFamily(events);

  const topology: PlanSummary["topology"] =
    explicitContract.topology ||
    impliedPlaybookContract?.topology ||
    (workerEvents.length === 0
      ? "single_agent"
      : routeRequiresVerifier(workerEvents)
        ? "planner_specialist_verifier"
        : "planner_specialist");
  const plannerAuthority: PlanSummary["plannerAuthority"] =
    explicitContract.plannerAuthority ||
    impliedPlaybookContract?.plannerAuthority ||
    (topology === "single_agent" ? "primary_agent" : "kernel");

  const explicitRoute = routeSignalEvent
    ? firstStringValue(
        detailsRecord(routeSignalEvent).selected_route,
        digestRecord(routeSignalEvent).selected_route,
        detailsRecord(routeSignalEvent).route,
        digestRecord(routeSignalEvent).route,
        digestRecord(routeSignalEvent).playbook_label,
        detailsRecord(routeSignalEvent).playbook_label,
        digestRecord(routeSignalEvent).playbook_id,
        detailsRecord(routeSignalEvent).playbook_id,
      )
    : undefined;

  const branchIds = new Set<string>();
  for (const entry of workerEvents) {
    const details = detailsRecord(entry);
    const childSessionId = stringFromRecord(details, "child_session_id");
    if (childSessionId) {
      branchIds.add(childSessionId);
    }
  }

  const activeWorkerEvent = [...workerEvents].reverse().find(eventIsActive);
  const activeStepEvent = [...workerEvents].reverse().find((entry) => {
    const digest = digestRecord(entry);
    return stringFromRecord(digest, "phase")?.toLowerCase() === "step_spawned";
  });
  const latestProgressEvent = [...workerEvents].reverse().find((entry) => {
    if (eventIsBlocked(entry)) return false;
    return !!eventNarrative(entry);
  });
  const latestStepEvent = [...workerEvents]
    .reverse()
    .find((entry) => !!eventStageLabel(entry));
  const latestBlockedEvent = [...events].reverse().find(eventIsBlocked);
  const activeWorkerLabel = activeWorkerEvent
    ? firstHumanizedValue(
        digestRecord(activeWorkerEvent).role,
        digestRecord(activeWorkerEvent).workflow_id,
        digestRecord(activeWorkerEvent).template_id,
      ) || null
    : approvalPending && activeStepEvent
      ? firstHumanizedValue(
          detailsRecord(activeStepEvent).step_label,
          digestRecord(activeStepEvent).playbook_label,
        ) || null
      : topology === "single_agent"
        ? "Primary agent"
        : null;
  const activeWorkerRoleCandidate = activeWorkerEvent
    ? firstHumanizedValue(
        digestRecord(activeWorkerEvent).workflow_id,
        digestRecord(activeWorkerEvent).role,
        digestRecord(activeWorkerEvent).template_id,
      ) || null
    : topology === "single_agent"
      ? "Planner"
      : null;
  const activeWorkerRole = sameLabel(
    activeWorkerLabel,
    activeWorkerRoleCandidate,
  )
    ? null
    : activeWorkerRoleCandidate;

  const latestVerifierEvent = [...workerEvents].reverse().find(isVerifierEntry);
  let verifierState: PlanSummary["verifierState"] =
    explicitContract.verifierState || "not_engaged";
  const verifierRole =
    explicitContract.verifierRole ||
    impliedPlaybookContract?.verifierRole ||
    defaultVerifierRole(routeFamily, topology);
  if (!explicitContract.verifierState) {
    if (latestVerifierEvent) {
      if (eventIsBlocked(latestVerifierEvent)) {
        verifierState = "blocked";
      } else if (eventIsTerminalSuccess(latestVerifierEvent)) {
        verifierState = "passed";
      } else if (eventIsActive(latestVerifierEvent)) {
        verifierState = "active";
      } else {
        verifierState = "queued";
      }
    } else if (
      impliedPlaybookContract?.requiresVerifier ||
      topology === "planner_specialist_verifier"
    ) {
      verifierState = "queued";
    }
  }
  const verifierOutcome =
    explicitContract.verifierOutcome ||
    defaultVerifierOutcome(
      verifierState,
      researchVerification,
      codingVerification,
      computerUseVerification,
      artifactQuality,
    );

  const policyBindings = Array.from(
    new Set(
      events.flatMap((entry) => {
        const digest = digestRecord(entry);
        const details = detailsRecord(entry);
        return [
          ...arrayFromRecord(details, "policy_bindings"),
          ...arrayFromRecord(digest, "policy_bindings"),
        ];
      }),
    ),
  );

  const evidenceCount = events.filter((entry) => {
    const digest = digestRecord(entry);
    const title = (entry.event.title || "").toLowerCase();
    return (
      workerLikeEntry(entry) ||
      routeEventHasApprovalSignal(entry) ||
      title.includes("routingreceipt") ||
      typeof digest.route_family === "string" ||
      typeof digest.output_intent === "string" ||
      typeof digest.selected_route === "string" ||
      typeof digest.route === "string"
    );
  }).length;

  if (
    evidenceCount === 0 &&
    routeFamily === "general" &&
    !explicitRoute &&
    workerEvents.length === 0
  ) {
    return null;
  }

  const latestStatusEvent = [...events].reverse().find((entry) => {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    return !!firstStringValue(
      details.status,
      digest.status,
      entry.event.status,
    );
  });
  const status = approvalPending
    ? "gate"
    : (latestStatusEvent
        ? firstStringValue(
            detailsRecord(latestStatusEvent).status,
            digestRecord(latestStatusEvent).status,
            latestStatusEvent.event.status,
          )
        : "captured")!
        .trim()
        .toLowerCase();
  const liveStageCandidate =
    approvalPending || activeWorkerEvent
      ? activeStepEvent || activeWorkerEvent || null
      : null;
  const currentStageEvent =
    latestStepEvent &&
    (!liveStageCandidate ||
      latestStepEvent.event.step_index >= liveStageCandidate.event.step_index)
      ? latestStepEvent
      : liveStageCandidate || latestStepEvent || activeStepEvent || null;
  const currentStage = currentStageEvent
    ? eventStageLabel(currentStageEvent)
    : null;
  const pauseEvent =
    latestApprovalEvent || activeStepEvent || latestStatusEvent || null;
  const pauseSummary = approvalPending
    ? (pauseEvent ? eventPauseNarrative(pauseEvent) : null) ||
      "Awaiting approval before the route can continue."
    : latestBlockedEvent
      ? eventPauseNarrative(latestBlockedEvent)
      : null;
  const progressSummary =
    firstStringValue(
      latestProgressEvent ? eventNarrative(latestProgressEvent) : null,
      latestStepEvent ? eventNarrative(latestStepEvent) : null,
      activeWorkerLabel
        ? `${activeWorkerLabel} is active in the selected route.`
        : null,
    ) || null;

  return {
    selectedRoute: explicitRoute
      ? humanizeToken(explicitRoute)
      : defaultRouteLabel(routeFamily, topology),
    routeFamily,
    topology,
    plannerAuthority,
    status,
    currentStage,
    progressSummary,
    pauseSummary,
    workerCount: branchIds.size || workerEvents.length,
    branchCount: branchIds.size,
    evidenceCount,
    activeWorkerLabel,
    activeWorkerRole,
    verifierState,
    verifierRole,
    verifierOutcome,
    approvalState: explicitApproval || (approvalPending ? "pending" : "clear"),
    selectedSkills: explicitPrep.selectedSkills,
    prepSummary: explicitPrep.prepSummary,
    artifactGeneration,
    computerUsePerception,
    researchVerification,
    artifactQuality,
    computerUseVerification,
    codingVerification,
    patchSynthesis,
    artifactRepair,
    computerUseRecovery,
    policyBindings,
    routeDecision,
  };
}

function joinHumanizedList(values: string[]): string {
  const unique = Array.from(
    new Set(
      values
        .map((value) => value.trim())
        .filter((value) => value.length > 0),
    ),
  );
  if (unique.length === 0) return "";
  if (unique.length === 1) return unique[0]!;
  if (unique.length === 2) return `${unique[0]} and ${unique[1]}`;
  return `${unique.slice(0, 2).join(", ")}, and ${unique.length - 2} more`;
}

function entryApprovalState(
  entry: ActivityEventRef,
): PlanSummary["approvalState"] | null {
  const digest = digestRecord(entry);
  const details = detailsRecord(entry);
  return parseApprovalState(
    stringFromRecord(
      details,
      "approval_state",
      "gate_state",
      "policy_decision",
    ) ||
      stringFromRecord(
        digest,
        "approval_state",
        "gate_state",
        "policy_decision",
      ),
  );
}

function approvalMomentStatus(
  state: PlanSummary["approvalState"],
): ExecutionMoment["status"] {
  switch (state) {
    case "approved":
      return "passed";
    case "denied":
      return "blocked";
    case "pending":
      return "pending";
    default:
      return "info";
  }
}

function verifierMomentStatus(
  state: PlanSummary["verifierState"],
  outcome: PlanSummary["verifierOutcome"],
): ExecutionMoment["status"] {
  if (outcome === "blocked" || state === "blocked") {
    return "blocked";
  }
  if (outcome === "warning") {
    return "warning";
  }
  if (outcome === "pass" || state === "passed") {
    return "passed";
  }
  switch (state) {
    case "queued":
    case "active":
      return "pending";
    default:
      return "info";
  }
}

function latestVerifierEntry(events: ActivityEventRef[]): ActivityEventRef | null {
  return [...events].reverse().find(isVerifierEntry) || null;
}

function verificationMomentFromPlan(
  planSummary: PlanSummary | null,
  events: ActivityEventRef[],
): ExecutionMoment | null {
  if (!planSummary || planSummary.verifierState === "not_engaged") {
    return null;
  }

  const stepIndex = latestVerifierEntry(events)?.event.step_index || 0;

  if (planSummary.researchVerification) {
    return {
      key: "verification",
      kind: "verification",
      status: verifierMomentStatus(
        planSummary.verifierState,
        planSummary.verifierOutcome,
      ),
      stepIndex,
      title: `${verifierRoleTitle(planSummary.verifierRole)} ${humanizeToken(planSummary.researchVerification.verdict)}`,
      summary:
        planSummary.researchVerification.notes ||
        `${planSummary.researchVerification.sourceCount} sources across ${planSummary.researchVerification.distinctDomainCount} domains. Quote grounding ${humanizeToken(planSummary.researchVerification.quoteGroundingStatus)}.`,
    };
  }

  if (planSummary.codingVerification) {
    return {
      key: "verification",
      kind: "verification",
      status: verifierMomentStatus(
        planSummary.verifierState,
        planSummary.verifierOutcome,
      ),
      stepIndex,
      title: `${verifierRoleTitle(planSummary.verifierRole)} ${humanizeToken(planSummary.codingVerification.verdict)}`,
      summary:
        planSummary.codingVerification.notes ||
        `${planSummary.codingVerification.targetedPassCount}/${planSummary.codingVerification.targetedCommandCount} targeted commands passed. Regression ${humanizeToken(planSummary.codingVerification.regressionStatus)}.`,
    };
  }

  if (planSummary.computerUseVerification) {
    return {
      key: "verification",
      kind: "verification",
      status: verifierMomentStatus(
        planSummary.verifierState,
        planSummary.verifierOutcome,
      ),
      stepIndex,
      title: `${verifierRoleTitle(planSummary.verifierRole)} ${humanizeToken(planSummary.computerUseVerification.verdict)}`,
      summary:
        planSummary.computerUseVerification.notes ||
        `Postcondition ${humanizeToken(planSummary.computerUseVerification.postconditionStatus)}. Recovery ${humanizeToken(planSummary.computerUseVerification.recoveryStatus)}.`,
    };
  }

  if (planSummary.artifactQuality) {
    return {
      key: "verification",
      kind: "verification",
      status: verifierMomentStatus(
        planSummary.verifierState,
        planSummary.verifierOutcome,
      ),
      stepIndex,
      title: `${verifierRoleTitle(planSummary.verifierRole)} ${humanizeToken(planSummary.artifactQuality.verdict)}`,
      summary:
        planSummary.artifactQuality.notes ||
        `Fidelity ${humanizeToken(planSummary.artifactQuality.fidelityStatus)}. Presentation ${humanizeToken(planSummary.artifactQuality.presentationStatus)}.`,
    };
  }

  return {
    key: "verification",
    kind: "verification",
    status: verifierMomentStatus(
      planSummary.verifierState,
      planSummary.verifierOutcome,
    ),
    stepIndex,
    title: `${verifierRoleTitle(planSummary.verifierRole)} ${humanizeToken(
      planSummary.verifierOutcome || planSummary.verifierState,
    )}`,
    summary:
      planSummary.progressSummary ||
      `Verifier state is ${humanizeToken(planSummary.verifierState)} for the selected route.`,
  };
}

export function buildExecutionMoments(
  events: ActivityEventRef[],
  planSummary: PlanSummary | null = buildPlanSummary(events),
): ExecutionMoment[] {
  if (events.length === 0 && !planSummary) {
    return [];
  }

  const moments: ExecutionMoment[] = [];

  const branchEntries = events.filter((entry) => {
    if (!workerLikeEntry(entry)) return false;
    return !!stringFromRecord(detailsRecord(entry), "child_session_id");
  });
  const branchLabels = branchEntries
    .map((entry) =>
      firstHumanizedValue(
        digestRecord(entry).role,
        detailsRecord(entry).role,
        detailsRecord(entry).step_label,
        digestRecord(entry).workflow_id,
        digestRecord(entry).template_id,
      ),
    )
    .filter((value): value is string => !!value);
  const branchSessionIds = new Set(
    branchEntries
      .map((entry) => stringFromRecord(detailsRecord(entry), "child_session_id"))
      .filter((value): value is string => !!value),
  );
  const branchCount = Math.max(branchSessionIds.size, planSummary?.branchCount || 0);
  if (branchCount > 0) {
    const branchSummary = branchLabels.length
      ? branchCount === 1
        ? `${branchLabels[0]} branch opened under the planner.`
        : `Planner split work across ${joinHumanizedList(branchLabels)}.`
      : `Planner opened ${branchCount} worker ${branchCount === 1 ? "branch" : "branches"}.`;
    moments.push({
      key: "branch",
      kind: "branch",
      status: "info",
      stepIndex: branchEntries[0]?.event.step_index || 0,
      title:
        branchCount === 1 ? "Opened worker branch" : `Opened ${branchCount} worker branches`,
      summary: branchSummary,
    });
  }

  const latestApprovalEntry =
    [...events]
      .reverse()
      .find(
        (entry) => entryApprovalState(entry) !== null || routeEventHasApprovalSignal(entry),
      ) || null;
  const approvalState =
    (latestApprovalEntry
      ? entryApprovalState(latestApprovalEntry) ||
        (routeEventHasApprovalSignal(latestApprovalEntry) ? "pending" : null)
      : null) ||
    (planSummary?.approvalState !== "clear" ? planSummary?.approvalState : null);
  const approvalSummary =
    firstStringValue(
      latestApprovalEntry ? eventPauseNarrative(latestApprovalEntry) : null,
      planSummary?.computerUseVerification?.notes,
      planSummary?.pauseSummary,
      approvalState === "approved"
        ? "Operator approval cleared the route to continue."
        : approvalState === "denied"
          ? "Operator denied the requested action."
          : approvalState === "pending"
            ? "Awaiting approval before the route can continue."
            : null,
    ) || null;

  if (approvalState) {
    moments.push({
      key: "approval",
      kind: "approval",
      status: approvalMomentStatus(approvalState),
      stepIndex:
        latestApprovalEntry?.event.step_index ||
        latestVerifierEntry(events)?.event.step_index ||
        events[events.length - 1]?.event.step_index ||
        0,
      title:
        approvalState === "approved"
          ? "Approval cleared"
          : approvalState === "denied"
            ? "Approval denied"
            : "Approval required",
      summary: approvalSummary || "Approval state changed for the selected route.",
    });
  }

  if (
    planSummary?.pauseSummary &&
    (!approvalSummary || planSummary.pauseSummary !== approvalSummary)
  ) {
    moments.push({
      key: "pause",
      kind: "pause",
      status:
        planSummary.verifierState === "blocked" ||
        planSummary.approvalState === "denied"
          ? "blocked"
          : "pending",
      stepIndex:
        [...events].reverse().find(eventIsBlocked)?.event.step_index ||
        events[events.length - 1]?.event.step_index ||
        0,
      title:
        planSummary.verifierState === "blocked"
          ? "Verifier blocked completion"
          : "Route paused",
      summary: planSummary.pauseSummary,
    });
  }

  const verificationMoment = verificationMomentFromPlan(planSummary, events);
  if (verificationMoment) {
    moments.push(verificationMoment);
  }

  const kindOrder: Record<ExecutionMoment["kind"], number> = {
    branch: 0,
    approval: 1,
    pause: 2,
    verification: 3,
  };

  return moments
    .filter((moment, index, list) =>
      list.findIndex((candidate) => candidate.key === moment.key) === index,
    )
    .sort(
      (left, right) =>
        left.stepIndex - right.stepIndex || kindOrder[left.kind] - kindOrder[right.kind],
    );
}

function groupTitle(stepIndex: number, events: ActivityEventRef[]): string {
  const firstTool = events.find((entry) => entry.toolName)?.toolName;
  if (firstTool) {
    return `Step ${stepIndex} · ${firstTool}`;
  }

  return `Step ${stepIndex}`;
}

export function buildActivityGroups(
  deduped: ActivityEventRef[],
): ActivityGroup[] {
  const byStep = new Map<number, ActivityEventRef[]>();
  for (const entry of deduped) {
    const list = byStep.get(entry.event.step_index) || [];
    list.push(entry);
    byStep.set(entry.event.step_index, list);
  }

  const orderedStepIndexes = Array.from(byStep.keys()).sort((a, b) => a - b);
  return orderedStepIndexes.map((stepIndex) => {
    const entries = byStep.get(stepIndex) || [];
    entries.sort((a, b) => a.event.timestamp.localeCompare(b.event.timestamp));
    return {
      stepIndex,
      title: groupTitle(stepIndex, entries),
      events: entries,
    };
  });
}

export function buildActivitySummary(
  events: ActivityEventRef[],
  artifacts: Artifact[],
): ActivitySummary {
  let searchCount = 0;
  let readCount = 0;
  let receiptCount = 0;
  let reasoningCount = 0;
  let systemCount = 0;

  for (const entry of events) {
    if (entry.kind === "receipt_event") {
      receiptCount += 1;
      continue;
    }

    if (entry.kind === "reasoning_event") {
      reasoningCount += 1;
      continue;
    }

    if (entry.kind === "system_event") {
      systemCount += 1;
      continue;
    }

    if (entry.kind === "workload_event") {
      const tool = entry.toolName?.toLowerCase() || "";
      if (tool.includes(WEB_SEARCH_TOOL)) {
        searchCount += 1;
      } else if (tool.includes(WEB_READ_TOOL)) {
        readCount += 1;
      } else {
        systemCount += 1;
      }
    }
  }

  return {
    searchCount,
    readCount,
    receiptCount,
    reasoningCount,
    systemCount,
    artifactCount: artifacts.length,
  };
}

export function collectArtifactRefs(
  events: ActivityEventRef[],
  artifacts: Artifact[],
): ArtifactRef[] {
  const seen = new Set<string>();
  const refs: ArtifactRef[] = [];

  for (const entry of events) {
    for (const ref of entry.event.artifact_refs || []) {
      const key = `${ref.artifact_type}:${ref.artifact_id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      refs.push(ref);
    }
  }

  for (const artifact of artifacts) {
    const key = `${artifact.artifact_type}:${artifact.artifact_id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    refs.push({
      artifact_id: artifact.artifact_id,
      artifact_type: artifact.artifact_type,
    });
  }

  return refs;
}
