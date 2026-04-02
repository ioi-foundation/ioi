import type { ActivityEventRef, PlanSummary } from "../../../types";

type StringFromRecord = (
  record: Record<string, unknown>,
  ...keys: string[]
) => string | undefined;

type RecordAccessor = (entry: ActivityEventRef) => Record<string, unknown>;

export type ExplicitRouteContract = {
  routeFamily: PlanSummary["routeFamily"] | null;
  topology: PlanSummary["topology"] | null;
  plannerAuthority: PlanSummary["plannerAuthority"] | null;
  verifierState: PlanSummary["verifierState"] | null;
  verifierRole: PlanSummary["verifierRole"] | null;
  verifierOutcome: PlanSummary["verifierOutcome"] | null;
};

export type KnownPlaybookRouteContract = {
  routeFamily: PlanSummary["routeFamily"];
  topology: PlanSummary["topology"];
  plannerAuthority: PlanSummary["plannerAuthority"];
  verifierRole: PlanSummary["verifierRole"] | null;
  requiresVerifier: boolean;
};

const BUILTIN_PLAYBOOK_ROUTE_CONTRACTS: Record<
  string,
  KnownPlaybookRouteContract
> = {
  evidence_audited_patch: {
    routeFamily: "coding",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierRole: "test_verifier",
    requiresVerifier: true,
  },
  citation_grounded_brief: {
    routeFamily: "research",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierRole: "citation_verifier",
    requiresVerifier: true,
  },
  browser_postcondition_gate: {
    routeFamily: "computer_use",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierRole: "postcondition_verifier",
    requiresVerifier: true,
  },
  artifact_generation_gate: {
    routeFamily: "artifacts",
    topology: "planner_specialist_verifier",
    plannerAuthority: "kernel",
    verifierRole: "artifact_quality_verifier",
    requiresVerifier: true,
  },
};

const BUILTIN_ROUTE_CONTRACT_ALIASES: Record<string, string> = {
  repo_context_brief: "evidence_audited_patch",
  patch_build_verify: "evidence_audited_patch",
  targeted_test_audit: "evidence_audited_patch",
  patch_synthesis_handoff: "evidence_audited_patch",
  live_research_brief: "citation_grounded_brief",
  citation_audit: "citation_grounded_brief",
  ui_state_brief: "browser_postcondition_gate",
  browser_postcondition_pass: "browser_postcondition_gate",
  browser_postcondition_audit: "browser_postcondition_gate",
  postcondition_audit: "browser_postcondition_gate",
  artifact_context_brief: "artifact_generation_gate",
  artifact_generate_repair: "artifact_generation_gate",
  artifact_quality_audit: "artifact_generation_gate",
  artifact_candidate_generation: "artifact_generation_gate",
};

function normalizePlaybookLookupKey(value?: string): string | null {
  const normalized = (value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return normalized || null;
}

function builtinPlaybookRouteContractForValue(
  value?: string,
): KnownPlaybookRouteContract | null {
  const key = normalizePlaybookLookupKey(value);
  if (!key) {
    return null;
  }
  const playbookKey = BUILTIN_ROUTE_CONTRACT_ALIASES[key] || key;
  return BUILTIN_PLAYBOOK_ROUTE_CONTRACTS[playbookKey] || null;
}

export function parseRouteFamily(
  value?: string,
): PlanSummary["routeFamily"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "research":
    case "coding":
    case "computer_use":
    case "artifacts":
    case "general":
      return value!.trim().toLowerCase() as PlanSummary["routeFamily"];
    default:
      return null;
  }
}

export function parseTopology(
  value?: string,
): PlanSummary["topology"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "single_agent":
    case "planner_specialist":
    case "planner_specialist_verifier":
      return value!.trim().toLowerCase() as PlanSummary["topology"];
    default:
      return null;
  }
}

export function parsePlannerAuthority(
  value?: string,
): PlanSummary["plannerAuthority"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "kernel":
    case "primary_agent":
      return value!.trim().toLowerCase() as PlanSummary["plannerAuthority"];
    default:
      return null;
  }
}

export function parseVerifierState(
  value?: string,
): PlanSummary["verifierState"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "not_engaged":
    case "queued":
    case "active":
    case "passed":
    case "blocked":
      return value!.trim().toLowerCase() as PlanSummary["verifierState"];
    default:
      return null;
  }
}

export function parseVerifierRole(
  value?: string,
): PlanSummary["verifierRole"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "verifier":
    case "citation_verifier":
    case "test_verifier":
    case "postcondition_verifier":
    case "artifact_quality_verifier":
      return value!.trim().toLowerCase() as PlanSummary["verifierRole"];
    default:
      return null;
  }
}

export function parseVerifierOutcome(
  value?: string,
): PlanSummary["verifierOutcome"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "pass":
    case "warning":
    case "blocked":
      return value!.trim().toLowerCase() as PlanSummary["verifierOutcome"];
    default:
      return null;
  }
}

export function parseApprovalState(
  value?: string,
): PlanSummary["approvalState"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "pending":
    case "require_approval":
    case "approval_required":
      return "pending";
    case "approved":
      return "approved";
    case "denied":
      return "denied";
    case "clear":
    case "cleared":
    case "none":
    case "allowed":
    case "not_needed":
      return "clear";
    default:
      return null;
  }
}

export function explicitRouteContract(
  events: ActivityEventRef[],
  digestRecord: RecordAccessor,
  detailsRecord: RecordAccessor,
  stringFromRecord: StringFromRecord,
): ExplicitRouteContract {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const routeFamily = parseRouteFamily(
      stringFromRecord(digest, "route_family") ||
        stringFromRecord(details, "route_family"),
    );
    const topology = parseTopology(
      stringFromRecord(digest, "topology") ||
        stringFromRecord(details, "topology"),
    );
    const plannerAuthority = parsePlannerAuthority(
      stringFromRecord(digest, "planner_authority") ||
        stringFromRecord(details, "planner_authority"),
    );
    const verifierState = parseVerifierState(
      stringFromRecord(digest, "verifier_state") ||
        stringFromRecord(details, "verifier_state"),
    );
    const verifierRole = parseVerifierRole(
      stringFromRecord(digest, "verifier_role") ||
        stringFromRecord(details, "verifier_role"),
    );
    const verifierOutcome = parseVerifierOutcome(
      stringFromRecord(digest, "verifier_outcome") ||
        stringFromRecord(details, "verifier_outcome"),
    );
    if (
      routeFamily ||
      topology ||
      plannerAuthority ||
      verifierState ||
      verifierRole ||
      verifierOutcome
    ) {
      return {
        routeFamily,
        topology,
        plannerAuthority,
        verifierState,
        verifierRole,
        verifierOutcome,
      };
    }
  }

  return {
    routeFamily: null,
    topology: null,
    plannerAuthority: null,
    verifierState: null,
    verifierRole: null,
    verifierOutcome: null,
  };
}

export function impliedRouteContractFromPlaybook(
  events: ActivityEventRef[],
  digestRecord: RecordAccessor,
  detailsRecord: RecordAccessor,
  stringFromRecord: StringFromRecord,
): KnownPlaybookRouteContract | null {
  for (const entry of [...events].reverse()) {
    const digest = digestRecord(entry);
    const details = detailsRecord(entry);
    const contractCandidates = [
      stringFromRecord(digest, "playbook_id"),
      stringFromRecord(details, "playbook_id"),
      stringFromRecord(digest, "playbook_label"),
      stringFromRecord(details, "playbook_label"),
      stringFromRecord(digest, "workflow_id"),
      stringFromRecord(details, "workflow_id"),
      stringFromRecord(digest, "selected_route"),
      stringFromRecord(details, "selected_route"),
      stringFromRecord(digest, "route"),
      stringFromRecord(details, "route"),
    ];
    for (const candidate of contractCandidates) {
      const contract = builtinPlaybookRouteContractForValue(candidate);
      if (contract) {
        return contract;
      }
    }
  }

  return null;
}

export function defaultVerifierRole(
  routeFamily: PlanSummary["routeFamily"],
  topology: PlanSummary["topology"],
): PlanSummary["verifierRole"] | null {
  if (topology !== "planner_specialist_verifier") {
    return null;
  }
  switch (routeFamily) {
    case "research":
      return "citation_verifier";
    case "coding":
      return "test_verifier";
    case "computer_use":
      return "postcondition_verifier";
    case "artifacts":
      return "artifact_quality_verifier";
    default:
      return "verifier";
  }
}

function verifierOutcomeFromVerdict(
  verdict?: string | null,
): PlanSummary["verifierOutcome"] | null {
  switch ((verdict || "").trim().toLowerCase()) {
    case "passed":
      return "pass";
    case "blocked":
      return "blocked";
    case "needs_attention":
    case "unknown":
      return "warning";
    default:
      return null;
  }
}

export function defaultVerifierOutcome(
  verifierState: PlanSummary["verifierState"],
  researchVerification: PlanSummary["researchVerification"],
  codingVerification: PlanSummary["codingVerification"],
  computerUseVerification: PlanSummary["computerUseVerification"],
  artifactQuality: PlanSummary["artifactQuality"],
): PlanSummary["verifierOutcome"] | null {
  return (
    verifierOutcomeFromVerdict(researchVerification?.verdict) ||
    verifierOutcomeFromVerdict(codingVerification?.verdict) ||
    verifierOutcomeFromVerdict(computerUseVerification?.verdict) ||
    verifierOutcomeFromVerdict(artifactQuality?.verdict) ||
    (verifierState === "blocked" ? "blocked" : null)
  );
}

export function verifierRoleTitle(
  role: PlanSummary["verifierRole"] | null,
): string {
  switch (role) {
    case "citation_verifier":
      return "Citation verifier";
    case "test_verifier":
      return "Test verifier";
    case "postcondition_verifier":
      return "Postcondition verifier";
    case "artifact_quality_verifier":
      return "Artifact quality verifier";
    default:
      return "Verifier";
  }
}
