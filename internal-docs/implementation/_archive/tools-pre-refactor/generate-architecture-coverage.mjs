#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import {
  checkDeterministic,
  failWith,
  git,
  implementationRoot,
  readJson,
  repoRoot,
  sha256,
  sha256File,
  stableJson,
  writeDeterministic,
} from "./lib.mjs";
import {
  buildReviewedAssignmentEntry,
  buildReviewedLocatorEntry,
  validateArchitectureCoverageReviewLedger,
} from "./architecture-coverage-review-ledger.mjs";

const auditPath = path.join(
  implementationRoot,
  "audits/2026-07-22-architecture-coverage.md",
);
const masterPath = path.join(
  implementationRoot,
  "ioi-target-end-state-master-implementation-guide.md",
);
const workItemsRoot = path.join(implementationRoot, "work-items");
const outputPath = path.join(
  implementationRoot,
  "generated/architecture-coverage.v1.json",
);
const REVIEW_LEDGER_REPO_PATH =
  "internal-docs/implementation/audits/reconciliation/2026-07-23-architecture-coverage-reviewed-digests.v1.json";
const reviewLedgerPath = path.join(repoRoot, REVIEW_LEDGER_REPO_PATH);
const EXPECTED_OBLIGATION_COUNT = 50;
const EXPECTED_LOCATOR_COUNT = 174;
const AUTHORITATIVE_INPUT_PATHS = {
  source_of_truth_map: "docs/architecture/_meta/source-of-truth-map.md",
  accepted_adr_index: "docs/decisions/README.md",
  execution_horizons: "docs/architecture/_meta/execution-horizons.md",
  implementation_matrix: "docs/architecture/_meta/implementation-matrix.md",
  canon_to_code_delta: "docs/architecture/_meta/canon-to-code-delta.md",
  architecture_contract_registry:
    "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json",
  conformance_index: "docs/conformance/README.md",
};

const NON_BUILD_OWNER_PATH_DISPOSITIONS = {
  "docs/architecture/START_HERE.md": "reader_entry_not_a_build_target",
  "docs/architecture/_meta/canon-readability-audit.md":
    "historical_readability_audit_not_a_build_target",
  "docs/architecture/_meta/doc-classes.md":
    "documentation_classification_control_not_a_build_target",
  "docs/architecture/_meta/execution-horizons.md":
    "authoritative_planning_input_not_an_independent_runtime_target",
  "docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md":
    "terminal_meta_history_not_a_current_build_target",
  "docs/architecture/_meta/hypervisor-kernel-substrate-unification-master-guide.md":
    "terminal_meta_history_not_a_current_build_target",
  "docs/architecture/_meta/implementation-matrix.md":
    "authoritative_implementation_index_not_an_independent_runtime_target",
  "docs/architecture/_meta/start-here.md": "reader_entry_not_a_build_target",
  "docs/architecture/_meta/vocabulary.md":
    "vocabulary_owner_realized_through_subject_contracts_not_a_standalone_target",
  "docs/architecture/whitepaper.tex":
    "architecture_synthesis_not_an_independent_build_target",
};

// These canonical owners are intentionally cross-cutting. They are not
// standalone runtime objects, so their implementation disposition is a
// reviewed split across bounded obligations rather than a fabricated product
// contract.
const CROSS_CUT_OWNER_ASSIGNMENTS = {
  "docs/architecture/foundations/canonical-enums.md": [
    "System package/release/profile",
    "Product-surface compiler/topology",
    "Same-System continuity",
    "Non-live embodied graph",
    "Connected/secured services",
  ],
  "docs/architecture/foundations/web4-and-ioi-stack.md": [
    "System package/release/profile",
    "P0 readiness",
    "Connected/secured services",
  ],
};

const CONFORMANCE_ASSIGNMENTS = {
  "docs/conformance/hypervisor-core/intent-resolution.md": [
    "Goal/harness/tool resolution",
    "Consequential UI actions",
  ],
  "docs/conformance/hypervisor-core/effect-execution.md": [
    "Consequential UI actions",
    "Receipt integrity/offline proof",
  ],
  "docs/conformance/hypervisor-core/harness-profile-adapter.md": [
    "Goal/harness/tool resolution",
    "SDK/CLI/ADK/ODK/public builder path",
  ],
  "docs/conformance/hypervisor-core/information-flow-propagation.md": [
    "Information-flow/declassification",
  ],
  "docs/conformance/hypervisor-core/institutional-learning-boundary.md": [
    "Institutional learning/custody",
  ],
  "docs/conformance/hypervisor-core/work-lifecycle.md": [
    "Context/session/work/result lifecycle",
  ],
  "docs/conformance/hypervisor-core/managed-work-billing.md": [
    "Billing/Work Credits/reconciliation",
  ],
  "docs/conformance/hypervisor-core/dispute-rails.md": [
    "Dispute/adjudication/remedy",
  ],
  "docs/conformance/hypervisor-core/attestation-assurance.md": [
    "Deployment membership/readiness",
    "Measured/private substrate",
  ],
  "docs/conformance/hypervisor-core/physical-action-safety.md": [
    "Non-live embodied graph",
    "Live physical promotion",
  ],
  "docs/conformance/hypervisor-core/platform-operability.md": [
    "Platform operation decisions",
  ],
  "docs/conformance/hypervisor-core/platform-fault-matrix.v1.json": [
    "Platform operation decisions",
    "Same-System continuity",
  ],
  "docs/conformance/hypervisor-core/sovereign-local-completeness.md": [
    "P0 readiness",
    "Wallet grants/receipts/exchange risk",
  ],
  "docs/conformance/hypervisor-core/sovereign-local-completeness-matrix.v1.json": [
    "P0 readiness",
    "Wallet grants/receipts/exchange risk",
  ],
};

// Accepted ADRs remain decision controls rather than a second implementation
// queue. Every currently accepted record must map to one or more bounded A-Z
// obligations so an index change cannot be silently absorbed.
const ACCEPTED_ADR_ASSIGNMENTS = {
  "docs/decisions/0001-scs-deprecation-and-memory-runtime-successor.md": [
    "Context/session/work/result lifecycle",
    "Institutional learning/custody",
  ],
  "docs/decisions/0002-execution-authority-and-client-boundaries.md": [
    "Goal/harness/tool resolution",
    "Platform operation decisions",
    "Consequential UI actions",
  ],
  "docs/decisions/0003-agentgres-operation-backed-domain-truth.md": [
    "Agentgres operation truth",
    "Agentgres persistence/branches/checkpoints",
  ],
  "docs/decisions/0004-worker-mow-and-training-doctrine.md": [
    "Worker ontology/training/marketplace",
  ],
  "docs/decisions/0005-domain-ontologies-and-data-recipes.md": [
    "Ontology definitions/actions",
    "Data recipes/transformations/provenance",
  ],
  "docs/decisions/0006-capability-authority-and-work-graph-vocabulary.md": [
    "Goal/harness/tool resolution",
    "Context/session/work/result lifecycle",
    "Wallet grants/receipts/exchange risk",
  ],
  "docs/decisions/0008-ioi-authority-gateway-sidecar-adoption-wedge.md": [
    "Consequential UI actions",
    "Wallet grants/receipts/exchange risk",
  ],
  "docs/decisions/0010-verifiable-bounded-agency-and-execution-boundary-alignment.md": [
    "Consequential UI actions",
    "Information-flow/declassification",
    "Receipt integrity/offline proof",
    "Wallet grants/receipts/exchange risk",
  ],
  "docs/decisions/0013-hypervisor-core-clients-surfaces-and-adapters.md": [
    "Product-surface compiler/topology",
    "Owner-application operational depth",
    "Production UI truth/source",
    "SDK/CLI/ADK/ODK/public builder path",
  ],
  "docs/decisions/0014-hypervisor-ide-of-ides-and-session-estate.md": [
    "Context/session/work/result lifecycle",
    "Product-surface compiler/topology",
    "Owner-application operational depth",
  ],
  "docs/decisions/0015-bounded-distributed-autonomous-systems-and-network-enrollment.md": [
    "Useful distribution",
    "Federated admission/portable exit",
    "Two-sovereign trial/surplus",
  ],
  "docs/decisions/0016-hypervisor-systems-work-and-application-taxonomy.md": [
    "Room/System graph",
    "Product-surface compiler/topology",
  ],
  "docs/decisions/0017-goal-pursuit-workflow-skill-and-harness-taxonomy.md": [
    "Goal/harness/tool resolution",
    "Context/session/work/result lifecycle",
  ],
  "docs/decisions/0018-bounded-recursive-improvement-campaign-taxonomy.md": [
    "Bounded improvement",
  ],
};

const AUTHORITATIVE_PLANNING_INPUT_DISPOSITIONS = {
  execution_horizons: {
    path: AUTHORITATIVE_INPUT_PATHS.execution_horizons,
    coverage_disposition:
      "reviewed_stage_horizon_input_not_an_independent_build_target",
  },
  implementation_matrix: {
    path: AUTHORITATIVE_INPUT_PATHS.implementation_matrix,
    coverage_disposition:
      "reviewed_architecture_implementation_index_not_an_independent_build_target",
  },
  canon_to_code_delta: {
    path: AUTHORITATIVE_INPUT_PATHS.canon_to_code_delta,
    coverage_disposition:
      "reviewed_canon_delta_input_not_an_independent_build_target",
  },
};

const LOCATOR_TABLE_HEADER =
  "| Ledger target | Exact canonical heading locator(s) |";
const LEDGER_SECTION_HEADINGS = [
  "#### Program, System, truth, runtime, and environment obligations",
  "#### Product, authority, semantic, learning, and supply obligations",
  "#### Distribution, embodied, federation, economics, and ecosystem obligations",
];

// This is the private, reviewable ownership join. Canon owns architecture
// meaning, the master owns sequence, and the records own their own status.
// The projection owns none of those facts.
const COVERAGE_ASSIGNMENTS = {
  "Canon owner/change intake": {
    stage: "M0",
    workItemIds: ["m0-canon-owner-coverage-and-orphan-verifier"],
    contractApplicability: "not_applicable_private_verifier",
    requiredPrivateArtifactClass: "private_architecture_coverage_projection",
  },
  "Public claim boundary": {
    stage: "M14",
    workItemIds: ["ecosystem-assurance-and-public-claim-estate"],
  },
  "System package/release/profile": {
    stage: "M1",
    workItemIds: [
      "m1-system-genesis-product-journey",
      "m1-dual-genesis-and-read-projection",
    ],
  },
  "Genesis/sequence zero/activation": {
    stage: "M1",
    workItemIds: [
      "m1-system-genesis-product-journey",
      "m1-dual-genesis-and-read-projection",
    ],
  },
  "Protected transitions": {
    stage: "M1",
    workItemIds: ["m1-protected-migration-dissolution-enrollment"],
  },
  "Agentgres operation truth": {
    stage: "M3",
    workItemIds: [
      "agentgres-production-readiness-and-branch-effects",
      "m3-goal-kernel-context-and-runtime-truth-spine",
    ],
  },
  "Agentgres persistence/branches/checkpoints": {
    stage: "M3",
    workItemIds: ["agentgres-production-readiness-and-branch-effects"],
  },
  "Deployment membership/readiness": {
    stage: "M2",
    workItemIds: [
      "m2-membership-readiness-plane",
      "m2-node-attestation-identity-secret-readiness",
    ],
  },
  "Writer fencing/reconciliation": {
    stage: "M2",
    workItemIds: ["m2-writer-fence-and-lost-suffix"],
  },
  "Environment discovery/startup": {
    stage: "M2",
    workItemIds: ["project-discovery-startup-and-session-chain"],
  },
  "Backup/restore/route/cleanup": {
    stage: "M2",
    workItemIds: [
      "m2-route-restore-activation-cleanup",
      "storage-profile-repair-and-availability",
    ],
  },
  "Goal/harness/tool resolution": {
    stage: "M3",
    workItemIds: ["m3-pursuit-definition-resolution"],
  },
  "Context/session/work/result lifecycle": {
    stage: "M3",
    workItemIds: [
      "m3-goal-kernel-context-and-runtime-truth-spine",
      "m3-result-lifecycle-negative-retention",
      "m3-work-session-automation-product-journey",
    ],
  },
  "Platform operation decisions": {
    stage: "M9",
    workItemIds: ["platform-operability-observability-and-incidents"],
  },
  "Measured/private substrate": {
    stage: "M9",
    workItemIds: ["hypervisoros-ctee-task-capsule-attestation"],
  },
  "Room/System graph": {
    stage: "M4",
    workItemIds: ["m4-room-graph-truth-and-product-projection"],
  },
  "Participant/frontier/result lifecycle": {
    stage: "M5",
    workItemIds: [
      "m5-participant-frontier-result-closeout",
      "m5-attribution-acceptance-and-challenge-boundary",
      "m5-portable-exit-independent-clients",
    ],
  },
  "P0 readiness": {
    stage: "M5",
    workItemIds: ["m5-p0-readiness-verifier"],
    contractApplicability: "not_applicable_private_verifier",
    requiredPrivateArtifactClass: "private_p0_readiness_verifier_projection",
  },
  "Product-surface compiler/topology": {
    stage: "M6",
    workItemIds: [
      "m6-surface-compiler-and-source-convergence",
      "m6-systems-work-projection-and-mission-alias-migration",
    ],
  },
  "Owner-application operational depth": {
    stage: "M6",
    workItemIds: [
      "m6-owner-application-registration-and-shell-state-coverage",
      "m6-applications-workspace-operational-journey",
    ],
  },
  "Production UI truth/source": {
    stage: "M6",
    workItemIds: [
      "m6-production-truth-fallback-retirement",
      "m6-surface-compiler-and-source-convergence",
    ],
  },
  "Consequential UI actions": {
    stage: "M6",
    workItemIds: ["m6-consequential-action-authority-receipt-unification"],
  },
  "Ontology definitions/actions": {
    stage: "M7",
    workItemIds: [
      "m7-ontology-action-final-invoker-and-product-proof",
      "m7-ontology-operational-journey",
    ],
  },
  "Data recipes/transformations/provenance": {
    stage: "M7",
    workItemIds: [
      "m7-data-transformation-provenance-replay",
      "m7-data-operational-journey",
    ],
  },
  "Information-flow/declassification": {
    stage: "M3",
    workItemIds: ["production-information-flow-and-declassification"],
  },
  "Receipt integrity/offline proof": {
    stage: "M3",
    workItemIds: ["production-receipt-checkpoint-and-offline-proof"],
  },
  "Identity/access/metering": {
    stage: "M9",
    workItemIds: ["m9-managed-optionality-overlay"],
  },
  "Wallet grants/receipts/exchange risk": {
    stage: "M9",
    workItemIds: [
      "m9-authority-gateway-equivalence-and-coverage",
      "m9-sovereign-local-terminal-journey",
      "m9-managed-optionality-overlay",
    ],
  },
  "Institutional learning/custody": {
    stage: "M8",
    workItemIds: [
      "m8-learning-boundary-provider-exit",
      "m8-learning-custody-memory-and-provider-rights",
    ],
  },
  "Bounded improvement": {
    stage: "M8",
    workItemIds: [
      "m8-order-zero-improvement-and-direct-path",
      "m8-improvement-operational-journey",
    ],
  },
  "Model/provider rights/supply": {
    stage: "M8",
    workItemIds: [
      "m8-learning-custody-memory-and-provider-rights",
      "m8-model-supply-route-substitution-and-selected-exit",
    ],
  },
  "Storage profiles/repair": {
    stage: "M2",
    workItemIds: ["storage-profile-repair-and-availability"],
  },
  "Same-System continuity": {
    stage: "M10",
    workItemIds: [
      "m10-attestation-temporal-floor-and-revocation-continuity",
      "m10-topology-chaos-and-operator-product-proof",
      "m10-operations-operational-journey",
    ],
  },
  "Useful distribution": {
    stage: "M11",
    workItemIds: ["m11-useful-same-system-distribution"],
  },
  "Non-live embodied graph": {
    stage: "M11",
    workItemIds: [
      "m11-canonical-embodied-contract-alignment",
      "m11-embodied-nonlive-graph-proof",
      "m11-foundry-promotion-safety-case-and-product-journey",
      "m11-embodied-systems-nonlive-operational-journey",
    ],
  },
  "Live physical promotion": {
    stage: "FUTURE",
    workItemIds: ["live-embodied-promotion"],
  },
  "AIIP channel/envelope/profile": {
    stage: "M12",
    workItemIds: ["m12-aiip-channel-envelope-profile"],
  },
  "AIIP discovery/terms/semantic/action negotiation": {
    stage: "M12",
    workItemIds: ["m12-terms-discovery-semantic-negotiation"],
  },
  "Federated admission/portable exit": {
    stage: "M12",
    workItemIds: [
      "m12-federated-admission-portable-exit-and-bindings",
      "m12-ifc-disclosure-receipt-and-settlement-binding",
      "m12-federation-product-and-operator-journey",
    ],
  },
  "Two-sovereign trial/surplus": {
    stage: "M13",
    workItemIds: [
      "m13-sovereignty-trial-preregistration",
      "m13-two-sovereign-surplus-and-decline-proof",
      "m13-independent-operation-and-external-worker-product-proof",
    ],
  },
  "Worker ontology/training/marketplace": {
    stage: "M8",
    workItemIds: ["worker-training-and-local-marketplace-supply"],
  },
  "Service order/marketplace": {
    stage: "M14",
    workItemIds: [
      "m14-service-family-owner-contract-and-product-surfaces",
      "m14-network-service-devnet",
    ],
  },
  "Billing/Work Credits/reconciliation": {
    stage: "M8",
    workItemIds: ["managed-billing-work-credits-and-supplier-reconciliation"],
  },
  "Dispute/adjudication/remedy": {
    stage: "M12",
    workItemIds: ["dispute-adjudication-remedy-kernel"],
  },
  "Marketplace neutrality/contribution": {
    stage: "M8",
    workItemIds: ["marketplace-neutral-routing-contribution-accounting"],
  },
  "Ecosystem assurance/liability": {
    stage: "M14",
    workItemIds: ["ecosystem-assurance-and-public-claim-estate"],
  },
  "Connected/secured services": {
    stage: "M14",
    workItemIds: [
      "m14-network-service-devnet",
      "m14-service-family-owner-contract-and-product-surfaces",
      "connected-worker-capability-supply-and-hiring",
    ],
  },
  "L1/no-L1 decision": {
    stage: "M14",
    workItemIds: [
      "m14-demand-security-economics",
      "m14-l1-authorization-decision",
    ],
  },
  "SDK/CLI/ADK/ODK/public builder path": {
    stage: "M6",
    workItemIds: ["sdk-cli-adk-odk-builder-journey"],
  },
  "Decentralized cloud/exchange/trade profiles": {
    stage: "M14",
    workItemIds: ["decentralized-profile-admission-and-exit"],
  },
};

function tableRows(markdown, header, endMarker) {
  const start = markdown.indexOf(header);
  const end = markdown.indexOf(endMarker, start);
  if (start < 0 || end < 0) {
    throw new Error(`cannot bound table ${header}`);
  }
  return markdown
    .slice(start, end)
    .split("\n")
    .filter(
      (line) =>
        /^\| .+ \|$/u.test(line) &&
        !line.includes("---") &&
        line !== header,
    )
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function repoPathFromLink(sourcePath, href) {
  const withoutFragment = href.split("#", 1)[0];
  if (
    withoutFragment.length === 0 ||
    /^[a-z][a-z0-9+.-]*:/iu.test(withoutFragment) ||
    withoutFragment.startsWith("/")
  ) {
    throw new Error(`non-repository link ${href} in ${sourcePath}`);
  }
  const resolved = path.posix.normalize(
    path.posix.join(path.posix.dirname(sourcePath), withoutFragment),
  );
  if (resolved === ".." || resolved.startsWith("../")) {
    throw new Error(`link escapes repository: ${href} in ${sourcePath}`);
  }
  return resolved;
}

function repoFileCensus(repoPath, extra = {}) {
  const absolute = path.join(repoRoot, repoPath);
  if (!fs.existsSync(absolute)) throw new Error(`missing input ${repoPath}`);
  const source = fs.readFileSync(absolute);
  return {
    path: repoPath,
    sha256: sha256(source),
    byte_count: source.length,
    ...extra,
  };
}

function markdownCensus(repoPath) {
  const source = fs.readFileSync(path.join(repoRoot, repoPath), "utf8");
  return repoFileCensus(repoPath, {
    markdown_heading_count: [...source.matchAll(/^#{1,6}\s+.+$/gmu)].length,
    markdown_table_line_count: source
      .split("\n")
      .filter((line) => /^\| .+ \|$/u.test(line) && !line.includes("---"))
      .length,
  });
}

function parseSourceOwnership(repoPath) {
  const source = fs.readFileSync(path.join(repoRoot, repoPath), "utf8");
  const rows = tableRows(
    source,
    "| Subject | Canonical Owner | Low-Level Reference | Supporting Context |",
    "\n## Edit Rules",
  );
  return rows.map((cells) => {
    if (cells.length < 2 || cells.length > 4) {
      throw new Error(`malformed source-of-truth owner row: ${cells.join(" | ")}`);
    }
    const ownerPaths = [...cells[1].matchAll(/\]\(([^)]+)\)/gu)]
      .map((match) => repoPathFromLink(repoPath, match[1]))
      .filter((value, index, values) => values.indexOf(value) === index)
      .sort();
    if (ownerPaths.length === 0) {
      throw new Error(`source-of-truth subject has no canonical owner: ${cells[0]}`);
    }
    for (const ownerPath of ownerPaths) {
      if (!fs.existsSync(path.join(repoRoot, ownerPath))) {
        throw new Error(
          `source-of-truth subject ${cells[0]} has missing owner ${ownerPath}`,
        );
      }
    }
    return {
      subject: cells[0],
      owner_paths: ownerPaths,
    };
  });
}

function parseAdrIndex(repoPath) {
  const source = fs.readFileSync(path.join(repoRoot, repoPath), "utf8");
  const start = source.indexOf("## Accepted ADRs");
  if (start < 0) throw new Error(`${repoPath} has no Accepted ADRs section`);
  const nextHeading = source.indexOf("\n## ", start + 1);
  const section = source.slice(start, nextHeading < 0 ? source.length : nextHeading);
  const entries = [];
  for (const line of section.split("\n")) {
    const match = line.match(/^- \[([^\]]+)\]\(([^)]+)\)(.*)$/u);
    if (!match) continue;
    const entryPath = repoPathFromLink(repoPath, match[2]);
    if (!fs.existsSync(path.join(repoRoot, entryPath))) {
      throw new Error(`ADR index references missing record ${entryPath}`);
    }
    entries.push({
      title: match[1],
      path: entryPath,
      sha256: sha256File(path.join(repoRoot, entryPath)),
      index_disposition: /\(superseded by /iu.test(match[3])
        ? "superseded_history"
        : "accepted_decision_control",
    });
  }
  if (entries.length === 0) throw new Error(`${repoPath} indexes no ADR records`);
  return entries;
}

function parseConformanceIndex(repoPath) {
  const source = fs.readFileSync(path.join(repoRoot, repoPath), "utf8");
  const rows = tableRows(
    source,
    "| Family | Owner | Purpose |",
    "\n## Compatibility Labels",
  );
  return rows.map((cells) => {
    if (cells.length !== 3) {
      throw new Error(`malformed conformance-index row: ${cells.join(" | ")}`);
    }
    const match = cells[0].match(/\[([^\]]+)\]\(([^)]+)\)/u);
    if (!match) throw new Error(`conformance family lacks a local link: ${cells[0]}`);
    const targetPath = repoPathFromLink(repoPath, match[2]);
    if (!fs.existsSync(path.join(repoRoot, targetPath))) {
      throw new Error(`conformance index references missing target ${targetPath}`);
    }
    return {
      family: match[1],
      path: targetPath,
      sha256: sha256File(path.join(repoRoot, targetPath)),
      index_owner: cells[1],
      purpose: cells[2],
    };
  });
}

function loadAuthoritativeInputs() {
  const sourceSubjects = parseSourceOwnership(
    AUTHORITATIVE_INPUT_PATHS.source_of_truth_map,
  );
  const sourceSubjectSetSha256 = sha256(
    stableJson(
      sourceSubjects.map(({ subject, owner_paths: ownerPaths }) => ({
        subject,
        owner_paths: ownerPaths,
      })),
    ),
  );
  const adrEntries = parseAdrIndex(AUTHORITATIVE_INPUT_PATHS.accepted_adr_index);
  const conformanceTargets = parseConformanceIndex(
    AUTHORITATIVE_INPUT_PATHS.conformance_index,
  );
  const contractRegistry = readJson(
    path.join(repoRoot, AUTHORITATIVE_INPUT_PATHS.architecture_contract_registry),
  );
  if (!Array.isArray(contractRegistry.contracts)) {
    throw new Error("architecture contract registry has no contracts array");
  }
  const contractIds = contractRegistry.contracts.map((entry) => entry.contract_id);
  if (
    contractIds.some((entry) => typeof entry !== "string") ||
    new Set(contractIds).size !== contractIds.length
  ) {
    throw new Error("architecture contract registry has missing or duplicate IDs");
  }

  const acceptedAdrs = adrEntries.filter(
    (entry) => entry.index_disposition === "accepted_decision_control",
  );
  const supersededAdrs = adrEntries.filter(
    (entry) => entry.index_disposition === "superseded_history",
  );
  const registryFixturePaths = contractRegistry.contracts.flatMap((entry) => [
    ...(entry.positive_fixture_refs ?? []),
    ...(entry.negative_fixture_refs ?? []).map((fixture) => fixture.path),
  ]);
  const registryInvariantPaths = contractRegistry.contracts.flatMap((entry) =>
    (entry.cross_field_invariant_refs ?? []).map((invariant) => invariant.path),
  );

  return {
    sourceSubjects,
    sourceSubjectSetSha256,
    adrEntries,
    acceptedAdrs,
    supersededAdrs,
    conformanceTargets,
    contractRegistry,
    census: {
      source_of_truth_map: repoFileCensus(
        AUTHORITATIVE_INPUT_PATHS.source_of_truth_map,
        {
          owner_subject_count: sourceSubjects.length,
          canonical_owner_path_count: new Set(
            sourceSubjects.flatMap((entry) => entry.owner_paths),
          ).size,
          owner_subject_set_sha256: sourceSubjectSetSha256,
        },
      ),
      accepted_adr_index: repoFileCensus(
        AUTHORITATIVE_INPUT_PATHS.accepted_adr_index,
        {
          accepted_record_count: acceptedAdrs.length,
          superseded_history_count: supersededAdrs.length,
          records: adrEntries,
        },
      ),
      execution_horizons: markdownCensus(
        AUTHORITATIVE_INPUT_PATHS.execution_horizons,
      ),
      implementation_matrix: markdownCensus(
        AUTHORITATIVE_INPUT_PATHS.implementation_matrix,
      ),
      canon_to_code_delta: markdownCensus(
        AUTHORITATIVE_INPUT_PATHS.canon_to_code_delta,
      ),
      architecture_contract_registry: repoFileCensus(
        AUTHORITATIVE_INPUT_PATHS.architecture_contract_registry,
        {
          contract_revision_count: contractRegistry.contracts.length,
          canonical_contract_name_count: new Set(
            contractRegistry.contracts.map((entry) => entry.canonical_name),
          ).size,
          invariant_ref_count: registryInvariantPaths.length,
          fixture_ref_count: registryFixturePaths.length,
        },
      ),
      conformance_index: repoFileCensus(
        AUTHORITATIVE_INPUT_PATHS.conformance_index,
        {
          active_target_count: conformanceTargets.length,
          active_targets: conformanceTargets,
        },
      ),
    },
  };
}

function parseAuditRegistry(markdown) {
  const locatorRows = tableRows(
    markdown,
    LOCATOR_TABLE_HEADER,
    LEDGER_SECTION_HEADINGS[0],
  );
  const locatorMap = new Map();
  for (const cells of locatorRows) {
    if (cells.length !== 2) {
      throw new Error(`malformed locator row: ${cells.join(" | ")}`);
    }
    const locators = [...cells[1].matchAll(/`([^`]+)`/gu)].map(
      (match) => match[1],
    );
    locatorMap.set(cells[0], locators);
  }

  const ledgerRows = [];
  for (let index = 0; index < LEDGER_SECTION_HEADINGS.length; index += 1) {
    const heading = LEDGER_SECTION_HEADINGS[index];
    const endMarker =
      LEDGER_SECTION_HEADINGS[index + 1] ?? "\n## M0–M14 plan audit";
    const rows = tableRows(
      markdown,
      "| Target and exact owner location | Required contract/behavior | Runtime/application owner and journey | Required proof | Stage/private slice | Code evidence | UI observation | Classification | Missing plan material |",
      endMarker,
    );
    const sectionStart = markdown.indexOf(heading);
    const nextSectionStart = markdown.indexOf(endMarker, sectionStart);
    const boundedRows = rows.filter((row) => {
      const rawTarget = row[0] ?? "";
      const rowOffset = markdown.indexOf(`| ${rawTarget} |`, sectionStart);
      return rowOffset >= sectionStart && rowOffset < nextSectionStart;
    });
    for (const cells of boundedRows) {
      if (cells.length !== 9) {
        throw new Error(`malformed obligation row: ${cells.join(" | ")}`);
      }
      ledgerRows.push({
        target: cells[0].replace(/ — .*$/u, ""),
        owner_location_summary: cells[0].replace(/^.*? — /u, ""),
        required_contract_or_behavior: cells[1],
        runtime_application_owner_and_journey: cells[2],
        required_proof: cells[3],
        prior_stage_or_slice: cells[4],
        prior_code_evidence: cells[5],
        prior_ui_observation: cells[6],
        baseline_classification: cells[7].replaceAll("`", ""),
        baseline_missing_plan_material: cells[8],
      });
    }
  }

  return { locatorMap, ledgerRows };
}

function githubHeadingAnchor(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[\p{P}\p{S}]/gu, (character) =>
      character === "-" || character === "_" ? character : "",
    )
    .replace(/\s/gu, "-");
}

function markdownHeadingSections(source) {
  const matches = [...source.matchAll(/^(#{1,6})\s+(.+?)\s*$/gmu)];
  return matches.map((match, index) => {
    const level = match[1].length;
    const next = matches
      .slice(index + 1)
      .find((candidate) => candidate[1].length <= level);
    const end = next?.index ?? source.length;
    return {
      level,
      heading: match[2],
      anchor: githubHeadingAnchor(match[2]),
      source: source.slice(match.index, end),
    };
  });
}

function resolveJsonPointer(document, pointer) {
  if (pointer === "") return document;
  if (!pointer.startsWith("/")) {
    throw new Error(`invalid RFC 6901 pointer ${pointer}`);
  }
  return pointer
    .slice(1)
    .split("/")
    .map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((value, token) => {
      if (value === null || typeof value !== "object" || !(token in value)) {
        throw new Error(`unresolved RFC 6901 pointer ${pointer}`);
      }
      return value[token];
    }, document);
}

function resolveLocator(locator) {
  const hashIndex = locator.indexOf("#");
  if (hashIndex <= 0) throw new Error(`locator lacks fragment: ${locator}`);
  const ownerPath = locator.slice(0, hashIndex);
  const fragment = locator.slice(hashIndex + 1);
  const absolute = path.join(repoRoot, ownerPath);
  if (!fs.existsSync(absolute)) throw new Error(`missing locator owner ${ownerPath}`);
  const source = fs.readFileSync(absolute, "utf8");
  const ownerKind = ownerPath.startsWith("docs/architecture/")
    ? "architecture_canon"
    : ownerPath.startsWith("docs/decisions/")
      ? "accepted_decision_control"
      : ownerPath ===
          "internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md"
        ? "sole_sequencer_demand"
        : "invalid_owner";
  if (ownerKind === "invalid_owner") {
    throw new Error(`locator uses a non-owner/non-sequencer path: ${locator}`);
  }

  if (fragment.startsWith("/")) {
    const value = resolveJsonPointer(JSON.parse(source), fragment);
    return {
      locator,
      owner_path: ownerPath,
      owner_kind: ownerKind,
      owner_sha256: sha256(source),
      fragment_kind: "rfc6901_json_pointer",
      fragment,
      fragment_sha256: sha256(stableJson(value)),
    };
  }

  const matches = markdownHeadingSections(source).filter(
    (entry) => entry.anchor === fragment,
  );
  if (matches.length !== 1) {
    throw new Error(
      `${locator} resolves to ${matches.length} Markdown headings; expected one`,
    );
  }
  const match = matches[0];
  return {
    locator,
    owner_path: ownerPath,
    owner_kind: ownerKind,
    owner_sha256: sha256(source),
    fragment_kind: "exact_markdown_heading",
    fragment,
    heading_level: match.level,
    heading_text: match.heading,
    fragment_sha256: sha256(match.source),
  };
}

function loadWorkItems() {
  const records = new Map();
  const files = fs
    .readdirSync(workItemsRoot)
    .filter((name) => name.endsWith(".v1.json"))
    .sort();
  for (const name of files) {
    const record = readJson(path.join(workItemsRoot, name));
    if (records.has(record.work_item_id)) {
      throw new Error(`duplicate work-item id ${record.work_item_id}`);
    }
    records.set(record.work_item_id, record);
  }
  return { records, files };
}

function ownerAndSurface(sourceText) {
  const parts = sourceText.split(";").map((part) => part.trim());
  if (parts.length > 1) {
    return {
      runtime_or_domain_owner: parts[0],
      applicable_surface_or_journey: parts.slice(1).join("; "),
    };
  }
  return {
    runtime_or_domain_owner: sourceText,
    applicable_surface_or_journey: sourceText,
  };
}

function contractFamiliesFor(workItemIds, records) {
  const families = new Map();
  for (const id of workItemIds) {
    const record = records.get(id);
    for (const family of record.contract_families) {
      const key = `${family.owner_path}\0${family.name}`;
      const current = families.get(key) ?? {
        name: family.name,
        owner_path: family.owner_path,
        owner_sha256: sha256File(path.join(repoRoot, family.owner_path)),
        owner_role: family.owner_role,
        semantic_owner_paths: [...(family.semantic_owner_paths ?? [])].sort(),
        canonical_owner_ref: family.canonical_owner_ref ?? null,
        contract_ids: [],
        schema_versions: [],
        registry_resolution: family.registry_resolution,
        classification: family.classification,
        source_work_item_ids: [],
      };
      if (
        current.owner_role !== family.owner_role ||
        current.canonical_owner_ref !== (family.canonical_owner_ref ?? null) ||
        current.registry_resolution !== family.registry_resolution ||
        current.classification !== family.classification
      ) {
        throw new Error(
          `inconsistent contract metadata for ${family.name} across ${id}`,
        );
      }
      current.contract_ids.push(...(family.contract_ids ?? []));
      current.schema_versions.push(...(family.schema_versions ?? []));
      current.semantic_owner_paths.push(...(family.semantic_owner_paths ?? []));
      current.source_work_item_ids.push(id);
      families.set(key, current);
    }
    for (const artifact of record.private_artifacts.filter(
      (entry) =>
        entry.artifact_class === "private_pending_contract_definition_gap",
    )) {
      const name = artifact.artifact_id.replace(
        /^pending-contract-definition:/u,
        "",
      );
      const key = `private-pending\0${name}`;
      const current = families.get(key) ?? {
        name,
        owner_path: null,
        owner_sha256: null,
        owner_role: "private_pending_definition_decision",
        semantic_owner_paths: [],
        canonical_owner_ref: null,
        contract_ids: [],
        schema_versions: [],
        registry_resolution: "pending_canon_decision",
        classification: "private_pending_contract_definition_gap",
        decision_owner: artifact.decision_owner,
        required_exit: artifact.required_exit,
        reason: artifact.reason,
        product_authority: false,
        architecture_canon: false,
        source_work_item_ids: [],
      };
      current.source_work_item_ids.push(id);
      families.set(key, current);
    }
  }
  return [...families.values()]
    .map((family) => ({
      ...family,
      semantic_owner_paths: [...new Set(family.semantic_owner_paths)].sort(),
      contract_ids: [...new Set(family.contract_ids)].sort(),
      schema_versions: [...new Set(family.schema_versions)].sort(),
      source_work_item_ids: [...new Set(family.source_work_item_ids)].sort(),
    }))
    .sort((left, right) =>
      `${left.owner_path ?? ""}:${left.name}`.localeCompare(
        `${right.owner_path ?? ""}:${right.name}`,
      ),
    );
}

function proofDefinition(row, workItemIds, records) {
  return {
    required_proof: row.required_proof,
    bar_rule:
      "Each named retained log must contain its exact literal *_EXIT=0 only after the record's positive and adversarial/fault criteria pass; task or process exit codes never establish the bar.",
    literal_exits: workItemIds.map((id) => {
      const evidenceIndex = records.get(id).evidence_index;
      return {
        work_item_id: id,
        literal_exit: evidenceIndex.literal_exit,
        expected_output_paths: evidenceIndex.expected_output_paths,
        negative_and_inconclusive_retention:
          evidenceIndex.negative_and_inconclusive_retention,
        producer_independence_required:
          evidenceIndex.producer_independence_required,
        task_exit_code_is_proof: evidenceIndex.task_exit_code_is_proof,
      };
    }),
  };
}

function disposition(stage) {
  if (stage === "FUTURE") {
    return {
      class: "conditional_future_requires_sequencer_amendment",
      activation:
        "Not in the active M0–M14 closure path; requires a later explicit user-approved sequencer amendment.",
      claim_language_gated: true,
      stage_or_capability_closed_by_projection: false,
    };
  }
  const stageNumber = Number.parseInt(stage.slice(1), 10);
  return {
    class: "sequenced_plan_owner_without_status_claim",
    activation:
      "The sole sequencer assigns the plan owner; the owning work-item records separately own status and retained evidence.",
    claim_language_gated: stageNumber >= 9,
    stage_or_capability_closed_by_projection: false,
  };
}

function conformanceCoverage(inputState, ledgerTargets, errors) {
  const refsByTarget = new Map(ledgerTargets.map((target) => [target, []]));
  const indexedPaths = new Set(
    inputState.conformanceTargets.map((entry) => entry.path),
  );
  for (const entry of inputState.conformanceTargets) {
    const assignedTargets = CONFORMANCE_ASSIGNMENTS[entry.path];
    if (!Array.isArray(assignedTargets) || assignedTargets.length === 0) {
      errors.push(
        `conformance target ${entry.path} has no reviewed architecture-obligation mapping`,
      );
      continue;
    }
    for (const target of assignedTargets) {
      if (!refsByTarget.has(target)) {
        errors.push(
          `conformance target ${entry.path} maps to unknown obligation ${target}`,
        );
        continue;
      }
      refsByTarget.get(target).push({
        path: entry.path,
        sha256: entry.sha256,
        family: entry.family,
        index_owner: entry.index_owner,
      });
    }
  }
  for (const configuredPath of Object.keys(CONFORMANCE_ASSIGNMENTS)) {
    if (!indexedPaths.has(configuredPath)) {
      errors.push(
        `reviewed conformance mapping references a target absent from the current index: ${configuredPath}`,
      );
    }
  }
  for (const refs of refsByTarget.values()) {
    refs.sort((left, right) => left.path.localeCompare(right.path));
  }
  return refsByTarget;
}

function canonicalOwnerPathFromRef(reference) {
  const match = reference?.match(/^canon:\/\/([^#]+)#/u);
  return match?.[1] ?? null;
}

function validateDecisionReferences(
  obligations,
  records,
  acceptedAdrs,
  supersededAdrs,
  errors,
) {
  const acceptedPaths = new Set(acceptedAdrs.map((entry) => entry.path));
  const supersededPaths = new Set(supersededAdrs.map((entry) => entry.path));
  const decisionIndexPath = AUTHORITATIVE_INPUT_PATHS.accepted_adr_index;
  for (const obligation of obligations) {
    for (const locator of obligation.exact_owner_locators) {
      if (
        locator.owner_kind === "accepted_decision_control" &&
        locator.owner_path !== decisionIndexPath &&
        !acceptedPaths.has(locator.owner_path)
      ) {
        errors.push(
          `${obligation.target}: decision locator is not currently accepted: ${locator.owner_path}`,
        );
      }
    }
    for (const id of obligation.bounded_work_item_ids) {
      for (const ownerPath of records.get(id)?.canon_owners ?? []) {
        if (supersededPaths.has(ownerPath)) {
          errors.push(`${obligation.target}: ${id} cites superseded ADR ${ownerPath}`);
        } else if (
          ownerPath.startsWith("docs/decisions/") &&
          ownerPath !== decisionIndexPath &&
          !acceptedPaths.has(ownerPath)
        ) {
          errors.push(`${obligation.target}: ${id} cites unindexed ADR ${ownerPath}`);
        }
      }
    }
  }
}

function buildContractOrphanCensus(obligations, contractRegistry, errors) {
  const byId = new Map(
    contractRegistry.contracts.map((entry) => [entry.contract_id, entry]),
  );
  const mappedObligationsById = new Map();
  for (const obligation of obligations) {
    for (const family of obligation.contract_families.filter(
      (entry) => entry.classification === "canonical_contract",
    )) {
      if (
        family.registry_resolution === "architecture_contract_registry" &&
        family.contract_ids.length === 0
      ) {
        errors.push(
          `${obligation.target}: registry-backed contract ${family.name} has no contract ID`,
        );
      }
      for (const contractId of family.contract_ids) {
        const registered = byId.get(contractId);
        if (!registered) {
          errors.push(
            `${obligation.target}: ${family.name} cites unknown contract ID ${contractId}`,
          );
          continue;
        }
        if (registered.canonical_name !== family.name) {
          errors.push(
            `${obligation.target}: ${contractId} is ${registered.canonical_name}, not ${family.name}`,
          );
        }
        const registryOwner = canonicalOwnerPathFromRef(
          registered.canonical_owner_ref,
        );
        if (registryOwner !== family.owner_path) {
          errors.push(
            `${obligation.target}: ${contractId} owner ${registryOwner ?? "unresolved"} does not match ${family.owner_path}`,
          );
        }
        const mapped = mappedObligationsById.get(contractId) ?? new Set();
        mapped.add(obligation.obligation_id);
        mappedObligationsById.set(contractId, mapped);
      }
    }
  }

  return contractRegistry.contracts
    .map((entry) => {
      const obligationIds = [...(mappedObligationsById.get(entry.contract_id) ?? [])]
        .sort();
      if (obligationIds.length === 0) {
        errors.push(
          `registered contract is orphaned from architecture coverage: ${entry.contract_id}`,
        );
      }
      return {
        contract_id: entry.contract_id,
        canonical_name: entry.canonical_name,
        canonical_owner_ref: entry.canonical_owner_ref,
        schema_version: entry.schema_version,
        mapped_obligation_ids: obligationIds,
        coverage_disposition:
          obligationIds.length > 0
            ? "mapped_registered_contract"
            : "orphan_registered_contract",
      };
    })
    .sort((left, right) => left.contract_id.localeCompare(right.contract_id));
}

function buildOwnerSubjectCensus(
  sourceSubjects,
  obligations,
  records,
  errors,
  lastReviewedAt,
) {
  const byTarget = new Map(obligations.map((entry) => [entry.target, entry]));
  const obligationIdsByOwnerPath = new Map();
  const addMapping = (ownerPath, obligationId) => {
    const ids = obligationIdsByOwnerPath.get(ownerPath) ?? new Set();
    ids.add(obligationId);
    obligationIdsByOwnerPath.set(ownerPath, ids);
  };

  for (const obligation of obligations) {
    for (const locator of obligation.exact_owner_locators.filter(
      (entry) => entry.owner_kind === "architecture_canon",
    )) {
      addMapping(locator.owner_path, obligation.obligation_id);
    }
    for (const id of obligation.bounded_work_item_ids) {
      for (const ownerPath of records.get(id)?.canon_owners ?? []) {
        if (ownerPath.startsWith("docs/architecture/")) {
          addMapping(ownerPath, obligation.obligation_id);
        }
      }
    }
    for (const family of obligation.contract_families) {
      if (family.owner_path?.startsWith("docs/architecture/")) {
        addMapping(family.owner_path, obligation.obligation_id);
      }
      for (const ownerPath of family.semantic_owner_paths ?? []) {
        if (ownerPath.startsWith("docs/architecture/")) {
          addMapping(ownerPath, obligation.obligation_id);
        }
      }
    }
  }

  for (const [ownerPath, targets] of Object.entries(
    CROSS_CUT_OWNER_ASSIGNMENTS,
  )) {
    for (const target of targets) {
      const obligation = byTarget.get(target);
      if (!obligation) {
        errors.push(`${ownerPath}: cross-cut mapping names unknown target ${target}`);
        continue;
      }
      addMapping(ownerPath, obligation.obligation_id);
    }
  }

  return sourceSubjects.map((entry, index) => {
    const ownerDispositions = entry.owner_paths.map((ownerPath) => {
      const nonBuildReason = NON_BUILD_OWNER_PATH_DISPOSITIONS[ownerPath];
      const obligationIds = [
        ...(obligationIdsByOwnerPath.get(ownerPath) ?? new Set()),
      ].sort();
      if (!nonBuildReason && obligationIds.length === 0) {
        errors.push(
          `build-relevant canonical owner is orphaned from architecture coverage: ${ownerPath} (${entry.subject})`,
        );
      }
      const workItemIds = [
        ...new Set(
          obligationIds.flatMap(
            (id) =>
              obligations.find((obligation) => obligation.obligation_id === id)
                ?.bounded_work_item_ids ?? [],
          ),
        ),
      ].sort();
      return {
        owner_path: ownerPath,
        owner_digest: sha256File(path.join(repoRoot, ownerPath)),
        mapped_obligation_ids: obligationIds,
        mapped_work_item_ids: workItemIds,
        coverage_disposition: nonBuildReason
          ? nonBuildReason
          : obligationIds.length > 0
            ? "mapped_build_relevant_canonical_owner"
            : "orphan_build_relevant_canonical_owner",
      };
    });
    return {
      owner_subject_id: `OWNER-SUBJECT-${String(index + 1).padStart(3, "0")}`,
      subject: entry.subject,
      owner_paths: entry.owner_paths,
      owner_dispositions: ownerDispositions,
      last_reviewed_at: lastReviewedAt,
    };
  });
}

function buildConformanceOrphanCensus(
  conformanceTargets,
  obligationByTarget,
  errors,
) {
  return conformanceTargets.map((entry) => {
    const targets = CONFORMANCE_ASSIGNMENTS[entry.path] ?? [];
    const mappedObligations = targets
      .map((target) => obligationByTarget.get(target))
      .filter(Boolean);
    if (mappedObligations.length === 0) {
      errors.push(
        `active conformance target is orphaned from architecture coverage: ${entry.path}`,
      );
    }
    return {
      path: entry.path,
      sha256: entry.sha256,
      family: entry.family,
      index_owner: entry.index_owner,
      mapped_obligation_ids: mappedObligations
        .map((obligation) => obligation.obligation_id)
        .sort(),
      mapped_work_item_ids: [
        ...new Set(
          mappedObligations.flatMap(
            (obligation) => obligation.bounded_work_item_ids,
          ),
        ),
      ].sort(),
      coverage_disposition:
        mappedObligations.length > 0
          ? "mapped_active_conformance_target"
          : "orphan_active_conformance_target",
    };
  });
}

function buildAcceptedAdrOrphanCensus(
  acceptedAdrs,
  obligationByTarget,
  errors,
) {
  const acceptedPaths = new Set(acceptedAdrs.map((entry) => entry.path));
  for (const configuredPath of Object.keys(ACCEPTED_ADR_ASSIGNMENTS)) {
    if (!acceptedPaths.has(configuredPath)) {
      errors.push(
        `reviewed accepted-ADR mapping references a record that is not currently accepted: ${configuredPath}`,
      );
    }
  }
  return acceptedAdrs.map((entry) => {
    const targets = ACCEPTED_ADR_ASSIGNMENTS[entry.path] ?? [];
    if (targets.length === 0) {
      errors.push(`accepted ADR is orphaned from architecture coverage: ${entry.path}`);
    }
    if (new Set(targets).size !== targets.length) {
      errors.push(`accepted ADR has duplicate obligation targets: ${entry.path}`);
    }
    const mappedObligations = targets
      .map((target) => {
        const obligation = obligationByTarget.get(target);
        if (!obligation) {
          errors.push(
            `accepted ADR ${entry.path} maps to unknown obligation ${target}`,
          );
        }
        return obligation;
      })
      .filter(Boolean);
    return {
      path: entry.path,
      title: entry.title,
      sha256: entry.sha256,
      index_disposition: entry.index_disposition,
      mapped_obligation_ids: mappedObligations
        .map((obligation) => obligation.obligation_id)
        .sort(),
      coverage_disposition:
        mappedObligations.length > 0
          ? "mapped_accepted_decision_control"
          : "orphan_accepted_decision_control",
    };
  });
}

function buildAuthoritativePlanningInputCensus(inputState, errors) {
  const entries = [];
  for (const [inputId, disposition] of Object.entries(
    AUTHORITATIVE_PLANNING_INPUT_DISPOSITIONS,
  )) {
    const census = inputState.census[inputId];
    if (!census) {
      errors.push(`authoritative planning input is missing from census: ${inputId}`);
      continue;
    }
    if (census.path !== disposition.path) {
      errors.push(
        `authoritative planning input ${inputId} resolves to ${census.path}, expected ${disposition.path}`,
      );
    }
    if (
      typeof disposition.coverage_disposition !== "string" ||
      disposition.coverage_disposition.length === 0
    ) {
      errors.push(
        `authoritative planning input ${inputId} lacks an explicit reviewed disposition`,
      );
    }
    entries.push({
      input_id: inputId,
      path: disposition.path,
      sha256: census.sha256,
      coverage_disposition: disposition.coverage_disposition,
    });
  }
  return entries;
}

function buildProjection() {
  const auditMarkdown = fs.readFileSync(auditPath, "utf8");
  const { locatorMap, ledgerRows } = parseAuditRegistry(auditMarkdown);
  const { records, files } = loadWorkItems();
  const errors = [];
  const inputState = loadAuthoritativeInputs();
  const reviewLedger = readJson(reviewLedgerPath);
  const lastReviewedAt = reviewLedger.review_transaction?.reviewed_at ?? null;

  if (locatorMap.size !== EXPECTED_OBLIGATION_COUNT) {
    errors.push(
      `audit locator registry has ${locatorMap.size} targets; expected ${EXPECTED_OBLIGATION_COUNT}`,
    );
  }
  if (ledgerRows.length !== EXPECTED_OBLIGATION_COUNT) {
    errors.push(
      `audit obligation ledger has ${ledgerRows.length} rows; expected ${EXPECTED_OBLIGATION_COUNT}`,
    );
  }
  if (Object.keys(COVERAGE_ASSIGNMENTS).length !== EXPECTED_OBLIGATION_COUNT) {
    errors.push(
      `coverage assignment registry has ${Object.keys(COVERAGE_ASSIGNMENTS).length} rows; expected ${EXPECTED_OBLIGATION_COUNT}`,
    );
  }

  const ledgerTargets = ledgerRows.map((row) => row.target);
  const conformanceRefsByTarget = conformanceCoverage(
    inputState,
    ledgerTargets,
    errors,
  );
  for (const target of ledgerTargets) {
    if (!locatorMap.has(target)) errors.push(`${target}: missing exact locator row`);
    if (!(target in COVERAGE_ASSIGNMENTS)) {
      errors.push(`${target}: missing coverage assignment`);
    }
  }
  for (const target of locatorMap.keys()) {
    if (!ledgerTargets.includes(target)) errors.push(`${target}: locator has no ledger row`);
  }
  for (const target of Object.keys(COVERAGE_ASSIGNMENTS)) {
    if (!ledgerTargets.includes(target)) {
      errors.push(`${target}: assignment has no audited obligation`);
    }
  }

  const obligations = [];
  for (let index = 0; index < ledgerRows.length; index += 1) {
    const row = ledgerRows[index];
    const assignment = COVERAGE_ASSIGNMENTS[row.target];
    if (!assignment) continue;
    if (!/^(?:M(?:[0-9]|1[0-4])|FUTURE)$/u.test(assignment.stage)) {
      errors.push(`${row.target}: invalid owning stage ${assignment.stage}`);
    }
    if (
      !Array.isArray(assignment.workItemIds) ||
      assignment.workItemIds.length < 1 ||
      assignment.workItemIds.length > 4 ||
      new Set(assignment.workItemIds).size !== assignment.workItemIds.length
    ) {
      errors.push(`${row.target}: work-item mapping is empty, duplicated, or unbounded`);
    }

    for (const id of assignment.workItemIds) {
      const record = records.get(id);
      if (!record) {
        errors.push(`${row.target}: unknown work-item ${id}`);
        continue;
      }
      if (record.stage_id !== assignment.stage) {
        errors.push(
          `${row.target}: ${id} belongs to ${record.stage_id}, not sole owner ${assignment.stage}`,
        );
      }
      const pendingContractDefinitions = record.private_artifacts.filter(
        (entry) =>
          entry.artifact_class === "private_pending_contract_definition_gap",
      );
      if (
        (!Array.isArray(record.contract_families) ||
          record.contract_families.length === 0) &&
        pendingContractDefinitions.length === 0 &&
        assignment.contractApplicability !==
          "not_applicable_private_verifier"
      ) {
        errors.push(
          `${row.target}: ${id} has neither a canonical contract family nor an explicitly classified private pending contract-definition gap`,
        );
      }
      if (
        assignment.contractApplicability ===
        "not_applicable_private_verifier"
      ) {
        if (
          assignment.workItemIds.length !== 1 ||
          !assignment.requiredPrivateArtifactClass ||
          !record.private_artifacts.some(
            (entry) =>
              entry.artifact_class === assignment.requiredPrivateArtifactClass &&
              entry.product_authority === false &&
              entry.architecture_canon === false,
          )
        ) {
          errors.push(
            `${row.target}: private verifier exception lacks its exact non-authoritative artifact classification`,
          );
        }
        if (
          record.contract_families.length !== 0 ||
          pendingContractDefinitions.length !== 0
        ) {
          errors.push(
            `${row.target}: private verifier exception must not manufacture a product contract`,
          );
        }
      }
      for (const family of record.contract_families ?? []) {
        if (
          typeof family.name !== "string" ||
          typeof family.owner_path !== "string" ||
          family.classification !== "canonical_contract"
        ) {
          errors.push(`${row.target}: ${id} has a malformed contract family`);
          continue;
        }
        const familyOwner = path.join(repoRoot, family.owner_path);
        if (!record.canon_owners.includes(family.owner_path)) {
          errors.push(
            `${row.target}: ${id} contract ${family.name} is outside its declared canon owners`,
          );
        }
        if (!fs.existsSync(familyOwner)) {
          errors.push(
            `${row.target}: ${id} contract ${family.name} has missing owner ${family.owner_path}`,
          );
        }
      }
      for (const pending of pendingContractDefinitions) {
        if (
          pending.product_authority !== false ||
          pending.architecture_canon !== false ||
          !pending.artifact_id.startsWith("pending-contract-definition:")
        ) {
          errors.push(
            `${row.target}: ${id} has a malformed private pending contract-definition gap`,
          );
        }
      }
      if (!record.evidence_index?.literal_exit?.match(/^[A-Z][A-Z0-9_]*_EXIT=0$/u)) {
        errors.push(`${row.target}: ${id} has no exact literal exit definition`);
      }
      if (record.evidence_index?.task_exit_code_is_proof !== false) {
        errors.push(`${row.target}: ${id} does not reject task-exit-code proof`);
      }
      if (!Array.isArray(record.positive_proof) || record.positive_proof.length === 0) {
        errors.push(`${row.target}: ${id} has no positive proof definition`);
      }
      if (!record.adversarial_or_fault_proof) {
        errors.push(`${row.target}: ${id} has no adversarial/fault definition`);
      }
    }

    let ownerLocators = [];
    try {
      ownerLocators = (locatorMap.get(row.target) ?? []).map(resolveLocator);
    } catch (error) {
      errors.push(`${row.target}: ${error.message}`);
    }
    if (ownerLocators.length === 0) errors.push(`${row.target}: no exact owner locator`);
    if (!ownerLocators.some((locator) => locator.owner_kind !== "sole_sequencer_demand")) {
      errors.push(`${row.target}: has no canonical/accepted-decision owner locator`);
    }

    const ownerSurface = ownerAndSurface(
      row.runtime_application_owner_and_journey,
    );
    if (
      !ownerSurface.runtime_or_domain_owner ||
      !ownerSurface.applicable_surface_or_journey
    ) {
      errors.push(`${row.target}: missing runtime/product owner or applicable surface`);
    }

    const availableIds = assignment.workItemIds.filter((id) => records.has(id));
    let families = [];
    try {
      families = contractFamiliesFor(availableIds, records);
    } catch (error) {
      errors.push(`${row.target}: ${error.message}`);
    }
    if (
      families.length === 0 &&
      assignment.contractApplicability !== "not_applicable_private_verifier"
    ) {
      errors.push(`${row.target}: no resolved contract families`);
    }

    const canonicalOwnerLocators = ownerLocators.filter(
      (entry) => entry.owner_kind !== "sole_sequencer_demand",
    );
    const primaryOwner = canonicalOwnerLocators[0] ?? null;
    const ownerDigests = [
      ...new Map(
        canonicalOwnerLocators.map((entry) => [
          entry.owner_path,
          {
            owner_path: entry.owner_path,
            owner_digest: entry.owner_sha256,
            owner_kind: entry.owner_kind,
          },
        ]),
      ).values(),
    ].sort((left, right) => left.owner_path.localeCompare(right.owner_path));
    const contractIds = [
      ...new Set(
        families
          .filter((entry) => entry.classification === "canonical_contract")
          .flatMap((entry) => entry.contract_ids),
      ),
    ].sort();
    const conformanceRefs = conformanceRefsByTarget.get(row.target) ?? [];

    obligations.push({
      obligation_id: `AZ-${String(index + 1).padStart(2, "0")}`,
      target: row.target,
      required_contract_or_behavior: row.required_contract_or_behavior,
      owner_path: primaryOwner?.owner_path ?? null,
      owner_digest: primaryOwner?.owner_sha256 ?? null,
      owner_paths: ownerDigests.map((entry) => entry.owner_path),
      owner_digests: ownerDigests,
      exact_owner_locators: ownerLocators,
      contract_ids: contractIds,
      contract_families: families,
      contract_applicability:
        assignment.contractApplicability ?? "canonical_or_pending_contracts",
      conformance_refs: conformanceRefs,
      stage_id: assignment.stage,
      owning_stage: assignment.stage,
      work_item_ids: assignment.workItemIds,
      bounded_work_item_ids: assignment.workItemIds,
      projection_surfaces: [
        ownerSurface.applicable_surface_or_journey,
      ],
      runtime_and_product_ownership: {
        source_text: row.runtime_application_owner_and_journey,
        ...ownerSurface,
      },
      proof_definition: proofDefinition(row, availableIds, records),
      coverage_disposition: disposition(assignment.stage),
      last_reviewed_at: lastReviewedAt,
      audit_baseline: {
        classification: row.baseline_classification,
        prior_stage_or_slice: row.prior_stage_or_slice,
        missing_plan_material: row.baseline_missing_plan_material,
        code_evidence_nonclaim: row.prior_code_evidence,
        ui_observation_nonclaim: row.prior_ui_observation,
      },
    });
  }

  const locatorCount = obligations.reduce(
    (count, obligation) => count + obligation.exact_owner_locators.length,
    0,
  );
  if (locatorCount !== EXPECTED_LOCATOR_COUNT) {
    errors.push(
      `resolved ${locatorCount} exact locators; expected ${EXPECTED_LOCATOR_COUNT}`,
    );
  }
  if (
    new Set(obligations.map((entry) => entry.obligation_id)).size !==
    EXPECTED_OBLIGATION_COUNT
  ) {
    errors.push("obligation IDs are incomplete or duplicated");
  }

  const currentReviewedLocators = obligations.flatMap((obligation) =>
    obligation.exact_owner_locators.map((resolvedLocator, index) =>
      buildReviewedLocatorEntry({
        obligationId: obligation.obligation_id,
        obligationTarget: obligation.target,
        locatorOrdinal: index + 1,
        resolvedLocator,
      }),
    ),
  );
  const currentReviewedAssignments = obligations.map((obligation) =>
    buildReviewedAssignmentEntry({
      obligation,
      assignment: COVERAGE_ASSIGNMENTS[obligation.target],
      records,
    }),
  );
  const obligationByTarget = new Map(
    obligations.map((entry) => [entry.target, entry]),
  );
  const acceptedAdrOrphanCensus = buildAcceptedAdrOrphanCensus(
    inputState.acceptedAdrs,
    obligationByTarget,
    errors,
  );
  const authoritativePlanningInputCensus =
    buildAuthoritativePlanningInputCensus(inputState, errors);
  errors.push(
    ...validateArchitectureCoverageReviewLedger({
      ledger: reviewLedger,
      currentEntries: currentReviewedLocators,
      currentAssignments: currentReviewedAssignments,
      currentAcceptedAdrs: acceptedAdrOrphanCensus,
      currentPlanningInputs: authoritativePlanningInputCensus,
      currentOwnerSubjectSetSha256: inputState.sourceSubjectSetSha256,
      expectedObligationCount: EXPECTED_OBLIGATION_COUNT,
      expectedLocatorCount: EXPECTED_LOCATOR_COUNT,
      expectedAcceptedAdrCount: inputState.acceptedAdrs.length,
      expectedPlanningInputCount: Object.keys(
        AUTHORITATIVE_PLANNING_INPUT_DISPOSITIONS,
      ).length,
    }),
  );

  validateDecisionReferences(
    obligations,
    records,
    inputState.acceptedAdrs,
    inputState.supersededAdrs,
    errors,
  );
  const contractOrphanCensus = buildContractOrphanCensus(
    obligations,
    inputState.contractRegistry,
    errors,
  );
  const ownerSubjectCensus = buildOwnerSubjectCensus(
    inputState.sourceSubjects,
    obligations,
    records,
    errors,
    lastReviewedAt,
  );
  const conformanceOrphanCensus = buildConformanceOrphanCensus(
    inputState.conformanceTargets,
    obligationByTarget,
    errors,
  );

  failWith("architecture-coverage generation", errors);

  const workItemDigests = files.map((name) => ({
    path: `internal-docs/implementation/work-items/${name}`,
    sha256: sha256File(path.join(workItemsRoot, name)),
  }));
  const stageCounts = obligations.reduce((counts, obligation) => {
    counts[obligation.owning_stage] =
      (counts[obligation.owning_stage] ?? 0) + 1;
    return counts;
  }, {});
  const dispositionCounts = obligations.reduce((counts, obligation) => {
    const key = obligation.coverage_disposition.class;
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
  const head = git(["rev-parse", "HEAD"]);

  return {
    evidence_format: "ioi.program.architecture_coverage.v1",
    projection_role:
      "Private deterministic architecture-to-plan coverage projection; not architecture canon, not a sequencer, not product authority, and not a status owner.",
    generator: {
      path: "internal-docs/implementation/tools/generate-architecture-coverage.mjs",
      write_command:
        "node internal-docs/implementation/tools/generate-architecture-coverage.mjs --write",
      check_command:
        "node internal-docs/implementation/tools/generate-architecture-coverage.mjs --check",
    },
    source_provenance: {
      checkout_head: head.status === 0 ? head.stdout.trim() : "unavailable",
      audit_path:
        "internal-docs/implementation/audits/2026-07-22-architecture-coverage.md",
      audit_sha256: sha256File(auditPath),
      sole_sequencer_path:
        "internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md",
      sole_sequencer_sha256: sha256File(masterPath),
      work_item_count: files.length,
      work_item_set_sha256: sha256(stableJson(workItemDigests)),
      private_contract_owner_configuration: repoFileCensus(
        "internal-docs/implementation/tools/contract-owner-locators.v1.json",
      ),
      architecture_coverage_review_ledger: repoFileCensus(
        REVIEW_LEDGER_REPO_PATH,
        {
          schema_version: reviewLedger.schema_version,
          review_transaction_id:
            reviewLedger.review_transaction.review_transaction_id,
          reviewed_at: reviewLedger.review_transaction.reviewed_at,
          automatic_update_permitted:
            reviewLedger.review_transaction.automatic_update_permitted,
          reviewed_owner_subject_set_sha256:
            reviewLedger.reviewed_owner_subject_set_sha256,
          reviewed_mapping_identity_set_sha256:
            reviewLedger.reviewed_mapping_identity_set_sha256,
          reviewed_locator_digest_set_sha256:
            reviewLedger.reviewed_locator_digest_set_sha256,
          reviewed_assignment_set_sha256:
            reviewLedger.reviewed_assignment_set_sha256,
          reviewed_accepted_adr_set_sha256:
            reviewLedger.reviewed_accepted_adr_set_sha256,
          reviewed_authoritative_planning_input_set_sha256:
            reviewLedger.reviewed_authoritative_planning_input_set_sha256,
          reviewed_locator_occurrence_count:
            reviewLedger.reviewed_locators.length,
          reviewed_assignment_count:
            reviewLedger.reviewed_assignments.length,
          reviewed_accepted_adr_count:
            reviewLedger.reviewed_accepted_adrs.length,
          reviewed_authoritative_planning_input_count:
            reviewLedger.reviewed_authoritative_planning_inputs.length,
        },
      ),
      authoritative_input_set_sha256: sha256(
        stableJson(inputState.census),
      ),
      authoritative_input_census: inputState.census,
    },
    proof_and_status_nonclaims: [
      "This projection assigns planning coverage only; it does not implement behavior or close a work item, stage, application, mechanism gate, or public claim.",
      "Work-item records and program-state.json remain the only private status sources; no work-item status is copied here.",
      "Coverage admission is status-agnostic: a mapped record may advance through any valid record status without changing its reviewed stage, claim, owner, contract, or scope identity, and this projection neither reads nor emits that status.",
      "Product authority remains wallet grants, sealed intents, owner policy, final-invoker checks, and receipts. This private projection and any unsigned workflow hash chain grant no authority.",
      "Federation, multi-node, two-sovereign, connected-service, embodied-live, and L1 language remains gated by its owning stage and literal retained exits.",
      "Owner-subject, contract-registry, and conformance-target mappings are maintenance joins only. They do not turn private projections or verifier records into product contracts.",
      "A matching reviewed-digest ledger proves only that the exact owner bytes, fragments, and mapping identities are the separately reviewed inputs. The ledger grants no product authority, changes no status, and closes no work item or stage.",
    ],
    summary: {
      build_relevant_obligation_count: obligations.length,
      exact_owner_locator_count: locatorCount,
      reviewed_exact_owner_locator_count:
        reviewLedger.reviewed_locators.length,
      canonical_or_accepted_owner_path_count: new Set(
        obligations.flatMap((obligation) =>
          obligation.exact_owner_locators
            .filter((locator) => locator.owner_kind !== "sole_sequencer_demand")
            .map((locator) => locator.owner_path),
        ),
      ).size,
      sole_sequencer_demand_locator_count: obligations
        .flatMap((obligation) => obligation.exact_owner_locators)
        .filter((locator) => locator.owner_kind === "sole_sequencer_demand")
        .length,
      owning_stage_counts: Object.fromEntries(
        Object.entries(stageCounts).sort(([left], [right]) =>
          left.localeCompare(right, undefined, { numeric: true }),
        ),
      ),
      disposition_counts: Object.fromEntries(
        Object.entries(dispositionCounts).sort(([left], [right]) =>
          left.localeCompare(right),
        ),
      ),
      source_of_truth_owner_subject_count: ownerSubjectCensus.length,
      accepted_adr_count: acceptedAdrOrphanCensus.length,
      authoritative_planning_input_count:
        authoritativePlanningInputCensus.length,
      registered_contract_revision_count: contractOrphanCensus.length,
      active_conformance_target_count: conformanceOrphanCensus.length,
      owner_subject_orphan_count: ownerSubjectCensus
        .flatMap((entry) => entry.owner_dispositions)
        .filter((entry) =>
          entry.coverage_disposition.startsWith("orphan_"),
        ).length,
      registered_contract_orphan_count: contractOrphanCensus.filter(
        (entry) => entry.coverage_disposition === "orphan_registered_contract",
      ).length,
      conformance_target_orphan_count: conformanceOrphanCensus.filter(
        (entry) =>
          entry.coverage_disposition === "orphan_active_conformance_target",
      ).length,
      accepted_adr_orphan_count: acceptedAdrOrphanCensus.filter(
        (entry) =>
          entry.coverage_disposition === "orphan_accepted_decision_control",
      ).length,
      authoritative_planning_input_orphan_count:
        authoritativePlanningInputCensus.filter(
          (entry) => !entry.coverage_disposition,
        ).length,
    },
    orphan_detection: {
      rule:
        "Every reviewed source-of-truth owner subject, accepted ADR, registered contract revision, and active conformance-index target must resolve to bounded architecture obligations; each authoritative planning input must carry an explicit reviewed non-build disposition. Mapped work-item status is deliberately irrelevant to this coverage join.",
      owner_subjects: ownerSubjectCensus,
      accepted_adrs: acceptedAdrOrphanCensus,
      authoritative_planning_inputs: authoritativePlanningInputCensus,
      registered_contracts: contractOrphanCensus,
      conformance_targets: conformanceOrphanCensus,
      superseded_adr_references_permitted: false,
      orphan_counts: {
        owner_subjects: 0,
        accepted_adrs: 0,
        authoritative_planning_inputs: 0,
        registered_contracts: 0,
        conformance_targets: 0,
      },
      last_reviewed_at: lastReviewedAt,
    },
    obligations,
  };
}

const modes = process.argv.slice(2);
if (modes.length !== 1 || !["--write", "--check"].includes(modes[0])) {
  process.stderr.write(
    "usage: node internal-docs/implementation/tools/generate-architecture-coverage.mjs --write|--check\n",
  );
  process.exit(2);
}

const projection = buildProjection();
if (modes[0] === "--write") {
  writeDeterministic(outputPath, projection);
  process.stdout.write(
    `architecture coverage written: ${projection.summary.build_relevant_obligation_count} obligations, ${projection.summary.exact_owner_locator_count} exact locators frozen by reviewed ledger ${projection.source_provenance.architecture_coverage_review_ledger.sha256}, ${projection.source_provenance.work_item_count} work items inspected\n`,
  );
} else {
  const result = checkDeterministic(outputPath, projection);
  failWith("architecture-coverage check", result.ok ? [] : [result.reason]);
  process.stdout.write(
    `architecture coverage check passed: ${projection.summary.build_relevant_obligation_count} obligations, ${projection.summary.exact_owner_locator_count} reviewed exact locators, one owning stage and bounded work-item map per obligation; changed owner or fragment digests require a separate dated review ledger\n`,
  );
}
