#!/usr/bin/env node
// Generates the single current-orientation view.
//
//   node tools/generate-now.mjs --write     write NOW.md + generated/program-state.v1.json
//   node tools/generate-now.mjs --check     fail if either is stale
//
// Everything here is DERIVED. NOW.md is never edited by hand and is never a
// second sequencer or a second status owner. It answers, in one screen:
// what stage is current, what cut is next, why it is next, which canon owners
// define it, what is in and out of scope, which checks to run, and what blocks
// advancement.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  finding,
  readJson,
  REPO_ROOT,
  report,
  sha256Text,
  writeJsonDeterministic,
} from "./lib/estate.mjs";
import {
  isOpen,
  LEDGER_REL as HOLD_LEDGER_REL,
  QUALIFIED_STATUS,
  readHoldLedger,
} from "./lib/holds.mjs";

const STATUS_ORDER = [
  "proposed",
  "scoped",
  "active",
  "evidence_ready",
  "verified",
];

export function loadWorkItems() {
  const out = [];
  const seen = new Set();
  for (const rel of ["work-items/active", "work-items/proposed", "work-items"]) {
    const dir = path.join(ESTATE_ROOT, rel);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir).sort()) {
      if (!f.endsWith(".v1.json") || seen.has(f)) continue;
      seen.add(f);
      const record = readJson(path.join(dir, f));
      out.push({ file: `${rel}/${f}`, ...record });
    }
  }
  return out;
}

// Status authority: where a cut ALSO exists as a merged, tracked record under
// docs/architecture/_meta/work-items/, that tracked record is the authority and
// the private record mirrors it. Everywhere else the private record is the
// authority. Exactly one owner per work item, always named.
export function statusAuthority(record) {
  const trackedPath = path.join(
    REPO_ROOT,
    "docs/architecture/_meta/work-items",
    `${record.work_item_id}.v1.json`,
  );
  if (fs.existsSync(trackedPath)) {
    const tracked = readJson(trackedPath);
    return {
      owner: "tracked_merged_record",
      ref: `docs/architecture/_meta/work-items/${record.work_item_id}.v1.json`,
      status: tracked.status,
      private_status: record.status,
      agrees: tracked.status === record.status,
    };
  }
  return {
    owner: "private_record",
    ref: `internal-docs/implementation/${record.file}`,
    status: record.status,
    private_status: record.status,
    agrees: true,
  };
}

export function stageState(stage, records, qualifiedBy = new Map()) {
  const mine = records.filter((r) => r.stage_id === stage.id);
  if (mine.length === 0) return { state: "pending", reason: "no records" };
  const exactExitId = stage.exit_gate?.aggregate_work_item_id;
  if (!exactExitId) return { state: "pending", reason: "condition-gated stage has no sequence exit gate" };
  const aggregate = mine.find((record) => record.work_item_id === exactExitId);
  if (!aggregate) return { state: "pending", reason: `sequence exit gate ${exactExitId} has no owning record` };
  const raw = statusAuthority(aggregate).status;
  const heldBy = qualifiedBy.get(exactExitId) ?? [];
  if (raw === "verified" && heldBy.length > 0) {
    return { state: "evidence_ready", reason: `exact sequence exit gate is verified_historical_with_open_successor under ${heldBy.join(", ")}` };
  }
  if (raw === "verified") return { state: "verified", reason: "exact sequence exit gate is verified" };
  if (raw === "evidence_ready") return { state: "evidence_ready", reason: "exact sequence exit gate evidence is under review" };
  if (raw === "active" || raw === "scoped") return { state: "active", reason: `exact sequence exit gate is ${raw}` };
  return { state: "pending", reason: `exact sequence exit gate is ${raw}` };
}

function topoOrder(stages) {
  const byId = new Map(stages.map((s) => [s.id, s]));
  const seen = new Set();
  const out = [];
  const visit = (id, trail = []) => {
    if (seen.has(id)) return;
    if (trail.includes(id)) {
      throw new Error(`dependency cycle: ${[...trail, id].join(" -> ")}`);
    }
    const stage = byId.get(id);
    if (!stage) return;
    for (const dep of stage.depends_on ?? []) visit(dep, [...trail, id]);
    seen.add(id);
    out.push(stage);
  };
  for (const s of stages) visit(s.id);
  return out;
}

export function buildProjection() {
  const sequence = readJson(
    path.join(ESTATE_ROOT, "program", "sequence.v1.json"),
  );
  const records = loadWorkItems();
  const ordered = topoOrder(sequence.stages);

  const holdLedger = readHoldLedger();
  const openHoldList = (holdLedger.holds ?? []).filter(isOpen);
  const qualifiedBy = new Map();
  for (const hold of openHoldList) {
    for (const id of hold.predecessor_records ?? []) {
      if (!qualifiedBy.has(id)) qualifiedBy.set(id, []);
      qualifiedBy.get(id).push(hold.hold_id);
    }
  }
  // The projection rule: a verified record named by an open hold projects as
  // verified_historical_with_open_successor, never as unqualified verified.
  const projected = (record) => {
    const status = statusAuthority(record).status;
    if (status !== "verified") return status;
    return qualifiedBy.has(record.work_item_id) ? QUALIFIED_STATUS : status;
  };

  const stages = ordered.map((stage) => {
    const state = stageState(stage, records, qualifiedBy);
    const mine = records.filter((r) => r.stage_id === stage.id);
    const aggregate = stage.exit_gate
      ? records.find((r) =>
        r.work_item_id === stage.exit_gate.aggregate_work_item_id
      )
      : null;
    return {
      id: stage.id,
      title: stage.title,
      depends_on: stage.depends_on ?? [],
      module: stage.module,
      state: state.state,
      state_reason: state.reason,
      record_count: mine.length,
      // Counted on the PROJECTED status, so a held closure is never counted
      // into an unqualified `verified` tally.
      status_counts: mine.reduce((acc, r) => {
        const s = projected(r);
        acc[s] = (acc[s] ?? 0) + 1;
        return acc;
      }, {}),
      held_records: mine
        .filter((r) => qualifiedBy.has(r.work_item_id))
        .map((r) => r.work_item_id)
        .sort(),
      aggregate_held_by: aggregate
        ? (qualifiedBy.get(aggregate.work_item_id) ?? []).sort()
        : [],
      exit_gate: stage.exit_gate,
      differential_lanes: stage.differential_lanes ?? [],
    };
  });

  const blockedOn = new Map(stages.map((s) => [s.id, s]));
  const currentStage = stages.find((s) =>
    s.state !== "verified" && !sequence.stages.find((q) => q.id === s.id)?.activation_rule &&
    (s.depends_on ?? []).every((d) => blockedOn.get(d)?.state === "verified")
  ) ?? stages.find((s) => s.state !== "verified") ?? null;

  // Open stages are every non-verified stage whose dependency edges are all
  // verified. Work legitimately proceeds in more than one open stage at a time,
  // so the frontier is a set, not a single value.
  // A condition-gated stage (no exit gate, activation by named external
  // condition) is never on the frontier: it is activated by the condition, not
  // by a predecessor.
  const conditionGated = new Set(
    sequence.stages.filter((s) => s.activation_rule).map((s) => s.id),
  );
  const dependencySatisfied = (s) =>
    (s.depends_on ?? []).every((d) => blockedOn.get(d)?.state === "verified");
  // A stage whose dependency edge is unsatisfied but which already holds
  // advanced records is reported, flagged. Hiding it would misdescribe where the
  // work actually is; silently treating it as open would misdescribe the
  // sequence. Both facts are stated.
  const openStages = stages
    .filter((s) => s.state !== "verified" && !conditionGated.has(s.id))
    .filter((s) => dependencySatisfied(s) || s.state !== "pending")
    .map((s) => ({
      ...s,
      ahead_of_dependencies: !dependencySatisfied(s),
      unsatisfied_dependencies: (s.depends_on ?? []).filter((d) =>
        blockedOn.get(d)?.state !== "verified"
      ),
    }));

  // The next cut is the globally highest-advanced non-aggregate record in any
  // open stage, preferring dependency-ready records, then
  // active > evidence_ready > scoped > proposed, then the earliest stage.
  const verifiedIds = new Set(
    records.filter((r) => projected(r) === "verified").map((r) =>
      r.work_item_id
    ),
  );
  const stageRank = new Map(stages.map((s, i) => [s.id, i]));
  const openIds = new Set(openStages.map((s) => s.id));
  const candidates = records
    .filter((r) => openIds.has(r.stage_id))
    .filter((r) => statusAuthority(r).status !== "verified")
    .filter((r) => r.record_role !== "aggregate_exit")
    .map((r) => ({
      record: r,
      authority: statusAuthority(r),
      ready: (r.dependency_work_item_ids ?? []).every((d) =>
        verifiedIds.has(d)
      ),
    }))
    .sort((a, b) => {
      const rank = STATUS_ORDER.indexOf(b.authority.status) -
        STATUS_ORDER.indexOf(a.authority.status);
      if (rank !== 0) return rank;
      if (a.ready !== b.ready) return a.ready ? -1 : 1;
      return (
        (stageRank.get(a.record.stage_id) ?? 0) -
        (stageRank.get(b.record.stage_id) ?? 0)
      );
    });
  const nextCut = candidates[0] ?? null;

  // A differential lane is an explicit sequence-owned exception to stage dependency
  // readiness. It never changes stage state. Each allowed work item must still satisfy its own
  // work-item dependencies on the hold-qualified projection; a held predecessor is not enough.
  const differentialLanes = stages
    .flatMap((stage) => (stage.differential_lanes ?? []).map((lane) => ({ stage, lane })))
    .map(({ stage, lane }) => {
      const allowed = new Set(lane.allowed_work_item_ids ?? []);
      const laneRecords = records
        .filter((record) => record.stage_id === stage.id && allowed.has(record.work_item_id))
        .map((record) => {
          const authority = statusAuthority(record);
          const unsatisfied = (record.dependency_work_item_ids ?? []).filter(
            (dependency) => !verifiedIds.has(dependency),
          );
          return {
            work_item_id: record.work_item_id,
            record_ref: `internal-docs/implementation/${record.file}`,
            status: authority.status,
            projected_status: projected(record),
            dependencies_satisfied: unsatisfied.length === 0,
            unsatisfied_dependencies: unsatisfied,
          };
        });
      const missingWorkItemIds = [...allowed].filter(
        (id) => !laneRecords.some((record) => record.work_item_id === id),
      );
      return {
        stage_id: stage.id,
        stage_state: stage.state,
        lane_id: lane.lane_id,
        title: lane.title,
        bypassed_stage_dependencies: lane.bypassed_stage_dependencies ?? [],
        scope: lane.scope,
        nonclaims: lane.nonclaims ?? [],
        records: laneRecords,
        missing_work_item_ids: missingWorkItemIds,
        permitted:
          missingWorkItemIds.length === 0 &&
          laneRecords.length > 0 &&
          laneRecords.some(
            (record) => record.status !== "verified" && record.dependencies_satisfied,
          ),
      };
    });

  const divergences = records
    .map((r) => ({ id: r.work_item_id, ...statusAuthority(r) }))
    .filter((s) => s.owner === "tracked_merged_record" && !s.agrees);

  const impactPath = path.join(
    ESTATE_ROOT,
    "generated",
    "canon-impact.v1.json",
  );
  const impact = fs.existsSync(impactPath) ? readJson(impactPath) : null;

  // --- open successor holds
  //
  // A verified record named by an open hold does NOT project as verified here.
  // It projects as verified_historical_with_open_successor, which is what it
  // is: proven against the revision it was proven against, with a successor
  // owed and unwritten. A projection that rounds that off would re-introduce
  // exactly the false green this qualification exists to remove.
  const qualifiedRecords = [...qualifiedBy.entries()]
    .filter(([id]) => {
      const record = records.find((r) => r.work_item_id === id);
      return record && statusAuthority(record).status === "verified";
    })
    .map(([id, holds]) => ({
      work_item_id: id,
      status_authority_status: "verified",
      projected_status: QUALIFIED_STATUS,
      held_by: holds.sort(),
    }))
    .sort((a, b) => a.work_item_id.localeCompare(b.work_item_id));

  const statusAuthorities = records.map((record) => ({
    work_item_id: record.work_item_id,
    ...statusAuthority(record),
  }));
  const orientationInputsSha256 = sha256Text(JSON.stringify({
    sequence,
    records,
    status_authorities: statusAuthorities,
    hold_ledger: holdLedger,
    canon_impact: impact,
  }));

  return {
    sequence,
    records,
    stages,
    currentStage,
    openStages,
    nextCut,
    differentialLanes,
    divergences,
    impact,
    holds: {
      ledger_ref: `internal-docs/implementation/${HOLD_LEDGER_REL}`,
      open: openHoldList.map((h) => ({
        hold_id: h.hold_id,
        subject: h.subject,
        source_kind: h.source?.kind ?? null,
        acceptance_sequence: h.source?.acceptance_sequence ?? null,
        required_successor: h.required_successor?.work_item_id ?? null,
        predecessor_records: h.predecessor_records ?? [],
      })),
      qualified_records: qualifiedRecords,
    },
    provenance: {
      orientation_inputs_sha256: orientationInputsSha256,
      sequence_sha256: sha256Text(
        fs.readFileSync(
          path.join(ESTATE_ROOT, "program", "sequence.v1.json"),
          "utf8",
        ),
      ),
    },
  };
}

function renderNow(p) {
  const L = [];
  const stage = p.currentStage;
  const cut = p.nextCut;
  L.push("# NOW");
  L.push("");
  L.push(
    "Generated. Do not edit. `node internal-docs/implementation/tools/generate-now.mjs --write`",
  );
  L.push("");
  L.push(
    "This file is a projection. It owns no sequence and no status. Sequence lives in",
  );
  L.push(
    "[`program/sequence.v1.json`](./program/sequence.v1.json); status lives in the work-item record named below.",
  );
  L.push("");
  L.push("## Open stages");
  L.push("");
  if (p.openStages.length === 0) {
    L.push("None — every stage whose dependencies are met is verified.");
  } else {
    L.push("| Stage | State | Records | Exit gate |");
    L.push("| --- | --- | --- | --- |");
    for (const s of p.openStages) {
      L.push(
        `| [${s.id}](./${s.module}) — ${s.title} | ${s.state}${
          s.ahead_of_dependencies
            ? ` — **ahead of ${s.unsatisfied_dependencies.join(", ")}**`
            : ""
        }${
          s.aggregate_held_by.length > 0
            ? ` — **exit gate held by ${s.aggregate_held_by.join(", ")}**`
            : ""
        } | ${
          Object.entries(s.status_counts).map(([k, v]) => `${k} ${v}`).join(", ")
        } | \`${s.exit_gate?.aggregate_work_item_id ?? "(none)"}\` |`,
      );
    }
  }
  L.push("");
  L.push("## Earliest open stage");
  L.push("");
  if (!stage) {
    L.push("Every stage is verified.");
  } else {
    L.push(`**${stage.id} — ${stage.title}** (${stage.state})`);
    L.push("");
    L.push(`- why it is current: ${stage.state_reason}`);
    L.push(
      `- depends on: ${
        stage.depends_on.length ? stage.depends_on.join(", ") : "(nothing)"
      }`,
    );
    L.push(`- stage module: [\`${stage.module}\`](./${stage.module})`);
    L.push(
      `- records: ${stage.record_count} (${
        Object.entries(stage.status_counts).map(([k, v]) => `${k} ${v}`).join(
          ", ",
        )
      })`,
    );
    if (stage.exit_gate) {
      L.push(
        `- exit gate: \`${stage.exit_gate.aggregate_work_item_id}\``,
      );
    }
  }
  L.push("");
  L.push("## Next cut");
  L.push("");
  if (!cut) {
    L.push("No unverified non-aggregate record remains in the current stage.");
  } else {
    const r = cut.record;
    L.push(`**\`${r.work_item_id}\`** — ${cut.authority.status}`);
    L.push("");
    L.push(`${(r.objective ?? "").trim()}`);
    L.push("");
    L.push(`- record: [\`${r.file}\`](./${r.file})`);
    L.push(`- status authority: \`${cut.authority.owner}\` → \`${cut.authority.ref}\``);
    L.push(
      `- dependencies satisfied: ${cut.ready ? "yes" : "no"}${
        cut.ready
          ? ""
          : ` (waiting on ${
            (r.dependency_work_item_ids ?? []).join(", ") || "an external gate"
          })`
      }`,
    );
    if ((r.canon_owners ?? []).length > 0) {
      L.push("- canon owners:");
      for (const owner of r.canon_owners) {
        const pth = typeof owner === "string" ? owner : owner?.path ?? "?";
        L.push(`  - \`${pth}\``);
      }
    }
    if ((r.in_scope ?? []).length > 0) {
      L.push("- in scope:");
      for (const s of r.in_scope.slice(0, 8)) L.push(`  - ${s}`);
    }
    if ((r.out_of_scope ?? []).length > 0) {
      L.push("- out of scope:");
      for (const s of r.out_of_scope.slice(0, 6)) L.push(`  - ${s}`);
    }
  }
  L.push("");
  L.push("## Permitted differential lanes");
  L.push("");
  L.push(
    "These lanes are derived from structured exceptions in `program/sequence.v1.json`. They do not change stage state or satisfy a stage dependency.",
  );
  L.push("");
  const permittedLanes = p.differentialLanes.filter((lane) => lane.permitted);
  if (permittedLanes.length === 0) {
    L.push("None currently permitted.");
  } else {
    for (const lane of permittedLanes) {
      L.push(`### ${lane.stage_id} / ${lane.title}`);
      L.push("");
      L.push(`- lane id: \`${lane.lane_id}\``);
      L.push(`- stage state remains: \`${lane.stage_state}\``);
      L.push(`- bypassed stage dependencies for this lane only: ${lane.bypassed_stage_dependencies.join(", ") || "(none)"}`);
      L.push(`- scope: ${lane.scope}`);
      L.push("- permitted records:");
      for (const record of lane.records.filter((record) => record.dependencies_satisfied)) {
        L.push(`  - \`${record.work_item_id}\` — ${record.status}; [record](./${record.record_ref.replace("internal-docs/implementation/", "")})`);
      }
      L.push("- nonclaims:");
      for (const nonclaim of lane.nonclaims) L.push(`  - ${nonclaim}`);
      L.push("");
    }
  }
  L.push("");
  L.push("## Open successor holds");
  L.push("");
  L.push(
    `Source of truth: [\`${p.holds.ledger_ref.replace("internal-docs/implementation/", "./")}\`](./${
      p.holds.ledger_ref.replace("internal-docs/implementation/", "")
    }). A hold opens when a review dispositions a change \`successor_required\`, or when a`,
  );
  L.push(
    "verification is withdrawn. While it is open every predecessor closure it names projects as",
  );
  L.push(
    `\`${QUALIFIED_STATUS}\` — proven against the revision it was proven against, with a`,
  );
  L.push("successor owed and unwritten. It is never projected as unqualified `verified`.");
  L.push("");
  if (p.holds.open.length === 0) {
    L.push("None open.");
  } else {
    L.push("| Hold | Subject | Source | Required successor | Predecessors projected as qualified |");
    L.push("| --- | --- | --- | --- | --- |");
    for (const h of p.holds.open) {
      L.push(
        `| \`${h.hold_id}\` | \`${h.subject}\` | ${h.source_kind}${
          h.acceptance_sequence ? ` (acceptance ${h.acceptance_sequence})` : ""
        } | ${
          h.required_successor ? `\`${h.required_successor}\`` : "**not yet named**"
        } | ${h.predecessor_records.length} |`,
      );
    }
    L.push("");
    L.push(
      `${p.holds.qualified_records.length} verified record(s) project as \`${QUALIFIED_STATUS}\`:`,
    );
    L.push("");
    for (const r of p.holds.qualified_records) {
      L.push(`- \`${r.work_item_id}\` — held by ${r.held_by.join(", ")}`);
    }
  }
  L.push("");
  L.push("## What to run");
  L.push("");
  L.push("```text");
  L.push("while developing   node internal-docs/implementation/tools/check-fast.mjs");
  L.push(
    `at stage exit      node internal-docs/implementation/tools/certify-stage.mjs ${
      stage?.id ?? "<STAGE>"
    }`,
  );
  L.push("at a release gate  node internal-docs/implementation/tools/check-program.mjs");
  L.push("```");
  L.push("");
  L.push("## What blocks advancement");
  L.push("");
  const blockers = [];
  if (p.divergences.length > 0) {
    for (const d of p.divergences) {
      blockers.push(
        `status divergence on \`${d.id}\`: tracked merged record says \`${d.status}\`, private record says \`${d.private_status}\``,
      );
    }
  }
  if (p.impact) {
    const orphans = p.impact.orphan_counts?.unclassified_subjects ?? 0;
    const changed = p.impact.impact?.changed?.length ?? 0;
    if (orphans > 0) {
      blockers.push(`${orphans} unclassified canon subject(s) in program/canon-map.v1.json`);
    }
    const unmerged = p.impact.orphan_counts?.unmerged_branch_subjects ?? 0;
    if (unmerged > 0) {
      blockers.push(
        `${unmerged} canon subject(s) exist only on this branch and carry no classification; they grant no coverage until they land`,
      );
    }
    if (changed > 0) {
      blockers.push(
        `${changed} canon subject digest(s) changed since the reviewed baseline; affected stages: ${
          (p.impact.review_required?.stages ?? []).join(", ") || "(none)"
        }`,
      );
    }
  }
  for (const h of p.holds.open) {
    blockers.push(
      `open successor hold \`${h.hold_id}\` on \`${h.subject}\`: successor ${
        h.required_successor ? `\`${h.required_successor}\`` : "not yet named"
      }; ${h.predecessor_records.length} predecessor closure(s) project as \`${QUALIFIED_STATUS}\``,
    );
  }
  for (const s of p.openStages.filter((s) => s.ahead_of_dependencies)) {
    blockers.push(
      `stage ${s.id} holds advanced records but its dependency edge ${
        s.unsatisfied_dependencies.join(", ")
      } is not verified; the sequence and the work disagree`,
    );
  }
  if (stage?.exit_gate) {
    blockers.push(
      `stage exit requires the aggregate record \`${stage.exit_gate.aggregate_work_item_id}\` to reach \`verified\` on proof`,
    );
  }
  if (blockers.length === 0) L.push("Nothing recorded.");
  else for (const b of blockers) L.push(`- ${b}`);
  L.push("");
  L.push("## Provenance");
  L.push("");
  L.push("```text");
  L.push(`orientation inputs  ${p.provenance.orientation_inputs_sha256}`);
  L.push(`sequence            ${p.provenance.sequence_sha256}`);
  L.push("```");
  L.push("");
  L.push(
    "Route presence, an HTTP 200, a screenshot, a plan, or a process exit code is not proof. See [`program/rules.md`](./program/rules.md) §6.",
  );
  L.push("");
  return L.join("\n");
}

function main() {
  const write = process.argv.includes("--write");
  const check = process.argv.includes("--check");
  const p = buildProjection();
  const now = renderNow(p);

  const state = {
    evidence_format: "ioi.program.state.v1",
    projection_role:
      "Derived session orientation. Not a sequencer and not a status owner.",
    generator: {
      path: "internal-docs/implementation/tools/generate-now.mjs",
      write_command:
        "node internal-docs/implementation/tools/generate-now.mjs --write",
      check_command:
        "node internal-docs/implementation/tools/generate-now.mjs --check",
    },
    provenance: p.provenance,
    current_stage: p.currentStage?.id ?? null,
    open_stages: p.openStages.map((s) => s.id),
    next_cut: p.nextCut
      ? {
        work_item_id: p.nextCut.record.work_item_id,
        status: p.nextCut.authority.status,
        status_authority: p.nextCut.authority.owner,
        status_authority_ref: p.nextCut.authority.ref,
        dependencies_satisfied: p.nextCut.ready,
        record_ref: `internal-docs/implementation/${p.nextCut.record.file}`,
      }
      : null,
    differential_lanes: p.differentialLanes,
    stages: p.stages,
    status_authority_divergences: p.divergences,
    open_successor_holds: {
      ledger_ref: p.holds.ledger_ref,
      projection_rule:
        `A verified record named as a predecessor by an open hold projects as ${QUALIFIED_STATUS}. This projection is not permitted to display it as unqualified verified, and the status_counts above are computed on the projected status for the same reason.`,
      open_count: p.holds.open.length,
      open: p.holds.open,
      qualified_records: p.holds.qualified_records,
    },
    nonclaims: [
      "This projection changes no status and closes no work item, stage, or gate.",
      "A stage marked verified here reflects its aggregate record's declared status authority, not an independent proof.",
      `A record projected as ${QUALIFIED_STATUS} was proven against the canon revision it was proven against; its successor is owed and unwritten. The qualification withholds nothing that was proven and grants nothing that was not.`,
      "The orientation-input digest binds tracked inputs; it does not assert review, merge, or release status.",
    ],
  };

  const nowPath = path.join(ESTATE_ROOT, "NOW.md");
  const statePath = path.join(
    ESTATE_ROOT,
    "generated",
    "program-state.v1.json",
  );

  if (write) {
    fs.writeFileSync(nowPath, now);
    writeJsonDeterministic(statePath, state);
    process.stdout.write(
      `wrote NOW.md (${now.split("\n").length} lines) and generated/program-state.v1.json\n`,
    );
    return;
  }

  const findings = [];
  if (check) {
    const currentNow = fs.existsSync(nowPath)
      ? fs.readFileSync(nowPath, "utf8")
      : "";
    if (currentNow !== now) {
      findings.push(
        finding("error", "now-stale", "NOW.md is stale; run --write"),
      );
    }
    const currentState = fs.existsSync(statePath)
      ? fs.readFileSync(statePath, "utf8")
      : "";
    if (currentState !== `${JSON.stringify(state, null, 2)}\n`) {
      findings.push(
        finding(
          "error",
          "program-state-stale",
          "generated/program-state.v1.json is stale; run --write",
        ),
      );
    }
    process.exit(report("generate-now", findings));
  }

  process.stdout.write(now);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
