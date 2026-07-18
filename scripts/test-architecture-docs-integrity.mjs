#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  IMPLEMENTATION_MATRIX_CROSS_BOUNDARY_OWNERS,
  checkArchivedTerminalRecordBoundary,
  checkImplementationRefs,
  checkImplementationMatrixEvidence,
  checkOwnerMetadata,
  checkOwningRegistryDuplicates,
  checkRecencyPrecedence,
  checkRetiredRuntimePathHonesty,
  checkSchemaIdentities,
  checkSchemeRegistry,
  checkStatusMetadata,
} from "./lib/architecture-docs-integrity.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const cases = JSON.parse(
  fs.readFileSync(path.join(here, "fixtures/architecture-docs-checker/cases.json"), "utf8"),
);
const header = (doctrine, implementation, body = "") => `# Fixture\n\nStatus: fixture\nCanonical owner: this file.\nDoctrine status: ${doctrine}\nImplementation status: ${implementation}\n\n## Purpose\n\n${body}\n`;

for (const fixture of cases.statusCases) {
  test(`status: ${fixture.name}`, () => {
    const failures = checkStatusMetadata("fixture.md", header(fixture.doctrine, fixture.implementation));
    assert.equal(failures.length === 0, fixture.valid, failures.join("\n"));
  });
}

for (const fixture of cases.precedenceCases) {
  test(`precedence: ${fixture.name}`, () => {
    const failures = checkRecencyPrecedence(
      "fixture.md",
      header(fixture.doctrine, "planned", fixture.body),
    );
    assert.equal(failures.length === 0, fixture.valid, failures.join("\n"));
  });
}

test("Implementation refs validate live paths but exclude routes, URIs, and explicit history", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-architecture-refs-"));
  fs.mkdirSync(path.join(root, "apps/live"), { recursive: true });
  const file = path.join(root, "docs/architecture/owner.md");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const content = `# Owner\n\nDoctrine status: canonical\nImplementation status: partial\nImplementation refs:\n  - \`apps/live/\`\n  - \`/v1/runtime/health\`\n  - \`schema://ioi/example/v1\`\n  - historical evidence: \`docs/evidence/missing.json\`\nLast implementation audit: 2026-07-16\n\n## Purpose\n`;
  assert.deepEqual(checkImplementationRefs({ root, file, rel: "docs/architecture/owner.md", content }), []);
  const missing = content.replace("apps/live/", "apps/missing/");
  assert.match(checkImplementationRefs({ root, file, rel: "owner.md", content: missing })[0], /missing live Implementation ref/);
});

test("implementation matrix rejects stale evidence and enforces cross-boundary owners", () => {
  const matrixFile = path.join(
    root,
    "docs/architecture/_meta/implementation-matrix.md",
  );
  const row = (concept, owners, current = "current Rust implementation") =>
    `| \`${concept}\` | ${owners} | ${current} | keep | \`scripts/check-runtime-layout.mjs\` | guard |`;
  const ownerLink = (fragment) => {
    const target = fragment.startsWith("foundations/")
      ? `../${fragment}`
      : `../components/${fragment}`;
    return `[owner](${target})`;
  };
  const valid = [
    ...[...IMPLEMENTATION_MATRIX_CROSS_BOUNDARY_OWNERS].map(
      ([concept, owners]) =>
        row(
          concept.slice(1, -1),
          owners.map((owner) => ownerLink(owner)).join(", "),
        ),
    ),
    row(
      "HypervisorKernelSubstrateMigration",
      "[matrix](./hypervisor-kernel-substrate-migration-matrix.md), [guide](./hypervisor-kernel-substrate-unification-master-guide.md)",
      "archived terminal provenance",
    ).replace(
      " | keep | ",
      " | route current implementation through this implementation matrix; archived records may not direct work | ",
    ),
  ].join("\n");
  assert.deepEqual(
    checkImplementationMatrixEvidence({ root, matrixFile, content: valid }),
    [],
  );
  assert.match(
    checkImplementationMatrixEvidence({
      root,
      matrixFile,
      content: valid.replace(
        "`scripts/check-runtime-layout.mjs`",
        "`scripts/missing-current-evidence.mjs`",
      ),
    }).join("\n"),
    /missing current-evidence path/u,
  );
  for (const concept of [
    "HypervisorSessionLaunchRecipe",
    "RuntimeDoctorReportProjectionControl",
  ]) {
    assert.match(
      checkImplementationMatrixEvidence({
        root,
        matrixFile,
        content: `${valid}\n${row(
          concept,
          ownerLink("daemon-runtime/doctrine.md"),
        ).replace(
          "`scripts/check-runtime-layout.mjs`",
          "`docs/architecture/README.md`",
        )}`,
      }).join("\n"),
      new RegExp(
        `${concept}.*not an allowed source artifact|not an allowed source artifact.*${concept}`,
        "u",
      ),
      `${concept}: README substitution must fail`,
    );
  }
  assert.match(
    checkImplementationMatrixEvidence({
      root,
      matrixFile,
      content: `${valid}\nJS remains a protocol edge.`,
    }).join("\n"),
    /stale live JavaScript-remains claim/u,
  );
  assert.match(
    checkImplementationMatrixEvidence({
      root,
      matrixFile,
      content: valid.replace(
        row(
          "ModelCapabilityTokenControl",
          `${ownerLink("model-router/doctrine.md")}, ${ownerLink("wallet-network/doctrine.md")}`,
        ),
        row(
          "ModelCapabilityTokenControl",
          ownerLink("model-router/doctrine.md"),
        ),
      ),
    }).join("\n"),
    /ModelCapabilityTokenControl.*wallet-network\/doctrine\.md/u,
  );
  assert.match(
    checkImplementationMatrixEvidence({
      root,
      matrixFile,
      content: valid.replace(
        "archived terminal provenance",
        "live migration status",
      ),
    }).join("\n"),
    /classify HypervisorKernelSubstrateMigration/u,
  );
});

test("archived migration sequencers require one whole-document non-actionable boundary", () => {
  const valid = [
    "# Archived",
    "",
    "Status: archived terminal record / non-actionable migration provenance.",
    "Canonical owner: none.",
    "Superseded by: implementation-matrix.md, daemon-runtime/doctrine.md, canon-to-code-delta.md",
    "Doctrine status: archived",
    "Implementation status: n/a (archived terminal record)",
    "",
    "## Archived Terminal Record Boundary",
    "",
    "Whole-document boundary: archived terminal record / non-actionable.",
    "Everything below this boundary is solely as historical provenance and MUST NOT direct current work.",
    "Use implementation-matrix.md, doctrine.md, and canon-to-code-delta.md.",
    "",
    "## Historical body",
    "",
    "Implement the old live Node/JS daemon_js mcp-manager wrap then delete sprint maintenance rule.",
  ].join("\n");
  assert.deepEqual(
    checkArchivedTerminalRecordBoundary("archive.md", valid),
    [],
  );
  assert.match(
    checkArchivedTerminalRecordBoundary(
      "archive.md",
      valid.replace(
        "Everything below this boundary",
        "Only selected passages below this boundary",
      ),
    ).join("\n"),
    /Everything below this boundary/u,
  );
});

test("retired runtime and bridge paths require explicit historical context", () => {
  const active =
    "## Current Work\n\nImplement `packages/runtime-daemon/src/new-route.mjs` next.\n";
  assert.match(
    checkRetiredRuntimePathHonesty("guide.md", active).join("\n"),
    /outside an explicit historical or retired context/u,
  );
  assert.deepEqual(
    checkRetiredRuntimePathHonesty(
      "guide.md",
      "## Historical Migration Program\n\nImplement `packages/runtime-daemon/src/old-route.mjs` next.\n",
    ),
    [],
  );
  assert.deepEqual(
    checkRetiredRuntimePathHonesty(
      "matrix.md",
      "## Current Status\n\nThe former `mcp-manager.mjs` is retired and must not return.\n",
    ),
    [],
  );
  assert.match(
    checkRetiredRuntimePathHonesty(
      "matrix.md",
      "## Current Status\n\nAdd a new `ioi-step-module-bridge` operation.\n",
    ).join("\n"),
    /outside an explicit historical or retired context/u,
  );
});

test("owner registries reject declarations, not cross-owner mentions or examples", () => {
  const objectRel = "docs/architecture/foundations/common-objects-and-envelopes.md";
  assert.equal(checkOwningRegistryDuplicates(objectRel, "```yaml\nThingEnvelope:\n```\nText mentions ThingEnvelope.\n").length, 0);
  assert.match(checkOwningRegistryDuplicates(objectRel, "```yaml\nThingEnvelope:\nThingEnvelope:\n```\n")[0], /duplicates canonical object/);
  const receiptRel = "docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md";
  assert.match(checkOwningRegistryDuplicates(receiptRel, "```json\n{\n  \"receipt_type\": \"route\"\n}\n```\n```yaml\nreceipt_type: route\n```\n")[0], /duplicates canonical receipt_type/);
  const enumRel = "docs/architecture/foundations/canonical-enums.md";
  assert.match(checkOwningRegistryDuplicates(enumRel, "## One (`state`)\n## Example\n## Two (`state`)\n")[0], /duplicates canonical enum/);
});

test("schema identity and version tuples are unique while distinct versions pass", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-architecture-schema-"));
  const one = path.join(root, "one.json");
  const duplicate = path.join(root, "duplicate.json");
  const next = path.join(root, "next.json");
  fs.writeFileSync(one, JSON.stringify({ $id: "schema://ioi/example", schemaVersion: "1" }));
  fs.writeFileSync(duplicate, JSON.stringify({ $id: "schema://ioi/example", schemaVersion: "1" }));
  fs.writeFileSync(next, JSON.stringify({ $id: "schema://ioi/example", schemaVersion: "2" }));
  assert.match(checkSchemaIdentities([one, duplicate])[0], /duplicates schema identity\/version/);
  assert.deepEqual(checkSchemaIdentities([one, next]), []);
});

test("invalid schemes require explicit read-only aliases and cannot enter machine schemas", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-architecture-scheme-"));
  const schema = path.join(root, "writer.json");
  const common = "## Common ID Conventions\n```text\ngood://... ok\nlegacy_name://... old\n```\n## Capability and Authority Tiers\n";
  const registry = JSON.stringify({ readPolicy: "read_only", writePolicy: "forbid_legacy_schemes", aliases: { legacy_name: "legacy-name" } });
  fs.writeFileSync(schema, JSON.stringify({ ref: "legacy_name://new-write" }));
  assert.match(checkSchemeRegistry({ commonObjectsContent: common, aliasRegistryContent: registry, machineSchemaFiles: [schema] })[0], /writes read-only legacy/);
  fs.writeFileSync(schema, JSON.stringify({ ref: "legacy-name://new-write" }));
  assert.deepEqual(checkSchemeRegistry({ commonObjectsContent: common, aliasRegistryContent: registry, machineSchemaFiles: [schema] }), []);
  assert.match(checkSchemeRegistry({ commonObjectsContent: common, aliasRegistryContent: JSON.stringify({ readPolicy: "read_only", writePolicy: "forbid_legacy_schemes", aliases: {} }) })[0], /missing from the read-side/);
});

test("source-map conflicts require exact duplicate subjects or an explicit owner redirect", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-architecture-owner-"));
  const map = path.join(root, "docs/architecture/_meta/source-of-truth-map.md");
  const a = path.join(root, "docs/architecture/a.md");
  const b = path.join(root, "docs/architecture/b.md");
  fs.mkdirSync(path.dirname(map), { recursive: true });
  const owner = "# A\n\nCanonical owner: this file for A.\nDoctrine status: canonical\nImplementation status: planned\n\n## Purpose\n";
  const contents = new Map([[a, owner], [b, owner]]);
  const valid = "## Subject Ownership\n\n| Subject | Canonical Owner |\n| --- | --- |\n| A | [a](../a.md) |\n";
  assert.deepEqual(checkOwnerMetadata({ root, sourceMapFile: map, sourceMapContent: valid, contentsByFile: contents }), []);
  const conflict = `${valid}| A | [b](../b.md) |\n`;
  assert.match(checkOwnerMetadata({ root, sourceMapFile: map, sourceMapContent: conflict, contentsByFile: contents })[0], /conflicting owner rows/);
  contents.set(a, owner.replace("this file for A", "[b](./b.md)"));
  assert.match(checkOwnerMetadata({ root, sourceMapFile: map, sourceMapContent: valid, contentsByFile: contents })[0], /redirects canonical ownership/);
});
