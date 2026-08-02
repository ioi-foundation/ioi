#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const sourcePath = path.join(
  repoRoot,
  "crates/services/src/agentic/runtime/kernel/mod.rs",
);
const sourceRoot = path.join(repoRoot, "crates/services/src");
const auditPath = path.join(
  repoRoot,
  "internal-docs/implementation/runtime-kernel-service-trust-boundary-audit.md",
);
const residualLedgerPath = path.join(
  repoRoot,
  "internal-docs/implementation/runtime-kernel-namespace-residual.v1.json",
);
const serviceTargets = [
  {
    key: "trustedKernel",
    typeName: "RuntimeKernelService",
    sourcePath,
  },
  {
    key: "owner",
    typeName: "RuntimeOwnerServices",
    sourcePath: path.join(sourceRoot, "agentic/runtime/owner_services.rs"),
  },
  {
    key: "projection",
    typeName: "RuntimeProjectionService",
    sourcePath: path.join(sourceRoot, "agentic/runtime/projection_service.rs"),
  },
  {
    key: "effectCompatibility",
    typeName: "RuntimeEffectCompatibilityGateway",
    sourcePath: path.join(
      sourceRoot,
      "agentic/runtime/kernel/runtime_effect_compatibility_gateway.rs",
    ),
  },
];

function fail(message) {
  process.stderr.write(`runtime-kernel trust audit invalid: ${message}\n`);
  process.exit(1);
}

function parserError(message) {
  throw new Error(message);
}

function maskRange(masked, source, start, end) {
  for (let index = start; index < end; index += 1) {
    if (source[index] !== "\n" && source[index] !== "\r") {
      masked[index] = " ";
    }
  }
}

function rustCharLiteralEnd(source, quoteIndex) {
  let cursor = quoteIndex + 1;
  if (source[cursor] === "\\") {
    cursor += 1;
    if (source[cursor] === "u" && source[cursor + 1] === "{") {
      const unicodeEnd = source.indexOf("}", cursor + 2);
      if (unicodeEnd < 0) return -1;
      cursor = unicodeEnd + 1;
    } else if (source[cursor] === "x") {
      cursor += 3;
    } else {
      cursor += 1;
    }
  } else {
    const codePoint = source.codePointAt(cursor);
    if (codePoint === undefined) return -1;
    cursor += codePoint > 0xffff ? 2 : 1;
  }
  return source[cursor] === "'" ? cursor + 1 : -1;
}

// Preserve byte offsets and line endings while removing braces and keywords from
// comments and literals. This keeps impl/method line provenance deterministic.
function maskRustNonCode(source) {
  const masked = [...source];
  let index = 0;

  while (index < source.length) {
    if (source.startsWith("//", index)) {
      const end = source.indexOf("\n", index + 2);
      const stop = end < 0 ? source.length : end;
      maskRange(masked, source, index, stop);
      index = stop;
      continue;
    }

    if (source.startsWith("/*", index)) {
      let depth = 1;
      let cursor = index + 2;
      while (cursor < source.length && depth > 0) {
        if (source.startsWith("/*", cursor)) {
          depth += 1;
          cursor += 2;
        } else if (source.startsWith("*/", cursor)) {
          depth -= 1;
          cursor += 2;
        } else {
          cursor += 1;
        }
      }
      if (depth !== 0) parserError("unterminated Rust block comment");
      maskRange(masked, source, index, cursor);
      index = cursor;
      continue;
    }

    const rawPrefix = source[index] === "r"
      ? index
      : source[index] === "b" && source[index + 1] === "r"
        ? index + 1
        : -1;
    if (rawPrefix >= 0) {
      let cursor = rawPrefix + 1;
      while (source[cursor] === "#") cursor += 1;
      if (source[cursor] === '"') {
        const hashes = cursor - rawPrefix - 1;
        const terminator = `"${"#".repeat(hashes)}`;
        const end = source.indexOf(terminator, cursor + 1);
        if (end < 0) parserError("unterminated Rust raw string literal");
        const stop = end + terminator.length;
        maskRange(masked, source, index, stop);
        index = stop;
        continue;
      }
    }

    const quoteIndex = source[index] === '"'
      ? index
      : source[index] === "b" && source[index + 1] === '"'
        ? index + 1
        : -1;
    if (quoteIndex >= 0) {
      let cursor = quoteIndex + 1;
      let escaped = false;
      for (; cursor < source.length; cursor += 1) {
        if (!escaped && source[cursor] === '"') {
          cursor += 1;
          break;
        }
        if (!escaped && source[cursor] === "\\") {
          escaped = true;
        } else {
          escaped = false;
        }
      }
      if (cursor > source.length || source[cursor - 1] !== '"') {
        parserError("unterminated Rust string literal");
      }
      maskRange(masked, source, index, cursor);
      index = cursor;
      continue;
    }

    // A lifetime such as 'a has no closing quote. Mask only a syntactically
    // char-shaped literal, including byte and Unicode escapes.
    const charQuote = source[index] === "'"
      ? index
      : source[index] === "b" && source[index + 1] === "'"
        ? index + 1
        : -1;
    if (charQuote >= 0) {
      const stop = rustCharLiteralEnd(source, charQuote);
      if (stop > 0) {
        maskRange(masked, source, index, stop);
        index = stop;
        continue;
      }
    }

    index += 1;
  }

  return masked.join("");
}

function matchingBrace(masked, open) {
  if (masked[open] !== "{") parserError(`expected opening brace at offset ${open}`);
  let depth = 1;
  for (let cursor = open + 1; cursor < masked.length; cursor += 1) {
    if (masked[cursor] === "{") depth += 1;
    if (masked[cursor] === "}") depth -= 1;
    if (depth === 0) return cursor;
  }
  parserError(`unbalanced Rust braces after offset ${open}`);
}

function normalizedHeader(masked, start, open) {
  return masked.slice(start, open).replace(/\s+/g, " ").trim();
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function inherentImplBlocks(
  source,
  masked,
  { requireImpl = true, typeName = "RuntimeKernelService" } = {},
) {
  const blocks = [];
  const implToken = /\bimpl\b/g;
  const escapedTypeName = escapeRegExp(typeName);
  const typeMention = new RegExp(`\\b${escapedTypeName}\\b`);
  const traitImpl = new RegExp(
    `\\bfor\\s+(?:[A-Za-z_][A-Za-z0-9_]*::)*${escapedTypeName}(?:\\s+where\\b.*)?$`,
  );
  const inherentImpl = new RegExp(
    `^impl ${escapedTypeName}(?:\\s+where\\b.*)?$`,
  );

  for (const match of masked.matchAll(implToken)) {
    const open = masked.indexOf("{", match.index + match[0].length);
    if (open < 0) continue;
    const header = normalizedHeader(masked, match.index, open);
    if (!typeMention.test(header)) continue;

    // Trait impls do not add inherent public callables and are outside this
    // inventory. Everything else mentioning the type must be understood or fail.
    if (traitImpl.test(header)) {
      continue;
    }
    if (!inherentImpl.test(header)) {
      parserError(`unrecognized ${typeName} impl header: ${header}`);
    }

    blocks.push({
      header,
      open,
      close: matchingBrace(masked, open),
    });
  }

  if (requireImpl && blocks.length === 0) {
    parserError(`no inherent ${typeName} impl blocks found`);
  }
  return blocks;
}

function lineAt(source, offset) {
  return source.slice(0, offset).split("\n").length;
}

function restrictedVisibilityIsValid(visibility) {
  const compact = visibility.replace(/\s+/g, " ").trim();
  if (compact === "pub") return true;
  const inner = compact.match(/^pub\s*\((.*)\)$/)?.[1]?.trim();
  return inner === "crate"
    || inner === "self"
    || inner === "super"
    || Boolean(inner?.startsWith("in "));
}

function publicCallables(
  source,
  { requireImpl = true, typeName = "RuntimeKernelService" } = {},
) {
  const masked = maskRustNonCode(source);
  const blocks = inherentImplBlocks(source, masked, { requireImpl, typeName });
  const callables = [];
  const callablePattern = /^(pub(?:\s*\([^)]*\))?)\s+(?:(?:const|async|unsafe|extern)\s+)*fn\s+([A-Za-z_][A-Za-z0-9_]*)\b/;
  const visibilityPattern = /^pub(?:\s*\([^)]*\))?/;
  const topLevelMacroPattern = /^(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*!\s*[({[]/;

  for (const block of blocks) {
    let depth = 0;
    for (let cursor = block.open + 1; cursor < block.close; cursor += 1) {
      const character = masked[cursor];
      if (character === "{") {
        depth += 1;
        continue;
      }
      if (character === "}") {
        depth -= 1;
        continue;
      }
      if (depth !== 0) continue;

      const previous = cursor === 0 ? "" : masked[cursor - 1];
      if (/[A-Za-z0-9_]/.test(previous)) continue;
      const tail = masked.slice(cursor, block.close);

      const macro = tail.match(topLevelMacroPattern);
      if (macro) {
        parserError(
          `top-level macro invocation in ${typeName} impl is not auditable at line ${lineAt(source, cursor)}: ${macro[0]}`,
        );
      }

      if (!tail.startsWith("pub")) continue;
      const visibility = tail.match(visibilityPattern)?.[0];
      if (!visibility) continue;
      if (!restrictedVisibilityIsValid(visibility)) {
        parserError(`unsupported restricted visibility at line ${lineAt(source, cursor)}: ${visibility}`);
      }

      const callable = tail.match(callablePattern);
      if (callable) {
        callables.push({
          method: callable[2],
          line: lineAt(source, cursor),
          visibility: callable[1].replace(/\s+/g, " "),
          implHeader: block.header,
        });
        cursor += callable[0].length - 1;
        continue;
      }

      const afterVisibility = tail.slice(visibility.length).trimStart();
      const firstToken = afterVisibility.match(/^([A-Za-z_][A-Za-z0-9_]*)/)?.[1];
      if (["fn", "async", "unsafe", "extern"].includes(firstToken)) {
        parserError(
          `unrecognized public callable form at line ${lineAt(source, cursor)}: ${tail.slice(0, 100).replace(/\s+/g, " ")}`,
        );
      }
      if (firstToken === "const") {
        const afterConst = afterVisibility.slice("const".length).trimStart();
        const secondToken = afterConst.match(/^([A-Za-z_][A-Za-z0-9_]*)/)?.[1];
        if (["fn", "async", "unsafe", "extern"].includes(secondToken)) {
          parserError(
            `unrecognized const public callable form at line ${lineAt(source, cursor)}: ${tail.slice(0, 100).replace(/\s+/g, " ")}`,
          );
        }
        continue;
      }
      if (firstToken === "type") continue;
      parserError(
        `unrecognized public inherent item at line ${lineAt(source, cursor)}: ${tail.slice(0, 100).replace(/\s+/g, " ")}`,
      );
    }
  }

  callables.sort((left, right) => left.line - right.line);
  return { blocks, callables };
}

function rustSourceFiles(root) {
  const files = [];
  const visit = (directory) => {
    const entries = fs.readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        parserError(`source-tree symlink is unsupported by the fail-closed audit: ${path.relative(repoRoot, entryPath)}`);
      }
      if (entry.isDirectory()) {
        visit(entryPath);
      } else if (entry.isFile() && entry.name.endsWith(".rs")) {
        files.push(entryPath);
      }
    }
  };
  visit(root);
  return files;
}

function rejectServiceAliases(source, typeName) {
  const masked = maskRustNonCode(source);
  const escapedTypeName = escapeRegExp(typeName);
  const importAlias = masked.match(new RegExp(
    `\\buse\\b[^;]*\\b${escapedTypeName}\\s+as\\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*\\s*;`,
  ));
  if (importAlias) {
    parserError(`aliasing ${typeName} is forbidden because an aliased inherent impl would escape the inventory`);
  }
  const typeAlias = masked.match(new RegExp(
    `\\btype\\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*(?:\\s*<[^;=]*>)?\\s*=\\s*[^;]*\\b${escapedTypeName}\\b[^;]*;`,
  ));
  if (typeAlias) {
    parserError(`type-aliasing ${typeName} is forbidden because an aliased inherent impl would escape the inventory`);
  }
}

function scanInherentSourceSet(entries, auditedSourceName, typeName) {
  let auditedInventory;
  for (const entry of entries) {
    let inventory;
    try {
      rejectServiceAliases(entry.source, typeName);
      inventory = publicCallables(entry.source, { requireImpl: false, typeName });
    } catch (error) {
      parserError(`${entry.name}: ${error instanceof Error ? error.message : String(error)}`);
    }

    if (entry.name === auditedSourceName) {
      auditedInventory = inventory;
      continue;
    }
    if (inventory.blocks.length > 0) {
      const lines = inventory.blocks
        .map((block) => lineAt(entry.source, block.open))
        .join(", ");
      parserError(
        `out-of-module inherent ${typeName} impl in ${entry.name} at line(s) ${lines}; policy requires all audited inherent methods to remain in ${auditedSourceName}`,
      );
    }
  }

  if (!auditedInventory) {
    parserError(`audited source is missing from recursive scan: ${auditedSourceName}`);
  }
  if (auditedInventory.blocks.length === 0) {
    parserError(`no inherent ${typeName} impl blocks found in ${auditedSourceName}`);
  }
  return auditedInventory;
}

function duplicates(values) {
  const seen = new Set();
  const repeated = new Set();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated].sort();
}

function countBy(values) {
  const counts = new Map();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return counts;
}

function assertSummaryCounts(label, actual, declared) {
  for (const [key, count] of actual) {
    if (declared.get(key) !== count) {
      fail(`${label} summary for ${key} is ${declared.get(key) ?? "missing"}; rows contain ${count}`);
    }
  }
  for (const key of declared.keys()) {
    if (!actual.has(key)) fail(`${label} summary contains stale category ${key}`);
  }
}

function runParserSelfTest() {
  const fixture = `
    impl RuntimeKernelService {
      pub fn plain() {}
      pub async fn asynchronous() {}
      pub unsafe fn unsafe_only() {}
      pub async unsafe fn combined() {}
      pub(crate) const unsafe extern "C" fn restricted_combined() {}
      pub const NON_CALLABLE: usize = 1;
    }
    impl RuntimeKernelService {
      pub(in crate) async fn second_block() {}
      fn private_helper() {}
    }
    impl ExampleTrait for RuntimeKernelService {
      fn trait_method() {}
    }
  `;
  const inventory = publicCallables(fixture);
  const expected = [
    "plain",
    "asynchronous",
    "unsafe_only",
    "combined",
    "restricted_combined",
    "second_block",
  ];
  if (inventory.blocks.length !== 2) {
    parserError(`parser self-test found ${inventory.blocks.length} inherent impls; expected 2`);
  }
  if (inventory.callables.map((row) => row.method).join(",") !== expected.join(",")) {
    parserError(
      `parser self-test callable mismatch: ${inventory.callables.map((row) => row.method).join(",")}`,
    );
  }

  let macroRejected = false;
  try {
    publicCallables("impl RuntimeKernelService { generated_methods!(); }");
  } catch (error) {
    macroRejected = error instanceof Error
      && error.message.includes("top-level macro invocation");
  }
  if (!macroRejected) parserError("parser self-test did not reject a method-generating macro escape");

  let externalImplRejected = false;
  try {
    scanInherentSourceSet(
      [
        {
          name: "kernel/mod.rs",
          source: "impl RuntimeKernelService { pub fn audited() {} }",
        },
        {
          name: "runtime/escape.rs",
          source: "impl RuntimeKernelService { pub async unsafe fn escaped() {} }",
        },
      ],
      "kernel/mod.rs",
      "RuntimeKernelService",
    );
  } catch (error) {
    externalImplRejected = error instanceof Error
      && error.message.includes("out-of-module inherent RuntimeKernelService impl");
  }
  if (!externalImplRejected) {
    parserError("parser self-test did not reject an out-of-module inherent impl");
  }
}

let sourceInventories;
let scannedSourceFileCount = 0;
try {
  runParserSelfTest();
  const sourceFiles = rustSourceFiles(sourceRoot);
  scannedSourceFileCount = sourceFiles.length;
  const sourceEntries = sourceFiles.map((file) => ({
    name: path.relative(repoRoot, file),
    source: fs.readFileSync(file, "utf8"),
  }));
  sourceInventories = new Map(serviceTargets.map((target) => [
    target.key,
    scanInherentSourceSet(
      sourceEntries,
      path.relative(repoRoot, target.sourcePath),
      target.typeName,
    ),
  ]));
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}

const audit = fs.readFileSync(auditPath, "utf8");

const auditRowLines = audit
  .split(/\r?\n/)
  .filter((line) => /^\|\s*RKS-\d{3}\s*\|/.test(line));
const auditRows = auditRowLines.map((line) => {
  const cells = line
    .split("|")
    .slice(1, -1)
    .map((cell) => cell.trim());
  if (cells.length !== 9 || cells.some((cell) => cell.length === 0)) {
    fail(`audit row must have nine non-empty cells: ${line.slice(0, 80)}`);
  }
  const idMatch = cells[0].match(/^RKS-(\d{3})$/);
  const methodMatch = cells[1].match(/^`([A-Za-z0-9_]+)`$/);
  const sourceMatch = cells[2].match(/^kernel\/mod\.rs:(\d+)\s+→\s+/);
  const delegateModuleMatch = cells[2].match(
    /→ kernel\/([^.:]+?)(?:\.rs|\/mod\.rs)(?::|\s|$)/,
  );
  if (!idMatch || !methodMatch || !sourceMatch || !delegateModuleMatch) {
    fail(`audit row marker, method, or source line is malformed: ${line.slice(0, 100)}`);
  }
  return {
    id: Number(idMatch[1]),
    method: methodMatch[1],
    line: Number(sourceMatch[1]),
    delegateModule: delegateModuleMatch?.[1] ?? null,
    crossing: cells[5].split(/[ :]/, 1)[0],
    relevance: cells[6],
    disposition: cells[7],
  };
});

const dispositionSummary = new Map(
  [...audit.matchAll(/^\| (Extract owner service|Keep facade but delegate|Projection \/ read separation|Retain trusted core|Retire \/ compatibility audit) \| (\d+) \|$/gm)]
    .map((match) => [match[1], Number(match[2])]),
);
const crossingSummary = new Map(
  [...audit.matchAll(/^\| (direct|delegated|none|unresolved) \| (\d+) \|/gm)]
    .map((match) => [match[1], Number(match[2])]),
);

const countMarker = audit.match(/<!-- runtime-kernel-method-count: (\d+) -->/);
if (!countMarker) fail("missing runtime-kernel-method-count marker");
const declaredCount = Number(countMarker[1]);

const duplicateAuditMethods = duplicates(auditRows.map((row) => row.method));
if (duplicateAuditMethods.length > 0) {
  fail(`duplicate audit methods: ${duplicateAuditMethods.join(", ")}`);
}

const duplicateAuditIds = duplicates(auditRows.map((row) => row.id));
if (duplicateAuditIds.length > 0) {
  fail(`duplicate audit ids: ${duplicateAuditIds.join(", ")}`);
}

if (declaredCount !== auditRows.length) {
  fail(`declared baseline count ${declaredCount} differs from audit row count ${auditRows.length}`);
}
assertSummaryCounts(
  "disposition",
  countBy(auditRows.map((row) => row.disposition)),
  dispositionSummary,
);
assertSummaryCounts(
  "authority crossing",
  countBy(auditRows.map((row) => row.crossing)),
  crossingSummary,
);

for (let index = 0; index < auditRows.length; index += 1) {
  const expectedId = index + 1;
  const row = auditRows[index];
  if (row.id !== expectedId) {
    fail(`row ${index + 1} has RKS-${String(row.id).padStart(3, "0")}; expected RKS-${String(expectedId).padStart(3, "0")}`);
  }
}

const isBlockedEffect = (row) => row.disposition === "Extract owner service"
  && row.relevance.startsWith("Performs");
const expectedInventories = new Map([
  [
    "trustedKernel",
    [
      "new",
      ...auditRows
        .filter((row) => row.disposition === "Retain trusted core")
        .map((row) => row.method),
    ],
  ],
  [
    "owner",
    [
      "new",
      ...auditRows
        .filter((row) => row.disposition === "Extract owner service" && !isBlockedEffect(row))
        .map((row) => row.method),
      ...auditRows
        .filter((row) => row.disposition === "Keep facade but delegate" && row.method !== "new")
        .map((row) => row.method),
    ],
  ],
  [
    "projection",
    [
      "new",
      ...auditRows
        .filter((row) => row.disposition === "Projection / read separation")
        .map((row) => row.method),
    ],
  ],
  [
    "effectCompatibility",
    [
      "new",
      ...auditRows.filter(isBlockedEffect).map((row) => row.method),
    ],
  ],
]);

function assertExactInventory(target, expectedMethods) {
  const inventory = sourceInventories.get(target.key);
  if (!inventory) fail(`missing parsed inventory for ${target.typeName}`);
  const actualMethods = inventory.callables.map((row) => row.method);
  const duplicateMethods = duplicates(actualMethods);
  if (duplicateMethods.length > 0) {
    fail(`duplicate ${target.typeName} methods: ${duplicateMethods.join(", ")}`);
  }
  if (actualMethods.length !== expectedMethods.length) {
    fail(`${target.typeName} has ${actualMethods.length} public callables; exact allowlist requires ${expectedMethods.length}`);
  }
  for (let index = 0; index < expectedMethods.length; index += 1) {
    if (actualMethods[index] !== expectedMethods[index]) {
      fail(`${target.typeName} callable ${index + 1} is ${actualMethods[index] ?? "missing"}; exact allowlist requires ${expectedMethods[index]}`);
    }
  }
}

for (const target of serviceTargets) {
  assertExactInventory(target, expectedInventories.get(target.key));
}

const retiredMethods = auditRows
  .filter((row) => row.disposition === "Retire / compatibility audit")
  .map((row) => row.method);
if (retiredMethods.length !== 2) {
  fail(`retired method set has ${retiredMethods.length} entries; expected exactly 2`);
}
for (const target of serviceTargets) {
  const actual = new Set(sourceInventories.get(target.key).callables.map((row) => row.method));
  const leaked = retiredMethods.filter((method) => actual.has(method));
  if (leaked.length > 0) {
    fail(`${target.typeName} re-exposes retired methods: ${leaked.join(", ")}`);
  }
}

let residualLedger;
try {
  residualLedger = JSON.parse(fs.readFileSync(residualLedgerPath, "utf8"));
} catch (error) {
  fail(`cannot parse namespace residual ledger: ${error instanceof Error ? error.message : String(error)}`);
}
if (residualLedger.schema_version !== "ioi.runtime-kernel-namespace-residual.v1") {
  fail(`unexpected namespace residual schema: ${residualLedger.schema_version ?? "missing"}`);
}
if (residualLedger.status !== "service_boundary_complete_namespace_extraction_residual") {
  fail(`namespace residual ledger overclaims status: ${residualLedger.status ?? "missing"}`);
}

function assertExactArray(label, actual, expected) {
  if (!Array.isArray(actual)) fail(`${label} must be an array`);
  if (actual.length !== expected.length) {
    fail(`${label} has ${actual.length} entries; expected ${expected.length}`);
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (actual[index] !== expected[index]) {
      fail(`${label} entry ${index + 1} is ${actual[index] ?? "missing"}; expected ${expected[index]}`);
    }
  }
}

const trustedDelegateModules = new Set(
  auditRows
    .filter((row) => row.disposition === "Retain trusted core")
    .map((row) => row.delegateModule)
    .filter((moduleName) => moduleName && moduleName !== "mod"),
);
const expectedResidualModules = [...new Set(
  auditRows
    .filter((row) => ![
      "Retain trusted core",
      "Retire / compatibility audit",
    ].includes(row.disposition))
    .map((row) => row.delegateModule)
    .filter((moduleName) => moduleName && moduleName !== "mod"),
)].sort();
const expectedMixedModules = expectedResidualModules
  .filter((moduleName) => trustedDelegateModules.has(moduleName));
const expectedEffectMethods = auditRows.filter(isBlockedEffect).map((row) => row.method);
assertExactArray(
  "namespace residual modules",
  residualLedger.residual_delegate_modules,
  expectedResidualModules,
);
assertExactArray(
  "mixed-trust residual modules",
  residualLedger.mixed_trust_delegate_modules,
  expectedMixedModules,
);
assertExactArray(
  "effect compatibility methods",
  residualLedger.effect_compatibility_methods,
  expectedEffectMethods,
);

const kernelSource = fs.readFileSync(sourcePath, "utf8");
const kernelRootPublicModules = [...kernelSource.matchAll(/^pub mod ([A-Za-z_][A-Za-z0-9_]*);$/gm)]
  .map((match) => match[1]);
const kernelRustFileCount = rustSourceFiles(path.dirname(sourcePath)).length;
const actualInventoryCounts = {
  kernel_rust_file_count: kernelRustFileCount,
  kernel_root_public_module_count: kernelRootPublicModules.length,
  trusted_kernel_service_callable_count: sourceInventories.get("trustedKernel").callables.length,
  owner_service_callable_count: sourceInventories.get("owner").callables.length,
  projection_service_callable_count: sourceInventories.get("projection").callables.length,
  effect_compatibility_gateway_callable_count: sourceInventories.get("effectCompatibility").callables.length,
};
if (residualLedger.baseline_snapshot_method_count !== auditRows.length) {
  fail(`namespace residual baseline is ${residualLedger.baseline_snapshot_method_count ?? "missing"}; expected ${auditRows.length}`);
}
for (const [key, expected] of Object.entries(actualInventoryCounts)) {
  if (residualLedger.current_inventory?.[key] !== expected) {
    fail(`namespace residual inventory ${key} is ${residualLedger.current_inventory?.[key] ?? "missing"}; current source is ${expected}`);
  }
}

const countSummary = serviceTargets
  .map((target) => `${target.typeName}=${sourceInventories.get(target.key).callables.length}`)
  .join(", ");
process.stdout.write(
  `runtime-kernel trust decomposition verified: baseline=${auditRows.length}; ${countSummary}; retired=${retiredMethods.length}; namespace_residual_modules=${expectedResidualModules.length}; kernel_files=${kernelRustFileCount}; scanned ${scannedSourceFileCount} Rust source files; exact ordered allowlists, residual ledger, and no out-of-module inherent impls\n`,
);
