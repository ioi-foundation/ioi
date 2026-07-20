import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  atomicWriteFileSync,
  assertUniqueIdentities,
  attachRustHandlerDefinitions,
  buildRustFunctionIndex,
  discoverAxumRoutes,
  discoverJsOutboundCalls,
  discoverJsStorageMutations,
  discoverJsSystemEffects,
  discoverProtoServiceNames,
  discoverRustMatchServiceMethods,
  discoverRustServiceInterfaceMethods,
  discoverTonicServiceRegistrations,
  discoverWalletServiceMethods,
  rustModuleSourceMap,
} from "./m0-program-control.mjs";
import {
  EVIDENCE_DIR,
  PG_IDS,
  README_FILE,
  assertRenderedArtifactsCurrent,
  buildM0Fingerprint,
  createInitialProgramSource,
  createInitialReview,
  discoverRepositorySurface,
  loadM0Sources,
  stableStringify,
  validateProgramSource,
  validateReviewLock,
} from "./m0-program-control-model.mjs";

const testFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(testFile), "../..");
const cli = "scripts/m0-program-control.mjs";
const discoveredEntries = discoverRepositorySurface(repoRoot);
const { reviewLock, programSource } = loadM0Sources(repoRoot);

function temporaryRepository(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-m0-fixture-"));
  for (const [relativePath, source] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, source);
  }
  return root;
}

function hashEvidenceTree() {
  const root = path.join(repoRoot, EVIDENCE_DIR);
  return Object.fromEntries(
    fs.readdirSync(root)
      .sort()
      .map((name) => {
        const source = fs.readFileSync(path.join(root, name));
        const stat = fs.statSync(path.join(root, name), { bigint: true });
        return [
          name,
          {
            sha256: crypto.createHash("sha256").update(source).digest("hex"),
            mtime_ns: stat.mtimeNs.toString(),
          },
        ];
      }),
  );
}

function expectReviewFailure(mutator, pattern) {
  const fixture = structuredClone(reviewLock);
  mutator(fixture);
  assert.throws(
    () => validateReviewLock(repoRoot, discoveredEntries, fixture),
    pattern,
  );
}

function expectProgramFailure(mutator, pattern) {
  const fixture = structuredClone(programSource);
  mutator(fixture);
  assert.throws(
    () => validateProgramSource(
      repoRoot,
      discoveredEntries,
      reviewLock,
      fixture,
    ),
    pattern,
  );
}

test("structured discovery finds every literal Axum method and route identity", () => {
  const root = temporaryRepository({
    "routes.rs": `
      fn app() {
        Router::new()
          .route("/v1/items", get(list_items).post(create_item))
          .route("/v1/items/:id", patch(update_item).delete(delete_item));
      }
    `,
  });
  try {
    const entries = discoverAxumRoutes({
      repoRoot: root,
      relativePath: "routes.rs",
      surface: "fixture",
    });
    assert.deepEqual(
      entries.map((entry) => entry.identity),
      [
        "http:fixture:GET /v1/items",
        "http:fixture:POST /v1/items",
        "http:fixture:PATCH /v1/items/:id",
        "http:fixture:DELETE /v1/items/:id",
      ],
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("Axum discovery resolves aliases, on filters, and any handlers", () => {
  const root = temporaryRepository({
    "handlers.rs": `
      pub async fn shared_handler() {}
      pub async fn any_handler() {}
    `,
    "routes.rs": `
      use crate::handlers::shared_handler as aliased_handler;
      fn app() {
        Router::new()
          .route(
            "/v1/mixed",
            get(aliased_handler).on(MethodFilter::POST, aliased_handler),
          )
          .route("/v1/any", any(handlers::any_handler));
      }
    `,
  });
  try {
    const relativePaths = ["routes.rs", "handlers.rs"];
    const entries = attachRustHandlerDefinitions({
      repoRoot: root,
      entries: discoverAxumRoutes({
        repoRoot: root,
        relativePath: "routes.rs",
        surface: "fixture",
      }),
      functionIndex: buildRustFunctionIndex({ repoRoot: root, relativePaths }),
      defaultSourceFile: "routes.rs",
      moduleSourceFiles: rustModuleSourceMap(relativePaths),
    });
    assert.deepEqual(entries.map((entry) => entry.method), ["GET", "POST", "ANY"]);
    assert.ok(entries.every((entry) => (
      entry.handler_resolution === "transitive_function_closure"
    )));
    assert.deepEqual(
      entries.map((entry) => entry.handler_source_file),
      ["handlers.rs", "handlers.rs", "handlers.rs"],
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("unsupported Axum registration forms fail discovery explicitly", () => {
  const fixtures = [
    ['Router::new().route_service("/x", service)', /route_service/u],
    ['Router::new().nest("/x", nested)', /nest/u],
    ["Router::new().fallback(handler)", /fallback/u],
    [
      "Router::new().method_not_allowed_fallback(handler)",
      /method_not_allowed_fallback/u,
    ],
    ["Router::new().route(path, get(handler))", /path is not one literal/u],
    [
      'Router::new().route("/x", on(dynamic_filter, handler))',
      /unsupported dynamic Axum method filter/u,
    ],
    [
      'Router::new().route("/x", get_service(service))',
      /unsupported Axum service router/u,
    ],
    [
      'Router::route(router, "/x", get(handler))',
      /unsupported associated Axum route registration/u,
    ],
  ];
  for (const [source, pattern] of fixtures) {
    const root = temporaryRepository({ "routes.rs": `fn app() { ${source}; }` });
    try {
      assert.throws(
        () => discoverAxumRoutes({
          repoRoot: root,
          relativePath: "routes.rs",
          surface: "fixture",
        }),
        pattern,
      );
    } finally {
      fs.rmSync(root, { force: true, recursive: true });
    }
  }
});

test("transitive Rust effects change unchanged GET classification and freshness", () => {
  const readHelper = `
    pub async fn status() { ensure_state(); }
    fn ensure_state() { read_record(); }
  `;
  const persistHelper = `
    pub async fn status() { ensure_state(); }
    fn ensure_state() { persist_record(); }
    fn persist_record() { std::fs::write("state.json", "{}"); }
  `;
  const root = temporaryRepository({
    [README_FILE]: "fixture evidence boundary\n",
    "helpers.rs": readHelper,
    "routes.rs": `
      use crate::helpers::status as aliased_status;
      fn app() {
        Router::new().route("/status", get(aliased_status));
      }
    `,
  });
  const discover = () => {
    const relativePaths = ["routes.rs", "helpers.rs"];
    return attachRustHandlerDefinitions({
      repoRoot: root,
      entries: discoverAxumRoutes({
        repoRoot: root,
        relativePath: "routes.rs",
        surface: "hypervisor-daemon",
      }),
      functionIndex: buildRustFunctionIndex({ repoRoot: root, relativePaths }),
      defaultSourceFile: "routes.rs",
      moduleSourceFiles: rustModuleSourceMap(relativePaths),
    });
  };
  try {
    const readEntries = discover();
    const readClassification = createInitialReview(root, readEntries)
      .entries[0].classification;
    const readFingerprint = buildM0Fingerprint(
      root,
      readEntries,
      { fixture: "review" },
      { fixture: "program" },
    );

    fs.writeFileSync(path.join(root, "helpers.rs"), persistHelper);
    const persistEntries = discover();
    const persistClassification = createInitialReview(root, persistEntries)
      .entries[0].classification;
    const persistFingerprint = buildM0Fingerprint(
      root,
      persistEntries,
      { fixture: "review" },
      { fixture: "program" },
    );

    assert.equal(readClassification, "read_only");
    assert.equal(persistClassification, "consequential");
    assert.deepEqual(readEntries[0].handler_effect_calls, []);
    assert.deepEqual(persistEntries[0].handler_effect_calls, [
      "persist_record",
      "std::fs::write",
    ]);
    assert.equal(
      readEntries[0].source_anchor.sha256,
      persistEntries[0].source_anchor.sha256,
    );
    assert.notEqual(
      readEntries[0].handler_anchor.sha256,
      persistEntries[0].handler_anchor.sha256,
    );
    assert.notEqual(readFingerprint, persistFingerprint);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("unresolved and ambiguous effect-relevant Rust helpers fail closed", () => {
  const fixtures = [
    {
      files: {
        "helpers.rs": "fn unrelated() {}",
        "routes.rs": `
          fn handler() { helpers::ensure_state(); }
          fn app() { Router::new().route("/x", get(handler)); }
        `,
      },
      expected: /unresolved effect-relevant Rust helper/u,
    },
    {
      files: {
        "routes.rs": `
          fn handler() { write_state(); }
          fn app() { Router::new().route("/x", get(handler)); }
        `,
      },
      expected: /unresolved effect-relevant Rust helper write_state/u,
    },
    {
      files: {
        "routes.rs": `
          fn handler() { persist(); }
          fn app() { Router::new().route("/x", get(handler)); }
        `,
      },
      expected: /unresolved effect-relevant Rust helper persist/u,
    },
    {
      files: {
        "a.rs": "fn ensure_state() {}",
        "b.rs": "fn ensure_state() {}",
        "routes.rs": `
          fn handler() { crate::ensure_state(); }
          fn app() { Router::new().route("/x", get(handler)); }
        `,
      },
      expected: /ambiguous effect-relevant Rust helper/u,
    },
  ];
  for (const fixture of fixtures) {
    const root = temporaryRepository(fixture.files);
    try {
      const relativePaths = Object.keys(fixture.files);
      const entries = attachRustHandlerDefinitions({
        repoRoot: root,
        entries: discoverAxumRoutes({
          repoRoot: root,
          relativePath: "routes.rs",
          surface: "fixture",
        }),
        functionIndex: buildRustFunctionIndex({ repoRoot: root, relativePaths }),
        defaultSourceFile: "routes.rs",
        moduleSourceFiles: rustModuleSourceMap(relativePaths),
      });
      assert.match(entries[0].handler_resolution, fixture.expected);
      assert.equal(entries[0].handler_anchor, null);
    } finally {
      fs.rmSync(root, { force: true, recursive: true });
    }
  }
});

test("duplicate Rust module names fail helper resolution explicitly", () => {
  assert.throws(
    () => rustModuleSourceMap([
      "first/shared.rs",
      "second/shared.rs",
    ]),
    /ambiguous Rust module shared/u,
  );
});

test("external Rust method effects stay distinct from unresolved helpers", () => {
  const root = temporaryRepository({
    "routes.rs": `
      fn handler() {
        client().send();
        command().spawn();
        MuxEngine::open(path, false);
        external.read();
      }
      fn app() { Router::new().route("/x", get(handler)); }
    `,
  });
  try {
    const relativePaths = ["routes.rs"];
    const entries = attachRustHandlerDefinitions({
      repoRoot: root,
      entries: discoverAxumRoutes({
        repoRoot: root,
        relativePath: "routes.rs",
        surface: "fixture",
      }),
      functionIndex: buildRustFunctionIndex({ repoRoot: root, relativePaths }),
      defaultSourceFile: "routes.rs",
      moduleSourceFiles: rustModuleSourceMap(relativePaths),
    });
    assert.equal(entries[0].handler_resolution, "transitive_function_closure");
    assert.deepEqual(entries[0].handler_effect_calls, [
      ".send",
      ".spawn",
      "MuxEngine::open",
    ]);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("external filesystem mutators are effects while read-only opens stay reads", () => {
  const readHelper = `
    use std::fs::OpenOptions;
    pub async fn status() {
      OpenOptions::new().read(true).open("state.json");
    }
  `;
  const variants = [
    {
      source: `
        use std::fs::File;
        pub async fn status() { File::create("state.json"); }
      `,
      effect: "File::create",
    },
    {
      source: `
        use std::fs;
        pub async fn status() { fs::copy("source.json", "state.json"); }
      `,
      effect: "fs::copy",
    },
    {
      source: `
        use std::fs::OpenOptions;
        pub async fn status() {
          OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open("state.json");
        }
      `,
      effect: "std::fs::OpenOptions::open[write]",
    },
  ];
  const root = temporaryRepository({
    [README_FILE]: "fixture evidence boundary\n",
    "helpers.rs": readHelper,
    "routes.rs": `
      use crate::helpers::status;
      fn app() { Router::new().route("/status", get(status)); }
    `,
  });
  const discover = () => {
    const relativePaths = ["routes.rs", "helpers.rs"];
    return attachRustHandlerDefinitions({
      repoRoot: root,
      entries: discoverAxumRoutes({
        repoRoot: root,
        relativePath: "routes.rs",
        surface: "hypervisor-daemon",
      }),
      functionIndex: buildRustFunctionIndex({ repoRoot: root, relativePaths }),
      defaultSourceFile: "routes.rs",
      moduleSourceFiles: rustModuleSourceMap(relativePaths),
    });
  };
  try {
    const readEntries = discover();
    const readFingerprint = buildM0Fingerprint(
      root,
      readEntries,
      { fixture: "review" },
      { fixture: "program" },
    );
    assert.deepEqual(readEntries[0].handler_effect_calls, []);
    assert.equal(
      createInitialReview(root, readEntries).entries[0].classification,
      "read_only",
    );

    for (const variant of variants) {
      fs.writeFileSync(path.join(root, "helpers.rs"), variant.source);
      const effectEntries = discover();
      const effectFingerprint = buildM0Fingerprint(
        root,
        effectEntries,
        { fixture: "review" },
        { fixture: "program" },
      );
      assert.ok(effectEntries[0].handler_effect_calls.includes(variant.effect));
      assert.equal(
        createInitialReview(root, effectEntries).entries[0].classification,
        "consequential",
      );
      assert.notEqual(
        readEntries[0].handler_anchor.sha256,
        effectEntries[0].handler_anchor.sha256,
      );
      assert.notEqual(readFingerprint, effectFingerprint);
    }

    fs.writeFileSync(path.join(root, "helpers.rs"), `
      use std::fs::OpenOptions;
      pub async fn status(write_enabled: bool) {
        OpenOptions::new().write(write_enabled).open("state.json");
      }
    `);
    assert.throws(
      () => discover(),
      /unsupported dynamic OpenOptions write mode/u,
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("Rust service discovery stops the last literal arm before the wildcard", () => {
  const root = temporaryRepository({
    "service.rs": `
      impl BlockchainService for FixtureService {
        fn id(&self) -> &str { "fixture" }
        async fn handle_service_call(&self, state: &mut State, method: &str) {
          match method {
            "first@v1" => { state.insert(b"first", b"value"); }
            "last@v1" => { state.delete(b"last"); }
            _ => Err(TransactionError::Unsupported(format!("unsupported {}", method))),
          }
        }
      }
    `,
  });
  try {
    const entries = discoverRustMatchServiceMethods({
      repoRoot: root,
      relativePath: "service.rs",
      serviceId: "fixture",
      serviceType: "FixtureService",
      activeState: "fixture",
    });
    assert.deepEqual(entries.map((entry) => entry.service_method), [
      "first@v1",
      "last@v1",
    ]);
    assert.ok(entries[0].handler_call_sequence.includes("state.insert"));
    assert.ok(entries[1].handler_call_sequence.includes("state.delete"));
    assert.equal(entries[1].handler_call_sequence.includes("format"), false);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("Rust dispatch selects the intended qualified trait and captures or-patterns", () => {
  const root = temporaryRepository({
    "service.rs": `
      impl crate::traits::BlockchainService for DecoyService {
        fn id(&self) -> &str { "decoy" }
        async fn handle_service_call(&self, method: &str) {
          match method { "decoy@v1" => decoy(), _ => unsupported() }
        }
      }

      impl crate::traits::BlockchainService for WalletNetworkService {
        fn id(&self) -> &str { "wallet_network" }
        async fn handle_service_call(&self, method: &str) {
          let selected = method;
          let decoy = || { match method { "shadow@v1" => shadow(), _ => other() } };
          match selected {
            "first@v1" | "second@v1" => handlers::persist(request),
            _ => unsupported(),
          }
        }
      }
    `,
  });
  try {
    const entries = discoverWalletServiceMethods({
      repoRoot: root,
      relativePath: "service.rs",
    });
    assert.deepEqual(entries.map((entry) => entry.service_method), [
      "first@v1",
      "second@v1",
    ]);
    assert.ok(entries.every((entry) => entry.handler === "handlers::persist"));
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("qualified service-interface macros enumerate every marked method", () => {
  const root = temporaryRepository({
    "service.rs": `
      #[ioi_macros::service_interface(id = "fixture")]
      impl FixtureService {
        #[ioi_macros::method]
        async fn persist_value(&self) { state.insert(key, value); }
      }
    `,
  });
  try {
    const entries = discoverRustServiceInterfaceMethods({
      repoRoot: root,
      relativePath: "service.rs",
      expectedServiceId: "fixture",
      activeState: "fixture",
    });
    assert.deepEqual(entries.map((entry) => entry.service_method), [
      "persist_value@v1",
    ]);
    assert.ok(entries[0].handler_call_sequence.includes("state.insert"));
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("service-interface method attribute variants fail discovery explicitly", () => {
  const root = temporaryRepository({
    "service.rs": `
      #[service_interface(id = "fixture")]
      impl FixtureService {
        #[method(version = 2)]
        async fn persist_value(&self) { state.insert(key, value); }
      }
    `,
  });
  try {
    assert.throws(
      () => discoverRustServiceInterfaceMethods({
        repoRoot: root,
        relativePath: "service.rs",
        expectedServiceId: "fixture",
        activeState: "fixture",
      }),
      /unsupported method attribute form/u,
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("proto services and tonic mounts enumerate additions and reject dynamic mounts", () => {
  const root = temporaryRepository({
    "api.proto": `
      syntax = "proto3";
      service Existing { rpc Read (Request) returns (Reply); }
      service AddedPublic { rpc Mutate (Request) returns (Reply); }
    `,
    "mount.rs": `
      fn serve() {
        Server::builder()
          .add_service(ExistingServer::new(existing))
          .add_service(AddedPublicServer::with_interceptor(added, auth));
      }
    `,
    "dynamic.rs": `
      fn serve() { Server::builder().add_service(selected_service); }
    `,
  });
  try {
    assert.deepEqual(discoverProtoServiceNames({
      repoRoot: root,
      relativePath: "api.proto",
    }), ["AddedPublic", "Existing"]);
    assert.deepEqual(discoverTonicServiceRegistrations({
      repoRoot: root,
      relativePath: "mount.rs",
    }), ["AddedPublic", "Existing"]);
    assert.throws(
      () => discoverTonicServiceRegistrations({
        repoRoot: root,
        relativePath: "dynamic.rs",
      }),
      /exactly one literal generated service constructor/u,
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("JavaScript discovery finds process, filesystem, and all-key storage effects", () => {
  const root = temporaryRepository({
    "effect.mjs": `
      function executeEffect() {
        spawn("fixture");
        writeFileSync("receipt.json", "{}");
        sessionStorage.clear();
      }
    `,
  });
  try {
    const system = discoverJsSystemEffects({
      repoRoot: root,
      relativePaths: ["effect.mjs"],
    });
    assert.equal(system.length, 1);
    assert.deepEqual(system[0].handler_call_sequence, ["spawn", "writeFileSync"]);
    const storage = discoverJsStorageMutations({
      repoRoot: root,
      relativePaths: ["effect.mjs"],
    });
    assert.equal(storage.length, 1);
    assert.equal(storage[0].storage_method, "sessionStorage.clear");
    assert.equal(storage[0].storage_key_expression, "<all-keys>");
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("JavaScript AST discovery resolves aliases, options, templates, and nesting", () => {
  const root = temporaryRepository({
    "effect.mjs": `
      import { fetch as importedFetch } from "undici";
      import { writeFileSync as esmPersist } from "node:fs";
      import { spawn as launch } from "node:child_process";
      import { exit as terminate } from "node:process";
      const { writeFileSync: cjsPersist } = require("node:fs");
      const fsNamespace = require("node:fs");
      const renamePersist = fsNamespace.renameSync;
      const send = fetch;
      const method = "POST";
      const options = { method };

      function nestedEffect() {
        esmPersist("esm.json", "{}");
        cjsPersist("cjs.json", "{}");
        renamePersist("before", "after");
        launch("fixture");
        terminate(1);
        importedFetch("/imported", { method: "POST" });
        return send?.("/aliased", options);
      }

      function unresolved(url, dynamicOptions) {
        return fetch(url, dynamicOptions);
      }

      const mutatedOptions = { method: "POST" };
      const mutatedAlias = mutatedOptions;
      mutatedAlias.method = dynamicMethod;
      fetch("/mutated-alias", mutatedOptions);

      const assignedOptions = { method: "POST" };
      Object.assign(assignedOptions, { method: dynamicMethod });
      fetch("/object-assign", assignedOptions);

      const spreadOptions = { method: "POST", ...dynamicOptions };
      fetch("/dynamic-spread", spreadOptions);

      const generatedScript = \`
        <script>
          fetch("/generated", { method: "POST" });
        </script>
      \`;
    `,
  });
  try {
    const outbound = discoverJsOutboundCalls({
      repoRoot: root,
      relativePaths: ["effect.mjs"],
      surface: "fixture",
      activeState: "fixture",
    });
    assert.deepEqual(
      outbound.map((entry) => [entry.method, entry.path]),
      [
        ["POST", "/imported"],
        ["POST", "/aliased"],
        ["DYNAMIC(dynamicOptions.method)", "url"],
        ["DYNAMIC(mutatedOptions.method)", "/mutated-alias"],
        ["DYNAMIC(assignedOptions.method)", "/object-assign"],
        ["DYNAMIC(spreadOptions.method)", "/dynamic-spread"],
        ["POST", "/generated"],
      ],
    );
    const unresolvedEntry = outbound.find((entry) => (
      entry.method.startsWith("DYNAMIC")
    ));
    assert.equal(
      createInitialReview(root, [unresolvedEntry]).entries[0].classification,
      "consequential",
    );

    const system = discoverJsSystemEffects({
      repoRoot: root,
      relativePaths: ["effect.mjs"],
    });
    const nested = system.find((entry) => entry.source_symbol === "nestedEffect");
    assert.deepEqual(nested.handler_call_sequence, [
      "writeFileSync",
      "writeFileSync",
      "renameSync",
      "spawn",
      "process.exit",
    ]);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("JavaScript dynamic computed effect members fail discovery explicitly", () => {
  const root = temporaryRepository({
    "effect.mjs": `
      import * as fs from "node:fs";
      function persist(name) { fs[name]?.("receipt.json", "{}"); }
    `,
  });
  try {
    assert.throws(
      () => discoverJsSystemEffects({
        repoRoot: root,
        relativePaths: ["effect.mjs"],
      }),
      /unsupported dynamic computed JavaScript effect member/u,
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("current shorthand wrappers stay dynamic and generated POSTs stay discovered", () => {
  const reviewByIdentity = new Map(
    createInitialReview(repoRoot, discoveredEntries).entries.map((entry) => (
      [entry.identity, entry]
    )),
  );
  const shorthandLocations = new Set([
    "apps/hypervisor/surfaces/ontology-manager/index.mjs:81",
    "apps/hypervisor/surfaces/pipeline/index.mjs:111",
    "apps/hypervisor/scripts/ioi-agent-runs.mjs:219",
    "apps/hypervisor/scripts/ioi-agent-runs.mjs:320",
    "apps/hypervisor/scripts/ioi-agent-runs.mjs:418",
    "apps/hypervisor/scripts/serve-product-ui.mjs:8429",
    "apps/hypervisor/scripts/serve-product-ui.mjs:9907",
    "apps/hypervisor/scripts/ioi-api-adapter.mjs:68",
  ]);
  const shorthandEntries = discoveredEntries.filter((entry) => (
    shorthandLocations.has(`${entry.source_file}:${entry.source_anchor.line}`)
  ));
  assert.equal(shorthandEntries.length, shorthandLocations.size);
  assert.ok(shorthandEntries.every((entry) => entry.method === "DYNAMIC(method)"));
  assert.ok(shorthandEntries.every((entry) => (
    reviewByIdentity.get(entry.identity).classification === "consequential"
  )));

  const generatedPosts = new Set([
    "/__ioi/automations/__IOI_TEMPLATE_EXPRESSION_0__/patch",
    "/api/ioi.v1.AgentService/SendToAgentExecution",
    "f.post",
  ]);
  for (const target of generatedPosts) {
    assert.ok(discoveredEntries.some((entry) => (
      entry.kind === "js_outbound"
      && entry.method === "POST"
      && entry.path === target
    )), `missing generated POST ${target}`);
  }
});

test("read-convergence GET helpers remain genuinely read-only", () => {
  const reviewByIdentity = new Map(reviewLock.entries.map((entry) => (
    [entry.identity, entry]
  )));
  const entries = discoveredEntries.filter((entry) => (
    (entry.handler_call_sequence ?? []).some((call) => (
      call.endsWith("ensure_read_converged")
    ))
  ));
  assert.equal(entries.length, 16);
  assert.ok(entries.every((entry) => (
    entry.handler_effect_calls.length === 0
    && reviewByIdentity.get(entry.identity).classification === "read_only"
  )));
});

test("proven stateful GETs are consequential after transitive review", () => {
  const identities = [
    "http:hypervisor-daemon:GET /v1/hypervisor/auth/bootstrap-status",
    "http:hypervisor-daemon:GET /v1/hypervisor/auth/whoami",
    "http:hypervisor-daemon:GET /v1/hypervisor/principals",
    "http:hypervisor-daemon:GET /v1/hypervisor/ioi-agent/launch-policies",
    "http:hypervisor-daemon:GET /v1/hypervisor/ioi-agent/launch-policies/:id",
    "http:hypervisor-daemon:GET /v1/hypervisor/cloud-candidates/placement-advisory",
    "http:hypervisor-daemon:GET /v1/hypervisor/placement/preview",
    "http:hypervisor-daemon:GET /v1/hypervisor/placement/venues",
  ];
  const reviewByIdentity = new Map(reviewLock.entries.map((entry) => (
    [entry.identity, entry]
  )));
  for (const identity of identities) {
    const discovered = discoveredEntries.find((entry) => entry.identity === identity);
    assert.ok(discovered, `missing ${identity}`);
    assert.ok(discovered.handler_effect_calls.length > 0, `no effect for ${identity}`);
    assert.equal(reviewByIdentity.get(identity).classification, "consequential");
  }
});

test("discovery and the committed review lock are complete and explicitly reviewed", () => {
  assert.equal(discoveredEntries.length, reviewLock.entries.length);
  assert.doesNotThrow(
    () => validateReviewLock(repoRoot, discoveredEntries, reviewLock),
  );
});

test("a newly discovered or changed mutation fails until explicitly classified", () => {
  const changedDiscovery = structuredClone(discoveredEntries);
  const targetIndex = changedDiscovery.findIndex((entry) => (
    entry.kind === "http" && entry.method === "POST"
  ));
  const target = changedDiscovery[targetIndex];
  changedDiscovery[targetIndex] = {
    ...target,
    identity: `${target.identity}-changed-fixture`,
    path: `${target.path}-changed-fixture`,
    operation: `${target.operation}-changed-fixture`,
  };
  assert.throws(
    () => validateReviewLock(repoRoot, changedDiscovery, reviewLock),
    /discovered identity is unclassified/u,
  );
});

test("omission and duplicate identities fail closed", () => {
  expectReviewFailure(
    (fixture) => fixture.entries.pop(),
    /discovered identity is unclassified/u,
  );
  expectReviewFailure(
    (fixture) => fixture.entries.push(structuredClone(fixture.entries[0])),
    /duplicate identity/u,
  );
  assert.throws(
    () => assertUniqueIdentities(
      [discoveredEntries[0], structuredClone(discoveredEntries[0])],
      "adversarial fixture",
    ),
    /duplicate identity/u,
  );
});

test("missing or laundered final invokers fail closed", () => {
  const effectIndex = reviewLock.entries.findIndex((entry) => (
    entry.classification === "consequential"
  ));
  expectReviewFailure(
    (fixture) => {
      fixture.entries[effectIndex].final_invoker = null;
    },
    /lacks a final invoker/u,
  );

  const candidateIndex = reviewLock.entries.findIndex((entry) => (
    entry.final_invoker?.claim_state === "candidate_or_handler_boundary_not_final"
  ));
  expectReviewFailure(
    (fixture) => {
      fixture.entries[candidateIndex].blocker_or_nonclaim_ref = null;
    },
    /launders a candidate boundary|non-terminal without a typed blocker/u,
  );
});

test("stale anchors, unsafe defaults, and heuristic review provenance fail closed", () => {
  expectReviewFailure(
    (fixture) => {
      fixture.entries[0].registration_anchor_sha256 = "0".repeat(64);
    },
    /stale registration anchor/u,
  );
  expectReviewFailure(
    (fixture) => {
      fixture.default_classification = "allow_by_default";
    },
    /fail_closed_unclassified/u,
  );
  expectReviewFailure(
    (fixture) => {
      fixture.entries[0].review_origin = "heuristic_suggestion";
    },
    /heuristic or unresolved review provenance/u,
  );
  assert.throws(
    () => validateReviewLock(
      repoRoot,
      discoveredEntries,
      createInitialReview(repoRoot, discoveredEntries),
    ),
    /not in reviewed state|heuristic or unresolved review provenance/u,
  );

  const badDiscovery = structuredClone(discoveredEntries);
  const badReview = structuredClone(reviewLock);
  badDiscovery[0].handler_resolution =
    "effect_reachability_error:fixture unresolved helper";
  badReview.entries[0].handler_resolution =
    "effect_reachability_error:fixture unresolved helper";
  assert.throws(
    () => validateReviewLock(repoRoot, badDiscovery, badReview),
    /unresolved handler resolution/u,
  );
});

test("false terminal claims fail without leaf, gates, evidence, and recovery proof", () => {
  const candidateIndex = reviewLock.entries.findIndex((entry) => (
    entry.final_invoker?.claim_state === "candidate_or_handler_boundary_not_final"
  ));
  expectReviewFailure(
    (fixture) => {
      const entry = fixture.entries[candidateIndex];
      entry.implementation_state = "terminal";
      entry.blocker_or_nonclaim_ref = null;
    },
    /falsely claims terminality without a verified effect leaf/u,
  );
});

test("PG and baseline incompleteness or fabricated zeros fail closed", () => {
  expectProgramFailure(
    (fixture) => fixture.pg_gate_map.entries.pop(),
    /PG map must contain exactly 58 entries|PG map omits/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.pg_gate_map.entries.push(
        structuredClone(fixture.pg_gate_map.entries[0]),
      );
    },
    /PG map duplicates/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.baselines[0].observed_value = 0;
    },
    /fabricates an observed value/u,
  );
  assert.equal(PG_IDS.length, 58);
});

test("proof lanes, lane bindings, and local identity ownership fail closed", () => {
  expectProgramFailure(
    (fixture) => fixture.selected_profile.proof_lanes.pop(),
    /exactly two proof lanes|managed proof lane/u,
  );
  expectProgramFailure(
    (fixture) => {
      for (const step of fixture.selected_profile.visible_terminal_journey) {
        delete step.lane_bindings;
      }
    },
    /exact required proof-lane binding set|omits required proof-lane binding|no journey binding coverage/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[12].lane_bindings.pop();
    },
    /exact required proof-lane binding set|omits required proof-lane binding managed-detach-and-continue/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[8].lane_bindings[0].lane_id =
        "managed_optionality_overlay";
    },
    /wrong journey step or proof lane/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[0].lane_bindings[0].lane_id =
        "unknown_lane";
    },
    /unknown proof lane/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[0].lane_bindings[0].blocker_ref =
        null;
    },
    /lacks a typed blocker|neither selected routes nor a typed unavailable contract/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.proof_lanes[0].required_evidence[0] =
        "placeholder-evidence";
    },
    /substituted required-evidence set/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.proof_lanes[1].required_evidence.push(
        "placeholder-evidence",
      );
    },
    /substituted required-evidence set/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.proof_lanes[0].required_evidence.pop();
    },
    /substituted required-evidence set/u,
  );
  expectProgramFailure(
    (fixture) => {
      const evidence =
        fixture.selected_profile.proof_lanes[0].required_evidence;
      evidence.push(evidence[0]);
    },
    /lacks unique required evidence|substituted required-evidence set/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[0]
        .lane_bindings[0].route_identities = [];
    },
    /substituted route set/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[8]
        .lane_bindings[0].route_identities = [
          "http:hypervisor-daemon:GET /v1/runs/:id/replay",
        ];
    },
    /substituted route set/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[8]
        .lane_bindings[1].route_identities.push(
          "http:hypervisor-daemon:GET /v1/runs/:id/replay",
        );
    },
    /substituted route set/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[0]
        .lane_bindings[0].blocker_ref =
          "BLK-M0-SELECTED-IDENTITY-STEP-UP";
    },
    /substituted blocker|blocker type or state/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.blocker_ledger.find((entry) => (
        entry.blocker_id === "BLK-M0-SELECTED-LOCAL-IDENTITY-AUTHORITY"
      )).type = "authority_path_unavailable";
    },
    /blocker type or state does not match/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.blocker_ledger.find((entry) => (
        entry.blocker_id === "BLK-M0-SELECTED-MANAGED-DETACH"
      )).state = "closed";
    },
    /blocker type or state does not match/u,
  );
  expectProgramFailure(
    (fixture) => {
      const owner = fixture.selected_profile.object_owners.find((entry) => (
        entry.object_set.startsWith("Deployment-local identity")
      ));
      owner.owner_doc = "docs/architecture/components/wallet-network/doctrine.md";
    },
    /canonical owner tuple|canonical identity owner source/u,
  );
  for (const sourceFile of [
    "docs/architecture/components/hypervisor/identity-access-and-metering.md",
    "docs/conformance/hypervisor-core/sovereign-local-completeness.md",
    "docs/conformance/hypervisor-core/sovereign-local-completeness-matrix.v1.json",
  ]) {
    expectProgramFailure(
      (fixture) => {
        fixture.canon_basis = fixture.canon_basis.filter(
          (entry) => entry.source_file !== sourceFile,
        );
      },
      /canon basis count is stale|omits canon basis/u,
    );
  }
  expectProgramFailure(
    (fixture) => {
      fixture.canon_basis.find((entry) => (
        entry.source_file
          === "docs/conformance/hypervisor-core/sovereign-local-completeness.md"
      )).source_sha256 = "0".repeat(64);
    },
    /stale source anchor/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.canon_basis.splice(
        fixture.canon_basis.findIndex((entry) => (
          entry.source_file
            === "docs/conformance/hypervisor-core/sovereign-local-completeness.md"
        )),
        0,
        {
          role: "landed owner canon",
          source_file:
            "docs/conformance/hypervisor-core/sovereign-local-completeness.md",
          source_sha256: "0".repeat(64),
        },
      );
    },
    /duplicates canon basis|canon basis count is stale/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[1].route_identities = [
        "http:hypervisor-daemon:GET /v1/runs/:id/replay",
      ];
    },
    /visible journey does not match the canonical/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.visible_terminal_journey[1].blocker_ref =
        "BLK-M0-SELECTED-INSPECTION-CHAIN";
    },
    /visible journey does not match the canonical/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.blocker_ledger.find((entry) => (
        entry.blocker_id === "BLK-M0-SELECTED-LOCAL-IDENTITY-AUTHORITY"
      )).summary = "This authority path is terminal and closed.";
    },
    /blocker ledger does not match the canonical/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.pg_gate_map.entries.find((entry) => (
        entry.pg_id === "PG-2.1"
      )).disposition = "required_now";
    },
    /PG map does not match the canonical/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.selected_profile.object_owners = fixture.selected_profile
        .object_owners
        .filter((entry) => !entry.object_set.startsWith(
          "Deployment-local policy and locally permitted",
        ));
    },
    /object-owner set is incomplete|local authority-provider owner source/u,
  );

  const reordered = structuredClone(programSource);
  reordered.selected_profile.proof_lanes[0].required_evidence.reverse();
  reordered.selected_profile.visible_terminal_journey[0]
    .lane_bindings[0].route_identities.reverse();
  assert.doesNotThrow(() => validateProgramSource(
    repoRoot,
    discoveredEntries,
    reviewLock,
    reordered,
  ));
  const initialized = createInitialProgramSource(repoRoot);
  assert.doesNotThrow(() => validateProgramSource(
    repoRoot,
    discoveredEntries,
    reviewLock,
    initialized,
  ));
  assert.equal(
    stableStringify(initialized),
    stableStringify(programSource),
    "the initializer and reviewed program source must be byte-stable semantic equivalents",
  );
});

test("bare invocation exits 2 with usage and writes nothing", () => {
  const before = hashEvidenceTree();
  const result = spawnSync(process.execPath, [cli], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /^Usage:/u);
  assert.deepEqual(hashEvidenceTree(), before);
});

test("stale generated artifacts fail before consumption", () => {
  const root = temporaryRepository({
    [`${EVIDENCE_DIR}/fixture.json`]: "stale\n",
  });
  try {
    assert.throws(
      () => assertRenderedArtifactsCurrent(
        root,
        new Map([["fixture.json", "expected\n"]]),
        ["fixture.json"],
      ),
      /stale generated artifact/u,
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("effect census binds transitive closures without duplicating call corpora", () => {
  const census = JSON.parse(
    fs.readFileSync(path.join(repoRoot, EVIDENCE_DIR, "effect-census.json"), "utf8"),
  );
  for (const entry of census.entries) {
    assert.equal("handler_calls" in entry, false);
    assert.equal("handler_call_sequence" in entry, false);
    assert.equal("registration_handler_call_sequence" in entry, false);
    assert.equal("discovered_handler_calls" in entry, false);
    assert.equal("discovered_handler_call_sequence" in entry, false);
  }
  const transitive = census.entries.find((entry) => (
    entry.handler_resolution === "transitive_function_closure"
    && entry.handler_effect_calls?.length > 0
  ));
  assert.ok(transitive);
  assert.ok(transitive.reachable_handler_functions.length > 0);
  assert.match(transitive.handler_anchor_sha256, /^[a-f0-9]{64}$/u);
});

test("README tampering changes the fingerprint and fails the read-only check", () => {
  const absolutePath = path.join(repoRoot, README_FILE);
  const original = fs.readFileSync(absolutePath);
  const stat = fs.statSync(absolutePath);
  const originalFingerprint = buildM0Fingerprint(
    repoRoot,
    discoveredEntries,
    reviewLock,
    programSource,
  );
  try {
    fs.writeFileSync(
      absolutePath,
      Buffer.concat([original, Buffer.from("\nfixture tamper\n")]),
    );
    const tamperedFingerprint = buildM0Fingerprint(
      repoRoot,
      discoveredEntries,
      reviewLock,
      programSource,
    );
    assert.notEqual(tamperedFingerprint, originalFingerprint);
    const result = spawnSync(process.execPath, [cli, "--check"], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /stale generated artifact/u);
  } finally {
    fs.writeFileSync(absolutePath, original);
    fs.utimesSync(absolutePath, stat.atime, stat.mtime);
  }
});

test("atomic writes clean temporary siblings after a failed replacement", () => {
  const root = temporaryRepository({ "target": "original\n" });
  try {
    assert.throws(
      () => atomicWriteFileSync(
        path.join(root, "target"),
        "replacement\n",
        { exclusive: true },
      ),
      /EEXIST/u,
    );
    assert.equal(fs.readFileSync(path.join(root, "target"), "utf8"), "original\n");
    assert.deepEqual(
      fs.readdirSync(root).filter((name) => name.endsWith(".tmp")),
      [],
    );

    const directoryTarget = path.join(root, "directory-target");
    fs.mkdirSync(directoryTarget);
    assert.throws(
      () => atomicWriteFileSync(directoryTarget, "replacement\n"),
      /EISDIR|ENOTEMPTY|EEXIST/u,
    );
    assert.deepEqual(
      fs.readdirSync(root).filter((name) => name.endsWith(".tmp")),
      [],
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("a second --write preserves every evidence byte and mtime", () => {
  const beforeCheck = hashEvidenceTree();
  const check = spawnSync(process.execPath, [cli, "--check"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(check.status, 0, `${check.stdout}\n${check.stderr}`);
  assert.deepEqual(hashEvidenceTree(), beforeCheck);

  const first = spawnSync(process.execPath, [cli, "--write"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(first.status, 0, `${first.stdout}\n${first.stderr}`);
  assert.match(first.stdout, /0 file\(s\) written/u);
  assert.deepEqual(hashEvidenceTree(), beforeCheck);

  const beforeSecond = hashEvidenceTree();
  const second = spawnSync(process.execPath, [cli, "--write"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(second.status, 0, `${second.stdout}\n${second.stderr}`);
  assert.match(second.stdout, /0 file\(s\) written/u);
  assert.deepEqual(hashEvidenceTree(), beforeSecond);
});

test("--check accepts current artifacts and remains read-only", () => {
  const before = hashEvidenceTree();
  const result = spawnSync(process.execPath, [cli, "--check"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /M0 check passed/u);
  assert.deepEqual(hashEvidenceTree(), before);
});
