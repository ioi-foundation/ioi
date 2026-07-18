export const ARCHITECTURE_CONTRACT_CONSUMER_TARGETS = Object.freeze([
  Object.freeze({
    kind: "typescript_projection",
    path: "packages/hypervisor-workbench/src/runtime/generated/architecture-contracts.ts",
    consumer_path: "scripts/test-architecture-contract-projections.mjs",
    consumer_marker:
      'from "../packages/hypervisor-workbench/src/runtime/generated/architecture-contracts.ts";',
  }),
  Object.freeze({
    kind: "rust_projection",
    path: "crates/types/src/app/generated/architecture_contracts.rs",
    consumer_path: "crates/types/src/app/mod.rs",
    consumer_marker: "pub mod architecture_contracts;",
  }),
]);

export const ARCHITECTURE_CONTRACT_CONSUMER_TARGET_BY_KIND = new Map(
  ARCHITECTURE_CONTRACT_CONSUMER_TARGETS.map((target) => [
    target.kind,
    target,
  ]),
);
