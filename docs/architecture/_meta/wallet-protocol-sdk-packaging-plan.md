# wallet.network Protocol and SDK Packaging Plan

Status: initial package boundary implemented; generator and product-import
hardening remain.
Canonical owner: this file for the plan to canonize and implement
`@ioi/wallet-protocol` and `@ioi/wallet-sdk` packaging.
Supersedes: ad hoc wallet package notes when they conflict with this plan.
Superseded by: completed implementation docs after product repos import the
packages and Rust-derived generation is fully automated.
Last alignment pass: 2026-06-17.

## Purpose

Move wallet.network from an architecture-correct but packaging-incomplete state
to a clean protocol/package boundary:

```text
Previous
  Rust wallet types + Rust service + tests are protocol truth.
  Wallet product repos own UI/product/prototype state.
  Generated wallet protocol/schema/SDK packages do not exist yet.

Current implementation boundary
  IOI monorepo owns checked-in @ioi/wallet-protocol and @ioi/wallet-sdk
  packages.
  @ioi/wallet-protocol exports TypeScript objects, method metadata, JSON
  Schema, OpenAPI, fixtures, and package tests tied to Rust wallet anchors.
  @ioi/wallet-sdk imports @ioi/wallet-protocol and provides client/helper
  facades.

Target hardening
  IOI monorepo generates @ioi/wallet-protocol from Rust-owned exports.
  Wallet product repos import those packages.
  Product UI never authors canonical scopes, grants, leases, receipts,
  ExchangeIntent, TradeIntent, CapabilityLease, AuthorityReview,
  or revocation behavior.
```

The work is both canon and implementation. The docs must make one owner clear,
and the repo must expose packages that enforce that owner in practice.

## Current Anchors

Authoritative implementation anchors today:

```text
crates/types/src/app/wallet_network/mod.rs
  Rust wallet control-plane/session/secret/connector/policy/mail/vault types.

crates/services/src/wallet_network/mod.rs
  Native wallet.network service, method dispatch, service ABI version,
  state schema, validation, and receipt writes.

crates/cli/tests/wallet_network_session_channel_e2e.rs
  Entry point for wallet session/channel E2E tests.

package.json
  JS workspace includes apps/* and packages/*.

packages/agent-sdk/
  Existing private TypeScript package pattern for build, exports, tests,
  and dist generation.
```

Remaining pieces:

```text
Rust-derived wallet JSON Schema/OpenAPI generation
deeper wallet receipt hash fixtures
wallet protocol conformance suite beyond package checks
wallet-network product import boundary
```

## Canonical Ownership Boundary

### IOI Monorepo Owns

```text
Rust wallet types
wallet.network service transitions
method registry
authority scope vocabulary
grant/lease/approval objects
secret brokerage object shapes
AuthorityReview object shape
ApprovalMode vocabulary
WalletPresentationProfile vocabulary
CapabilityLease object shape
ExchangeIntent / TradeIntent / PredictionIntent object shapes
wallet receipt envelopes and typed receipt fixtures
JSON Schema / OpenAPI generated from canonical contracts
@ioi/wallet-protocol
@ioi/wallet-sdk
protocol conformance tests
```

### wallet-network Product Repo Owns

```text
Wallet app UI
website and marketing copy
design system
screenshots and prototypes
frontend-only state
storybook/demo fixtures marked non-authoritative
app-specific adapters to imported SDK calls
```

### Product Repo Must Not Own

```text
scope:* semantics
AuthorityGrant semantics
CapabilityLease semantics
ApprovalMode semantics
WalletReceipt schemas
ExchangeIntent / TradeIntent semantics
secret-release policy
revocation epoch behavior
Agentgres receipt linkage
canonical wallet OpenAPI / JSON Schema
```

## Target Package Shape

### `@ioi/wallet-protocol`

Purpose: versioned protocol objects, generated schemas, method metadata,
fixtures, and canonical examples.

Directory:

```text
packages/wallet-protocol/
  package.json
  tsconfig.json
  scripts/
    build.mjs
    verify-generated.mjs
  src/
    index.ts
    generated/
      types.ts
      method-registry.ts
      schemas.ts
      openapi.ts
      fixtures.ts
    constants.ts
    hashes.ts
  schemas/
    wallet-network.schema.json
    authority-review.schema.json
    capability-lease.schema.json
    wallet-receipt.schema.json
  openapi/
    wallet-network.openapi.json
  fixtures/
    authority-review.basic.json
    capability-lease.gmail-send.json
    exchange-intent.usdc-eth.json
    trade-intent.paper-perp.json
    wallet-receipt.capability-use.json
  test/
    protocol-fixtures.test.mjs
    schema-validation.test.mjs
```

Exports:

```text
.
./schemas
./openapi
./fixtures
./method-registry
./testing
```

Core responsibilities:

```text
1. Re-export generated TypeScript interfaces.
2. Export JSON Schema and OpenAPI artifacts.
3. Export wallet method names, ABI version, state schema version, and receipt
   type constants.
4. Export fixture objects used by SDK tests, product UI tests, and conformance.
5. Provide hashes of generated artifacts so product repos can detect drift.
```

### `@ioi/wallet-sdk`

Purpose: typed client helpers over `@ioi/wallet-protocol` for Wallet app,
Hypervisor, agents, services, and third-party clients.

Directory:

```text
packages/wallet-sdk/
  package.json
  tsconfig.json
  scripts/
    build.mjs
  src/
    index.ts
    client.ts
    authority-review.ts
    approvals.ts
    capabilities.ts
    secrets.ts
    receipts.ts
    exchange.ts
    trade.ts
    prediction.ts
    errors.ts
    testing.ts
  test/
    sdk.test.mjs
    authority-review.test.mjs
    capability-lease.test.mjs
```

Exports:

```text
.
./client
./authority-review
./approvals
./capabilities
./secrets
./receipts
./exchange
./trade
./prediction
./testing
```

Core responsibilities:

```text
1. Provide typed request builders.
2. Validate local payload shape against @ioi/wallet-protocol schemas.
3. Submit requests to wallet.network HTTP/RPC endpoints.
4. Normalize WalletReceipt and typed receipt responses.
5. Expose test helpers for product repos without letting product repos define
   canonical schemas.
```

SDK non-goals:

```text
does not sign without wallet.network authority
does not invent scopes
does not mutate policy locally
does not store durable secrets
does not bypass service tests or conformance
does not become the Wallet app
```

## Generation Strategy

### Source of Truth

Rust remains protocol truth.

```text
crates/types/src/app/wallet_network/*
crates/services/src/wallet_network/*
```

### Schema Derivation

Use `schemars` for wallet types. `crates/types` already has `schemars`
available, but wallet.network structs do not currently derive `JsonSchema`.

Implementation target:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ...
```

Where `JsonSchema` cannot be added immediately, create a temporary explicit
schema fixture and mark it as provisional. Provisional schemas must have a
tracked issue in this plan and must be replaced by Rust-derived schemas before
the package is considered complete.

### Generator

Add:

```text
crates/types/src/bin/export_wallet_protocol.rs
scripts/generate-wallet-protocol.mjs
scripts/check-wallet-protocol-generated.mjs
```

Generation flow:

```text
cargo run -p ioi-types --bin export_wallet_protocol
  -> writes target/generated/wallet-protocol/*.json

node scripts/generate-wallet-protocol.mjs
  -> reads generated Rust artifacts
  -> writes packages/wallet-protocol/src/generated/*
  -> writes packages/wallet-protocol/schemas/*
  -> writes packages/wallet-protocol/openapi/*
  -> writes packages/wallet-protocol/fixtures/*

node scripts/check-wallet-protocol-generated.mjs
  -> fails if generated files are stale
```

Build rule:

```text
Rust type changes that affect wallet protocol must regenerate protocol package
artifacts in the same slice.
```

## Implementation Phases

Each phase should end with a small git commit so the worktree stays clean during
iteration. This repo is alpha; do not preserve legacy compatibility shims unless
an active test depends on them.

### Phase 0: Baseline Inventory

Objective: prove the current contract anchors before packaging.

Work:

```text
rg --files crates/types/src/app/wallet_network
rg -n 'handle_service_call|abi_version|state_schema' crates/services/src/wallet_network
rg -n 'wallet_network_session_channel' crates/cli/tests
npm pkg get workspaces
```

Acceptance:

```text
Current Rust modules, service methods, E2E tests, and JS workspace layout are
listed in this plan or follow-up implementation notes.
```

### Phase 1: Canon Reconciliation

Objective: make docs point to the package target before implementation begins.

Docs to update:

```text
docs/architecture/components/wallet-network/doctrine.md
docs/architecture/components/wallet-network/api-authority-scopes.md
docs/architecture/components/wallet-network/product-exchange-risk.md
docs/architecture/_meta/source-of-truth-map.md
docs/architecture/_meta/implementation-matrix.md
docs/architecture/_meta/vocabulary.md
docs/architecture/START_HERE.md
```

Required canon statements:

```text
@ioi/wallet-protocol is generated from IOI-owned wallet contracts.
@ioi/wallet-sdk consumes @ioi/wallet-protocol.
wallet-network product repos import protocol/SDK artifacts.
Product repos do not own canonical authority semantics.
```

Checks:

```text
git diff --check -- docs/architecture
npm run check:architecture-docs
```

### Phase 2: Package Skeletons

Objective: create empty but buildable workspace packages.

Work:

```text
mkdir packages/wallet-protocol
mkdir packages/wallet-sdk
```

Mirror the private package pattern from `packages/agent-sdk`:

```text
type: module
main: ./dist/index.cjs
module: ./dist/index.js
types: ./dist/index.d.ts
exports map
scripts: build, typecheck, test
engines: node >=18
```

Root scripts to add:

```json
{
  "build:wallet-protocol": "npm run build --workspace=@ioi/wallet-protocol",
  "test:wallet-protocol": "npm test --workspace=@ioi/wallet-protocol",
  "build:wallet-sdk": "npm run build --workspace=@ioi/wallet-sdk",
  "test:wallet-sdk": "npm test --workspace=@ioi/wallet-sdk",
  "generate:wallet-protocol": "node scripts/generate-wallet-protocol.mjs",
  "check:wallet-protocol": "node scripts/check-wallet-protocol-generated.mjs"
}
```

Acceptance:

```text
npm run build:wallet-protocol
npm run test:wallet-protocol
npm run build:wallet-sdk
npm run test:wallet-sdk
```

### Phase 3: Rust Schema Exporter

Objective: derive schema artifacts from Rust protocol truth.

Work:

```text
Add JsonSchema derives to wallet_network public protocol structs.
Add crates/types/src/bin/export_wallet_protocol.rs.
Export:
  protocol metadata
  method registry
  JSON schemas
  receipt type constants
  example fixtures where Rust can construct them
```

Initial minimum object set:

```text
AuthorityGrant
CapabilityLease
AuthorityReview
ApprovalMode
WalletPresentationProfile
RiskCoverageState
SecretExecutionRequest
SecretExecutionReceipt
SessionGrant
SessionLease
SessionChannelEnvelope
WalletReceipt
```

If an object is not yet represented in Rust, add it to Rust first or document it
as a provisional protocol schema with a blocking TODO.

Rust checks:

```text
cargo check -p ioi-types
cargo test -p ioi-types wallet_network
```

Acceptance:

```text
cargo run -p ioi-types --bin export_wallet_protocol
target/generated/wallet-protocol/ exists
generated JSON validates as JSON
```

### Phase 4: Protocol Package Generation

Objective: turn Rust exports into `@ioi/wallet-protocol` artifacts.

Work:

```text
Implement scripts/generate-wallet-protocol.mjs.
Implement scripts/check-wallet-protocol-generated.mjs.
Write generated TypeScript interfaces into packages/wallet-protocol/src/generated.
Copy schemas and OpenAPI into packages/wallet-protocol.
Add fixture validation tests.
```

Package tests:

```text
node --test packages/wallet-protocol/test/*.mjs
npm run build --workspace=@ioi/wallet-protocol
```

Acceptance:

```text
@ioi/wallet-protocol exports types, schemas, fixtures, method registry, and
artifact hashes.
check-wallet-protocol-generated fails when generated artifacts are stale.
```

### Phase 5: SDK Implementation

Objective: expose typed helpers without duplicating authority truth.

Work:

```text
packages/wallet-sdk/src/client.ts
  WalletNetworkClient with request/response transport abstraction.

packages/wallet-sdk/src/authority-review.ts
  buildAuthorityReview, renderProfile, approveReview, denyReview.

packages/wallet-sdk/src/capabilities.ts
  requestCapabilityLease, revokeCapabilityLease, listCapabilities.

packages/wallet-sdk/src/secrets.ts
  requestSecretExecution, normalizeSecretExecutionReceipt.

packages/wallet-sdk/src/receipts.ts
  parseWalletReceipt, assertReceiptType, receiptHash helpers.

packages/wallet-sdk/src/exchange.ts
  buildExchangeIntent, requestRouteCandidates, approveExchangeIntent.

packages/wallet-sdk/src/trade.ts
  buildTradeIntent, buildPredictionIntent, requestVenueCandidates.
```

Rules:

```text
SDK imports protocol constants and schemas from @ioi/wallet-protocol.
SDK validates payloads before send.
SDK cannot define new scope names outside protocol/test fixtures.
SDK cannot silently coerce unknown risk labels into safe states.
```

Tests:

```text
npm run build --workspace=@ioi/wallet-sdk
npm test --workspace=@ioi/wallet-sdk
```

Acceptance:

```text
SDK tests prove AuthorityReview, CapabilityLease, receipt parsing, and
ExchangeIntent/TradeIntent helpers use protocol artifacts rather than local
schemas.
```

### Phase 6: Service and Fixture Conformance

Objective: prove JS packages match Rust service behavior.

Work:

```text
Add scripts/conformance/wallet-protocol-conformance.mjs.
Add fixture round-trip tests:
  Rust fixture -> protocol package schema -> SDK parse -> service method payload.
Add service method registry check:
  exported method names match WalletNetworkService dispatch methods.
Add receipt fixture check:
  fixture receipt hashes match generated protocol hashes.
```

Checks:

```text
cargo test -p ioi-services wallet_network
cargo test --test wallet_network_session_channel_e2e
npm run check:wallet-protocol
npm run test:wallet-protocol
npm run test:wallet-sdk
node scripts/conformance/wallet-protocol-conformance.mjs
```

Acceptance:

```text
Conformance fails on method drift, schema drift, fixture drift, or SDK-local
semantic drift.
```

### Phase 7: Product Repo Integration

Objective: make wallet-network product consume the packages.

Work in wallet-network product repo:

```text
Remove authoritative local copies of wallet types/scopes/receipt schemas.
Import @ioi/wallet-protocol for constants, schemas, fixtures.
Import @ioi/wallet-sdk for authority review and capability flows.
Keep UI fixtures marked demo-only.
Add product tests that fail if canonical objects are locally redefined.
```

Boundary check:

```text
rg -n 'scope:|AuthorityGrant|CapabilityLease|WalletReceipt|ExchangeIntent|TradeIntent'
```

Acceptance:

```text
Every canonical object reference in product repo imports from IOI packages or is
explicitly marked demo-only.
```

### Phase 8: CI and Pre-Next-Leg Guard

Objective: make the package boundary hard to regress.

Root checks to include in pre-next-leg readiness:

```text
npm run check:wallet-protocol
npm run test:wallet-protocol
npm run test:wallet-sdk
node scripts/conformance/wallet-protocol-conformance.mjs
git diff --check -- docs/architecture packages scripts crates
```

Optional root script:

```json
{
  "check:wallet-packaging": "npm run check:wallet-protocol && npm run test:wallet-protocol && npm run test:wallet-sdk && node scripts/conformance/wallet-protocol-conformance.mjs"
}
```

Acceptance:

```text
Wallet packaging drift blocks CI/pre-next-leg checks.
```

## Conformance Invariants

```text
1. Rust wallet types remain protocol truth.
2. Generated protocol package matches Rust-exported schemas and method metadata.
3. SDK imports protocol artifacts and does not define canonical semantics.
4. Product UI imports protocol/SDK artifacts and does not author authority truth.
5. Unknown, unassessed, stale, or conflicting risk states cannot be coerced to safe.
6. Capability leases never expose long-lived secrets by default.
7. Receipt fixtures are machine-verifiable and versioned.
8. Service method registry drift is detected.
9. Revocation epoch is present wherever grants, leases, approvals, or receipts need it.
10. `scope:*` remains authority vocabulary; `prim:*` remains primitive execution capability vocabulary.
```

## Anti-Patterns

```text
Product repo defines a new canonical scope.
Product repo copies receipt schemas and edits them by hand.
SDK invents a risk label that protocol does not know.
SDK treats missing risk labels as safe.
Wallet UI signs a route/trade candidate without Wallet policy review.
Generated package is edited manually without generator source changes.
Protocol package ships fixtures that Rust service tests cannot parse.
Capability lease grants durable plaintext secret access by default.
OpenAPI is maintained separately from schema/types.
Legacy compatibility shims hide old Autopilot naming or stale wallet objects.
```

## Suggested Commit Slices

```text
1. docs: wallet protocol/sdk packaging plan
2. docs: source-of-truth and implementation-matrix package boundary updates
3. pkg: add @ioi/wallet-protocol skeleton
4. pkg: add @ioi/wallet-sdk skeleton
5. rust: add wallet JsonSchema derives and exporter
6. gen: add wallet protocol generator and stale check
7. test: add wallet protocol fixture/schema tests
8. sdk: add client/review/capability/receipt helpers
9. conf: add wallet packaging conformance suite
10. product: migrate wallet-network app imports to packages
```

## Definition of Done

```text
@ioi/wallet-protocol exists and builds.
@ioi/wallet-sdk exists and builds.
Rust wallet protocol exporter produces schema/method/fixture artifacts.
Generated protocol artifacts are checked into packages/wallet-protocol.
OpenAPI and JSON Schema are exported from @ioi/wallet-protocol.
SDK helpers import from @ioi/wallet-protocol.
Wallet product repo imports protocol/SDK packages.
Conformance checks fail on drift.
Docs identify one canonical owner for wallet protocol packaging.
git diff --check passes.
Relevant Rust and Node package tests pass.
```
