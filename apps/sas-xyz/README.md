# sas.xyz

sas.xyz is the governed outcome marketplace. The implemented MVP slice covers
service releases, frozen ServiceOrders, settlement reservation, runtime
assignment, provider claim, immutable partial/final delivery, revision,
acceptance, dispute evidence and resolution, governed provider substitution,
and CAD artifact/production rights.

Operational, delivery, settlement, and rights state are deliberately separate:

```text
service release -> order -> delivery -> acceptance/dispute
                     |          |             |
                  runtime    artifacts     settlement intent + rights
```

## Run locally

```bash
npm run dev
```

The app runs on `http://127.0.0.1:5174`. Development authority is visibly
labelled and writes to an atomic durable store under `.data/`. The UI contains
no `localStorage` operational path and never generates receipt material.
Development authority refuses non-loopback listeners. The BFF issues a signed,
HttpOnly, SameSite session cookie and requires its CSRF token plus exact
same-origin requests for mutations; browser principal/tenant headers are
rejected.

## Production refusal

`npm run build` produces static assets, but `NODE_ENV=production node server.mjs`
intentionally refuses startup. Canonical ServiceOrder runtime, settlement,
artifact storage, download-authority, and governed-production contracts are not
all registered in this repository. The service-composition receipt-bundle
planner is delivery evidence admission, not a runtime-assignment substitute.
Arbitrary owner URLs therefore cannot enable production.

## CAD rights

The UI forces one honest mode:

- contractual/audited quantity: downloadable bytes with buyer reporting and
  audit obligations; or
- governed remote production: raw CAD remains controlled and CAS reservations
  plus owner-admitted, evidence-bound usage receipts meter only the observed
  adapter boundary.

A download authorization response says whether its owner actually supplied a
short-lived capability. A local receipt alone is never presented as downloadable
bytes.

## Verification

```bash
npm run check
npm test
npm run build
npm run check:production
```

Tests cover signed HTTP sessions, forged-header and CSRF refusal, cross-tenant
order parties, restart durability, tampered-chain refusal, idempotency, partial
and final delivery transitions, monotonic disputes, successor tenant binding,
both CAD modes, licensee/evidence/CAS production controls, malformed owner 2xx
refusal, concurrent-safe unit accounting, and refusal of over-consumption.

## Remaining canonical blockers

- the missing owner contracts above must land and pass real cross-service tests;
- the JSON store is a single-process development projection, not production
  ServiceOrder authority;
- reserve/runtime/delivery/settlement workflows require an Agentgres
  expected-head saga, durable outbox, recovery UI, and compensation before
  production can admit multi-owner effects.

`npm run build` emits a Vite manifest, then walks the real entry/import graph,
proves the prior localStorage/random-receipt prototype under
`fixtures/legacy-ui/` is unreachable, scans the bundled output, and writes a
hash-bearing `dist/production-authority-scan.json`. `npm run check:production`
repeats that verification against an existing build.
