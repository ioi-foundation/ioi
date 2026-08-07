# aiagent.xyz

aiagent.xyz is the worker-supply marketplace for the IOI network. This app now
ships a functional domain slice for typed worker drafts, immutable package-owner
admission, private registration, explicit public promotion, benchmarking,
listing, quote, entitlement, install/Hire, managed instances, integration
grants, lifecycle requests, events, and hash-linked receipts.

The important boundary is enforced in code:

```text
draft != package release != private registration != public listing
      != quote != entitlement != install != managed instance != runtime
```

The web application never owns package admission, benchmark authority,
credentials, monetary movement, or runtime execution. Replaceable adapters call
Packages, Evaluations, wallet/authority, settlement, and Hypervisor owners.

## Run locally

```bash
npm install
npm run dev
```

Development starts on `http://127.0.0.1:5173` with an explicit local authority
adapter and a visible `LOCAL DEVELOPMENT AUTHORITY — NOT NETWORK STATE` banner.
State is atomically persisted under `.data/`; restart does not reset accepted
domain transitions. Development authority refuses non-loopback listeners. The
BFF issues a signed, HttpOnly, SameSite session cookie and requires its CSRF
token plus an exact same-origin request for every mutation. Browser-supplied
principal and tenant headers are rejected.

## Production refusal

`npm run build` produces static assets, but `NODE_ENV=production node server.mjs`
intentionally refuses startup. The repository does not yet expose all canonical
package-release, benchmark, settlement, credential-authority, and durable
managed-instance contracts required by the worker lifecycle. Arbitrary URLs and
the older pure-admission planners are not treated as compatibility substitutes.

When those owner contracts land, production must use a server-verified product
session (Secure HttpOnly cookie or an equivalently verified wallet/network
session), strict typed owner-decision envelopes, and an Agentgres-backed saga.
The browser is never an identity authority.

## Canonical product routes

- `/builder` — draft through explicit publication
- `/my-workers` — private/organization registrations
- `/agents` and `/agents/:worker_id` — admitted public supply and Hire
- `/instances` and `/instances/:instance_id` — desired/observed lifecycle,
  subscriptions, and credential-reference-only integration bindings

## Verification

```bash
npm run lint
npm test
npm run build
npm run check:production
```

The Node test suite exercises the worker supply and buyer lifecycle under the
explicit development authority, restart durability, tampered-chain refusal,
principal and tenant isolation, immutable release/publication transitions,
idempotent retry, secret rejection, malformed-owner-success refusal, signed
HTTP sessions, and CSRF/origin enforcement.

## Remaining canonical blockers

- owner contracts listed in the production refusal must be implemented and
  exercised against the real daemon;
- the JSON store is a single-process development projection, not production
  marketplace authority;
- multi-owner Hire/release flows still require an Agentgres expected-head saga,
  durable outbox, recovery UI, and compensation for partial external effects.

`npm run build` emits a Vite manifest, then walks the real entry/import graph,
proves the retired static prototype under `fixtures/legacy-ui/` is unreachable,
scans the bundled output, and writes a hash-bearing
`dist/production-authority-scan.json`. `npm run check:production` repeats that
verification against an existing build.
