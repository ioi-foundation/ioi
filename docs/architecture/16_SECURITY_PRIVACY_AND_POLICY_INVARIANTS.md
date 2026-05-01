# Security, Privacy, and Policy Invariants

## Canonical Definition

This document defines the non-negotiable authority, security, privacy, and execution boundaries for canonical Web4.

## Authority Invariants

1. Agents do not directly mutate canonical truth.
2. Agents propose scoped changes; the fabric validates, merges, receipts, and settles them.
3. No effectful action without a tool contract and risk class.
4. No sensitive action without a persisted policy decision.
5. No policy-required approval without exact request hash, policy hash, scope, expiry, and revocation epoch.
6. No raw root secrets to agents, apps, marketplace workers, or untrusted runtimes.
7. wallet.network is the authority plane for secrets, capabilities, approvals, and payments.
8. Agentgres records authority artifacts but does not own root secrets.

## Runtime Invariants

1. No workflow-only, benchmark-only, UI-only, or dogfooding-only runtime path for consequential work.
2. All surfaces use stable runtime envelopes.
3. Runtime nodes emit typed events and receipts.
4. Untrusted DePIN nodes cannot execute final effects directly.
5. Enterprise-private plaintext requires local, customer VPC, trusted hosted, or TEE execution.
6. Long-running operations require deadline, cancellation, and progress.

## State Invariants

1. Agentgres is per-domain and does not run on IOI L1.
2. IOI L1 stores commitments and economic state, not operational traces.
3. Filecoin/CAS stores payloads, not authority.
4. Local speculative state must be labeled speculative.
5. Projection state must expose freshness and source watermark.
6. Receipts are bundled; only sparse roots may reach IOI L1.

## File and Artifact Invariants

1. No artifact trusted by URL alone.
2. Hash/signature verification is mandatory.
3. Private plaintext requires key-release policy.
4. Public ciphertext is not public plaintext.
5. Sensitive artifacts must have privacy class.

## Model/Provider Invariants

1. No hardcoded provider in production-critical routing.
2. BYOK keys live in wallet.network.
3. Private tasks must not route to disallowed external providers.
4. Fallbacks must be policy-aware.
5. Model invocation receipts should be available for consequential runs.

## Connector Invariants

1. Connector refresh tokens remain in wallet.network.
2. External send/spend/publish actions require appropriate approval.
3. Commerce purchase actions require explicit human or policy approval.
4. Tool outputs validate against declared schemas.
5. Tool failures feed quality/recovery ledgers.

## Marketplace Invariants

1. Default harness remains neutral.
2. Marketplace worker internals cannot be silently cloned.
3. Contributions receive attribution.
4. Service redirection is opt-in unless the service is explicitly ordered.
5. Quality/reputation roots should be based on receipts and outcomes.

## Mainnet Invariants

1. IOI L1 gas applies to registry/rights/settlement boundaries, not every runtime step.
2. L2s/rollups are scaling contingencies, not default first-party architecture.
3. Independent L1s register for discovery; they need not settle into IOI.
4. Mainnet is the notary, not the notebook.

## Privacy Doctrine

> **Share intelligence, not raw data. Share ciphertext availability, not plaintext readability. Share proofs/receipts, not secrets.**

## Execution Privacy Doctrine

> **Without TEE/MPC/FHE, do not make the host blind by hiding execution from it. Make the host unable to see enough or do enough to matter.**

## One-Line Doctrine

> **Canonical Web4 is safe only when authority, execution, state, payloads, and settlement remain separated by design.**

