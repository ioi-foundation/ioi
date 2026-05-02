# wallet.network Authority Layer Specification

Status: canonical architecture authority.
Canonical owner: this file for wallet.network authority doctrine; low-level scope APIs live in [`wallet-network-api-and-authority-scopes.md`](./api-authority-scopes.md).
Supersedes: older generic capability-grant wording when it conflicts with `scope:*` authority grants.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Canonical Definition

**wallet.network is the canonical Web4 authority layer: the identity, secret,
authority-scope, approval, payment, and revocation control plane for
autonomous software.**

It owns identity, secrets, authority scope grants, session authority, approvals, payments, revocation, and audit lineage. It is not merely a crypto wallet.

## Core Doctrine

> **Autopilot runs agents. Agentgres remembers and settles what changed. wallet.network decides what power agents are allowed to use.**

Put more sharply:

> **wallet.network authorizes power. It does not do the work, store the app, or
> become the chain.**

## Boundary Statement

wallet.network does not execute work, store app-domain operational truth, or
serve as the marketplace database.

- Autopilot / IOI daemon executes work.
- Agentgres records operational state, runs, receipts, projections, delivery,
  and contribution accounting.
- IOI L1 settles registry, rights, escrows, bonds, disputes, and public
  commitments.
- wallet.network authorizes scopes, protects secrets, controls payments, and
  issues approval/session grants.

Authority receipts flow through the operational substrate:

```text
wallet.network authority receipt
→ Agentgres domain operation/evidence/delivery bundle
→ optional IOI L1 commitment when economically or security relevant
```

## What wallet.network Owns

wallet.network owns:

- user identity;
- agent/app/domain authority grants;
- root secrets;
- API keys;
- OAuth refresh tokens;
- connector credentials;
- BYOK model provider keys;
- authority scope leases;
- approval tokens;
- session grants;
- policy envelopes;
- revocation epochs;
- payment authorization;
- panic/emergency controls;
- audit lineage.

## What wallet.network Does Not Own

wallet.network does not own:

- rich application state;
- workflow graphs;
- worker marketplace listings;
- service order operational state;
- full run traces;
- Agentgres projections;
- artifact payload bytes;
- model inference execution.
- IOI L1 registry, settlement, or dispute state.

## Availability Profiles

wallet.network is the trusted authority plane. It may be always-on locally,
hosted, mobile-assisted, enterprise-managed, or wakeable depending on profile.

Examples:

- Autopilot desktop may use a background local wallet authority service.
- Hosted workers may use delegated wallet authority with narrow standing
  grants.
- High-risk actions may require mobile/passkey/security-key step-up before
  sealed secret release, payment authorization, or policy widening.

## Account Abstraction

User-facing onboarding should hide wallet complexity.

A user may create a wallet.network account through:

- Google;
- GitHub;
- passkey;
- Web3 wallet linking;
- email/OIDC provider;
- enterprise SSO.

A frictionless login creates a native wallet.network account with a Level 1 authority profile.

The external login is an authentication factor, not the root identity.

## Frictionless-to-Fortress Security Ladder

### Level 1: Frictionless Account

- Google/GitHub/OIDC/Web3 login;
- native wallet.network identity created automatically;
- low-risk authority scopes;
- managed recovery;
- limited autonomy.

### Level 2: Trusted Device

- passkey;
- biometric;
- mobile approver;
- higher risk limits;
- stronger approval flows.

### Level 3: Sovereign Vault

- multiple factors;
- hardware key;
- MPC/shards;
- high-value assets;
- policy widening;
- institutional autonomy.

## Authority Scope Request Flow

```text
agent/runtime requests authority scope
→ wallet.network evaluates policy
→ if allowed, issues scoped authority grant/session/approval token
→ runtime executes operation without raw secret exposure where possible
→ receipt emitted
→ Agentgres records effect state/evidence
```

## Authority Scope Examples

```text
scope:model.openai.chat
scope:model.anthropic.messages
scope:gmail.read
scope:gmail.draft
scope:gmail.send
scope:calendar.create
scope:slack.post
scope:github.comment
scope:instacart.cart_create
scope:instacart.order_submit
scope:wallet.transfer_under_limit
```

## Risk Classes

```text
read
draft
local_write
external_message
commerce
funds
policy_widening
secret_export
identity_change
```

Higher classes require stronger approval or security tier.

## Marketplace Role

wallet.network authorizes:

- worker installation;
- worker authority grants;
- WorkerInvocation escrow;
- ContributionReceipt payment;
- UsageReceipt settlement;
- service escrow funding;
- ServiceOrder escrow;
- SLA bond approval;
- payment release;
- payout authorization;
- refund/dispute authorization;
- recurring worker standing orders;
- BYOK model calls;
- connector OAuth usage;
- policy widening;
- revocation/panic.

## Relationship to IOI L1

wallet.network may interact with IOI L1 for:

- gas payments;
- escrow funding;
- SLA bond posting;
- license/installation rights;
- payout acceptance;
- disputes;
- identity commitments.

wallet.network abstracts gas and payment complexity from the user.

IOI L1 is not the wallet database. IOI L1 stores registry, economic,
settlement, dispute, and sparse public commitments. wallet.network stores
authority state locally or in a secure authority deployment profile, and
Agentgres stores operational receipts and projections.

## Relationship to Agentgres

wallet.network emits authority artifacts:

```text
PolicyEnvelope
RootGrant
SubGrant
AuthorityScopeLease
ApprovalToken
RevocationEvent
SecretExecutionReceipt
StepUpReceipt
```

Agentgres records the effect of these in domain state, but does not own the raw secrets.

## IOI Daemon / Guardian Profile Boundary

Public architecture names the execution boundary as the IOI daemon. A hardened
Guardian profile may exist inside that boundary for policy gates, attestation,
tool execution, and authority mediation.

```text
wallet.network ↔ IOI daemon / Guardian execution profile
```

The daemon requests authority scopes and receives bounded grants, approval
tokens, or operation-scoped secret execution. It does not become a key
custodian.

## Runtime Privacy Modes

wallet.network should support authority-release policy by runtime privacy mode.

### Mutual Blind Mode

- no raw secrets;
- no final effects solely from untrusted execution;
- opaque, narrow, operation-scoped authority only;
- receipts must prove what was requested, released, used, and revoked.

### Enterprise Secure Mode

- TEE or equivalent attestation required before sealed secret or authority
  release;
- authority release binds to code identity, request hash, policy hash, expiry,
  and revocation epoch;
- Agentgres records the resulting authority and execution receipts.

## Cryptography Positioning

The target profile is hybrid classical + post-quantum authority, not a blanket
claim that every connected legacy system becomes post-quantum safe.

Appropriate claims:

- hybrid signatures for policy envelopes, grants, and approval records;
- hybrid KEM for control-plane handshakes;
- authenticated encryption such as XChaCha20-Poly1305 for vault storage;
- legacy-chain custody remains constrained by the legacy chain's own
  cryptographic limits.

## Non-Negotiables

1. Agents never receive raw root secrets.
2. Apps and runtimes are authority clients, not key custodians.
3. Policy widening requires step-up.
4. Sensitive actions bind to exact request hash, policy hash, scope, expiry, and revocation epoch.
5. Panic/revocation must kill active grants.
6. BYOK keys live in wallet.network, not workflow node configs.
7. Agent execution accounts are not default for every agent; they are required
   only when the agent needs on-chain execution power.
8. High-risk on-chain actions require wallet.network step-up and/or
   smart-account module enforcement.

## One-Line Doctrine

> **Do not make users create a wallet. Let them create an account that can grow into a vault.**

## Preserved wallet.network Product Spec Module

The following module preserves the detailed wallet.network v3.2 product-spec context from the former `docs/specs/wallet_network.md`. It is mostly aligned with the current architecture. The canonical doctrine above still wins where deployment availability, IOI daemon / Guardian-profile naming, Agentgres receipt sinks, IOI L1 commitments, runtime privacy modes, marketplace settlement, or hybrid-cryptography claims differ.

---

# 📑 Product Specification: wallet.network (The Sovereign IAM Hub)

**Version:** 3.2 (Frictionless-to-Fortress Architecture, Superset Custody & Zero-Trust Extensibility)
**Target:** Desktop (Primary), Browser Extension (Bridge), Mobile (Notifier / Approver)
**Core Philosophy:** **“Security tolerance is defined by the user. The Vault owns both assets and agency.”**
**Positioning Note:** Treat **`wallet.network`** as a **foundational Identity & Access Management (IAM) control plane and native Web4 Custodian** — not just a wrapped app. Wrapped apps/agents are **clients** of wallet capabilities and are **never key custodians**.

---

## 0. System Model & Boundaries

### 0.1 The IOI Ecosystem (Non-Negotiable Separation)

1.  **`wallet.network` = Foundational Control Plane**
    *   Trusted, stateful, profile-based availability.
    *   Owns root secrets, dual-entropy mnemonic, hybrid asset custody, session authority, policy enforcement, audit lineage, and approvals.
2.  **External Domains & Connectors = Permissionless Capability Clients**
    *   **First-Party Platforms:** `sas.xyz` (Supply/Developers) and `aiagent.xyz` (Demand/Marketplace).
    *   **Third-Party Platforms:** Any external dApp or enterprise dashboard can integrate the `wallet-sdk` to programmatically request Session Keys and agentic authority scopes.
    *   **Extensible Connectors:** Swappable provider adapters (e.g., Stripe, custom local banks). Third-party code runs in strictly isolated WASM sandboxes to preserve Vault invariants.
3.  **Wrapped Apps / Agents = Ephemeral Execution**
    *   Ephemeral/untrusted by design.
    *   Receive **scoped authority tokens**, never raw secrets or custodial keys.

### 0.2 Practical Code Boundary (Recommended Modules)

1.  **`wallet-core`**
    *   Vault database + encryption (`dcrypt`), dual-entropy derivation, MPC shard management, policy engine, sessions, approvals, attestations, audit log.
2.  **`wallet-connector-*`**
    *   Provider OAuth + API adapters; token brokerage; provider-specific schemas.
3.  **`wallet-sdk`**
    *   Client library for external domains, wrapped apps, and Agent IDEs to request capabilities and handle receipts/errors.
4.  **UI shells**
    *   Desktop/Extension/Mobile — all consume the same core API and policy semantics.

---

## 1. Executive Summary

**`wallet.network`** is the **Web4 Authority Layer** for the decentralized internet. It abandons the rigid "One-Size-Fits-All" Web3 onboarding model. Instead, it scales dynamically from a frictionless Web2-style "Sign in with Google" experience up to an institutional "hybrid classical + post-quantum authority profile," based entirely on the user's risk appetite.

It functions as a secure **Cryptographic Superset** that manages the pillars of agentic operation:

1.  **Native Hybrid Custody:** Natively holds legacy assets (ETH/SOL) and Web4 assets (Service NFTs, Labor Gas).
2.  **Session Authority:** Issuing bounded, automated permissions so agents can operate without constant human clicks.
3.  **Secret Injection (and Authority-Scope Execution):** Securely storing non-blockchain credentials (API keys, OAuth tokens) and injecting them via policy. The AI model never sees the raw secret.
4.  **Future-Proof Identity:** Establishing a **Hybrid hybrid classical + post-quantum** root of trust while bridging to legacy EOAs.
5.  **Policy-Locked Autonomy + Recursive Delegation:** Humans approve power (policy); agents spend power (sessions) and may re-delegate downward (sub-grants) without expanding scope.

### 1.1 Value Proposition
*   **For Users:** “The last wallet you’ll ever need. Hybrid classical + post-quantum authority for your assets, and Sovereign IAM for your AI workforce.”
*   **For Developers:** “A unified, extensible interface for secrets, sessions, and safety policies—across all providers.”
*   **For the Network:** “The enforcement point for the IOI Safety Sandwich: deterministic policy + cryptographic audit + safe autonomy.”

---

## 2. Architecture: The Superset Identity Stack

### 2.1 The Hybrid Asset & Agency Custody Stack

`wallet.network` operates as a Cryptographic Superset. Because it implements the **Dual-Entropy Mnemonic** (deriving both classical and lattice-based keys from one master seed), it natively manages both static asset ownership and dynamic autonomous agency.

| Custody Domain | Managed By | Cryptography (via `dcrypt`) | Assets / Artifacts Held |
| :--- | :--- | :--- | :--- |
| **Legacy Web3 Assets** | `wallet.network` (Native) | **Classical:** `secp256k1` / `Ed25519` | ETH, SOL, ERC-20s, standard NFTs. |
| **Web4 Native Assets** | `wallet.network` (Native) | **Hybrid Sigs:** `Ed25519` + `ML-DSA-44` | Service NFTs, Gig Escrows, SLA Bonds, Labor Gas. |
| **Agentic Authority** | `wallet.network` (Vault) | **Hybrid KEM & Sigs** | Session Keys, ApprovalTokens, Policy Envelopes. |

### 2.2 The "Frictionless-to-Fortress" Authentication Tiers

Users configure their "Authority Policy" based on risk appetite, managed as **Configurable Signature Thresholds**.

*   **Level 1: Frictionless (1FA):** Google OIDC (Social Login) + ZK-Login. A "Managed Shard" is generated via Multi-Party Computation (MPC). User experiences standard Web2 flow.
*   **Level 2: The Trusted Device (2FA):** 6-digit TOTP OR Mobile Biometric (FaceID/Android Fingerprint). Utilizing the mobile **Secure Enclave (TEE)** guarantees the private key never leaves the physical chip, providing hardware-attested "Physical Presence."
*   **Level 3: The Sovereign Fortress (3FA+):** Configurable MPC Sharding. Requires fractional or absolute approvals (e.g., "Google + FaceID + YubiKey") for high-risk actions, modifying policies, or large value transfers.

### 2.3 The "Link and Upgrade" Web3 Bridge

We do not let legacy Web3 wallets (MetaMask) *be* the Web4 identity, to avoid inheriting legacy cryptographic vulnerabilities. Instead, we use them as Onboarding Factors and Liquidity Sources.
1.  **Native Generation:** `wallet.network` *always* generates a native, hybrid classical + post-quantum Web4 identity upon account creation.
2.  **Web3 Sign-In (SIWE):** Users can click "Connect MetaMask" to cryptographically link their legacy `0x...` address to the new Web4 identity as an authentication factor.
3.  **Liquidity Bridging:** Users can grant their native Web4 identity an allowance to trade funds held in their Web3 cold storage via ERC-4337 Smart Accounts (See Appendix A).

### 2.4 The Sovereign Vault (Control Plane Database)

A local, encrypted database that stores what EOAs cannot:
*   **Secrets:** API keys, refresh tokens, connector credentials, private service keys.
*   **Policy Commitments:** Signed, versioned policy envelopes that define the boundaries of autonomy.
*   **Sessions & Grants:** Ephemeral keys/tokens granted to specific agents for specific scopes and durations.
*   **Audit Lineage:** Cryptographically linked log of approvals, grants, interceptions, and authority-scope executions.

### 2.5 Integration with IOI Kernel (IOI Daemon / Guardian Profile Link)

The Vault communicates directly with the local **IOI daemon / Guardian execution profile** over **mTLS**.
*   **Handshake (App-Layer):** While transport is mTLS, `wallet-core` and IOI daemon / Guardian profile performs an additional **application-layer hybrid KEM handshake** (X25519 + ML-KEM-768) to derive session secrets. This prevents "harvest-now, decrypt-later" attacks even if the TLS layer is compromised or recorded.
*   **Inbound:** Receives `FirewallInterception` events when an agent hits a policy gate or step-up trigger.
*   **Outbound:** Issues:
    *   `ApprovalTokens` (action-bound, scoped, replay-resistant)
    *   Injected secrets (as ephemeral, operation-scoped releases)
    *   Session grants and sub-grants
    *   Policy updates and revocations

---

## 3. Autonomy Model: Policy-Locked Power, Session-Spent Autonomy

### 3.1 “Humans Approve Power; Agents Spend Power”

The system is designed so autonomy is safe and scalable:
*   **Humans** approve a **Policy Envelope** (capabilities + constraints).
*   **Agents** run autonomously within that envelope using short-lived sessions.
*   **Policy changes** (widening scope, raising limits, adding connectors) require step-up human approval based on the user's configured Auth Tier.
*   **Delegation** is allowed only as **monotonic narrowing** (no privilege inflation).

### 3.2 Grants: Root Grants and Recursive Sub-Grants

**RootGrant**
*   Issued by `wallet-core` after onboarding and step-up approval.
*   Includes: allowed authority scopes, explicit constraints (amount caps, domains, recipients, categories), TTL / renewal policy, and delegation rules (max depth, issuance budget).

**SubGrant (Agent → Agent)**
*   Minted by an agent only if:
    *   `SubGrant.scope ⊆ ParentGrant.scope`
    *   `SubGrant.limits ≤ ParentGrant.limits`
    *   `SubGrant.expiry ≤ ParentGrant.expiry`
    *   Delegation depth/budget is not exceeded.

### 3.3 Step-Up Triggers (First-Class Policy Clauses)

Step-up requirements are explicit, not ad-hoc. Examples:
*   New connector onboarding / new destination domain.
*   Action > configured caps (daily spend, per-tx threshold, volume anomaly).
*   Exporting, revealing, or “raw secret access”.
*   Any **policy envelope widening**.

When triggered:
1.  IOI daemon / Guardian profile blocks the action.
2.  `wallet.network` notifies Desktop/Mobile.
3.  User approves with their configured authentication threshold (e.g., passkey/biometric/security key).
4.  Vault issues an action-bound `ApprovalToken`.
5.  IOI daemon / Guardian profile resumes and records the receipt.

### 3.4 Core Data Models (Schema Definition)

To ensure interoperability and security, the following fields are mandatory for Grant and Policy structures:
*   `issuer_id`: Vault Identity (Hybrid Public Key)
*   `subject_id`: Agent / App Identity (or Ephemeral Key)
*   `policy_hash`: Cryptographic commitment to the governing policy logic
*   `policy_version`: Monotonically increasing integer
*   `authority_scope_set`: List of allowed actions (e.g., `['email:send', 'twitter:post']`)
*   `constraints`: Parameter limits (e.g., `{'max_usd': 50, 'allowlist': [...]}`)
*   `delegation_rules`: `{'max_depth': 2, 'can_redelegate': true}`
*   `expiry`: Unix timestamp (Absolute)
*   `revocation_epoch`: Minimum valid epoch (allows bulk revocation)
*   `signatures`: **Hybrid Signature Block** (Must contain both Ed25519 and ML-DSA signatures)

---

## 4. User Experience (UX) Flows

### 4.1 Progressive Onboarding ("Start Simple, Secure Later")

1.  **The Hook:** User clicks "Login" on a Web4 interface (`aiagent.xyz` or `sas.xyz`).
2.  **Auth Choice:**
    *   *Path A (Web2 Native):* "Sign in with Google." A native Web4 identity is spun up via MPC. User funds account via fiat-ramp.
    *   *Path B (Web3 Native):* "Connect MetaMask." Web4 identity is generated and cryptographically linked to the EOA via SIWE.
3.  **Security Upgrades:** Inside the Vault dashboard, user adds FaceID (2FA) or YubiKey (3FA) to unlock higher limits and institutional autonomy.

### 4.2 Marketplace Flow (Delegating Agency)

1.  **Discovery:** User selects “Hedge Fund Agent” on `aiagent.xyz`.
2.  **Delegation (Handoff):**
    *   Marketplace requests: “Needs 24h session + Twitter authority scope.”
    *   `wallet.network` prompts: *“Authorize ‘Hedge Fund Agent’ to run for 24h under Policy Envelope X?”*
    *   User approves via configured tier (e.g., passkey/phone/biometric).
3.  **Autonomy:** Agent runs continuously without repeated prompts, strictly within policy and spend caps.

### 4.3 Human-in-the-Loop Intercept (Step-Up)

1.  **Trigger:** Agent hits a step-up clause.
2.  **Notification:** `wallet.network` alerts Desktop/Mobile.
3.  **Resolution:** User approves on phone.
4.  **Resume:** Vault issues a one-time, action-bound `ApprovalToken`.

### 4.4 Emergency Controls (Panic + Revocation)

*   **Panic Button:** Instantly revoke all sessions and freeze delegation.
*   **Connector Kill Switch:** Revoke connector tokens and rotate refresh tokens.
*   **Policy Freeze:** Lock envelopes to “deny except allowlisted” mode.

---

## 5. Software Modules

### 5.1 `wallet-core` (The Vault Control Plane)

*   **Role:** Always-on local server for user agency.
*   **Implementation:** Pure Rust, `forbid(unsafe_code)` via `dcrypt` library for high assurance.
*   **Responsibilities:**
    *   Vault encryption, dual-entropy derivation, MPC shard management.
    *   Policy engine and envelope commitments.
    *   Session issuance and delegation verification.
    *   Approvals, step-up gating, revocation.
    *   Attestation verification (IOI daemon / Guardian profile + sensitive executors).
    *   Audit log: immutable, hash-linked lineage.

### 5.2 `wallet-connector-*` (Provider Adapters)

*   **Role:** Modular OAuth + API adapters (gmail/outlook/stripe/etc).
*   **Responsibilities:** OAuth flows, refresh token storage, access token minting, token brokerage (short-lived access tokens and operation-scoped authority), provider schema normalization.

### 5.3 `wallet-sdk` (Client Capability Interface)

*   **Role:** Used by wrapped apps / Agent IDE / marketplace clients.
*   **Responsibilities:** Request capabilities and sessions, handle interception/step-up responses, enforce “no raw secret visibility” in the client API design.

### 5.4 UI Shells

*   **`wallet-desktop` (Primary):** Tauri + React + Rust. Background/tray service, secret management, policy graph, audit feed, local approvals fallback.
*   **`wallet-extension` (Bridge):** Chrome Extension (Manifest V3). **Crypto Role:** Uses `dcrypt` WASM bindings *only* for request integrity, local pairing, and channel encryption to the desktop. **Constraint:** The extension is a relay and UI surface; it **never** holds vault DEKs/KEKs or decrypts secrets directly.
*   **`wallet-mobile` (Notifier / Approver):** React Native / Native. Push notifications for gates, passkey / FaceID approval signing, panic + revocation controls.

### 5.5 Zero-Trust Extensibility Framework (Open Ecosystem)

To ensure `wallet.network` serves as a universal standard, it supports programmatic extensibility bounded by zero-trust architecture.

**5.5.1 Permissionless Domain Integration (The "WalletConnect" of Agency)**
Any third-party platform can integrate `wallet.network` using `wallet-sdk`.
*   **Standardized Handshake:** Domains submit a `CapabilityRequest` specifying requested scopes, limits, and TTL.
*   **Origin Isolation:** The Vault cryptographically verifies the domain's origin to prevent phishing.
*   **No Ambient Authority:** Third-party domains **never** receive root keys or raw secrets; they receive ephemeral `SessionKeys` mapped specifically to their requested task.

**5.5.2 Sandboxed Connector Marketplace (Third-Party API Adapters)**
Developers can publish new API connectors without compromising Vault security.
*   **Declarative Schemas:** Connectors must adhere to the Canonical Connector Manifest (Whitepaper Appendix F).
*   **WASM Isolation (WASI):** Custom connector logic is compiled to WebAssembly. `wallet-core` executes them within a hermetic sandbox.
*   **Data Siloing:** The WASM sandbox is injected *only* with the specific secret required for that connector. It has zero memory access to the rest of the Vault's encrypted database.

---

## 6. Security & Cryptography (Strict Hybrid Model)

### 6.1 Hybrid Security Model (Classical + hybrid classical + post-quantum)

We utilize the `dcrypt` library to implement a "Hybrid" model.

*   **Data Confidentiality at Rest (Symmetric):**
    *   **Algorithm:** **XChaCha20-Poly1305** (Pure Rust).
    *   **PQ Resilience:** Achieved via 256-bit key space (resists Grover's Algorithm) and robust KDFs.
    *   **Note:** We expressly do **not** use PQC (ML-KEM/ML-DSA) for database encryption, as they are asymmetric primitives unsuited for bulk storage.
*   **Control Plane Signaling (Hybrid KEM):**
    *   **Algorithm:** **X25519 + ML-KEM-768**.
    *   **Usage:** Application-layer handshake to establish session keys between Vault, IOI daemon / Guardian profile, and agents.
    *   **Benefit:** "Harvest now, decrypt later" protection.
*   **Identity & Policy (Hybrid Signatures):**
    *   **Algorithm:** **Ed25519 + ML-DSA-44**.
    *   **Verification:** Default verification requires **both** signatures for high-stakes Web4 artifacts. Compatibility mode may accept either only with explicit policy flag and prominent audit marking.

### 6.2 Threat Model (Practical Guarantees)

**Goal:** Protect secrets against stolen device, offline disk exfiltration, and rollback attacks.
**Non-Goal / Reality:** A fully compromised, active host (root access) can attempt impersonation and memory scraping.
*   **Mitigation:** We mitigate by minimizing plaintext exposure, never exporting raw secrets, enforcing short-lived grants, requiring out-of-band step-up, and executor attestation.
*   **Role of Memory Safety:** Using memory-safe Rust (`dcrypt`) reduces the risk of *bug-class exploits* (buffer overflows) allowing an attacker in, but it is not a substitute for host isolation.

### 6.3 Vault Encryption: Envelope Keys + Multi-Factor Unlock

Use **envelope encryption**:
*   **DEKs** encrypt vault records (secrets/policies) using **XChaCha20-Poly1305**.
*   **KEKs** wrap DEKs; KEKs are derived using **Argon2id** (memory-hard KDF) to resist GPU/ASIC cracking.
*   **Factors:** Device factor (TPM), User factor (Bio/Passphrase), Out-of-band factor (Phone).

### 6.4 Monotonic Counter + Anti-Grinding / Anti-Rollback (IOI-daemon/Guardian-profile-grade)

To resist grinding and rollback:
*   Incorporate a **monotonic counter** stored outside snapshot boundaries (hardware/TEE when available).
*   Enforce attempt limits, exponential backoff, and lockout thresholds.

### 6.5 Out-of-Band Approval Factors

**Default step-up factor:** **Passkey (FIDO2/WebAuthn)**, preferably **phone-as-security-key over Bluetooth**.

### 6.6 ApprovalTokens (Action-Bound, Replay-Resistant)

An `ApprovalToken` is signed using the **Hybrid Signature** scheme and must contain:
*   **action:** (approve tx / widen policy / release authority)
*   **audience:** (IOI daemon / Guardian profile instance ID / specific executor)
*   **target:** (connector/provider/app/agent identity)
*   **mode:** (`one_shot` vs `lease` with TTL)
*   **grant_linkage:** (`parent_grant_id` for audit lineage)
*   **scope:** (caps, allowlists)
*   **nonce + counter:** (replay protection)

### 6.7 Secret Injection Protocol (Refined to “Authority-Scope Execution”)

1.  **Request:** Agent asks the IOI daemon / Guardian profile for an authority scope (e.g., `scope:model.openai.chat`), not a raw secret.
2.  **Challenge:** IOI daemon / Guardian profile proves it is running valid, attested code (remote attestation).
3.  **Policy Check:** Vault evaluates the authority scope against current envelope.
4.  **Release / Execute:**
    *   *Preferred:* Vault/IOI daemon / Guardian profile executes operation using secret internally (no raw secret to agent).
    *   *Otherwise:* Vault encrypts ephemeral secret material to the IOI daemon / Guardian profile ephemeral key (Hybrid KEM) with strict TTL.

### 6.8 Connector Token Brokerage (Minimize Long-Lived Exposure)

*   Store refresh tokens in vault.
*   Mint short-lived access tokens per operation.
*   Rotate and revoke rapidly.

### 6.9 Auditing & Lineage (Control Plane Receipts)

Every important event yields a receipt:
*   Policy commitment signed + hash-addressed.
*   Session issuance / sub-grant issuance.
*   Step-up approval token issuance.
*   Secret injection or authority-scope execution receipt.

Receipts are hash-linked for tamper-evidence and can be anchored into IOI’s broader audit substrate.

---

## 7. Adoption Strategy: “Embrace and Extend”

### 7.1 The “Trojan Horse” (DX Wedge)
*   **Pitch:** “Don’t trust your API keys to a browser. Keep them in your Sovereign Vault.”
*   **Wedge:** Developers need secrets + sessions + safe automation; `wallet.network` solves this first as a standalone Secret Manager before they even care about blockchains.

### 7.2 Ecosystem Integration
*   **WalletConnect v2:** Compatibility for legacy Tier 1 ownership wallets.
*   **Passkeys/OIDC:** Eliminates the "seed phrase bounce rate."
*   **Marketplace:** Capability-based integrations that never transfer custody of secrets.

---

## 8. Development Roadmap

### Phase 1: The Local Control Panel (Q3 2025)
*   Desktop App only.
*   Local key management (Hybrid PQ + EC) via `dcrypt` + Dual-Entropy Mnemonic.
*   Vault DB encryption (XChaCha20) + envelope keys (Argon2id).
*   Basic policy engine (Allow/Block) + audit log.
*   IOI Daemon / Guardian Profile Link + basic step-up flow.

### Phase 2: The Web Bridge & Extensibility (Q4 2025)
*   Browser extension bridge (WASM for channel crypto only).
*   “Connect with Vault” protocol via `wallet-sdk`.
*   Capability requests and programmatic domain integration.
*   Connector framework (`wallet-connector-*`) with OAuth + token brokerage.

### Phase 3: The Mobile Approver (Q1 2026)
*   Mobile notifier/approver app.
*   Out-of-band approvals via passkeys / FaceID.
*   Panic button + remote revocation.
*   Stronger step-up rules + anomaly triggers.

### Phase 4: Delegation Envelope + Advanced Hardening (Post Q1 2026)
*   RootGrant/SubGrant formalization (depth + issuance budgets).
*   Monotonic counter integration for anti-rollback/grinding where available.
*   Policy commitments + authority receipts recorded into Agentgres and optionally committed to IOI L1.
*   WASM/WASI Connector Marketplace activation.

---

## 9. Success Metrics

1.  **Vault Activations:** Users who stored at least one secret or onboarded one connector.
2.  **Session Density:** Autonomous actions per session (higher = better autonomy).
3.  **Intervention Rate:** High-risk actions intercepted and resolved successfully.
4.  **Policy Stability:** Percentage of actions executed without policy widening (healthy autonomy).
5.  **Delegation Safety:** Number of sub-grants issued that remain monotonic and within budgets.

---

## Appendix A — Web3 Account Control Model (Web4 Vault → Web3 Execution)

**Purpose:** Define how **`wallet.network`** (The Native Web4 Custodian) governs execution endpoints (smart accounts/EOAs) for users and agents, integrating legacy Web3 liquidity with Web4 security.

### A.1 Design Principles

1.  **Unified Sovereignty:** `wallet.network` serves as the ultimate custodian for both the assets (Funds) and the capabilities (Agency). 
2.  **Authority-Scope-First:** Agents receive **authority scope grants** (e.g., "Trade ETH for USDC on Uniswap"), never raw signing keys.
3.  **Approvals by Default Deny:** Token approvals (ERC-20 `approve`) default to **DENY** unless the contract, token, and amount are explicitly allowlisted.
4.  **On-Chain Enforcement:** Security constraints MUST survive a compromised runtime. High-risk actions require on-chain guarantees (Smart Account Modules).
5.  **Unified Audit:** Every action, whether on-chain or off-chain, yields a cryptographic receipt linked to a specific Policy Envelope.

---

### A.2 Account Roles (The Superset Topology)

1.  **The Master Custodian Account (Native `wallet.network`)**
    *   **Type:** Native Web4 Identity (Dual-Entropy Seed).
    *   **Purpose:** Holds the bulk of classical (ETH) and PQ assets (Service NFTs, Escrows). Secured by the highest configured threshold (e.g., 3FA/MPC).
    *   **Constraint:** **Never** directly connected to a running agent session.
2.  **The Agent Execution Account (Ops Wallet)**
    *   **Type:** Smart Account (ERC-4337, Safe, Kernel) with Policy Modules.
    *   **Purpose:** Routine autonomous execution.
    *   **Characteristics:** Limited funds (capped exposure), controlled by revocable **Session Keys**, subject to on-chain guards (Spending Limits, Allowlist).
3.  **The Web3 Cold Storage (Optional Linked EOA)**
    *   **Type:** External EOA / Hardware Wallet (MetaMask, Ledger).
    *   **Purpose:** Optional legacy storage. Can be used to deploy and fund the Ops Wallet via Smart Account delegation if the user wishes to keep their life savings out of the `wallet.network` seed.

---

### A.3 Control Mechanisms

`wallet.network` controls execution via three layers:

#### A.3.1 Policy Envelope (The Law)
*   **Definition:** Defined off-chain in the Vault. `PolicyCommitment` defines the `allowlist` (chains, contracts, selectors), `spend_caps`, `approval_limits`, and `step_up_triggers`.
*   **Enforcement:** Verified by the IOI daemon / Guardian profile before signing any intent.

#### A.3.2 Session Signers (The Keys)
*   **Type:** Ephemeral ECDSA/Ed25519 keys.
*   **Storage Invariant:** Private keys reside **solely** in IOI daemon / Guardian profile/executor memory (or TEE). They are **NEVER** persisted unencrypted and **NEVER** exposed to client apps/agents.
*   **Lifecycle:** Generated per-session, bounded by TTL, revocable via Epoch.

#### A.3.3 Smart Account Modules (The Enforcer)
*   **Type:** On-chain contracts (Validators/Guards).
*   **Role:** Enforce constraints (Spend Limits, Allowlisted Call Targets) at the blockchain level.
*   **Benefit:** Prevents a compromised IOI daemon / Guardian profile from draining the wallet beyond the limits.

---

### A.4 Risk Classification & Enforcement Requirements

Actions are classified by risk; enforcement strictness scales accordingly.

#### A.4.1 Low Risk (Autonomous)
*   *Examples:* Read-only calls, claiming rewards, swaps on allowlisted routers under strict slippage caps.
*   **Requirement:** Valid Grant + Valid Session Lease.
*   **Enforcement:** Off-chain IOI daemon / Guardian profile checks are sufficient. Receipts required.

#### A.4.2 Medium Risk (Restricted Autonomy)
*   *Examples:* Transfers under daily spend cap, interacting with curated contracts.
*   **Requirement:**
    *   **SHOULD** use On-Chain Module enforcement (Spend Limit).
    *   If On-Chain enforcement is unavailable, IOI daemon / Guardian profile **MUST** perform strict transaction simulation and rate-limiting.
    *   **MUST** block unknown token approvals.

#### A.4.3 High Risk (Step-Up Required)
*   *Examples:* New contract interaction, bridging, transfers > cap, policy widening.
*   **Requirement:**
    *   **MUST** be enforced via On-Chain Module (e.g., Multisig/Guard requiring User signature) **OR** require a direct Master Custodian Signature.
    *   **MUST** trigger Out-of-Band Step-Up (Phone/Passkey).
    *   Pure off-chain IOI daemon / Guardian profile checks are **insufficient**.

---

### A.5 Canonical Data Model: `TxIntent`

To ensure what the Agent requests is exactly what the User approves (and what the Chain executes), we define a canonical `TxIntent` object.

```rust
struct TxIntent {
    chain_id: u64,
    from: Address,      // Agent Account
    to: Address,        // Target Contract/Recipient
    value: U256,
    data: Bytes,        // Calldata
    nonce: u64,
    gas_limits: GasConfig,
    
    // Policy Bindings
    policy_hash: Hash,
    grant_id: Hash,
    lease_id: Hash,
    revocation_epoch: u64,
    
    // Safety Constraints
    slippage_bounds: Option<u64>, 
    simulation_hash: Hash, // Commitment to expected outcome
}
```
*   **Binding:** The `ApprovalToken` (A.7) signs the hash of `TxIntent`.
*   **Verification:** Smart Account Modules (Phase B) should ideally verify `policy_hash` or `lease_id` if supported.

---

### A.6 Funding & Exposure Controls

#### A.6.1 The "Token Approval" Invariant
*   **Default:** `DENY` all ERC-20 `approve` calls.
*   **Exception:** Allow only if `(Contract, Token, Amount)` is explicitly defined in the Policy Envelope.
*   **Preference:** Use `permit` (EIP-2612) with strict deadlines where possible.

#### A.6.2 Exposure Budget
*   **Rule:** Agent Accounts must be funded only with "Loss Tolerant" capital.
*   **Mechanism:** Master Custodian (or Linked Web3 Wallet) sends funds; Vault tracks "Burn Rate." Re-funding requires Step-Up.

---

### A.7 Step-Up & Approval Tokens

When a High-Risk action triggers a Step-Up:
1.  IOI daemon / Guardian profile pauses execution.
2.  User receives notification on Mobile/Desktop.
3.  User signs an `ApprovalToken` binding to `Hash(TxIntent)`.

**ApprovalToken Fields:**
*   `intent_hash` (The specific Tx)
*   `audience` (specific executor / IOI daemon / Guardian profile)
*   `mode` (`one_shot` default)
*   `expiry`
*   `sig_hybrid_user`

---

### A.8 Revocation & Emergency Stop

#### A.8.1 Off-Chain (Immediate)
*   **Action:** Bump `revocation_epoch`.
*   **Effect:** IOI daemon / Guardian profile rejects all `TxIntents` with old epochs. Immediate cessation of new signing.

#### A.8.2 On-Chain (Durable)
*   **Action:** Call `disableModule` or `rotateKey` on the Smart Account.
*   **Effect:** Invalidates the Session Key on-chain. Even a rogue Guardian cannot sign.

**Panic Button:** Triggers **both** A.8.1 and A.8.2 simultaneously.

---

### A.9 Implementation Roadmap

#### Phase A: The Guarded EOA (Fastest)
*   **Setup:** Master Custodian (or Tier-1 linked wallet) funds a standard EOA (Agent Account).
*   **Control:** Private Key in IOI daemon / Guardian profile memory (TEE/Secure Enclave).
*   **Enforcement:** Strict Off-Chain Policy checking + Simulation.
*   **Risk:** Relies on IOI daemon / Guardian profile integrity.

#### Phase B: The Smart Agent (Secure-by-Design)
*   **Setup:** Master Custodian deploys ERC-4337/Safe Account.
*   **Control:** Vault manages ephemeral Session Keys authorized as Module Signers.
*   **Enforcement:** **On-Chain Modules** for Spend Limits and Allowlist.
*   **Benefit:** High-Risk autonomy is now safe; compromised runtime cannot drain funds.

#### Phase C: Enterprise Fleet
*   **Setup:** Multiple Strategy Sub-Accounts.
*   **Control:** Hierarchical Grants, Aggregate Reporting.
*   **Enforcement:** On-Chain Receipt Anchoring for compliance.
