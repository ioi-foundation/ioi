# IOI Kernel Plugins

**Optional verification extensions for high-stakes agents.**

This directory contains **opt-in** crates that extend the IOI Kernel’s default safety model (**Level 1: Auditable receipts + policy enforcement**) with additional, *market-driven* assurance:

- **Level 2: Bonded / Insured** (handled by settlement + marketplace policy; not a plugin requirement)
- **Level 3: Certified (optional attestations)** via pluggable verifiers
- **Level 4: Enforced** via dispute settlement / arbitration lanes (evidence-first)

> **Thin Kernel, Thick Market.**  
> The Kernel ships a safe runtime and a deterministic evidence pipeline. Plugins are where specialized verification lives—only when an agent developer or user *chooses to pay for it*.

---

## 🧠 Architectural Philosophy

The core Kernel (e.g. `crates/node`, `crates/orchestration`) is designed to be **small, fast, and local-first**.

Plugins exist because “best practice” security is not one-size-fits-all:
- A desktop assistant should not compile heavy dependencies or download large verifier artifacts.
- A financial or infrastructure agent may need stronger assurances to earn trust, reduce premiums, or satisfy counterparties.

Plugins are therefore:
- **Optional** at build time (feature flags)
- **Pluggable** at runtime (registered verifier capabilities)
- **Evidence-driven** (consume receipts / proofs, return boolean judgments)

---

## ✅ What Plugins Are (and Aren’t)

### Plugins ARE:
- **Verifier drivers** (ZK, TEE attestation, TLS notarization, state proof verification)
- **Transport-agnostic proof tooling** (decode and verify evidence from external systems)
- **Reference implementations** for third-party assurance lanes

### Plugins are NOT:
- A required foundation for IOI
- A mandatory cross-chain bridge stack
- A promise that IOI validators generate proofs for users

If an agent wants “trustless $1M cross-chain transfers,” the *agent developer* bundles or depends on the relevant proving / attestation infra and pays the costs. IOI provides the **verification harness**.

---

## 📦 Crates in This Directory

| Crate | Status | Purpose |
| :--- | :--- | :--- |
| **`ibc-host`** | Active | Legacy name. A **proof host + ICS-23/IAVL utilities** for verifying membership proofs and deriving roots. Intended to evolve into a generic **transport proof host** rather than a “Cosmos/IBC identity.” |
| **`ioi-relayer`** | Active (tests/tools) | A native relayer + handshake harness used primarily for testing and dev workflows. Not a required runtime dependency for IOI as a product. |
| **`zk-driver-succinct`** | Alpha | Reference **Level 3 verifier** using SP1 / Succinct. Useful as a *plug-in example*, not as a core dependency. |
| **`sp1-guests`** | Alpha (support) | Guest programs / circuits used by the SP1-based verifier reference implementation. |
| **`zk-types`** | Active | Shared types for proof public inputs used by `zk-driver-succinct` and guest code. |
| **`tee-driver`** | Planned | Verifiers for TEE attestations (e.g., Nitro / SGX). |

> **Naming note:** expect ongoing renames as we demote “IBC/ZK as pillars” and promote “verification plugins as optional lanes.”  
> Concretely: `ibc-host` is a good candidate to rename to `transport-verifier` or `proof-host` once call sites are updated.

---

## 🔌 Integration

Plugins are integrated via **feature flags** and a **verifier registry**.

### Feature flags (recommended pattern)

```toml
# crates/node/Cargo.toml

[features]
default = []

# Minimal node / desktop runtime: no heavy verifiers
local-mode = []

# Validator / high-stakes profile: include optional verifiers
validator-mode = [
  "plugins/zk-driver-succinct",
  "plugins/ibc-host",
]
````

> Keep `ioi-local` lean. Enable plugins only for validator builds or agent-dev distributions that explicitly require them.

### Runtime registration (conceptual)

At startup, enabled plugins register capabilities like:

* “I can verify SP1 proofs for these VK hashes”
* “I can verify ICS-23 membership proofs”
* “I can verify Nitro attestation quotes”

The Kernel calls a plugin verifier only when an agent receipt or claim requires it (typically Level 3 / optional certification).

---

## 🛡 Security Model

Plugins must be treated as **untrusted extensions** even when maintained in-tree.

Guidelines:

1. **Deterministic inputs:** verification must be based on canonical, signed evidence (receipts, proof blobs, commitment roots).
2. **No ambient authority:** plugins should not gain filesystem/network access beyond what the Kernel explicitly provides.
3. **Config hygiene:** verification keys / trust anchors must be versioned, hashed, and loadable via explicit config.
4. **Fail-closed:** verification errors should fail the claim unless a policy explicitly allows “best effort.”

---

## 🧩 Contributing a Plugin

If you’re adding a new verification capability (e.g., TLSNotary, zk-email, hardware quote verifier):

1. Create a new crate under `crates/plugins/<your-plugin>/`.
2. Implement the relevant Kernel-facing trait(s) (e.g., a `Verifier`-style interface used by the registry).
3. Define a `Config` struct for trust anchors (VK bytes, cert chains, accepted measurement hashes, etc.).
4. Add a feature flag so it can be compiled **only when explicitly enabled**.
5. Document:

   * What the plugin verifies
   * What it does *not* verify
   * Threat model and expected evidence format

---

## 🚫 What We’re Avoiding (by design)

* Hard-coupling IOI identity to IBC
* Treating ZK as a default requirement for agent safety
* “IOI validators generate proofs for everyone” economics

Instead:

* **Receipts + policy + bonds/insurance + arbitration** are the default safety stack
* **Proof systems** are optional and supplied by agent developers or specialized providers
* IOI remains ecosystem-agnostic: Ethereum, Solana, Cosmos, Web2—whatever—via transport-agnostic verification plugins