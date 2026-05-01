# `ai://` Registry and Manifest Specification

## Canonical Definition

**`ai://` is the canonical Web4 naming and resolution scheme for intelligence, workers, services, applications, domains, manifests, and capabilities.**

IOI L1 provides the root registry for public `ai://` namespace commitments.

## Purpose

`ai://` answers:

- What is this worker/service/application/domain?
- Who published it?
- What version is active?
- Where is its manifest?
- What runtime profile does it require?
- What capabilities does it expose?
- How is it verified?
- Which contracts, Agentgres domain, and runtime endpoints serve it?

## What IOI L1 Registers

IOI L1 should register:

```text
namespace
publisher identity
manifest root
current version pointer
resolver endpoints
runtime profile
verification profile
contract addresses
revocation/deprecation status
```

## What Manifests Describe

A manifest may describe:

- application;
- worker;
- service;
- workflow;
- model endpoint;
- connector;
- Agentgres domain;
- runtime node;
- artifact package;
- policy profile;
- verification schema.

## Example Worker Manifest

```yaml
id: ai://workers.runtime-auditor.ioi
kind: worker
publisher: ioi://publisher/ioi
version: 1.0.3
manifest_root: bafy...
package:
  cid: bafy...
  sha256: ...
runtime:
  requires:
    - ioi-daemon>=0.8
    - agentgres>=0.1
capabilities:
  - git.read
  - file.read
  - test.run
permissions:
  code_write: approval_required
receipts:
  required: true
pricing:
  license: usage_metered
verification_profile: worker-receipt-v1
```

## Example Service Manifest

```yaml
id: ai://services.weekly-runtime-audit.sas
kind: service
provider: ioi://provider/acme
version: 2.1.0
service_contract: ioi://contract/service-order-v1
sla:
  delivery_window: 24h
  refund_policy: partial
outputs:
  - audit_report
  - evidence_bundle
  - hardening_tasks
runtime:
  modes:
    - hosted
    - enterprise_secure
```

## Resolution Flow

```text
client requests ai:// name
→ IOI L1 registry returns resolver/manifest commitment
→ client fetches manifest from resolver/Filecoin/CAS/CDN
→ client verifies hash/signature/root
→ client discovers contracts, Agentgres domain, runtime endpoints, package refs
→ wallet.network authorizes capability if needed
→ runtime executes or app renders
```

## Relationship to Independent Domains

Independent L1s or sovereign domains can register an `ai://` namespace without settling all state into IOI L1.

Their registry entry should include:

- domain ID;
- resolver endpoint;
- manifest root;
- proof/receipt schema;
- verification profile;
- runtime API profile.

## Versioning

Version pointers should distinguish:

- latest stable;
- latest canary;
- deprecated;
- revoked;
- security-blocked;
- local pinned version;
- enterprise-approved version.

## Security Invariants

1. No executable package without signed manifest.
2. No manifest update without publisher authority.
3. No package install without hash verification.
4. No hidden capability requirements outside manifest.
5. No silent downgrade or revoked-version install.
6. No marketplace listing without manifest root.

## One-Line Doctrine

> **`ai://` gives intelligence a name, a manifest, a publisher, a runtime profile, and a verification path.**

