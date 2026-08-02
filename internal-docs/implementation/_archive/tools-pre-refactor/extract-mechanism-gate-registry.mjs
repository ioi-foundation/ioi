#!/usr/bin/env node

// Migration-only extractor. It copied the approved PG definition rows from the
// preserved historical ledger into a status-free subordinate registry. Future
// definition changes are reviewed in the registry itself, not inferred from the
// archived ledger.

import fs from "node:fs";
import path from "node:path";
import { implementationRoot } from "./lib.mjs";

const sourcePath = path.join(implementationRoot, "_archive/plans/canon-mechanism-hardening-action-plan.md");
const targetPath = path.join(implementationRoot, "proof-gates/mechanism-gate-registry.md");
const source = fs.readFileSync(sourcePath, "utf8");
const rows = source.split(/\r?\n/u).filter((line) => /^\| PG-[0-9A-Z.]+ \|/u.test(line));
if (rows.length !== 58) {
  process.stderr.write(`expected 58 PG definition rows, found ${rows.length}\n`);
  process.exit(1);
}

const output = `---
document_class: implementation_module
sequencer: ../ioi-target-end-state-master-implementation-guide.md#62-production-gate-rail
stage_ids: [M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14]
work_packages: [R-OPS]
canon_owners:
  - docs/architecture/_meta/source-of-truth-map.md
  - docs/architecture/foundations/security-privacy-policy-invariants.md
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/architecture/components/daemon-runtime/platform-operability.md
owns: status-free PG identifiers, production-integration definitions, applicability semantics, and proof shapes
does_not_own: [sequence, status, architecture doctrine, product authority]
regeneration: none
---

# Mechanism Gate Registry

The master activates these gates and owning work-item records carry their
applicability and closure status. This registry contains no live disposition,
current-state summary, Cut order, or completion claim. A passing reference test
does not satisfy a production-integration gate.

Applicability values in records are \`required_now\`, \`conditional\`, \`later\`,
or \`out_of_scope\`. Closing one gate never closes another. Each closure needs
owner integration, real final-invoker behavior where consequential, positive
and zero-invoker negative proof, retained evidence, and the owning record's
exact content-bound literal exit.

| Gate | Required production integration | Closure evidence shape |
| --- | --- | --- |
${rows.join("\n")}

## Reusable adversarial proof shapes

| Boundary | Positive proof | Required negative proof |
| --- | --- | --- |
| Schema | All selected runtimes accept one golden object. | Missing condition, wrong enum, invalid ref, incompatible version. |
| Canonical hash | Independent runtimes reproduce the digest. | Type, version, domain, number, Unicode, or payload alteration. |
| Authority | A valid narrowed grant admits at the final PEP. | Widened child, wrong audience/holder, expired/revoked/stale grant; zero invoker calls. |
| Receipt export | Offline manifest/inclusion verifies. | Tamper, absent inclusion, inconsistent checkpoint, unknown signer. |
| Information flow | Admitted input reaches only an allowed destination. | Restrictive labels are dropped or untrusted input gains instruction authority. |
| Failover/fencing | A valid successor acts once. | Old-writer effect, stale read, missing CAS, skew or floor violation. |
| Work lifecycle | Retry/cancel/replay converges. | Duplicate effect, illegal transition, orphaned invocation/lease/reservation. |
| Embodied | The admitted non-live profile stays inside declared bounds. | Unassured input, late switch, ignored ODD exit, teleop loss, two writers. |
| Billing/dispute | Quote/hold/use/remedy reconcile. | Double debit, stale price, unauthorized adjudication, lost refund or bond. |
| Attestation | Fresh appraisal binds the exact workload. | Replayed nonce, changed build, stale result, self-declared hardware. |
| Recovery | Checkpoint restores the declared state/root. | Missing suffix silently accepted, schema guessed, or restored currentness inferred. |

Product authority remains local/domain policy plus the applicable authority
provider, including wallet.network where portable delegation or a designated
high-risk scope requires it. Unsigned review evidence cannot satisfy a PG gate
that requires product authority.
`;
fs.writeFileSync(targetPath, output);
process.stdout.write(`mechanism gate registry extracted: ${rows.length} status-free definitions\n`);

