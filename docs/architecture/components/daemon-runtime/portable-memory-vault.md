# Portable Memory Vault

Status: canonical architecture authority with an implemented initial contract (daemon `ioi_intelligence_routes.rs`)
Doctrine status: canonical
Implementation status: mixed (export/import with bidirectional credential scrub and basic memory-mutation review built; OutcomeRoom finding/attempt lineage, taint, license/export, and assurance gates planned)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/ioi_intelligence_routes.rs`
Last alignment pass: 2026-07-11.
Last implementation audit: 2026-07-05
Canonical owner: this file for the vault serialization format and the memory-mutation
proposal review lane. Object/envelope authority remains
`docs/architecture/foundations/common-objects-and-envelopes.md` (Agent Wiki / `ioi-memory`,
`ContextMutationEnvelope`, `MemoryProjection`).

## Doctrine

Persistent IOI Agent intelligence is workspace/project/domain daemon truth. Harness-local
memory is cache. Harnesses receive scoped `MemoryProjection`s, never the raw store — and they
**propose** durable changes, never write them silently (canon: "runs propose
ContextMutationEnvelope changes").

OutcomeRoom discussion, participant messages, attempts, findings, summaries,
leaderboard results, ontology mappings, and verifier suggestions are not memory
by default. They remain tainted provenance-bearing inputs until a memory
mutation proposal binds the source participant/domain and affiliation,
attempt/finding/result lineage, license/export and privacy policy, evidence and
assurance state, contradiction/supersession posture, and the declared
room/domain admission receipt. Participant agreement is never sufficient
promotion authority.

Negative and inconclusive results may be promoted when their admitted
information prevents repeated failure or improves verification, but their
memory representation must retain scope, applicability, uncertainty, and
counterevidence. Memory promotion does not automatically change an ontology,
route policy, evaluator, worker package, or production behavior; those use
their own proposal/evaluation/governance path.

## Vault format — `ioi.hypervisor.memory-vault.v1`

An Obsidian-class, human-readable bundle for a `MemorySpace` and its records:

```text
vault/
  space.md                    MemorySpace (frontmatter + description body)
  entries/<entry_id>.md       MemoryEntry
  skills/<skill_id>.md        SkillEntry
  affinities/<affinity_id>.md AutomationAffinity
manifest.json                 schema_version, space_ref, exported_at, counts,
                              sidecars.structured_payloads (JSON-only fields),
                              scrubbed (credential-scrub report; expected empty)
```

- Frontmatter lines are strict `key: <JSON value>` — human-readable and machine-exact
  (round-trips without a YAML dependency).
- Preserved verbatim: `memory-space://`, `memory-entry://`, `skill-entry://`,
  `automation-affinity://` refs, tags, source refs, confidence, sensitivity, compatibility
  refs, expiry, archive/revoke status, connector refs, timestamps.
- `structured_payload` travels ONLY in the manifest sidecar (Markdown cannot carry it safely).
- **No credential material, ever**: export scrubs-and-reports any record carrying credential
  markers; import rejects the whole bundle (`memory_vault_credential_material_forbidden`).

## Transport

- `GET  /v1/hypervisor/intelligence/spaces/:id/export` → `{ vault: { format, manifest, files } }`
- `POST /v1/hypervisor/intelligence/spaces/import`     → `{ imported, unchanged, conflicts, rejected }`

Import is idempotent and conflict-explicit: an existing record with identical content counts
as `unchanged`; a differing record with the same id is reported in `conflicts` and skipped —
never duplicated, never silently overwritten. Imported records pass the SAME validation gates
as live creation (entry-kind/sensitivity enums, connector-derived requires connector refs).

## Memory mutation proposals — `memory-mutation-proposal://ctxmut_*`

The review lane realizing `ContextMutationEnvelope` proposal semantics:

- `POST /v1/hypervisor/memory-mutation-proposals` — a harness/run proposes
  (`operation: add | supersede | archive`, canon `mutation_type` + `source_authority` enums,
  `suggested` payload, `target_ref`, `reason`, `confidence`, `source_run_ref`).
  The target contract additionally permits `outcome_room_ref`,
  `participant_ref`, `attempt_ref`, `finding_ref`, `work_result_ref`,
  `admission_receipt_ref`, `license_and_export_policy_refs`,
  `supporting_and_contradicting_evidence_refs`, and `assurance_stage`; these
  fields and their fail-closed validation remain planned.
- `POST …/:id/approve` — applies the durable change through the ordinary record gates and
  mints a `receipt_type: context_mutation` receipt (`receipt://hypervisor/memory-mutation/*`).
- `POST …/:id/reject` — the proposal remains as evidence with the review verdict.
- Review is one-shot; credential material is refused at propose time.
