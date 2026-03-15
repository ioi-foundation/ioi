# Convergent Runbooks

## Registry Rollback Event

1. Freeze new committee and witness registrations.
2. Compare current registry root with the last anchored checkpoint.
3. Mark validators with stale registry epoch as non-voting.
4. Submit rollback evidence and, if needed, witness-fault evidence on-chain.
5. Resume only after epoch seed, active witness set, and committee manifests are re-anchored.

## Committee Member Compromise

1. Remove the compromised member from the next committee manifest.
2. Publish a new committee manifest and active epoch seed.
3. If conflicting certificates exist, submit divergence evidence immediately.
4. Rotate key-authority credentials for the affected provider or host class.

## Cross-Provider KMS Outage

1. Determine whether threshold is still reachable.
2. If threshold is not reachable, self-quarantine affected validators.
3. Rotate to a replacement committee only through a new registered manifest.
4. Do not downgrade to `DevMemory` or local fallbacks.

## Transparency Log Unavailability

1. If checkpoint anchoring is required, pause certificate issuance.
2. Keep gathering local evidence but do not treat it as production-valid finality input.
3. Resume only after the log checkpoint is anchored and freshness is restored.

## Witness Omission

1. Record deterministic assignment, reassignment depth, and timeout evidence.
2. Reassign within the configured maximum depth.
3. Submit witness fault evidence if omission persists.
4. Do not silently drop witnesses from the safety argument.
