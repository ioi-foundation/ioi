# U1 provider placement attestation request

Status: pre-measurement template. Completing this document is evidence work; it
does not authorize a deployment or benchmark spend.

## Requested attestor

- Akash provider address:
  `akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk`
- Provider endpoint: `provider.hurricane.akash.pub`
- Attestor must identify their operational authority for this provider and bind
  the statement to the provider address above.

## Placement facts to attest

For each U1 deployment sequence (`dseq`) and campaign ID, state:

1. whether the tenant allocation ran directly on a physical host, in a virtual
   machine, or in a container on a shared Kubernetes node;
2. whether its eight allocated CPU units were dedicated/non-oversubscribed for
   the complete measurement interval;
3. the physical CPU vendor, family/model, socket count, physical-core count,
   thread count, SMT posture, and any frequency/governor constraint;
4. the maximum scheduler overcommit ratio and whether another tenant could run
   on the same physical cores during the measurement interval;
5. the enforced memory limit and whether memory ballooning or host swap could
   affect the allocation;
6. whether campaigns A and B ran on the same physical host and hardware
   configuration; and
7. a stable, pseudonymous host fingerprint derived by the provider that lets an
   independent verifier compare placements without revealing a serial number,
   management address, credential, or other host secret.

The statement must identify the observation interval, campaign IDs, dseqs,
provider address, immutable OCI digest, and exact resource allocation. Generic
marketing copy, provider-wide `location-type=colo`, guest-visible `/proc`
output, and audited provider attributes do not establish tenant-specific
dedicated bare-metal placement.

## Evidence form

Preferred evidence is a UTF-8 JSON object signed by the Akash provider operator
key or another independently resolvable operator key:

```json
{
  "schema_version": "ioi.aft.provider-placement-attestation.v1",
  "provider_address": "akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk",
  "campaigns": [
    {
      "campaign_id": "OWNER_APPROVED_CAMPAIGN_A",
      "dseq": "PROVIDER_DSEQ_A",
      "image_digest": "sha256:IMMUTABLE_IMAGE_DIGEST",
      "observed_from": "RFC3339",
      "observed_until": "RFC3339"
    },
    {
      "campaign_id": "OWNER_APPROVED_CAMPAIGN_B",
      "dseq": "PROVIDER_DSEQ_B",
      "image_digest": "sha256:IMMUTABLE_IMAGE_DIGEST",
      "observed_from": "RFC3339",
      "observed_until": "RFC3339"
    }
  ],
  "placement": {
    "class": "reserved_bare_metal | dedicated_physical_cores | shared_container",
    "same_physical_host": true,
    "host_fingerprint": "sha256:PROVIDER_DERIVED_PSEUDONYM",
    "cpu": {
      "vendor": "...",
      "family_model": "...",
      "sockets": 1,
      "physical_cores": 8,
      "threads": 16,
      "smt": "enabled | disabled",
      "governor_or_frequency_posture": "...",
      "maximum_overcommit_ratio": "1:1"
    },
    "memory": {
      "limit_bytes": 17179869184,
      "ballooning": false,
      "host_swap_during_interval": false
    }
  },
  "attestor": {
    "name_or_role": "...",
    "authority_ref": "...",
    "public_key_ref": "..."
  },
  "signature": "..."
}
```

The verifier hashes canonical JSON with the `signature` field omitted, resolves
the signer independently, verifies the signature, and checks every campaign
field against provider-native and C2 evidence.

## Honesty-class ruling

- Complete, valid evidence for a reserved physical host permits
  `qualified_reserved_bare_metal`.
- Valid evidence for exclusive physical cores without an exclusive host permits
  `provider_attested_dedicated_cpu`.
- Missing, unsigned, generic, mismatched, or unverifiable evidence permits only
  `same_provider_container_unknown_host`.

The guest environment manifest remains useful variance evidence, but it cannot
upgrade the placement class by itself.
