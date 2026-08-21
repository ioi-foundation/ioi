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

Preferred evidence is a UTF-8 JSON object signed directly by the pinned Akash
provider operator key. The verifier derives the Akash bech32 address from the
supplied secp256k1 public key and requires it to equal the provider address;
merely writing the provider address beside an unrelated signing key is refused:

```json
{
  "schema_version": "ioi.aft.provider-placement-attestation.v2",
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
    "authority_ref": "akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk",
    "public_key_ref": "sha256:SPKI_DER_SHA256",
    "signature_algorithm": "secp256k1-sha256-der"
  },
  "signature": "..."
}
```

The provider signs UTF-8 canonical JSON (recursively sorted object keys, compact
encoding) with the `signature` field omitted. `signature` is base64 ECDSA over
SHA-256 using secp256k1, encoded as ASN.1 DER; P1363 is also supported when the
declared algorithm is `secp256k1-sha256-p1363`. `public_key_ref` is the
`sha256:` digest of the independently supplied SPKI DER public key. The verifier
derives the `akash1...` account address from that key, verifies the signature,
and checks every campaign field against both certified provider lifecycles. Run
`check:u1-placement-attestation` with the attestation, provider public-key file,
and campaign A/B certificates.

## Honesty-class ruling

- Complete, valid evidence for a reserved physical host permits
  `qualified_reserved_bare_metal`.
- Valid evidence for exclusive physical cores without an exclusive host permits
  `provider_attested_dedicated_cpu`.
- Missing, unsigned, generic, self-asserted, mismatched, or unverifiable evidence
  permits only `same_provider_container_unknown_host`.

The guest environment manifest remains useful variance evidence, but it cannot
upgrade the placement class by itself.
