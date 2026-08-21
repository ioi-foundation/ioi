# U1 provider qualification packet

Captured: 2026-08-21T16:23:02Z

Provider: `akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk`

Console provider name: `provider.hurricane.akash.pub`

Canonicalized provider-response SHA-256: `af3b720fae000fc299a0bd2b52ccda449815d375ad4c966390db09dfa3d8db0e`

## Independent provider facts

The Akash Console Providers API reported the exact provider online, on a valid version, officially audited, and at 100% one-day and seven-day uptime (99.9787% over 30 days). Its audited attributes identify a US colo operated by Overclock, x86-64 Intel CPU, DDR4 memory, 10 Gbps advertised network links, shared-memory support, and Akash host status.

Every listed attribute was signed by auditor `akash1365yvmc4s7awdyj3n2sav7xfx76adc6dnmlx63`. Akash documents provider audit as verification of on-chain attributes, infrastructure, and a long-running audit workload. Sources: [Providers API](https://akash.network/docs/api-documentation/rest-api/providers-api/), [Provider Audit](https://akash.network/docs/providers/operations/provider-audit/), and [Provider Attributes](https://akash.network/docs/providers/operations/provider-attributes/).

## Qualification decision

This provider is qualified for an exact-provider, same-provider container measurement. It is a known bidder from C7, currently online, officially audited, and exposes the result ingress needed by U1.

It is **not yet qualified as a dedicated bare-metal runner for this tenant workload**. `location-type=colo` and an audited provider describe the provider’s infrastructure; they do not prove that a specific Kubernetes container received a reserved physical host, non-oversubscribed cores, or stable host identity across leases. The workload environment manifest can identify the CPU/kernel visible inside each lease, but that observation is not a provider attestation.

Permitted pre-run label: `same exact audited provider; container allocation; physical-host dedication unproven`.

Class C bare-metal wording requires additional evidence that binds both campaigns to the same reserved host or an attested equivalent. Without it, the measurement may still be published as measured-container/variance-caveated evidence, but it must not close the bare-metal residual by implication.

## Live-campaign checks

Before each spend, refresh the provider record and compare its owner, audit status, online status, valid-version status, CPU architecture, and relevant audited attributes with this packet. After endpoint discovery, compare CPU model, online cores, memory, kernel, and governor between campaigns. Any provider-address mismatch, mutable image, missing result bundle, readiness failure, hardware-manifest mismatch, or open/unknown settlement exposure invalidates the campaign.
