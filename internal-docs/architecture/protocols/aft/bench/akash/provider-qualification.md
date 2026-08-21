# U1 provider qualification packet

Captured: 2026-08-21T16:23:02Z

Provider: `akash15tl6v6gd0nte0syyxnv57zmmspgju4c3xfmdhk`

Console provider name: `provider.hurricane.akash.pub`

Canonicalized provider-response SHA-256: `af3b720fae000fc299a0bd2b52ccda449815d375ad4c966390db09dfa3d8db0e`

## Independent provider facts

The Akash Console Providers API reported the exact provider online, on a valid version, officially audited, and at 100% one-day and seven-day uptime (99.9787% over 30 days). Its audited attributes identify a US colo operated by Overclock, x86-64 Intel CPU, DDR4 memory, 10 Gbps advertised network links, shared-memory support, and Akash host status.

Every listed attribute was signed by auditor `akash1365yvmc4s7awdyj3n2sav7xfx76adc6dnmlx63`. Akash documents provider audit as verification of on-chain attributes, infrastructure, and a long-running audit workload. Sources: [Providers API](https://akash.network/docs/api-documentation/rest-api/providers-api/), [Provider Audit](https://akash.network/docs/providers/operations/provider-audit/), and [Provider Attributes](https://akash.network/docs/providers/operations/provider-attributes/).

## Qualification decision

This provider is qualified for the tiny exact-provider C7 rerun and remains a
known bidder, online, officially audited, and capable of ordinary result
ingress. It is **not currently capacity-qualified for the planned U1
envelope**.

## Capacity refresh — 2026-08-21T19:14:44Z

A fresh provider-detail response remained online, audited, and version-valid,
but reported only `905` CPU units available against U1's planned `8000`, with
`17,202,253,312` bytes of memory available against the requested
`17,179,869,184`. Canonicalized response SHA-256:
`1c4e13136eca70a2ccc0f5607ba8be81fa440c7249bec96870c12c1a3deff7b8`.

The Console API's unauthenticated bid-screening endpoint was then evaluated
against one replica with 8000 CPU units, 16 GiB memory, 20 GiB ephemeral
storage, zero GPU, and a 1000 uact ceiling. It returned 53 eligible provider
records and did not include the C7 provider. Bid screening is spend-free and is
not a promise that any screened provider will bid after a deployment is funded.

The full providers inventory captured through
`2026-08-21T19:39:48.000Z` had canonicalized SHA-256
`e3b277bfc147e98664823d820dd50296bdef68170d54feb8af82afd890b8b5ee`.
Twenty-six providers were simultaneously online, audited, version-valid,
x86-64, and above the planned CPU, memory, and storage minima. Three
non-selected candidates retained for owner review are:

| Provider | Relevant live inventory | Qualification note |
|---|---|---|
| `akash19zzh7whjt4vfwxd5wtj3tjtyatnpntfhldshd8` (`provider.cpu.dal.aes.akash.pub`) | 28,115 CPU units; 147,866,385,408 memory bytes; AMD x86-64; DDR4; audited datacenter; advertised 10 Gbps; screened eligible; no open incident | Leading CPU-only capacity candidate; response SHA-256 `91323a09ffc865603c3347ae93254ea6424269b3d48faccc2fd000872df1ab1d` |
| `akash1ggfvyhr9sar4uxjs4hth3p4kzrwk7lysnenj3g` (`provider.cpu.phl.aes.akash.pub`) | 20,615 CPU units; 180,763,490,304 memory bytes; AMD x86-64; DDR4; audited datacenter; advertised 10 Gbps; screened eligible; no open incident | Capacity-qualified alternate; response SHA-256 `a3a3de017e64b8d2d12f0066605ba47b62bad3e1bdb0b51ae64e59e863d52c32` |
| `akash1aaul837r7en7hpk9wv2svg8u78fdq0t2j2e82z` (`provider.h6i-dedicated.eu-se-1.digitalfrontier.so`) | 96,105 CPU units; 445,642,622,464 memory bytes; Intel x86-64; DDR4 ECC; audited datacenter; screened eligible; no open incident | The provider name contains “dedicated,” but that is not tenant placement evidence; response SHA-256 `c0d000ca31568211ef0ecf1671696b067c4a127a4ddd77ad2635615a38a421e4` |

No candidate is selected by this packet. The owner must choose the exact pin,
and the selected record must be refreshed immediately before challenge review.
The U1 provider may differ from C7 without weakening C7's clean-rerun claim;
both U1 campaigns must use the same owner-approved U1 pin.

Current public operator contacts are `hosting@ovrclk.com` for both Overclock
CPU candidates and `admin@digitalfrontier.so` for the Digital Frontier
candidate. Recording these public contacts is not authorization to message
them. For the ordinary measured-container lane, Dallas is the leading current
choice because it has the strongest combination of available CPU, audited
10-Gbps datacenter attributes, perfect one- and seven-day uptime, and a
spend-free eligibility result. The string “dedicated” in the Digital Frontier
provider name is not a reason to elevate its placement class.

The Console API's spend-free pricing endpoint estimated the complete planned
8 CPU / 16 GiB / 20 GiB envelope at `$59.19/month` on 2026-08-21. This is a
market-level planning estimate, not the exact selected provider's bid. It does
not authorize a deposit or ceiling and does not supersede the daemon's dry
challenge. The runnable campaign configuration therefore retains explicit
owner-review placeholders for provider address, deposit, and `uact` ceiling.
The canonical pricing response captured at `2026-08-21T19:54:35Z` has SHA-256
`5c98c8e54c9324d5be7203c723538fd6677a91518ac52bdc504a1509711798a4`.

It is **not yet qualified as a dedicated bare-metal runner for this tenant workload**. `location-type=colo` and an audited provider describe the provider’s infrastructure; they do not prove that a specific Kubernetes container received a reserved physical host, non-oversubscribed cores, or stable host identity across leases. The workload environment manifest can identify the CPU/kernel visible inside each lease, but that observation is not a provider attestation.

Permitted pre-run label: `same exact audited provider; container allocation; physical-host dedication unproven`.

Class C bare-metal wording requires additional evidence that binds both campaigns to the same reserved host or an attested equivalent. Without it, the measurement may still be published as measured-container/variance-caveated evidence, but it must not close the bare-metal residual by implication.

## Live-campaign checks

Before each spend, refresh the provider record and compare its owner, audit status, online status, valid-version status, CPU architecture, and relevant audited attributes with this packet. After endpoint discovery, compare CPU model, online cores, memory, kernel, and governor between campaigns. Any provider-address mismatch, mutable image, missing result bundle, readiness failure, hardware-manifest mismatch, or open/unknown settlement exposure invalidates the campaign.
