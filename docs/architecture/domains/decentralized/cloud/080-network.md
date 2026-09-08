# 080 — Network: service and routed profiles, cross-provider fabric, discovery, ingress, addresses, egress, residency

Status: adopted product specification (owner, 2026-09-08); design baseline September 7, 2026.
Canonical owner: this file for network profiles, the cross-provider fabric, discovery, ingress, addresses, egress and residency.
Doctrine status: canonical
Implementation status: planned (the selected architecture, adopted 2026-09-08; nothing here is a claim that the product exists — what the Hypervisor daemon implements today is in `../cloud.md`)

**Spec section:** 15. **Depends on:** 010, 090, 190, 250. **Defines:** service-connect
and routed profiles, tunnels, isolation, egress, and path diagnostics; connection,
route, attachment, flow-meter schemas. **Required diagrams:** overlay, relay paths,
tenant isolation.

## 15. Networking

### 15.1 Two honest private-network profiles

**Service Network — default.**

Provides identity-based private connections between declared services using outbound authenticated tunnels and local/service proxies.

Supports the common application model:

```text
API → database
API → cache
worker → object service
frontend → API
```

It does not promise arbitrary layer-3 connectivity, broadcast, privileged networking, or every UDP workload.

**Routed Network — advanced.**

Provides isolated virtual subnets, private IPs, routed connectivity, and network policy on providers that support the required node/guest integration.

This distinction prevents the abstraction from making promises the provider cannot implement.

### 15.2 Cross-provider fabric

Use a sparse connectivity graph, not an all-to-all mesh:

```text
Workload or node connector
    → direct authenticated peer path when supported
    → otherwise regional relay
    → destination service connector
```

Use WireGuard for qualified routed paths and mutually authenticated service tunnels for portable application paths. WireGuard's cryptokey-routing model associates authenticated peers with permitted tunnel addresses; the cloud still owns address allocation, tenant isolation, policy, relay selection, and lifecycle. ([WireGuard][9])

Connectors initiate outbound sessions so provider NAT and inbound-port restrictions do not prevent basic service connectivity.

When UDP is unavailable, a service-tunnel profile may use TLS over TCP, with its performance limitations exposed to placement qualification.

### 15.3 Discovery and stable addresses

Service names resolve to logical destinations:

```text
api.service.<project>
postgres.service.<project>
objects.service.<project>
```

Where transparent DNS integration is unavailable, generated connection variables point to the portable service proxy.

Provider-native IPs are never the canonical application identity.

### 15.4 Public ingress

```text
Customer domain
→ platform-controlled DNS
→ qualified edge gateways
→ authenticated origin connection
→ current healthy service attempts
```

Use Envoy at platform gateways, with versioned configuration, staged publication, and backend readiness checks. Envoy's xDS interfaces provide dynamic configuration and acknowledgement mechanisms, but configuration propagation remains something the platform must sequence and verify. ([Envoy Proxy][10])

At launch, buy DDoS-protected edge capacity rather than attempting to invent a global scrubbing network.

A resilient ingress profile uses multiple qualified edge operators. DNS-level failover is not the same as seamless survival of existing TCP connections.

### 15.5 Public IPs

Offer:

```text
Shared HTTPS endpoint
Dedicated ingress address
Dedicated egress address
Advanced L4 endpoint
```

An address belongs to the gateway product and has a stated portability scope.

Do not advertise arbitrary provider IP portability. Akash's IP-lease documentation, for example, describes an address associated with the lease lifetime and distinguishes ingress addressing from egress behavior. ([Akash Network][11])

### 15.6 Egress, security, and observability

Default managed workloads use controlled egress paths where required for metering and policy.

Enforce:

```text
tenant-separated routing
identity-based connection authorization
default-deny service access
destination and port policy
connection and bandwidth quotas
IPv6-first internal addressing where supported
explicit IPv4 allocation
MTU/path diagnostics
flow telemetry
```

Cross-provider traffic is not "free internal traffic." Its price and performance must be included in placement.

### 15.7 Residency

A data-residency policy includes storage, backups, logs, model artifacts, secret release, TLS termination, and support access.

A guarantee about processing location does not automatically establish a guarantee about every Internet transit jurisdiction. Offer those as distinct policy concepts.

[9]: https://www.wireguard.com/
[10]: https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol
[11]: https://akash.network/docs/learn/core-concepts/ip-leases/
