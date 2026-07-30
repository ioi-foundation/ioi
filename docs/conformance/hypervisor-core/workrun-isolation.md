# WorkRun Isolation Conformance

Status: target profile. No shipped secure-sandbox claim is implied by this file.

The selected release passes only when risk compilation cannot be weakened by a
caller; each applicable WorkRun receives a fresh or explicitly admitted-reuse
boundary; inputs, image, VMM, guest agent, mounts, network identity, dependency
broker, capability leases, final invokers, output quarantine, and cleanup are
content-bound; and current capability plus enforcement evidence proves the
requested mechanisms.

Required negative cases include weaker recipe substitution, stale capability or
coverage, ambient host/home/daemon/container sockets, metadata/control-plane/
peer egress, raw secret access, package redirect/digest/size/budget violations,
direct external effects, unsafe archive members, output limit/scanner failure,
daemon loss, cancellation, timeout, uncertain effect, teardown failure, and
host fallback. Every denial reaches zero forbidden invokers. Every terminal or
ambiguous outcome either proves cleanup or retains a durable obligation.

Hostile-to-kernel or hostile-to-VMM work requires a separately disposable host;
a VM on a shared host does not pass that profile.

Machine-readable coverage: [workrun-isolation-matrix.v1.json](./workrun-isolation-matrix.v1.json).
