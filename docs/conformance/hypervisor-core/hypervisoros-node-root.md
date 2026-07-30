# HypervisorOS Node-root Conformance

Status: conditional future profile. No current image, installer, or node-root
product is claimed.

A single-host node-root claim requires one signed installable image and
installer; admitted boot and update/rollback; hardware, storage, networking,
device and VMM readiness; daemon-root workload admission; node identity and
current attestation/enforcement evidence; break-glass policy; logs and support;
ordinary machine lifecycle; tamper, rollback, node-loss/rejoin, and recovery
labs; and verified cleanup.

Clustered/datacenter replacement is a distinct later profile requiring
membership, scheduling, storage/network continuity, fencing, HA and operational
support. Passing this single-node profile cannot imply it.
