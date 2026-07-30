# Hypervisor Workstation Conformance

Status: future selected-profile gate. The current microVM preview does not pass.

One first-time operator must complete, using daemon/Agentgres truth, host
readiness; empty inventory; create or import; CPU/RAM/disk/network
configuration; boot and desired-versus-observed readiness; scoped serial or SSH
access; stop/reboot; machine snapshot, restore, and clone; delete; and verified
cleanup. The release publishes the exact host, guest, architecture, backend,
firmware, disk, network, device, access, snapshot, and migration support matrix.

Unavailable backend, unsupported operation, permission denial, boot failure,
missing guest agent, network degradation, storage exhaustion, invalid restore,
orphan/unknown state, cleanup pending, and out-of-band mutation must be honest
recoverable states. Manual operation is complete without enabling WorkRuns,
Automations, Systems, or any autonomy capability.
