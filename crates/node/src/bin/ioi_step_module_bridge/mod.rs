// Retired bridge module tombstone.
//
// Runtime command transport is owned by
// `ioi_services::agentic::runtime::kernel::command_dispatch`; the temporary
// `ioi-step-module-bridge` binary calls that service-kernel entry point
// directly. Keep this module empty so static conformance can prove old bridge
// wrappers, proof modules, helper imports, and command facades are not
// recreated here.
