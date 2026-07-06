import { u as e } from "./runner_manager_pb-BYgy9Ytq.js";
function t(t) {
  return t?.status?.capabilities ? t.status.capabilities.includes(e.AGENT_EXECUTION) : !1;
}
function n(t) {
  return t?.status?.capabilities ? t.status.capabilities.includes(e.RUNNER_SIDE_AGENT) : !1;
}
function r(t) {
  return t?.status?.capabilities ? t.status.capabilities.includes(e.WARM_POOL) : !1;
}
function i(t) {
  return t?.status?.capabilities ? t.status.capabilities.includes(e.ASG_WARM_POOL) : !1;
}
function a(e) {
  return r(e) && !i(e);
}
function o(t) {
  return t?.status?.capabilities ? t.status.capabilities.includes(e.PORT_AUTHENTICATION) : !1;
}
export { a as i, o as n, n as r, t };
