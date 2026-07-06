import { g_ as e } from "./vendor-DAwbZtf0.js";
import { Ga as t, ka as n } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { R as r, s as i } from "./agent-queries-CGWy3JAw.js";
var a = (function (e) {
  return (
    (e.Agent = `agent`),
    (e.Spec = `spec`),
    (e.Ralph = `ralph`),
    (e.CodexApp = `codex-app`),
    (e.CodexAppPlan = `codex-app-plan`),
    (e.CodexAppGoal = `codex-app-goal`),
    e
  );
})({});
function o(e) {
  return e === `spec` || e === `codex-app-plan`;
}
function s(e) {
  return e === `codex-app-goal`;
}
function c(e) {
  return e === `codex-app` || e === `codex-app-plan` || e === `codex-app-goal`;
}
function l(e, t) {
  let n = t.indexOf(e);
  return n === -1 ? t[0] : t[(n + 1) % t.length];
}
var u = {
  "codex-app": r.InEnvironmentCodexAppAgent.id,
  "codex-app-plan": r.InEnvironmentCodexAppAgent.id,
  "codex-app-goal": r.InEnvironmentCodexAppAgent.id,
};
function d(e) {
  return u[e];
}
function f(e) {
  if (e) return Object.entries(u).find(([, t]) => t === e)?.[0];
}
function p(e) {
  let t = d(e.agentMode);
  return t
    ? { selectedAgentId: t }
    : {
        selectedAgentId: e.selectedAgentId ?? void 0,
        defaultAgentId: f(e.defaultAgentId ?? void 0) === void 0 ? (e.defaultAgentId ?? void 0) : void 0,
      };
}
function m(e) {
  let t = [];
  (e.isCodexRolloutEnabled &&
    (t.push(`codex-app`), t.push(`codex-app-plan`), e.isCodexGoalModeEnabled && t.push(`codex-app-goal`)),
    t.push(`agent`),
    t.push(`spec`),
    e.isRalphModeEnabled && t.push(`ralph`));
  let n = f(i({ defaultAgentId: e.defaultAgentId, rsaEnabled: e.rsaEnabled }).agentId);
  return (n && !c(n) && !t.includes(n) && t.push(n), t);
}
function h(e) {
  return v(e)[0] ?? e[0] ?? `agent`;
}
function g(e) {
  let t = e.isCodexRolloutEnabled ? h(e.availableModes) : void 0;
  return [e.defaultAgentMode, t].find((t) => t && e.availableModes.includes(t));
}
function _(e) {
  return e.filter((e) => !c(e));
}
function v(e) {
  return e.filter(c);
}
function y(e, t) {
  let n = c(e) ? v(t) : _(t);
  return n.length > 0 ? n : t;
}
var b = `/ioi:ralph`,
  x = `/ioi:spec`,
  S = `/ioi:goal`;
function C(e, t) {
  return t === `ralph` ? `${b} ${e}` : o(t) ? `${x} ${e}` : s(t) ? `${S} ${e}` : e;
}
function w(r) {
  let i = [];
  if ((r && o(r) && i.push(n.SPEC), r && s(r) && i.push(n.GOAL), i.length !== 0)) return e(t, { modes: i });
}
var T = {
  agent: { label: `Agent`, description: `For executing multi-step work.` },
  spec: { label: `Plan`, description: `For defining requirements and intent.` },
  ralph: { label: `Ralph`, description: `For iterative work with a feedback loop.` },
  "codex-app": { label: `Agent`, description: `Use for implementation and code changes.` },
  "codex-app-plan": { label: `Plan`, description: `Use to scope work before changing code.` },
  "codex-app-goal": { label: `Goal`, description: `Use to set a persistent objective.` },
};
function E(e) {
  return T[e]?.label ?? `Agent`;
}
function D(e) {
  return T[e]?.description ?? ``;
}
function O(e) {
  if (o(e)) return `Outline requirements, constraints, and success criteria`;
  switch (e) {
    case `ralph`:
      return `Describe goals, constraints, or priorities`;
    case `codex-app-goal`:
      return `Set or update Codex's current goal`;
    default:
      return `Describe your task or type / for commands`;
  }
}
function k(e) {
  if (o(e)) return `rgb(var(--surface-prompt-spec) / var(--surface-prompt-spec-opacity))`;
  if (s(e)) return `rgb(var(--surface-prompt-ralph) / var(--surface-prompt-ralph-opacity))`;
  switch (e) {
    case `ralph`:
      return `rgb(var(--surface-prompt-ralph) / var(--surface-prompt-ralph-opacity))`;
    default:
      return `rgb(var(--surface-muted) / var(--surface-muted-opacity))`;
  }
}
export {
  s as _,
  D as a,
  O as c,
  v as d,
  f,
  c as g,
  w as h,
  y as i,
  p as l,
  g as m,
  C as n,
  k as o,
  _ as p,
  l as r,
  E as s,
  a as t,
  m as u,
  o as v,
};
