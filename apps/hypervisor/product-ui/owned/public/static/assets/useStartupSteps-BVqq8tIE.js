import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { n } from "./phase-DI4YEQQ1.js";
import { a as r, i, o as a, r as o, s, t as c } from "./environment-start-steps-state-D0khfUq8.js";
var l = e(t(), 1);
function u(e, t) {
  let n = 0,
    l = [
      {
        id: `provision`,
        index: n++,
        state: s(e),
        label: t.resuming ? `Starting machine` : `Provisioning machine`,
        description: t.resuming
          ? `Waking your environment from hibernation`
          : `Getting your remote isolated environment ready`,
      },
    ];
  t.resuming ||
    l.push({
      id: `clone`,
      index: n++,
      state: i(e),
      label: `Cloning repository`,
      description: `Cloning your repository into the environment`,
    });
  let u = a(e);
  u !== c.Empty &&
    l.push({
      id: `secrets`,
      state: u,
      index: n++,
      label: t.resuming ? `Updating secrets` : `Injecting secrets`,
      description: t.resuming
        ? `Ensuring secrets use the latest value`
        : `Ensuring organizational, user, and project secrets are available in the environment`,
    });
  let d = o(e);
  return (
    !t.resuming &&
      d !== c.Empty &&
      l.push({
        id: `automations`,
        index: n++,
        state: d,
        label: `Preparing automations`,
        description: `Loading automations from your repository`,
      }),
    l.push({
      id: `devcontainer`,
      index: n++,
      state: r(e).state,
      label: t.resuming ? `Starting dev container` : `Building dev container`,
      description: t.resuming
        ? `Making sure the dev container is up and running`
        : `Installing the tools, runtimes, and everything else you and your agents needs`,
    }),
    l
  );
}
function d(e) {
  let t = e.find((e) => e.state === c.Running);
  if (t) return { label: `${t.label}…`, id: t.id, description: t.description, index: t.index, state: t.state };
  let n = [...e].reverse().find((e) => e.state === c.Success || e.state === c.Warning);
  if (n) return { label: `${n.label}…`, id: n.id, description: n.description, index: n.index, state: n.state };
  let r = e[0];
  return {
    index: r ? r.index : 0,
    label: r ? `${r.label}…` : `Provisioning machine`,
    id: r?.id ?? `provision`,
    description: r ? r.description : `Starting your remote isolated environment`,
    state: c.Running,
  };
}
function f(e) {
  let t = (0, l.useMemo)(() => n(e), [e]),
    r = (0, l.useMemo)(() => u(e, t), [e, t]);
  return { steps: r, activeStep: (0, l.useMemo)(() => d(r), [r]) };
}
export { f as t };
