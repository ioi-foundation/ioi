import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { Cn as t } from "./SegmentProvider-CXCNBY9U.js";
import { n } from "./@mux-DLaEVubF.js";
import { v_ as r, xg as i } from "./vendor-DAwbZtf0.js";
import { js as a, tr as o } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as s } from "./toast-axaLeIzZ.js";
import { t as c } from "./button-6YP03Qf2.js";
import { f as l, u } from "./automations-queries-HjQabXcP.js";
import { t as d } from "./IconStop-CQFVzze5.js";
import { t as f } from "./IconRefresh-Clasnt5q.js";
import { t as p } from "./PhaseLabel-D_o2DK40.js";
var m = e(n(), 1),
  h = r(),
  g = ({ taskExecution: e, task: n, environmentId: r }) => {
    let p = l(),
      g = u(),
      { toast: _ } = s(),
      v = i(),
      { ensureEnvironmentStarted: y, isStarting: b } = t(r),
      x = (0, m.useCallback)(async () => {
        await p.mutateAsync(
          { taskExecutionId: e.id, environmentId: r },
          { onError: (e) => _({ title: `Failed to stop ${n.metadata?.name || `task run`}`, description: o(e) }) },
        );
      }, [_, p, e, n, r]),
      S = (0, m.useCallback)(async () => {
        try {
          await y();
          let e = await g.mutateAsync(n.id);
          v(`/details/${r}/task/${n.id}/run/${e.id}`);
        } catch (e) {
          _({ title: `Failed to restart ${n.metadata?.name || `task`}`, description: o(e) });
        }
      }, [y, g, n.id, n.metadata?.name, v, r, _]),
      C = e.status?.phase === a.SUCCEEDED || e.status?.phase === a.FAILED || e.status?.phase === a.STOPPED,
      w = p.isPending || (!C && e.spec?.desiredPhase !== a.RUNNING);
    return (0, h.jsxs)(`div`, {
      className: `flex gap-2 self-center`,
      children: [
        !C &&
          (0, h.jsx)(c, {
            size: `sm`,
            variant: `secondary`,
            className: `min-h-7`,
            onClick: x,
            loading: w,
            LeadingIcon: d,
            "data-tracking-id": `stop-task-environment-task-run-actions`,
            children: `Stop`,
          }),
        C &&
          (0, h.jsx)(c, {
            size: `sm`,
            variant: `secondary`,
            className: `min-h-7`,
            onClick: S,
            loading: g.isPending || b,
            LeadingIcon: f,
            "data-tracking-id": `rerun-task-environment-task-run-actions`,
            children: `Re-run task`,
          }),
      ],
    });
  },
  _ = ({ taskExecution: e }) =>
    (0, h.jsx)(p, {
      phase: (0, m.useMemo)(() => {
        let t = e.status?.phase === a.SUCCEEDED || e.status?.phase === a.FAILED || e.status?.phase === a.STOPPED;
        if (e.spec?.desiredPhase === a.STOPPED && !t) return `stopping`;
        switch (e.status?.phase) {
          case a.SUCCEEDED:
            return `succeeded`;
          case a.FAILED:
            return `failed`;
          case a.RUNNING:
            return `running`;
          case a.PENDING:
            return `starting`;
          case a.STOPPED:
            return `stopped`;
          default:
            return `unspecified`;
        }
      }, [e.status?.phase, e.spec?.desiredPhase]),
    });
export { g as n, _ as t };
