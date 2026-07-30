import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { n as t } from "./@mux-DLaEVubF.js";
import { cs as n } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { j as r } from "./environment-queries-zpiLcWfm.js";
import { m as i } from "./runner-queries-BAY_7mHt.js";
import { _ as a } from "./project-queries-BMZ3qCU_.js";
var o = e(t(), 1),
  s = (e) => {
    let { runners: t, isLoading: r } = i({});
    return {
      runners: (0, o.useMemo)(
        () =>
          t
            ? t.filter((t) => {
                if (t.provider === n.LINUX_HOST) return !1;
                let r = t.status?.additionalInfo?.find((e) => e.key === `apiEndpoint`)?.value;
                if (!r) return !1;
                try {
                  return new URL(r).hostname === e;
                } catch {
                  return !1;
                }
              })
            : [],
        [t, e],
      ),
      isLoading: r,
    };
  },
  c = ({ runnerId: e, runnerKinds: t }) => {
    let { data: n, isPending: i } = a({ runnerIds: e ? [e] : void 0, runnerKinds: t, page: 0 }),
      { data: o, isPending: s } = r(t ? { runnerKind: t[0] } : { runnerID: e });
    return {
      projectCount: n?.totalCount ?? 0,
      environmentCount: o?.environments.length ?? 0,
      hasMoreEnvironments: !!o?.nextToken,
      isLoading: i || s,
    };
  };
export { c as n, s as t };
