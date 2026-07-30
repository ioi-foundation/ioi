import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { Er as t } from "./SegmentProvider-CXCNBY9U.js";
import { n } from "./@mux-DLaEVubF.js";
import { xg as r } from "./vendor-DAwbZtf0.js";
import { tr as i } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { d as a } from "./prebuild_pb-CVBD5kln.js";
import { n as o } from "./toast-axaLeIzZ.js";
var s = e(n(), 1),
  c = (e, n, a) => {
    let { toast: c } = o(),
      l = r(),
      u = t(),
      [d, f] = (0, s.useState)(!1);
    return {
      trigger: (0, s.useCallback)(async () => {
        if (e) {
          if (a === !1) {
            c({
              title: `Prebuilds are not enabled`,
              description: `Enable 'Prebuild Environments' in project settings to use prebuilds`,
            });
            return;
          }
          if (n.length === 0) {
            c({
              title: `No prebuild environment classes configured`,
              description: `Please configure environment classes for this project to run prebuilds`,
            });
            return;
          }
          try {
            f(!0);
            for (let t of n) await u.mutateAsync({ projectId: e, environmentClassId: t });
            let t = n.length;
            c({
              title: t === 1 ? `Prebuild triggered` : `${t} prebuilds triggered`,
              link: {
                label: `View prebuilds`,
                href: `/projects/${e}/prebuilds`,
                onClick: () => l(`/projects/${e}/prebuilds`),
                "data-tracking-id": `view-prebuilds-prebuild-button`,
              },
            });
          } catch (e) {
            c({ title: `Could not run prebuild`, description: i(e) });
          } finally {
            f(!1);
          }
        }
      }, [e, n, a, u, c, l]),
      isSubmitting: d,
    };
  },
  l = (e) => e === a.PENDING || e === a.STARTING || e === a.RUNNING || e === a.STOPPING || e === a.SNAPSHOTTING;
export { c as n, l as t };
