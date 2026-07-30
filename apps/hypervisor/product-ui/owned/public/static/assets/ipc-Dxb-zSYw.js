import { Js as e, cs as t, qs as n } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { r, t as i } from "./api-BgkI4l83.js";
import { t as a } from "./toast-axaLeIzZ.js";
import { a as o, i as s, o as c, r as l, s as u, t as d } from "./local-runner-CjYkmMpQ.js";
async function f(e) {
  return await new Promise((t) => {
    let n = e.actions?.[0],
      r = a({
        title: e.title,
        description: e.message,
        duration: e.duration,
        indefinite: e.indefinite,
        action: n
          ? {
              label: n,
              onClick: () => {
                (t({ action: n }), r.dismiss());
              },
              "data-tracking-id": `dismiss-notification-renderer-notifications`,
            }
          : void 0,
        onClose: () => {
          t({});
        },
      });
  });
}
var p = { type: `NotificationRendererService`, methods: { show: u() } };
window.ipcRenderer &&
  (o(s, window.ipcRenderer, {
    onDidChangeUser: (t) => {
      let r = () => {
        let e = n(),
          r;
        (e && (r = e), t({ userId: r }));
      };
      return (r(), e(r));
    },
    createRunner: async (e, n) => {
      let a = await i.runnerService.createRunner(
        { name: e.runnerName, provider: t.DESKTOP_MAC },
        r({ signal: n }, e.userId),
      );
      return {
        runnerId: a.runner?.runnerId || `unknown`,
        token: a.accessToken,
        endpoint: `${window.location.origin}/api`,
      };
    },
    createRunnerToken: async (e, t) => ({
      token: (await i.runnerService.createRunnerToken({ runnerId: e.runnerId }, r({ signal: t }, e.userId)))
        .accessToken,
    }),
    deleteRunner: async (e, t) => {
      await i.runnerService.deleteRunner({ runnerId: e.runnerId, force: e.force }, r({ signal: t }, e.userId));
    },
  }),
  o(p, window.ipcRenderer, { show: f }));
var m = window.ipcRenderer && c(l, window.ipcRenderer),
  h = window.ipcRenderer && c(d, window.ipcRenderer);
export { m as n, h as t };
