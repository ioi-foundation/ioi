import { a as e } from "./rolldown-runtime-CGYlQKCx.js";
import { Er as t, jr as n } from "./SegmentProvider-CXCNBY9U.js";
import { n as r } from "./@mux-DLaEVubF.js";
import { v_ as i, xg as a } from "./vendor-DAwbZtf0.js";
import { Dt as o, Lr as s, tr as c } from "./use-boot-in-app-chat-t-J_VjKS.js";
import { n as l, t as u } from "./toast-axaLeIzZ.js";
import { t as d } from "./button-6YP03Qf2.js";
import { t as f } from "./dialog-BtjFqa-w.js";
import { t as p } from "./text-fFCFeCas.js";
import { t as m } from "./use-resource-permission-Dd1Jv7de.js";
import { n as h, r as g, t as _ } from "./dropdown-menu-D3UmjGpQ.js";
import { o as v } from "./project-queries-BMZ3qCU_.js";
import { t as y } from "./use-share-resource-CE0EPrcD.js";
var b = e(r(), 1),
  x = i(),
  S = ({ actions: e, includeEdit: t = !1 }) => {
    let {
        canShare: n,
        canEdit: r,
        canDelete: i,
        prebuildsEnabled: a,
        isTriggeringPrebuild: o,
        handleCopyId: s,
        handleCopyUrl: c,
        handleTriggerPrebuild: l,
        handleShare: u,
        handleEdit: d,
        handleDelete: f,
      } = e,
      p = t && r,
      m = n || p || i;
    return (0, x.jsxs)(x.Fragment, {
      children: [
        (0, x.jsx)(g.Item, { onClick: s, "data-tracking-id": `copy-id-project-actions`, children: `Copy ID` }),
        (0, x.jsx)(g.Item, { onClick: c, "data-tracking-id": `copy-url-project-actions`, children: `Copy URL` }),
        a &&
          (0, x.jsxs)(x.Fragment, {
            children: [
              (0, x.jsx)(g.Separator, { className: `bg-content-tertiary/20` }),
              (0, x.jsx)(g.Item, {
                onClick: l,
                disabled: o,
                "data-testid": `project-actions-dropdown-trigger-prebuild`,
                "data-tracking-id": `trigger-prebuild-project-actions`,
                children: o ? `Running prebuild...` : `Run prebuild`,
              }),
            ],
          }),
        m &&
          (0, x.jsxs)(x.Fragment, {
            children: [
              (0, x.jsx)(g.Separator, { className: `bg-content-tertiary/20` }),
              n &&
                (0, x.jsx)(g.Item, {
                  onClick: u,
                  "data-testid": `project-actions-dropdown-share`,
                  "data-tracking-id": `share-project-actions`,
                  children: `Share project`,
                }),
              p &&
                (0, x.jsx)(g.Item, {
                  onClick: d,
                  "data-testid": `project-actions-dropdown-edit`,
                  "data-tracking-id": `edit-project-actions`,
                  children: `Edit`,
                }),
              i &&
                (0, x.jsx)(g.Item, {
                  onClick: f,
                  className: `text-content-red`,
                  "data-tracking-id": `delete-project-actions`,
                  children: `Delete`,
                }),
            ],
          }),
      ],
    });
  },
  C = ({ open: e, projectWithState: { project: t, state: r }, onClose: i, onDeleted: a }) => {
    let { toast: s } = l(),
      u = v(),
      m = n(e ? t.id : void 0),
      h = (e) => {
        e || i();
      },
      g = (0, b.useCallback)(() => {
        u.mutate(
          { projectId: t.id },
          {
            onSuccess: () => {
              (s({ title: `Project deleted` }), i(), a?.());
            },
            onError: (e) => {
              s({ title: `Failed to delete project`, description: c(e) });
            },
          },
        );
      }, [u, i, a, t, s]);
    return (0, x.jsx)(f, {
      open: e,
      onOpenChange: h,
      children: (0, x.jsxs)(f.Content, {
        className: `max-w-xl`,
        "data-track-location": o.ProjectDeleteModal,
        children: [
          (0, x.jsxs)(f.Header, {
            children: [
              (0, x.jsx)(f.Title, { children: `Delete project` }),
              (0, x.jsxs)(f.Description, {
                children: [
                  (m.data?.prebuilds.length ?? 0) > 0
                    ? (0, x.jsxs)(x.Fragment, {
                        children: [
                          (0, x.jsx)(p, {
                            children: `All prebuilds associated with this project will also be deleted.`,
                          }),
                          (0, x.jsxs)(p, {
                            className: `font-bold`,
                            children: [
                              `This will affect `,
                              m.data?.prebuilds.length,
                              ` prebuild`,
                              (0, x.jsx)(`span`, { children: (m.data?.prebuilds.length ?? 0) > 1 ? `s` : `` }),
                              `.`,
                            ],
                          }),
                        ],
                      })
                    : (0, x.jsx)(p, { children: `There are no prebuilds associated with this project.` }),
                  (0, x.jsx)(p, { children: `Are you sure you'd like to delete it?` }),
                ],
              }),
            ],
          }),
          (0, x.jsx)(f.Body, {
            className: `flex flex-col gap-4`,
            children: (0, x.jsx)(`div`, {
              className: `group flex flex-col justify-between gap-4 overflow-x-hidden rounded-xl border border-border-base bg-surface-glass px-4 py-2.5 pl-3`,
              children: (0, x.jsxs)(`div`, {
                className: `flex flex-col`,
                children: [
                  (0, x.jsx)(p, { className: `text-base font-bold`, children: t.metadata?.name }),
                  (0, x.jsxs)(p, {
                    className: `text-sm text-content-secondary`,
                    children: [
                      r.shared &&
                        (0, x.jsxs)(`span`, { children: [`Shared · used by `, t.usedBy?.totalSubjects, ` members`] }),
                      !r.shared && (0, x.jsx)(`span`, { children: `Not shared` }),
                    ],
                  }),
                ],
              }),
            }),
          }),
          (0, x.jsxs)(f.Footer, {
            children: [
              (0, x.jsx)(f.Close, {
                asChild: !0,
                children: (0, x.jsx)(d, {
                  type: `button`,
                  variant: `outline`,
                  onClick: i,
                  "data-tracking-id": `cancel-delete-project-modal`,
                  children: `Cancel`,
                }),
              }),
              (0, x.jsx)(d, {
                autoFocus: !0,
                variant: `destructive`,
                loading: u.isPending,
                onClick: g,
                "data-tracking-id": `confirm-delete-project-modal`,
                children: `Yes, delete`,
              }),
            ],
          }),
        ],
      }),
    });
  };
function w(e, { enabled: n = !0 } = {}) {
  let r = a(),
    { openShareDialog: i } = y(),
    o = t(),
    [l, d] = (0, b.useState)(!1),
    [f, p] = (0, b.useState)(!1),
    { hasPermission: h } = m(s.PROJECT, e?.id ?? ``, `project:grant`, { enabled: n }),
    { hasPermission: g } = m(s.PROJECT, e?.id ?? ``, `project:update`, { enabled: n }),
    { hasPermission: _ } = m(s.PROJECT, e?.id ?? ``, `project:delete`, { enabled: n }),
    v = e?.prebuildConfiguration?.enabled ?? !1,
    x = (0, b.useCallback)(async () => {
      if (e)
        try {
          (await navigator.clipboard.writeText(e.id),
            u({ title: `Project ID copied to clipboard`, description: e.id }));
        } catch (e) {
          u({ title: `Failed to copy ID to your clipboard`, description: c(e) });
        }
    }, [e]),
    S = (0, b.useCallback)(async () => {
      if (e)
        try {
          (await navigator.clipboard.writeText(`${window.location.origin}/projects/${e.id}`),
            u({ title: `Project URL copied to clipboard` }));
        } catch (e) {
          u({ title: `Failed to copy URL to your clipboard`, description: c(e) });
        }
    }, [e]),
    C = (0, b.useCallback)(async () => {
      if (!e) return;
      if (!e.prebuildConfiguration?.enabled) {
        u({
          title: `Prebuilds are not enabled`,
          description: `Please enable prebuilds in project settings to run prebuilds`,
        });
        return;
      }
      let t = e.prebuildConfiguration.environmentClassIds ?? [];
      if (t.length === 0) {
        u({
          title: `No prebuild environment classes configured`,
          description: `Please configure environment classes for this project to run prebuilds`,
        });
        return;
      }
      try {
        d(!0);
        for (let n of t) await o.mutateAsync({ projectId: e.id, environmentClassId: n });
        let n = t.length;
        u({
          title: n === 1 ? `Prebuild triggered` : `${n} prebuilds triggered`,
          link: {
            label: `View prebuilds`,
            href: `/projects/${e.id}/prebuilds`,
            onClick: () => r(`/projects/${e.id}/prebuilds`),
            "data-tracking-id": `view-prebuilds-prebuild-button`,
          },
        });
      } catch (e) {
        u({ title: `Could not run prebuild`, description: c(e) });
      } finally {
        d(!1);
      }
    }, [e, o, r]),
    w = (0, b.useCallback)(() => {
      e && i({ resourceType: s.PROJECT, resourceId: e.id, resourceName: e.metadata?.name || `Untitled Project` });
    }, [e, i]),
    T = (0, b.useCallback)(() => {
      e && r(`/projects/${e.id}`);
    }, [r, e]),
    E = (0, b.useCallback)(() => {
      p(!0);
    }, []);
  if (e)
    return {
      canShare: h,
      canEdit: g,
      canDelete: _,
      prebuildsEnabled: v,
      isTriggeringPrebuild: l,
      showDeleteModal: f,
      setShowDeleteModal: p,
      handleCopyId: x,
      handleCopyUrl: S,
      handleTriggerPrebuild: C,
      handleShare: w,
      handleEdit: T,
      handleDelete: E,
    };
}
var T = ({ projectWithState: e, includeEdit: t, buttonSize: n = `sm`, buttonVariant: r = `ghost`, onDeleted: i }) => {
  let [a, o] = (0, b.useState)(!1),
    s = (0, b.useCallback)(() => {
      a || o(!0);
    }, [a]),
    c = w(e?.project, { enabled: a });
  return c
    ? (0, x.jsxs)(`div`, {
        className: `flex items-center`,
        onClick: (e) => {
          e.stopPropagation();
        },
        "data-tracking-id-none": !0,
        children: [
          (0, x.jsx)(_, {
            triggerTestId: `project-actions-dropdown-trigger`,
            triggerButton: (0, x.jsx)(d, {
              variant: r,
              "aria-label": `More actions`,
              LeadingIcon: h,
              size: n,
              onMouseEnter: s,
              onFocus: s,
            }),
            contentClassName: `w-48`,
            children: (0, x.jsx)(S, { actions: c, includeEdit: t }),
          }),
          e &&
            (0, x.jsx)(C, {
              open: c.showDeleteModal,
              projectWithState: e,
              onClose: () => c.setShowDeleteModal(!1),
              onDeleted: i,
            }),
        ],
      })
    : null;
};
export { S as i, w as n, C as r, T as t };
